use super::test::{TestAgent, progress};
use super::*;
use std::time::Duration;
use tracing::info_span;

fn peers() -> (TestAgent, TestAgent) {
    let mut a = TestAgent::new(info_span!("L"));
    let mut b = TestAgent::new(info_span!("R"));
    let ca = Candidate::host("192.0.2.1:10000".parse().unwrap(), "udp").unwrap();
    let cb = Candidate::host("192.0.2.2:10000".parse().unwrap(), "udp").unwrap();
    a.add_local_candidate(ca.clone());
    b.add_remote_candidate(ca);
    b.add_local_candidate(cb.clone());
    a.add_remote_candidate(cb);
    a.set_controlling(true);
    b.set_controlling(false);
    while !a.state().is_connected() || !b.state().is_connected() {
        progress(&mut a, &mut b);
    }
    (a, b)
}

fn retire(a: &mut TestAgent, b: &mut TestAgent) {
    let at = a.time.max(b.time) + Duration::from_secs(31);
    a.time = at;
    b.time = at;
    a.handle_timeout(at);
    b.handle_timeout(at);
    while a.poll_transmit().is_some() {}
    while b.poll_transmit().is_some() {}
    a.progress_count = 0;
    b.progress_count = 0;
    assert!(!a.state().is_connected() && !b.state().is_connected());
}

fn restart(a: &mut TestAgent, b: &mut TestAgent, fresh: bool) {
    let ca = if fresh {
        IceCreds::new()
    } else {
        a.local_credentials().clone()
    };
    let cb = if fresh {
        IceCreds::new()
    } else {
        b.local_credentials().clone()
    };
    a.ice_restart(ca.clone(), true);
    b.ice_restart(cb.clone(), true);
    a.set_remote_credentials(cb);
    b.set_remote_credentials(ca);
    a.add_remote_candidate(Candidate::host("192.0.2.2:10000".parse().unwrap(), "udp").unwrap());
    b.add_remote_candidate(Candidate::host("192.0.2.1:10000".parse().unwrap(), "udp").unwrap());
    a.progress_count = 0;
    b.progress_count = 0;
}

#[test]
fn expired_tuple_requires_fresh_credentials_even_after_restart() {
    let (mut a, mut b) = peers();
    retire(&mut a, &mut b);
    restart(&mut a, &mut b, false);
    for _ in 0..20 {
        progress(&mut a, &mut b);
    }
    assert!(!a.state().is_connected() && !b.state().is_connected());
    restart(&mut a, &mut b, true);
    while !a.state().is_connected() || !b.state().is_connected() {
        progress(&mut a, &mut b);
    }
}

#[test]
fn retired_tuples_share_candidate_capacity_and_restart_releases_it() {
    let (mut a, mut b) = peers();
    a.set_max_candidate_pairs(1);
    b.set_max_candidate_pairs(1);
    retire(&mut a, &mut b);
    for port in 20000..20010 {
        a.add_remote_candidate(
            Candidate::host(format!("192.0.2.2:{port}").parse().unwrap(), "udp").unwrap(),
        );
    }
    for _ in 0..20 {
        progress(&mut a, &mut b);
    }
    assert!(
        a.poll_transmit().is_none(),
        "retired slot must not be evicted to probe another tuple"
    );
    assert!(!a.state().is_connected());
    restart(&mut a, &mut b, true);
    while !a.state().is_connected() || !b.state().is_connected() {
        progress(&mut a, &mut b);
    }
}

#[test]
fn restarted_generation_forbidden_does_not_revoke_old_selected_transport() {
    use crate::stun::{StunMessage, StunMessageBuilder, StunPacket};
    let (mut a, mut b) = peers();
    let old_a = a.local_credentials().clone();
    let old_b = b.local_credentials().clone();
    let ca = IceCreds::new();
    let cb = IceCreds::new();
    let mut now = a.time.max(b.time);
    a.ice_restart(ca.clone(), true);
    b.ice_restart(cb.clone(), true);
    a.set_remote_credentials(cb.clone());
    b.set_remote_credentials(ca.clone());
    a.add_remote_candidate(Candidate::host("192.0.2.2:10000".parse().unwrap(), "udp").unwrap());
    b.add_remote_candidate(Candidate::host("192.0.2.1:10000".parse().unwrap(), "udp").unwrap());
    let finish = now + Duration::from_secs(40);
    let tuple = (
        Protocol::Udp,
        "192.0.2.1:10000".parse().unwrap(),
        "192.0.2.2:10000".parse().unwrap(),
    );
    let mut rejected = false;
    let mut new_checks_after_rejection = 0;
    while now < finish {
        a.handle_timeout(now);
        b.handle_timeout(now);
        for from_a in [true, false] {
            loop {
                let packet = if from_a {
                    a.poll_transmit()
                } else {
                    b.poll_transmit()
                };
                let Some(packet) = packet else { break };
                let message = StunMessage::parse(&packet.contents).unwrap();
                let old_name = if from_a {
                    format!("{}:{}", old_b.ufrag, old_a.ufrag)
                } else {
                    format!("{}:{}", old_a.ufrag, old_b.ufrag)
                };
                if message.is_binding_request() && message.username() != Some(old_name.as_str()) {
                    if from_a && !rejected {
                        let reply = StunMessageBuilder::new()
                            .binding()
                            .failure()
                            .error_code(403, "Forbidden")
                            .build(message.trans_id());
                        let mut bytes = vec![0; 1500];
                        let len = reply
                            .to_bytes(Some(cb.pass.as_bytes()), &mut bytes, |key, data| {
                                crate::DefaultSha1HmacProvider.sha1_hmac(key, data)
                            })
                            .unwrap();
                        let reply = StunMessage::parse(&bytes[..len]).unwrap();
                        a.handle_packet(
                            now,
                            StunPacket {
                                proto: packet.proto,
                                source: packet.destination,
                                destination: packet.source,
                                message: reply,
                            },
                        );
                        rejected = true;
                    } else if from_a {
                        new_checks_after_rejection += 1;
                    }
                    continue;
                }
                let incoming = StunPacket {
                    proto: packet.proto,
                    source: packet.source,
                    destination: packet.destination,
                    message,
                };
                if from_a {
                    b.handle_packet(now, incoming);
                } else {
                    a.handle_packet(now, incoming);
                }
            }
        }
        assert!(
            a.can_send(now, tuple.0, tuple.1, tuple.2),
            "new-generation revocation must preserve independently authorized old path"
        );
        now += Duration::from_millis(50);
    }
    assert!(rejected);
    assert_eq!(
        new_checks_after_rejection, 0,
        "current tuple stays retired in its own generation"
    );
}
