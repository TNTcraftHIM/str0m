//! Owned RTC peers and synthetic RTP/SCTP in memory. No sockets are opened.
use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};
use str0m::{
    Candidate, Event, Input, Output, Rtc,
    format::Codec,
    media::{Direction, MediaKind},
    net::{Receive, Transmit},
    rtp::RtpWrite,
};

#[derive(Clone, Copy, Debug, PartialEq)]
enum Link {
    Healthy,
    NoResponse,
    Silent,
    Recover,
    LiteSender,
    LiteReceiver,
    Restart,
    RepeatedRestart,
    RestartNoResponse,
    RestartTuple,
    WrongTuple,
    DelayedWake,
    Forbidden,
    UnauthForbidden,
    Replay,
    RestartUnboundRequest,
    AlternateAfterExpiry,
    FreshAfterExpiry,
    ReaddBeforeExpiry,
    RoleConflict,
    RestartRoleConflict,
    ReaddAfterExpiry,
    OldTupleReturns,
    ForbiddenAlternate,
}

#[derive(Default)]
struct Observation {
    last_success: Option<Instant>,
    requests_received: u64,
    responses_dropped: u64,
    messages: u64,
    rtp_received: u64,
    late_transmits: u64,
    last_application: Option<Instant>,
    state: Vec<String>,
    closed: [Option<Instant>; 2],
    restart_messages: u64,
    final_messages: u64,
    latest_tuple_transmits: u64,
    rtp_sent: u64,
    dtls_sent: u64,
    rtcp_sent: u64,
    unbound_replies: u64,
    conflicts: u64,
    checks: [Vec<Instant>; 2],
    old_after_recovery: u64,
    recovery_rtp: Option<Instant>,
    recovery_data: Option<Instant>,
}
struct Lab {
    peers: [Rtc; 2],
    deadlines: [Instant; 2],
    packets: VecDeque<(Instant, usize, Transmit)>,
    epoch: Instant,
    fault: Instant,
    mode: Link,
    observed: Observation,
    old_names: [String; 2],
    response_key: String,
    replay: Vec<u8>,
    role_error_sent: bool,
}
fn stun_kind(bytes: &[u8]) -> Option<u16> {
    (bytes.len() >= 20 && bytes[0] & 0xc0 == 0 && bytes[4..8] == [0x21, 0x12, 0xa4, 0x42])
        .then(|| u16::from_be_bytes([bytes[0], bytes[1]]))
}
fn username(bytes: &[u8]) -> Option<&str> {
    let mut index = 20;
    while index + 4 <= bytes.len() {
        let kind = u16::from_be_bytes([bytes[index], bytes[index + 1]]);
        let size = u16::from_be_bytes([bytes[index + 2], bytes[index + 3]]) as usize;
        if index + 4 + size > bytes.len() {
            return None;
        }
        if kind == 6 {
            return std::str::from_utf8(&bytes[index + 4..index + 4 + size]).ok();
        }
        index += 4 + (size + 3) / 4 * 4;
    }
    None
}
impl Lab {
    fn drain(&mut self, peer: usize, now: Instant) {
        for _ in 0..10_000 {
            match self.peers[peer].poll_output().expect("SDK output") {
                Output::Timeout(at) => {
                    self.deadlines[peer] = at;
                    return;
                }
                Output::Transmit(mut packet) => {
                    let kind = stun_kind(&packet.contents);
                    if peer == 1
                        && kind == Some(0x0101)
                        && now >= self.fault
                        && !self.role_error_sent
                        && matches!(self.mode, Link::RoleConflict | Link::RestartRoleConflict)
                    {
                        self.role_error_sent = true;
                        let original = is::stun::StunMessage::parse(&packet.contents).unwrap();
                        let response =
                            is::stun::StunMessage::binding_role_conflict_reply(original.trans_id());
                        let provider = str0m_rust_crypto::default_provider();
                        let mut contents = vec![0; 1500];
                        let size = response
                            .to_bytes(
                                Some(self.response_key.as_bytes()),
                                &mut contents,
                                |key, data| provider.sha1_hmac_provider.sha1_hmac(key, data),
                            )
                            .unwrap();
                        contents.truncate(size);
                        self.observed.conflicts += 1;
                        self.packets.push_back((
                            now + Duration::from_millis(1),
                            peer,
                            Transmit {
                                proto: packet.proto,
                                source: packet.source,
                                destination: packet.destination,
                                contents: contents.into(),
                            },
                        ));
                        continue;
                    }
                    if kind == Some(0x0111)
                        && is::stun::StunMessage::parse(&packet.contents)
                            .unwrap()
                            .error_code()
                            .is_some_and(|(code, _)| code == 487)
                    {
                        self.observed.conflicts += 1;
                    }
                    if kind == Some(0x0001) && now >= self.epoch + Duration::from_secs(10) {
                        self.observed.checks[peer].push(now);
                    }
                    if peer == 0
                        && kind.is_none()
                        && packet.source.port() == 10000
                        && now >= self.epoch + Duration::from_secs(51)
                    {
                        self.observed.old_after_recovery += 1;
                    }
                    if peer == 0 && kind == Some(0x0101) && packet.destination.port() == 19998 {
                        self.observed.unbound_replies += 1;
                    }
                    if self.mode == Link::RestartUnboundRequest
                        && now >= self.fault
                        && peer == 1
                        && kind == Some(0x0001)
                        && username(&packet.contents) == Some(self.old_names[peer].as_str())
                    {
                        let mut source = packet.source;
                        source.set_port(19998);
                        self.packets.push_back((
                            now + Duration::from_millis(1),
                            peer,
                            Transmit {
                                proto: packet.proto,
                                source,
                                destination: packet.destination,
                                contents: packet.contents.to_vec().into(),
                            },
                        ));
                    }
                    if peer == 0 && kind.is_none() {
                        self.observed.last_application = Some(now);
                        if packet.contents[0] & 0xc0 == 0x80 {
                            if (192..=223).contains(&packet.contents[1]) {
                                self.observed.rtcp_sent += 1;
                            } else {
                                self.observed.rtp_sent += 1;
                            }
                        } else {
                            self.observed.dtls_sent += 1;
                        }
                        if packet.source.port() == 20000 {
                            self.observed.latest_tuple_transmits += 1;
                        }
                        if self
                            .observed
                            .last_success
                            .is_some_and(|at| now.duration_since(at) >= Duration::from_secs(30))
                        {
                            self.observed.late_transmits += 1;
                        }
                    }
                    if peer == 1 && kind == Some(0x0101) && now < self.fault {
                        self.replay = packet.contents.to_vec();
                    }
                    if peer == 1
                        && kind == Some(0x0101)
                        && now >= self.fault
                        && (self.mode != Link::ForbiddenAlternate
                            || packet.destination.port() == 10000)
                        && matches!(
                            self.mode,
                            Link::Forbidden | Link::UnauthForbidden | Link::ForbiddenAlternate
                        )
                    {
                        let original = is::stun::StunMessage::parse(&packet.contents).unwrap();
                        let revoked = is::stun::StunMessageBuilder::new()
                            .binding()
                            .failure()
                            .error_code(403, "Forbidden")
                            .build(original.trans_id());
                        let provider = str0m_rust_crypto::default_provider();
                        let key = if matches!(self.mode, Link::Forbidden | Link::ForbiddenAlternate)
                        {
                            self.response_key.as_bytes()
                        } else {
                            b"owned-wrong-key"
                        };
                        let mut contents = vec![0; 1500];
                        let size = revoked
                            .to_bytes(Some(key), &mut contents, |key, data| {
                                provider.sha1_hmac_provider.sha1_hmac(key, data)
                            })
                            .unwrap();
                        contents.truncate(size);
                        self.packets.push_back((
                            now + Duration::from_millis(1),
                            peer,
                            Transmit {
                                proto: packet.proto,
                                source: packet.source,
                                destination: packet.destination,
                                contents: contents.into(),
                            },
                        ));
                        if matches!(self.mode, Link::Forbidden | Link::ForbiddenAlternate) {
                            continue;
                        }
                    }
                    if now >= self.fault {
                        if matches!(
                            self.mode,
                            Link::AlternateAfterExpiry
                                | Link::FreshAfterExpiry
                                | Link::OldTupleReturns
                        ) && now < self.epoch + Duration::from_secs(45)
                            && peer == 1
                            && kind == Some(0x0101)
                        {
                            continue;
                        }
                        if self.mode == Link::Silent {
                            continue;
                        }
                        let restarting = matches!(
                            self.mode,
                            Link::Restart
                                | Link::RepeatedRestart
                                | Link::RestartNoResponse
                                | Link::RestartTuple
                                | Link::RestartUnboundRequest
                                | Link::RestartRoleConflict
                        );
                        if restarting
                            && now < self.epoch + Duration::from_secs(45)
                            && kind == Some(0x0001)
                            && username(&packet.contents) != Some(self.old_names[peer].as_str())
                        {
                            continue;
                        }
                        let no_response = matches!(
                            self.mode,
                            Link::NoResponse
                                | Link::RestartNoResponse
                                | Link::WrongTuple
                                | Link::Replay
                                | Link::ReaddAfterExpiry
                        ) || (self.mode == Link::Recover
                            && now < self.epoch + Duration::from_secs(25));
                        if no_response && peer == 1 && kind == Some(0x0101) {
                            self.observed.responses_dropped += 1;
                            if self.mode == Link::Replay {
                                packet.contents = self.replay.clone().into();
                            } else if self.mode == Link::WrongTuple {
                                packet.source.set_port(19999);
                            } else {
                                continue;
                            }
                        }
                    }
                    self.packets
                        .push_back((now + Duration::from_millis(1), peer, packet));
                }
                Output::Event(Event::IceConnectionStateChange(state)) => {
                    self.observed.state.push(format!(
                        "{peer}:{state:?}@{:.3}",
                        now.duration_since(self.epoch).as_secs_f64()
                    ));
                    // Deliberately do not disconnect: test the SDK output gate itself.
                }
                Output::Event(Event::Closed) => {
                    self.observed.closed[peer] = Some(now);
                }
                Output::Event(Event::ChannelData(_)) if peer == 1 => {
                    if now >= self.epoch + Duration::from_secs(50) {
                        self.observed.recovery_data.get_or_insert(now);
                    }
                    self.observed.messages += 1;
                    let elapsed = now.duration_since(self.epoch);
                    if elapsed >= Duration::from_secs(11) && elapsed < Duration::from_secs(44) {
                        self.observed.restart_messages += 1;
                    }
                    if elapsed >= Duration::from_secs(50) {
                        self.observed.final_messages += 1;
                    }
                }
                Output::Event(Event::RtpPacket(_)) if peer == 1 => {
                    if now >= self.epoch + Duration::from_secs(50) {
                        self.observed.recovery_rtp.get_or_insert(now);
                    }
                    self.observed.rtp_received += 1;
                }
                _ => {}
            }
        }
        panic!("output drain must terminate");
    }
    fn receive_due(&mut self, now: Instant) {
        while self.packets.front().is_some_and(|(at, _, _)| *at <= now) {
            let (_, from, packet) = self.packets.pop_front().unwrap();
            let to = 1 - from;
            let kind = stun_kind(&packet.contents);
            let valid_tuple = packet.source.port() != 19999;
            let incoming = Receive::new(
                packet.proto,
                packet.source,
                packet.destination,
                &packet.contents,
            )
            .unwrap();
            self.peers[to]
                .handle_input(Input::Receive(now, incoming))
                .expect("SDK packet input");
            if to == 0
                && kind == Some(0x0101)
                && valid_tuple
                && !(self.mode == Link::Replay && now >= self.fault)
            {
                self.observed.last_success = Some(now);
            }
            if to == 0 && now >= self.fault && kind == Some(0x0001) {
                self.observed.requests_received += 1;
            }
            self.drain(to, now);
        }
    }
}
fn main() {
    let baseline = std::env::args().any(|arg| arg == "--baseline");
    for mode in [
        Link::Healthy,
        Link::NoResponse,
        Link::Silent,
        Link::Recover,
        Link::LiteSender,
        Link::LiteReceiver,
        Link::Restart,
        Link::RepeatedRestart,
        Link::RestartNoResponse,
        Link::RestartTuple,
        Link::WrongTuple,
        Link::DelayedWake,
        Link::Forbidden,
        Link::UnauthForbidden,
        Link::Replay,
        Link::RestartUnboundRequest,
        Link::AlternateAfterExpiry,
        Link::FreshAfterExpiry,
        Link::ReaddBeforeExpiry,
        Link::RoleConflict,
        Link::RestartRoleConflict,
        Link::ReaddAfterExpiry,
        Link::OldTupleReturns,
        Link::ForbiddenAlternate,
    ] {
        if let Some(only) =
            std::env::args().find_map(|arg| arg.strip_prefix("--case=").map(str::to_owned))
        {
            if format!("{mode:?}") != only {
                continue;
            }
        }
        let epoch = Instant::now();
        let mut a = Rtc::builder()
            .set_ice_lite(mode == Link::LiteSender)
            .set_rtp_mode(true)
            .build(epoch);
        let mut b = Rtc::builder()
            .set_ice_lite(mode == Link::LiteReceiver)
            .set_rtp_mode(true)
            .build(epoch);
        a.add_local_candidate(Candidate::host("192.0.2.1:10000".parse().unwrap(), "udp").unwrap())
            .unwrap();
        b.add_local_candidate(Candidate::host("192.0.2.2:10000".parse().unwrap(), "udp").unwrap())
            .unwrap();
        let mut change = a.sdp_api();
        let channel = change.add_channel("owned-test".into());
        let mid = change.add_media(MediaKind::Video, Direction::SendRecv, None, None, None);
        let (offer, pending) = change.apply().unwrap();
        let answer = b.sdp_api().accept_offer(offer).unwrap();
        a.sdp_api().accept_answer(pending, answer).unwrap();
        let pt = a
            .codec_config()
            .params()
            .iter()
            .find(|p| p.spec().codec == Codec::Vp8)
            .unwrap()
            .pt();
        let old_a = a.direct_api().local_ice_credentials();
        let old_b = b.direct_api().local_ice_credentials();
        let old_names = [
            format!("{}:{}", old_b.ufrag, old_a.ufrag),
            format!("{}:{}", old_a.ufrag, old_b.ufrag),
        ];
        let mut lab = Lab {
            peers: [a, b],
            deadlines: [epoch; 2],
            packets: VecDeque::new(),
            epoch,
            fault: epoch + Duration::from_secs(10),
            mode,
            observed: Observation::default(),
            old_names,
            response_key: old_b.pass,
            replay: vec![],
            role_error_sent: false,
        };
        let seconds = std::env::args()
            .find_map(|arg| {
                arg.strip_prefix("--seconds=")
                    .and_then(|v| v.parse::<u64>().ok())
            })
            .unwrap_or(if mode == Link::ForbiddenAlternate {
                150
            } else {
                70
            });
        let finish = epoch + Duration::from_secs(seconds);
        let mut now = epoch;
        let mut write_at = epoch;
        let mut sequence = 0_u64;
        let mut turns = 0_u64;
        let restart = matches!(
            mode,
            Link::Restart
                | Link::RepeatedRestart
                | Link::RestartNoResponse
                | Link::RestartTuple
                | Link::RestartUnboundRequest
                | Link::RestartRoleConflict
        );
        let mut restart_at = restart.then_some(epoch + Duration::from_secs(10));
        let mut switch_at = (mode == Link::RestartTuple).then_some(epoch + Duration::from_secs(45));
        let mut paused = false;
        let mut changed = false;
        let mut restored = false;
        let mut returned = false;
        while now < finish {
            turns += 1;
            assert!(turns < 200_000, "driver must make progress");
            if mode == Link::DelayedWake && !paused && now >= epoch + Duration::from_secs(10) {
                now = epoch + Duration::from_secs(50);
                paused = true;
            }
            lab.receive_due(now);
            if !changed
                && now >= epoch + Duration::from_secs(10)
                && matches!(
                    mode,
                    Link::ReaddBeforeExpiry
                        | Link::ReaddAfterExpiry
                        | Link::RoleConflict
                        | Link::RestartRoleConflict
                )
            {
                changed = true;
                if matches!(mode, Link::ReaddBeforeExpiry | Link::ReaddAfterExpiry) {
                    let old = Candidate::host("192.0.2.1:10000".parse().unwrap(), "udp").unwrap();
                    assert!(lab.peers[0].direct_api().invalidate_candidate(&old));
                } else {
                    lab.peers[0].direct_api().set_ice_controlling(true);
                    lab.peers[1].direct_api().set_ice_controlling(true);
                }
            }
            let restore_time = if mode == Link::ReaddBeforeExpiry {
                25
            } else {
                50
            };
            if !restored
                && now >= epoch + Duration::from_secs(restore_time)
                && matches!(
                    mode,
                    Link::AlternateAfterExpiry
                        | Link::FreshAfterExpiry
                        | Link::OldTupleReturns
                        | Link::ReaddBeforeExpiry
                        | Link::ReaddAfterExpiry
                        | Link::ForbiddenAlternate
                )
            {
                restored = true;
                if mode == Link::FreshAfterExpiry {
                    let mut change = lab.peers[0].sdp_api();
                    change.ice_restart(true);
                    let (offer, pending) = change.apply().unwrap();
                    let answer = lab.peers[1].sdp_api().accept_offer(offer).unwrap();
                    lab.peers[0]
                        .sdp_api()
                        .accept_answer(pending, answer)
                        .unwrap();
                } else {
                    let port = if matches!(mode, Link::ReaddBeforeExpiry | Link::ReaddAfterExpiry) {
                        10000
                    } else {
                        20000
                    };
                    let next = Candidate::host(format!("192.0.2.1:{port}").parse().unwrap(), "udp")
                        .unwrap();
                    lab.peers[0].add_local_candidate(next.clone());
                    lab.peers[1].add_remote_candidate(next);
                }
                lab.drain(0, now);
                lab.drain(1, now);
            }
            if mode == Link::OldTupleReturns
                && restored
                && !returned
                && now >= epoch + Duration::from_secs(55)
            {
                returned = true;
                lab.peers[0].add_local_candidate(
                    Candidate::host("192.0.2.1:10000".parse().unwrap(), "udp").unwrap(),
                );
                lab.peers[1].add_remote_candidate(
                    Candidate::host("192.0.2.1:10000".parse().unwrap(), "udp").unwrap(),
                );
            }
            if restart_at.is_some_and(|at| now >= at) {
                let mut change = lab.peers[0].sdp_api();
                change.ice_restart(true);
                let (offer, pending) = change.apply().unwrap();
                let answer = lab.peers[1].sdp_api().accept_offer(offer).unwrap();
                lab.peers[0]
                    .sdp_api()
                    .accept_answer(pending, answer)
                    .unwrap();
                restart_at =
                    if mode == Link::RepeatedRestart && now < epoch + Duration::from_secs(20) {
                        Some(epoch + Duration::from_secs(20))
                    } else {
                        None
                    };
                lab.drain(0, now);
            }
            if switch_at.is_some_and(|at| now >= at) && lab.peers[0].is_alive() {
                if mode == Link::RestartTuple {
                    let old = Candidate::host("192.0.2.1:10000".parse().unwrap(), "udp").unwrap();
                    let new = Candidate::host("192.0.2.1:20000".parse().unwrap(), "udp").unwrap();
                    lab.peers[0].add_local_candidate(new.clone());
                    lab.peers[1].add_remote_candidate(new);
                    lab.peers[0].direct_api().invalidate_candidate(&old);
                    lab.peers[1].direct_api().invalidate_candidate(&old);
                }
                lab.drain(0, now);
                lab.drain(1, now);
                switch_at = None;
            } else if switch_at.is_some_and(|at| now >= at) {
                switch_at = None;
            }
            if write_at <= now {
                for peer in 0..2 {
                    lab.peers[peer]
                        .handle_input(Input::Timeout(now))
                        .expect("write clock");
                }
                if lab.peers[0].is_alive() {
                    if let Some(mut writer) = lab.peers[0].channel(channel) {
                        let _ = writer
                            .write(true, &sequence.to_be_bytes())
                            .expect("owned message");
                        sequence += 1;
                    }
                    if let Some(tx) = lab.peers[0].direct_api().stream_tx_by_mid(mid, None) {
                        tx.write_rtp(
                            RtpWrite::new(
                                pt,
                                sequence.into(),
                                (sequence * 9_000) as u32,
                                now,
                                [0x10, 0x00, 0xAA, 0xBB],
                            )
                            .marker(true),
                        );
                    }
                }
                lab.drain(0, now);
                lab.drain(1, now);
                write_at = now + Duration::from_millis(100);
            }
            for peer in 0..2 {
                if lab.deadlines[peer] <= now {
                    lab.peers[peer]
                        .handle_input(Input::Timeout(now))
                        .expect("SDK timeout");
                    lab.drain(peer, now);
                }
            }
            let next_packet = lab.packets.front().map_or(finish, |(at, _, _)| *at);
            let next = finish
                .min(write_at)
                .min(next_packet)
                .min(lab.deadlines[0])
                .min(lab.deadlines[1])
                .min(restart_at.unwrap_or(finish))
                .min(switch_at.unwrap_or(finish));
            assert!(next > now, "deadline progress: {mode:?} {turns}");
            now = next;
        }
        let o = &lab.observed;
        let seconds = |at: Option<Instant>| at.map(|at| at.duration_since(epoch).as_secs_f64());
        println!(
            "mode={mode:?} alive={:?} connected={:?} delivered={} rtp_received={} rtp_sent={} rtcp_sent={} dtls_sent={} late_transmits={} last_response={:?} closed={:?} restart_messages={} final_messages={} latest_tuple={} last_application={:?} states={:?}",
            [lab.peers[0].is_alive(), lab.peers[1].is_alive()],
            [lab.peers[0].is_connected(), lab.peers[1].is_connected()],
            o.messages,
            o.rtp_received,
            o.rtp_sent,
            o.rtcp_sent,
            o.dtls_sent,
            o.late_transmits,
            seconds(o.last_success),
            [seconds(o.closed[0]), seconds(o.closed[1])],
            o.restart_messages,
            o.final_messages,
            o.latest_tuple_transmits,
            seconds(o.last_application),
            o.state
        );
        assert!(
            o.messages > 50 && o.rtp_received > 50,
            "initial RTP/SCTP exchange"
        );
        if matches!(
            mode,
            Link::ForbiddenAlternate | Link::AlternateAfterExpiry | Link::FreshAfterExpiry
        ) {
            println!(
                "recovery={mode:?} rtp_at={:?} sctp_at={:?}",
                seconds(o.recovery_rtp),
                seconds(o.recovery_data)
            );
        }
        assert_eq!(
            o.unbound_replies, 0,
            "old credentials cannot authorize a different tuple after restart"
        );
        if !baseline {
            if matches!(
                mode,
                Link::NoResponse
                    | Link::WrongTuple
                    | Link::RestartNoResponse
                    | Link::DelayedWake
                    | Link::Forbidden
                    | Link::Replay
                    | Link::ReaddAfterExpiry
            ) {
                assert!(
                    !lab.peers[0].is_connected(),
                    "expired tuple must lose egress authority"
                );
                assert_eq!(o.late_transmits, 0, "no application datagram after expiry");
            } else if mode != Link::Silent {
                assert!(
                    lab.peers[0].is_alive() && lab.peers[1].is_alive(),
                    "healthy alive"
                );
                assert!(o.final_messages > 150, "healthy final delivery: {mode:?}");
                assert_eq!(
                    o.late_transmits, 0,
                    "no late output during recovery: {mode:?}"
                );
                if restart {
                    assert!(o.restart_messages > 300, "restart preserves playback");
                }
            }
            if mode == Link::Healthy {
                for checks in &o.checks {
                    for interval in checks.windows(2) {
                        let delay = interval[1].duration_since(interval[0]);
                        assert!(
                            delay >= Duration::from_secs(4) && delay <= Duration::from_secs(6),
                            "consent cadence {delay:?}"
                        );
                    }
                }
            }
            if matches!(mode, Link::RoleConflict | Link::RestartRoleConflict) {
                assert!(o.conflicts > 0, "actual authenticated 487 exchange");
            }
            if matches!(
                mode,
                Link::OldTupleReturns | Link::AlternateAfterExpiry | Link::ForbiddenAlternate
            ) {
                assert_eq!(
                    o.old_after_recovery, 0,
                    "expired old tuple must not regain selection"
                );
            }
            if mode == Link::Forbidden {
                assert!(
                    o.last_application
                        .is_some_and(|at| at < epoch + Duration::from_secs(17)),
                    "authenticated revocation is immediate"
                );
            }
            if mode == Link::RestartTuple {
                assert!(o.latest_tuple_transmits > 200, "new tuple takes over");
            }
        }
    }
}

#[test]
fn consent_freshness_and_recovery_public_api() {
    main();
}
