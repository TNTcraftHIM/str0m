use std::collections::VecDeque;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use crate::pair::RECENT_BINDING_REQUEST;
use crate::stun::{StunMessage, StunPacket, StunTiming, TransId};
use crate::{Candidate, IceCreds, Sha1HmacProvider};
use str0m_proto::{NonCryptographicRng, Protocol, Transmit};

// RFC 7675 §5.1: response-only expiry and randomized 4–6 second checks.
pub(crate) const EXPIRY: Duration = Duration::from_secs(30);
pub(crate) type Tuple = (Protocol, SocketAddr, SocketAddr);

/// The selected transport outlives candidate gathering, including ICE restart.
/// Only this owner generates established-path consent checks.
#[derive(Debug)]
pub(crate) struct ActiveConsent {
    pub proto: Protocol,
    pub source: SocketAddr,
    pub destination: SocketAddr,
    pub local: IceCreds,
    pub remote: IceCreds,
    deadline: Option<Instant>,
    next_check: Instant,
    requests: VecDeque<(TransId, Instant, bool)>,
    last_response: Instant,
    last_request: Option<Instant>,
    pub withdrawn: bool,
    priority: u32,
}

impl ActiveConsent {
    pub fn new(
        local_candidate: &Candidate,
        remote_candidate: &Candidate,
        local: IceCreds,
        remote: IceCreds,
        validated: Instant,
        lite: bool,
    ) -> Self {
        Self {
            proto: local_candidate.proto(),
            source: local_candidate.base(),
            destination: remote_candidate.addr(),
            local,
            remote,
            deadline: (!lite).then_some(validated + EXPIRY),
            next_check: validated + Self::interval(),
            requests: VecDeque::new(),
            last_response: validated,
            last_request: None,
            withdrawn: false,
            priority: local_candidate.prio_prflx(),
        }
    }

    fn interval() -> Duration {
        Duration::from_millis(4_000 + NonCryptographicRng::u64() % 2_001)
    }

    pub fn same_generation(&self, local: &IceCreds, remote: &IceCreds) -> bool {
        self.local.ufrag == local.ufrag
            && self.local.pass == local.pass
            && self.remote.ufrag == remote.ufrag
            && self.remote.pass == remote.pass
    }

    pub fn matches(&self, proto: Protocol, source: SocketAddr, destination: SocketAddr) -> bool {
        self.proto == proto && self.source == source && self.destination == destination
    }

    pub fn expired(&self, now: Instant) -> bool {
        self.deadline.is_some_and(|deadline| now >= deadline)
    }

    pub fn tuple(&self) -> Tuple {
        (self.proto, self.source, self.destination)
    }

    pub fn withdraw(&mut self) {
        self.withdrawn = true;
        self.requests.clear();
    }

    pub fn received_request(&mut self, now: Instant) {
        self.last_request = Some(now);
    }

    pub fn viable(&self, now: Instant, timing: &StunTiming) -> bool {
        !self.withdrawn
            && !self.expired(now)
            && (self
                .last_request
                .is_some_and(|at| now.saturating_duration_since(at) < RECENT_BINDING_REQUEST)
                || now.saturating_duration_since(self.last_response) < timing.timeout())
    }

    pub fn renew(&mut self, now: Instant) {
        if self.deadline.is_some() && !self.expired(now) && now > self.last_response {
            self.deadline = Some(now + EXPIRY);
            self.last_response = now;
        }
    }

    pub fn timeout(&self) -> Option<Instant> {
        self.deadline.map(|deadline| {
            if self.withdrawn {
                deadline
            } else {
                deadline.min(self.next_check)
            }
        })
    }

    pub fn poll_check(
        &mut self,
        now: Instant,
        provider: &dyn Sha1HmacProvider,
        mtu: usize,
        controlling: bool,
        tie_breaker: u64,
    ) -> Option<Transmit> {
        if self.withdrawn || self.deadline.is_none() || self.expired(now) || now < self.next_check {
            return None;
        }
        self.next_check = now + Self::interval();
        self.requests
            .retain(|(_, sent, _)| now.saturating_duration_since(*sent) < EXPIRY);
        let id = TransId::new();
        self.requests.push_back((id, now, controlling));
        let username = format!("{}:{}", self.remote.ufrag, self.local.ufrag);
        let message = StunMessage::binding_request(
            &username,
            id,
            controlling,
            tie_breaker,
            self.priority,
            controlling,
        );
        Some(self.serialize(message, &self.remote.pass, provider, mtu))
    }

    pub fn accepts(&self, message: &StunMessage<'_>, provider: &dyn Sha1HmacProvider) -> bool {
        let password = if message.is_binding_request() {
            if message.split_username()
                != Some((self.local.ufrag.as_str(), self.remote.ufrag.as_str()))
            {
                return false;
            }
            &self.local.pass
        } else if (message.is_successful_binding_response() || message.is_failed_binding_response())
            && self
                .requests
                .iter()
                .any(|(id, _, _)| *id == message.trans_id())
        {
            &self.remote.pass
        } else {
            return false;
        };
        message.verify(password.as_bytes(), |key, payloads| {
            provider.sha1_hmac(key, payloads)
        })
    }

    pub fn accepts_packet(&self, packet: &StunPacket<'_>, provider: &dyn Sha1HmacProvider) -> bool {
        self.matches(packet.proto, packet.destination, packet.source)
            && self.accepts(&packet.message, provider)
    }

    pub fn take_response(
        &mut self,
        now: Instant,
        message: &StunMessage<'_>,
    ) -> Option<(Duration, bool)> {
        if self.expired(now) {
            return None;
        }
        let index = self
            .requests
            .iter()
            .position(|(id, _, _)| *id == message.trans_id())?;
        let (_, sent, role) = self.requests.remove(index)?;
        Some((now.saturating_duration_since(sent), role))
    }

    pub fn reply(
        &self,
        packet: &StunPacket<'_>,
        provider: &dyn Sha1HmacProvider,
        mtu: usize,
        role_conflict: bool,
    ) -> Transmit {
        self.serialize(
            if role_conflict {
                StunMessage::binding_role_conflict_reply(packet.message.trans_id())
            } else {
                StunMessage::binding_reply(packet.message.trans_id(), packet.source)
            },
            &self.local.pass,
            provider,
            mtu,
        )
    }

    fn serialize(
        &self,
        message: StunMessage<'_>,
        password: &str,
        provider: &dyn Sha1HmacProvider,
        mtu: usize,
    ) -> Transmit {
        let mut contents = vec![0; mtu];
        let size = message
            .to_bytes(Some(password.as_bytes()), &mut contents, |key, payloads| {
                provider.sha1_hmac(key, payloads)
            })
            .expect("STUN serialization");
        contents.truncate(size);
        Transmit {
            proto: self.proto,
            source: self.source,
            destination: self.destination,
            contents: contents.into(),
        }
    }
}
