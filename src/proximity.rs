//! Fail-closed ClipTown proximity wire, replay, consent, and BLE framing rules.
//!
//! Bluetooth is an untrusted byte transport. It never proves identity or raises
//! Shared Auth assurance; callers must verify enrolled device signatures and
//! obtain separate one-use user consent before decrypting or importing a clip.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, VerifyingKey};
use hmac::{Hmac, Mac as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use uuid::Uuid;

pub const PROTOCOL: &str = "cliptown.proximity.v1";
pub const SERVICE_UUID: Uuid = Uuid::from_u128(0xc11f7a00_7b9e_4d8a_9c3a_4b8a0d86e001);
pub const MAX_CIPHERTEXT_BYTES: usize = 32 * 1024;
pub const MAX_ENCODED_ENVELOPE_BYTES: usize = 48 * 1024;
pub const MAX_MESSAGE_LIFETIME_MS: u64 = 120_000;
pub const MAX_CLOCK_SKEW_MS: u64 = 30_000;
pub const DEFAULT_ADVERTISEMENT_ROTATION_MS: u64 = 120_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProximityMessageKind {
    PairingHello,
    ClipboardOffer,
    ClipboardChunk,
    SharedAuthStepUp,
}

impl ProximityMessageKind {
    pub const fn required_scope(self) -> &'static str {
        match self {
            Self::PairingHello => "cliptown:device:pair",
            Self::ClipboardOffer | Self::ClipboardChunk => "cliptown:clipboard:import",
            Self::SharedAuthStepUp => "shared-auth:step-up:relay",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProximityAdvertisement {
    pub protocol: String,
    pub service_uuid: Uuid,
    pub rotation_epoch: u64,
    pub rotating_id: String,
}

impl ProximityAdvertisement {
    pub fn derive(
        discovery_secret: &[u8],
        device_key_id: &str,
        now_ms: u64,
    ) -> Result<Self, ProximityError> {
        if discovery_secret.len() < 32 || !bounded_identifier(device_key_id, 128) {
            return Err(ProximityError::InvalidAdvertisement);
        }
        let epoch = now_ms / DEFAULT_ADVERTISEMENT_ROTATION_MS;
        let input = format!("{PROTOCOL}\0{SERVICE_UUID}\0{device_key_id}\0{epoch}");
        let mut mac = <Hmac<Sha256> as hmac::digest::KeyInit>::new_from_slice(discovery_secret)
            .map_err(|_| ProximityError::InvalidAdvertisement)?;
        mac.update(input.as_bytes());
        let bytes = mac.finalize().into_bytes();
        let advertisement = Self {
            protocol: PROTOCOL.to_owned(),
            service_uuid: SERVICE_UUID,
            rotation_epoch: epoch,
            rotating_id: URL_SAFE_NO_PAD.encode(&bytes[..9]),
        };
        advertisement.validate()?;
        Ok(advertisement)
    }

    pub fn validate(&self) -> Result<(), ProximityError> {
        if self.protocol != PROTOCOL
            || self.service_uuid != SERVICE_UUID
            || self.rotating_id.len() != 12
            || !base64url_chars(&self.rotating_id)
        {
            return Err(ProximityError::InvalidAdvertisement);
        }
        Ok(())
    }

    pub fn display_name(&self) -> Result<String, ProximityError> {
        self.validate()?;
        Ok(format!("CT-{}", &self.rotating_id[..6]))
    }
}

pub fn derive_safety_code(
    initiator_ephemeral_key: &[u8],
    responder_ephemeral_key: &[u8],
    session_nonce: &[u8],
) -> Result<String, ProximityError> {
    if initiator_ephemeral_key.len() < 16
        || responder_ephemeral_key.len() < 16
        || session_nonce.len() < 16
    {
        return Err(ProximityError::IncompleteHandshake);
    }
    let mut digest = Sha256::new();
    digest.update(PROTOCOL.as_bytes());
    digest.update([0]);
    for component in [
        initiator_ephemeral_key,
        responder_ephemeral_key,
        session_nonce,
    ] {
        let length =
            u32::try_from(component.len()).map_err(|_| ProximityError::IncompleteHandshake)?;
        digest.update(length.to_be_bytes());
        digest.update(component);
    }
    let output = digest.finalize();
    let number = u32::from_be_bytes([output[0], output[1], output[2], output[3]]) & 0x7fff_ffff;
    Ok(format!("{:06}", number % 1_000_000))
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProximityEnvelope {
    pub protocol: String,
    pub message_kind: ProximityMessageKind,
    pub message_id: Uuid,
    pub session_id: String,
    pub sequence: u32,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub sender_device_id: Uuid,
    pub recipient_device_id: Uuid,
    pub scope: String,
    pub ciphertext: String,
    pub ciphertext_sha256: String,
    pub signing_key_id: String,
    pub signature: String,
}

#[derive(Serialize)]
struct UnsignedEnvelope<'a> {
    protocol: &'a str,
    message_kind: ProximityMessageKind,
    message_id: Uuid,
    session_id: &'a str,
    sequence: u32,
    issued_at_unix_ms: u64,
    expires_at_unix_ms: u64,
    sender_device_id: Uuid,
    recipient_device_id: Uuid,
    scope: &'a str,
    ciphertext: &'a str,
    ciphertext_sha256: &'a str,
    signing_key_id: &'a str,
}

impl ProximityEnvelope {
    pub fn from_slice(bytes: &[u8]) -> Result<Self, ProximityError> {
        if bytes.is_empty() || bytes.len() > MAX_ENCODED_ENVELOPE_BYTES {
            return Err(ProximityError::OversizedEnvelope);
        }
        let envelope: Self =
            serde_json::from_slice(bytes).map_err(|_| ProximityError::InvalidEnvelope)?;
        envelope.validate_structure()?;
        Ok(envelope)
    }

    pub fn to_vec(&self) -> Result<Vec<u8>, ProximityError> {
        self.validate_structure()?;
        let bytes = serde_json::to_vec(self).map_err(|_| ProximityError::InvalidEnvelope)?;
        if bytes.len() > MAX_ENCODED_ENVELOPE_BYTES {
            return Err(ProximityError::OversizedEnvelope);
        }
        Ok(bytes)
    }

    pub fn signing_bytes(&self) -> Result<Vec<u8>, ProximityError> {
        serde_json::to_vec(&UnsignedEnvelope {
            protocol: &self.protocol,
            message_kind: self.message_kind,
            message_id: self.message_id,
            session_id: &self.session_id,
            sequence: self.sequence,
            issued_at_unix_ms: self.issued_at_unix_ms,
            expires_at_unix_ms: self.expires_at_unix_ms,
            sender_device_id: self.sender_device_id,
            recipient_device_id: self.recipient_device_id,
            scope: &self.scope,
            ciphertext: &self.ciphertext,
            ciphertext_sha256: &self.ciphertext_sha256,
            signing_key_id: &self.signing_key_id,
        })
        .map_err(|_| ProximityError::InvalidEnvelope)
    }

    pub fn validate_structure(&self) -> Result<(), ProximityError> {
        if self.protocol != PROTOCOL
            || !(22..=86).contains(&self.session_id.len())
            || !base64url_chars(&self.session_id)
            || self.sequence == 0
            || self.sequence > 0x7fff_ffff
            || self.expires_at_unix_ms <= self.issued_at_unix_ms
            || self.expires_at_unix_ms - self.issued_at_unix_ms > MAX_MESSAGE_LIFETIME_MS
            || self.sender_device_id == self.recipient_device_id
            || self.scope != self.message_kind.required_scope()
            || self.ciphertext_sha256.len() != 64
            || !self
                .ciphertext_sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || !bounded_identifier(&self.signing_key_id, 128)
        {
            return Err(ProximityError::InvalidEnvelope);
        }
        let ciphertext = self.ciphertext_bytes()?;
        if ciphertext.is_empty() || ciphertext.len() > MAX_CIPHERTEXT_BYTES {
            return Err(ProximityError::OversizedEnvelope);
        }
        let signature = URL_SAFE_NO_PAD
            .decode(&self.signature)
            .map_err(|_| ProximityError::InvalidEnvelope)?;
        if signature.len() != 64 || !base64url_chars(&self.signature) {
            return Err(ProximityError::InvalidEnvelope);
        }
        Ok(())
    }

    pub fn validate_time(&self, now_ms: u64) -> Result<(), ProximityError> {
        if self.issued_at_unix_ms > now_ms.saturating_add(MAX_CLOCK_SKEW_MS) {
            return Err(ProximityError::FromFuture);
        }
        if self.expires_at_unix_ms <= now_ms {
            return Err(ProximityError::Expired);
        }
        Ok(())
    }

    pub fn ciphertext_bytes(&self) -> Result<Vec<u8>, ProximityError> {
        if self.ciphertext.is_empty() || !base64url_chars(&self.ciphertext) {
            return Err(ProximityError::InvalidEnvelope);
        }
        URL_SAFE_NO_PAD
            .decode(&self.ciphertext)
            .map_err(|_| ProximityError::InvalidEnvelope)
    }

    pub fn verify_digest(&self) -> Result<(), ProximityError> {
        let digest = Sha256::digest(self.ciphertext_bytes()?);
        if hex::encode(digest) != self.ciphertext_sha256 {
            return Err(ProximityError::DigestMismatch);
        }
        Ok(())
    }

    pub fn verify_signature(&self, enrolled_public_key: &[u8]) -> Result<(), ProximityError> {
        let key_bytes: [u8; 32] = enrolled_public_key
            .try_into()
            .map_err(|_| ProximityError::SignatureMismatch)?;
        let signature_bytes: [u8; 64] = URL_SAFE_NO_PAD
            .decode(&self.signature)
            .map_err(|_| ProximityError::SignatureMismatch)?
            .try_into()
            .map_err(|_| ProximityError::SignatureMismatch)?;
        let key =
            VerifyingKey::from_bytes(&key_bytes).map_err(|_| ProximityError::SignatureMismatch)?;
        let signature = Signature::from_bytes(&signature_bytes);
        key.verify_strict(&self.signing_bytes()?, &signature)
            .map_err(|_| ProximityError::SignatureMismatch)
    }

    /// Verifies structure, digest, and the enrolled device signature before any
    /// replay state can be committed. This is the only public receive path.
    pub fn verify_and_accept(
        &self,
        enrolled_public_key: &[u8],
        replay_guard: &mut ProximityReplayGuard,
        now_ms: u64,
        local_device_id: Uuid,
        expected_sender_device_id: Uuid,
    ) -> Result<ReplayDecision, ProximityError> {
        self.validate_structure()?;
        self.verify_digest()?;
        self.verify_signature(enrolled_public_key)?;
        Ok(replay_guard.accept_verified(self, now_ms, local_device_id, expected_sender_device_id))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplayDecision {
    Accepted,
    Duplicate,
    OutOfOrder,
    Expired,
    FromFuture,
    WrongRecipient,
    WrongSender,
    Invalid,
}

pub struct ProximityReplayGuard {
    capacity: usize,
    seen: HashSet<Uuid>,
    order: VecDeque<Uuid>,
    last_sequence: HashMap<(Uuid, Uuid, String), u32>,
    session_order: VecDeque<(Uuid, Uuid, String)>,
}

impl ProximityReplayGuard {
    pub fn new(capacity: usize) -> Result<Self, ProximityError> {
        if !(16..=4096).contains(&capacity) {
            return Err(ProximityError::InvalidCapacity);
        }
        Ok(Self {
            capacity,
            seen: HashSet::new(),
            order: VecDeque::new(),
            last_sequence: HashMap::new(),
            session_order: VecDeque::new(),
        })
    }

    fn accept_verified(
        &mut self,
        envelope: &ProximityEnvelope,
        now_ms: u64,
        local_device_id: Uuid,
        expected_sender_device_id: Uuid,
    ) -> ReplayDecision {
        if envelope.validate_structure().is_err() {
            return ReplayDecision::Invalid;
        }
        if envelope.recipient_device_id != local_device_id {
            return ReplayDecision::WrongRecipient;
        }
        if envelope.sender_device_id != expected_sender_device_id {
            return ReplayDecision::WrongSender;
        }
        match envelope.validate_time(now_ms) {
            Err(ProximityError::Expired) => return ReplayDecision::Expired,
            Err(ProximityError::FromFuture) => return ReplayDecision::FromFuture,
            Err(_) => return ReplayDecision::Invalid,
            Ok(()) => {}
        }
        if self.seen.contains(&envelope.message_id) {
            return ReplayDecision::Duplicate;
        }
        let session = (
            envelope.sender_device_id,
            envelope.recipient_device_id,
            envelope.session_id.clone(),
        );
        if envelope.sequence <= *self.last_sequence.get(&session).unwrap_or(&0) {
            return ReplayDecision::OutOfOrder;
        }
        if !self.last_sequence.contains_key(&session) {
            self.session_order.push_back(session.clone());
        }
        self.last_sequence.insert(session, envelope.sequence);
        while self.session_order.len() > self.capacity {
            if let Some(oldest) = self.session_order.pop_front() {
                self.last_sequence.remove(&oldest);
            }
        }
        self.seen.insert(envelope.message_id);
        self.order.push_back(envelope.message_id);
        while self.order.len() > self.capacity {
            if let Some(oldest) = self.order.pop_front() {
                self.seen.remove(&oldest);
            }
        }
        ReplayDecision::Accepted
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConsentState {
    Idle,
    ComparingCode,
    Ready,
    AwaitingConsent,
    Closed,
}

pub struct ProximityConsentGate {
    state: ConsentState,
    local_code_accepted: bool,
    remote_code_accepted: bool,
    pending_offer: Option<String>,
    consumed_offers: HashSet<String>,
}

impl Default for ProximityConsentGate {
    fn default() -> Self {
        Self {
            state: ConsentState::Idle,
            local_code_accepted: false,
            remote_code_accepted: false,
            pending_offer: None,
            consumed_offers: HashSet::new(),
        }
    }
}

impl ProximityConsentGate {
    pub const fn state(&self) -> ConsentState {
        self.state
    }

    pub fn begin_code_comparison(&mut self) -> Result<(), ProximityError> {
        if self.state != ConsentState::Idle {
            return Err(ProximityError::ConsentState);
        }
        self.state = ConsentState::ComparingCode;
        Ok(())
    }

    pub fn confirm_code(&mut self, local: bool) -> Result<(), ProximityError> {
        if self.state != ConsentState::ComparingCode {
            return Err(ProximityError::ConsentState);
        }
        if local {
            self.local_code_accepted = true;
        } else {
            self.remote_code_accepted = true;
        }
        if self.local_code_accepted && self.remote_code_accepted {
            self.state = ConsentState::Ready;
        }
        Ok(())
    }

    pub fn present_offer(&mut self, offer_id: &str) -> Result<(), ProximityError> {
        if self.state != ConsentState::Ready
            || !bounded_identifier(offer_id, 128)
            || self.consumed_offers.contains(offer_id)
        {
            return Err(ProximityError::ConsentState);
        }
        self.pending_offer = Some(offer_id.to_owned());
        self.state = ConsentState::AwaitingConsent;
        Ok(())
    }

    pub fn approve_once(&mut self, offer_id: &str) -> bool {
        if self.state != ConsentState::AwaitingConsent
            || self.pending_offer.as_deref() != Some(offer_id)
            || self.consumed_offers.contains(offer_id)
        {
            return false;
        }
        self.consumed_offers.insert(offer_id.to_owned());
        self.pending_offer = None;
        self.state = ConsentState::Ready;
        true
    }

    pub fn close(&mut self) {
        self.pending_offer = None;
        self.local_code_accepted = false;
        self.remote_code_accepted = false;
        self.state = ConsentState::Closed;
    }
}

const FRAME_MAGIC: u16 = 0x4354;
const FRAME_VERSION: u8 = 1;
const FRAME_HEADER_BYTES: usize = 12;
const MAX_FRAME_PARTS: usize = 4096;
const REASSEMBLY_TIMEOUT_MS: u64 = 15_000;

pub fn fragment_ble_message(
    message: &[u8],
    packet_bytes: usize,
) -> Result<Vec<Vec<u8>>, ProximityError> {
    if message.is_empty()
        || message.len() > MAX_ENCODED_ENVELOPE_BYTES
        || !(20..=512).contains(&packet_bytes)
    {
        return Err(ProximityError::InvalidFrame);
    }
    let payload_bytes = packet_bytes - FRAME_HEADER_BYTES;
    let total = message.len().div_ceil(payload_bytes);
    if total == 0 || total > MAX_FRAME_PARTS {
        return Err(ProximityError::InvalidFrame);
    }
    let mut id_bytes = [0_u8; 4];
    getrandom::fill(&mut id_bytes).map_err(|_| ProximityError::InvalidFrame)?;
    let frame_id = u32::from_be_bytes(id_bytes);
    let mut packets = Vec::with_capacity(total);
    for (index, payload) in message.chunks(payload_bytes).enumerate() {
        let mut packet = Vec::with_capacity(FRAME_HEADER_BYTES + payload.len());
        packet.extend_from_slice(&FRAME_MAGIC.to_be_bytes());
        packet.push(FRAME_VERSION);
        packet.push(u8::from(index == total - 1));
        packet.extend_from_slice(&frame_id.to_be_bytes());
        packet.extend_from_slice(
            &u16::try_from(index)
                .map_err(|_| ProximityError::InvalidFrame)?
                .to_be_bytes(),
        );
        packet.extend_from_slice(
            &u16::try_from(total)
                .map_err(|_| ProximityError::InvalidFrame)?
                .to_be_bytes(),
        );
        packet.extend_from_slice(payload);
        packets.push(packet);
    }
    Ok(packets)
}

pub struct BleFrameReassembler {
    capacity: usize,
    pending: HashMap<u32, PendingFrame>,
    order: VecDeque<u32>,
}

struct PendingFrame {
    total: usize,
    expires_at_ms: u64,
    byte_count: usize,
    parts: BTreeMap<usize, Vec<u8>>,
}

impl BleFrameReassembler {
    pub fn new(capacity: usize) -> Result<Self, ProximityError> {
        if !(1..=32).contains(&capacity) {
            return Err(ProximityError::InvalidCapacity);
        }
        Ok(Self {
            capacity,
            pending: HashMap::new(),
            order: VecDeque::new(),
        })
    }

    pub fn add(&mut self, packet: &[u8], now_ms: u64) -> Result<Option<Vec<u8>>, ProximityError> {
        self.expire(now_ms);
        if !(FRAME_HEADER_BYTES + 1..=512).contains(&packet.len()) {
            return Err(ProximityError::InvalidFrame);
        }
        let magic = u16::from_be_bytes([packet[0], packet[1]]);
        let version = packet[2];
        let flags = packet[3];
        let frame_id = u32::from_be_bytes(
            packet[4..8]
                .try_into()
                .map_err(|_| ProximityError::InvalidFrame)?,
        );
        let index = usize::from(u16::from_be_bytes(
            packet[8..10]
                .try_into()
                .map_err(|_| ProximityError::InvalidFrame)?,
        ));
        let total = usize::from(u16::from_be_bytes(
            packet[10..12]
                .try_into()
                .map_err(|_| ProximityError::InvalidFrame)?,
        ));
        if magic != FRAME_MAGIC
            || version != FRAME_VERSION
            || flags & !1 != 0
            || total == 0
            || total > MAX_FRAME_PARTS
            || index >= total
            || ((flags & 1) == 1) != (index == total - 1)
        {
            return Err(ProximityError::InvalidFrame);
        }
        if !self.pending.contains_key(&frame_id) {
            self.order.push_back(frame_id);
            self.pending.insert(
                frame_id,
                PendingFrame {
                    total,
                    expires_at_ms: now_ms.saturating_add(REASSEMBLY_TIMEOUT_MS),
                    byte_count: 0,
                    parts: BTreeMap::new(),
                },
            );
        }
        let frame = self
            .pending
            .get_mut(&frame_id)
            .ok_or(ProximityError::InvalidFrame)?;
        if frame.total != total || frame.parts.contains_key(&index) {
            self.pending.remove(&frame_id);
            self.order.retain(|candidate| *candidate != frame_id);
            return Err(ProximityError::InvalidFrame);
        }
        frame.byte_count += packet.len() - FRAME_HEADER_BYTES;
        if frame.byte_count > MAX_ENCODED_ENVELOPE_BYTES {
            self.pending.remove(&frame_id);
            self.order.retain(|candidate| *candidate != frame_id);
            return Err(ProximityError::InvalidFrame);
        }
        frame
            .parts
            .insert(index, packet[FRAME_HEADER_BYTES..].to_vec());
        while self.order.len() > self.capacity {
            if let Some(oldest) = self.order.pop_front() {
                self.pending.remove(&oldest);
            }
        }
        if self
            .pending
            .get(&frame_id)
            .is_none_or(|value| value.parts.len() != total)
        {
            return Ok(None);
        }
        let frame = self
            .pending
            .remove(&frame_id)
            .ok_or(ProximityError::InvalidFrame)?;
        self.order.retain(|candidate| *candidate != frame_id);
        let mut message = Vec::with_capacity(frame.byte_count);
        for index in 0..total {
            message.extend_from_slice(
                frame
                    .parts
                    .get(&index)
                    .ok_or(ProximityError::InvalidFrame)?,
            );
        }
        Ok(Some(message))
    }

    pub fn clear(&mut self) {
        self.pending.clear();
        self.order.clear();
    }

    fn expire(&mut self, now_ms: u64) {
        let expired: Vec<u32> = self
            .pending
            .iter()
            .filter_map(|(id, frame)| (frame.expires_at_ms <= now_ms).then_some(*id))
            .collect();
        for id in expired {
            self.pending.remove(&id);
            self.order.retain(|candidate| *candidate != id);
        }
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum ProximityError {
    #[error("invalid or linkable proximity advertisement")]
    InvalidAdvertisement,
    #[error("incomplete proximity handshake transcript")]
    IncompleteHandshake,
    #[error("invalid proximity envelope")]
    InvalidEnvelope,
    #[error("proximity envelope exceeds reviewed size")]
    OversizedEnvelope,
    #[error("proximity envelope expired")]
    Expired,
    #[error("proximity envelope was issued too far in the future")]
    FromFuture,
    #[error("proximity ciphertext digest mismatch")]
    DigestMismatch,
    #[error("proximity device signature mismatch")]
    SignatureMismatch,
    #[error("invalid replay or reassembly capacity")]
    InvalidCapacity,
    #[error("invalid BLE frame")]
    InvalidFrame,
    #[error("invalid proximity consent transition")]
    ConsentState,
}

fn bounded_identifier(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:@/-".contains(&byte))
}

fn base64url_chars(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer as _, SigningKey};

    const NOW: u64 = 1_787_590_800_000;
    const SENDER: Uuid = Uuid::from_u128(0x22222222_2222_4222_8222_222222222222);
    const RECIPIENT: Uuid = Uuid::from_u128(0x33333333_3333_4333_8333_333333333333);

    fn envelope(sequence: u32, id: Uuid, key: &SigningKey) -> ProximityEnvelope {
        let ciphertext = b"encrypted-clip-envelope";
        let mut value = ProximityEnvelope {
            protocol: PROTOCOL.to_owned(),
            message_kind: ProximityMessageKind::ClipboardOffer,
            message_id: id,
            session_id: "AQIDBAUGBwgJCgsMDQ4PEA".to_owned(),
            sequence,
            issued_at_unix_ms: NOW,
            expires_at_unix_ms: NOW + MAX_MESSAGE_LIFETIME_MS,
            sender_device_id: SENDER,
            recipient_device_id: RECIPIENT,
            scope: ProximityMessageKind::ClipboardOffer
                .required_scope()
                .to_owned(),
            ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
            ciphertext_sha256: hex::encode(Sha256::digest(ciphertext)),
            signing_key_id: "device-key-1".to_owned(),
            signature: URL_SAFE_NO_PAD.encode([0_u8; 64]),
        };
        value.signature =
            URL_SAFE_NO_PAD.encode(key.sign(&value.signing_bytes().unwrap()).to_bytes());
        value
    }

    #[test]
    fn advertisements_rotate_without_stable_device_metadata() {
        let secret = [7_u8; 32];
        let first = ProximityAdvertisement::derive(&secret, "device-key-1", NOW).unwrap();
        let next = ProximityAdvertisement::derive(
            &secret,
            "device-key-1",
            NOW + DEFAULT_ADVERTISEMENT_ROTATION_MS,
        )
        .unwrap();
        assert_ne!(first.rotating_id, next.rotating_id);
        assert!(
            !serde_json::to_string(&first)
                .unwrap()
                .contains("device-key-1")
        );
        assert!(first.display_name().unwrap().starts_with("CT-"));
    }

    #[test]
    fn shared_proximity_certification_fixture_parses_and_keeps_valid_digests() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/proximity_v1.json")).unwrap();
        let advertisement: ProximityAdvertisement =
            serde_json::from_value(fixture["advertisement"].clone()).unwrap();
        assert_eq!(advertisement.protocol, PROTOCOL);
        let envelopes: Vec<ProximityEnvelope> =
            serde_json::from_value(fixture["envelopes"].clone()).unwrap();
        assert_eq!(envelopes.len(), 2);
        for envelope in envelopes {
            envelope.verify_digest().unwrap();
        }
    }

    #[test]
    fn signature_digest_and_replay_guards_fail_closed() {
        let key = SigningKey::from_bytes(&[9_u8; 32]);
        let value = envelope(
            1,
            Uuid::from_u128(0xaaaaaaaa_aaaa_4aaa_8aaa_aaaaaaaaaaaa),
            &key,
        );
        value.verify_digest().unwrap();
        value
            .verify_signature(key.verifying_key().as_bytes())
            .unwrap();
        let mut replay = ProximityReplayGuard::new(16).unwrap();
        assert_eq!(
            value
                .verify_and_accept(
                    key.verifying_key().as_bytes(),
                    &mut replay,
                    NOW,
                    RECIPIENT,
                    SENDER
                )
                .unwrap(),
            ReplayDecision::Accepted
        );
        assert_eq!(
            value
                .verify_and_accept(
                    key.verifying_key().as_bytes(),
                    &mut replay,
                    NOW,
                    RECIPIENT,
                    SENDER
                )
                .unwrap(),
            ReplayDecision::Duplicate
        );
        let mut wrong_recipient = ProximityReplayGuard::new(16).unwrap();
        assert_eq!(
            value
                .verify_and_accept(
                    key.verifying_key().as_bytes(),
                    &mut wrong_recipient,
                    NOW,
                    SENDER,
                    SENDER
                )
                .unwrap(),
            ReplayDecision::WrongRecipient
        );

        let mut unsigned = value.clone();
        unsigned.signature = URL_SAFE_NO_PAD.encode([0_u8; 64]);
        let mut signature_guard = ProximityReplayGuard::new(16).unwrap();
        assert_eq!(
            unsigned.verify_and_accept(
                key.verifying_key().as_bytes(),
                &mut signature_guard,
                NOW,
                RECIPIENT,
                SENDER
            ),
            Err(ProximityError::SignatureMismatch)
        );
        assert_eq!(
            value
                .verify_and_accept(
                    key.verifying_key().as_bytes(),
                    &mut signature_guard,
                    NOW,
                    RECIPIENT,
                    SENDER
                )
                .unwrap(),
            ReplayDecision::Accepted
        );
    }

    #[test]
    fn unknown_or_credential_fields_are_rejected() {
        let key = SigningKey::from_bytes(&[9_u8; 32]);
        let value = envelope(1, Uuid::new_v4(), &key);
        let mut json = serde_json::to_value(value).unwrap();
        json.as_object_mut()
            .unwrap()
            .insert("otp_code".to_owned(), serde_json::json!("123456"));
        assert_eq!(
            serde_json::from_value::<ProximityEnvelope>(json)
                .unwrap_err()
                .classify(),
            serde_json::error::Category::Data
        );
    }

    #[test]
    fn consent_is_bilateral_and_offer_specific() {
        let mut gate = ProximityConsentGate::default();
        gate.begin_code_comparison().unwrap();
        gate.confirm_code(true).unwrap();
        assert_eq!(gate.state(), ConsentState::ComparingCode);
        gate.confirm_code(false).unwrap();
        gate.present_offer("offer-1").unwrap();
        assert!(!gate.approve_once("offer-2"));
        assert!(gate.approve_once("offer-1"));
        assert!(!gate.approve_once("offer-1"));
    }

    #[test]
    fn ble_frames_round_trip_out_of_order_and_reject_duplicates() {
        let message: Vec<u8> = (0..700).map(|value| (value % 251) as u8).collect();
        let packets = fragment_ble_message(&message, 64).unwrap();
        let mut reassembler = BleFrameReassembler::new(8).unwrap();
        let mut result = None;
        for packet in packets.iter().rev() {
            result = reassembler.add(packet, NOW).unwrap().or(result);
        }
        assert_eq!(result.unwrap(), message);
        let mut duplicate = BleFrameReassembler::new(8).unwrap();
        assert!(duplicate.add(&packets[0], NOW).unwrap().is_none());
        assert_eq!(
            duplicate.add(&packets[0], NOW).unwrap_err(),
            ProximityError::InvalidFrame
        );
    }

    #[test]
    fn safety_code_changes_with_transcript() {
        let first = derive_safety_code(&[1; 32], &[2; 32], &[3; 32]).unwrap();
        let second = derive_safety_code(&[1; 32], &[2; 32], &[4; 32]).unwrap();
        assert_eq!(first.len(), 6);
        assert_ne!(first, second);
    }
}
