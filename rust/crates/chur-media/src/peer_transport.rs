//! Ephemeral, authenticated, direct device connections. No relay or durable service.
//!
//! Version 2 adds an X25519 exchange to the invitation secret and a signed
//! transcript: each device proves its enrolled device key before any frame of
//! the caller is sent or received.
use chur_core::{ChurStatus, Error, Id, Result, ensure};
use chur_crypto::peer::{EphemeralKey, HELLO_LEN};
use chur_crypto::{Key, Nonce, aead, random};
use chur_sync_protocol::peer_auth::{PeerCredential, RECORD_LEN};
use std::io::{Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

/// Maximum plaintext in one bounded peer frame.
pub const FRAME_MAX: usize = 4 * 1024 * 1024;
const MAGIC: &[u8; 8] = b"CHURP2P2";
/// The version-1 hello magic, refused with `UNSUPPORTED_VERSION`.
const LEGACY_MAGIC: &[u8; 8] = b"CHURP2P1";
/// The initiator role signs 1 and the listener role signs 0.
const INITIATOR: u8 = 1;
const LISTENER: u8 = 0;
/// Unproven connections that one invitation examines at the same time.
const CANDIDATES_MAX: usize = 4;
/// Failed connections after which an invitation closes.
const ATTEMPTS_MAX: u32 = 32;
const CANDIDATE_TIMEOUT: Duration = Duration::from_secs(10);
const IDLE_TIMEOUT: Duration = Duration::from_secs(120);

/// One foreground-only invitation or connected peer. Secrets never enter durable storage.
pub struct Peer {
    listener: Option<TcpListener>,
    candidates: Vec<Channel>,
    channel: Option<Channel>,
    secret: Key,
    initiator: bool,
    deadline: Instant,
    failures: u32,
    credential: PeerCredential,
    remote: Option<Id>,
    legacy: bool,
}
impl Peer {
    /// Opens a one-use invitation on a random port of one device interface address.
    /// The listener never binds all interfaces.
    pub fn listen(address: IpAddr, credential: PeerCredential) -> Result<(Self, u16, Key)> {
        ensure!(
            !address.is_unspecified() && !address.is_multicast(),
            InvalidInput,
            "invalid peer address"
        );
        let listener = TcpListener::bind((address, 0)).map_err(network)?;
        listener.set_nonblocking(true).map_err(network)?;
        let port = listener.local_addr().map_err(network)?.port();
        let secret = Key::new(random::array()?);
        let mut peer = Self::new(secret.duplicate(), false, credential);
        peer.listener = Some(listener);
        Ok((peer, port, secret))
    }
    /// Connects directly to a literal device IP address, without DNS, discovery, or relays.
    pub fn connect(
        address: IpAddr,
        port: u16,
        secret: Key,
        credential: PeerCredential,
    ) -> Result<Self> {
        ensure!(
            port != 0 && !address.is_unspecified() && !address.is_multicast(),
            InvalidInput,
            "invalid peer address"
        );
        let stream =
            TcpStream::connect_timeout(&SocketAddr::new(address, port), Duration::from_secs(3))
                .map_err(network)?;
        let mut peer = Self::new(secret, true, credential);
        peer.channel = Some(Channel::create(stream, FRAME_MAX, IDLE_TIMEOUT)?);
        Ok(peer)
    }
    fn new(secret: Key, initiator: bool, credential: PeerCredential) -> Self {
        Self {
            listener: None,
            candidates: Vec::new(),
            channel: None,
            secret,
            initiator,
            deadline: Instant::now() + IDLE_TIMEOUT,
            failures: 0,
            credential,
            remote: None,
            legacy: false,
        }
    }
    /// The device whose enrolled key signed this session, once verified.
    pub const fn remote_device(&self) -> Option<&Id> {
        self.remote.as_ref()
    }
    /// Pumps bounded nonblocking IO; true means both devices proved the invitation
    /// secret and the remote device signature verified against its enrolled key.
    pub fn poll(&mut self) -> Result<bool> {
        if self.channel.is_none() {
            self.accept()?;
        }
        let Some(channel) = self.channel.as_mut() else {
            return Ok(false);
        };
        channel.pump(true)?;
        if channel.handshake(&self.secret, self.initiator)? {
            // The initiator proves itself first; the listener answers only a verified peer.
            channel.authenticate(&self.credential, INITIATOR)?;
        }
        if self.remote.is_none()
            && let Some(record) = channel.open()?
        {
            self.remote = Some(channel.verify(&self.credential, LISTENER, &record)?);
        }
        Ok(self.remote.is_some() && channel.outgoing.is_empty())
    }
    /// Examines bounded unproven connections until one opens its first frame with the
    /// invitation keys. A failed connection is closed and the invitation stays open.
    fn accept(&mut self) -> Result<()> {
        if Instant::now() >= self.deadline {
            return Err(self.closed(ChurStatus::NetworkFailure, "peer invitation expired"));
        }
        let listener = self
            .listener
            .as_ref()
            .ok_or_else(|| Error::new(ChurStatus::NetworkFailure, "peer disconnected"))?;
        let mut accepted = Vec::new();
        while self.candidates.len() + accepted.len() < CANDIDATES_MAX {
            match listener.accept() {
                Ok((stream, _)) => accepted.push(stream),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(network(e)),
            }
        }
        for stream in accepted {
            match Channel::create(stream, RECORD_LEN, CANDIDATE_TIMEOUT) {
                Ok(candidate) => self.candidates.push(candidate),
                Err(_) => self.reject()?,
            }
        }
        let mut index = 0;
        while index < self.candidates.len() {
            match self.candidates[index].prove(&self.secret) {
                Ok(None) => index += 1,
                Ok(Some(record)) => {
                    // The frame opened, so this host holds the invitation. A device
                    // signature that does not verify fails the invitation.
                    let mut channel = self.candidates.swap_remove(index);
                    self.candidates.clear();
                    self.listener = None;
                    self.remote = Some(channel.verify(&self.credential, INITIATOR, &record)?);
                    channel.authenticate(&self.credential, LISTENER)?;
                    channel.frame_max = FRAME_MAX;
                    channel.deadline = Instant::now() + IDLE_TIMEOUT;
                    self.channel = Some(channel);
                    return Ok(());
                }
                Err(error) => {
                    self.legacy |= error.status() == ChurStatus::UnsupportedVersion;
                    self.candidates.swap_remove(index);
                    self.reject()?;
                }
            }
        }
        Ok(())
    }
    fn reject(&mut self) -> Result<()> {
        self.failures += 1;
        if self.failures >= ATTEMPTS_MAX {
            return Err(self.closed(
                ChurStatus::AuthenticationFailed,
                "too many failed peer connections",
            ));
        }
        Ok(())
    }
    /// Closes the invitation. This is reached only while no connection has proven the
    /// invitation, so a version-1 hello is reported only as a refused connection. It
    /// is not a session result, and an unauthenticated host can send it.
    fn closed(&self, status: ChurStatus, message: &'static str) -> Error {
        if self.legacy {
            Error::new(
                ChurStatus::UnsupportedVersion,
                "the invitation closed; a refused connection used an unsupported peer protocol version",
            )
        } else {
            Error::new(status, message)
        }
    }
    /// Queues exactly one authenticated frame. Call flush before another send.
    pub fn send(&mut self, bytes: &[u8]) -> Result<()> {
        let channel = self
            .channel
            .as_mut()
            .filter(|_| self.remote.is_some())
            .ok_or_else(|| Error::new(ChurStatus::Conflict, "peer handshake pending"))?;
        ensure!(
            channel.outgoing.is_empty(),
            ResourceLimitExceeded,
            "peer output is full"
        );
        channel.seal(bytes)
    }
    /// Flushes queued output without blocking.
    pub fn flush(&mut self) -> Result<bool> {
        self.poll()?;
        Ok(self
            .channel
            .as_ref()
            .is_some_and(|channel| channel.outgoing.is_empty()))
    }
    /// Receives a full verified frame, retaining incomplete TCP reads for the next poll.
    pub fn receive(&mut self) -> Result<Option<Zeroizing<Vec<u8>>>> {
        self.poll()?;
        match self.channel.as_mut() {
            Some(channel) if self.remote.is_some() => channel.open(),
            _ => Ok(None),
        }
    }
}

/// One TCP stream with its handshake state and direction keys.
struct Channel {
    stream: TcpStream,
    hello: [u8; HELLO_LEN],
    tx_key: Option<Key>,
    rx_key: Option<Key>,
    tx_sequence: u64,
    rx_sequence: u64,
    incoming: Vec<u8>,
    outgoing: Zeroizing<Vec<u8>>,
    sent: usize,
    deadline: Instant,
    frame_max: usize,
    ephemeral: Option<EphemeralKey>,
    transcript: [u8; 32],
    binding: Option<Key>,
}
impl Channel {
    fn create(stream: TcpStream, frame_max: usize, timeout: Duration) -> Result<Self> {
        stream.set_nonblocking(true).map_err(network)?;
        stream.set_nodelay(true).map_err(network)?;
        let ephemeral = EphemeralKey::generate()?;
        let mut hello = [0; HELLO_LEN];
        hello[..8].copy_from_slice(MAGIC);
        hello[8..40].copy_from_slice(&random::array::<32>()?);
        hello[40..].copy_from_slice(&ephemeral.public_key());
        let mut outgoing = Zeroizing::new(Vec::new());
        outgoing.extend_from_slice(&hello);
        Ok(Self {
            stream,
            hello,
            tx_key: None,
            rx_key: None,
            tx_sequence: 0,
            rx_sequence: 0,
            incoming: Vec::new(),
            outgoing,
            sent: 0,
            deadline: Instant::now() + timeout,
            frame_max,
            ephemeral: Some(ephemeral),
            transcript: [0; 32],
            binding: None,
        })
    }
    /// Advances an unproven listener connection; a frame means the secret is proven.
    fn prove(&mut self, secret: &Key) -> Result<Option<Zeroizing<Vec<u8>>>> {
        self.pump(false)?;
        self.handshake(secret, false)?;
        self.open()
    }
    /// Pumps bounded nonblocking IO. An established stream extends its idle deadline.
    fn pump(&mut self, extend: bool) -> Result<()> {
        ensure!(
            Instant::now() < self.deadline,
            NetworkFailure,
            "peer connection timed out"
        );
        // A bounded pump never holds up a vault lock waiting for a peer.
        for _ in 0..16 {
            if self.sent == self.outgoing.len() {
                break;
            }
            match self.stream.write(&self.outgoing[self.sent..]) {
                Ok(0) => return Err(Error::new(ChurStatus::NetworkFailure, "peer write ended")),
                Ok(n) => {
                    self.sent += n;
                    if extend {
                        self.deadline = Instant::now() + IDLE_TIMEOUT;
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(network(e)),
            }
        }
        if self.sent == self.outgoing.len() {
            self.outgoing.clear();
            self.sent = 0;
        }
        let mut chunk = [0; 64 * 1024];
        for _ in 0..16 {
            match self.stream.read(&mut chunk) {
                Ok(0) => {
                    // A full final frame survives FIN; a truncated frame fails immediately.
                    let complete = if self.tx_key.is_none() {
                        self.incoming.len() >= HELLO_LEN
                    } else if self.incoming.len() >= 4 {
                        self.incoming.len() >= frame_length(&self.incoming)? + 4
                    } else {
                        false
                    };
                    ensure!(
                        complete,
                        NetworkFailure,
                        "peer closed an incomplete connection"
                    );
                    break;
                }
                Ok(n) => {
                    ensure!(
                        self.incoming.len() + n <= self.frame_max + HELLO_LEN + 64,
                        ResourceLimitExceeded,
                        "peer frame exceeds limit"
                    );
                    self.incoming.extend_from_slice(&chunk[..n]);
                    if extend {
                        self.deadline = Instant::now() + IDLE_TIMEOUT;
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(network(e)),
            }
        }
        Ok(())
    }
    /// Derives both direction keys when the remote hello is complete; true once.
    fn handshake(&mut self, secret: &Key, initiator: bool) -> Result<bool> {
        if self.tx_key.is_some() || self.incoming.len() < 8 {
            return Ok(false);
        }
        ensure!(
            &self.incoming[..8] != LEGACY_MAGIC,
            UnsupportedVersion,
            "the peer at this address uses an unsupported peer protocol version"
        );
        ensure!(
            &self.incoming[..8] == MAGIC,
            AuthenticationFailed,
            "peer protocol differs"
        );
        if self.incoming.len() < HELLO_LEN {
            return Ok(false);
        }
        let remote: [u8; HELLO_LEN] = self.incoming[..HELLO_LEN]
            .try_into()
            .map_err(|_| Error::new(ChurStatus::InvalidInput, "peer hello length"))?;
        self.incoming.drain(..HELLO_LEN);
        let (first, second) = if initiator {
            (&self.hello, &remote)
        } else {
            (&remote, &self.hello)
        };
        self.transcript = chur_crypto::peer::transcript(first, second)?;
        let remote_key: [u8; 32] = remote[40..]
            .try_into()
            .map_err(|_| Error::new(ChurStatus::InvalidInput, "peer hello length"))?;
        let shared = self
            .ephemeral
            .take()
            .ok_or_else(|| Error::new(ChurStatus::InternalFailure, "peer key was used"))?
            .agree(&remote_key)?;
        let keys = chur_crypto::peer::session_keys(secret, &shared, &self.transcript)?;
        let (tx, rx) = if initiator {
            (keys.initiator, keys.listener)
        } else {
            (keys.listener, keys.initiator)
        };
        self.tx_key = Some(tx);
        self.rx_key = Some(rx);
        self.binding = Some(keys.binding);
        Ok(true)
    }
    /// Queues the signed authentication record as this direction's first frame.
    fn authenticate(&mut self, credential: &PeerCredential, role: u8) -> Result<()> {
        let binding = self
            .binding
            .as_ref()
            .ok_or_else(|| Error::new(ChurStatus::Conflict, "peer handshake pending"))?;
        let record = credential.sign(role, &self.transcript, binding.expose());
        self.seal(&record)
    }
    /// Verifies the remote authentication record against the enrolled device keys.
    fn verify(&self, credential: &PeerCredential, role: u8, record: &[u8]) -> Result<Id> {
        let binding = self
            .binding
            .as_ref()
            .ok_or_else(|| Error::new(ChurStatus::Conflict, "peer handshake pending"))?;
        credential.verify(role, &self.transcript, binding.expose(), record)
    }
    fn seal(&mut self, bytes: &[u8]) -> Result<()> {
        ensure!(
            bytes.len() <= FRAME_MAX,
            ResourceLimitExceeded,
            "peer output is full"
        );
        let key = self
            .tx_key
            .as_ref()
            .ok_or_else(|| Error::new(ChurStatus::Conflict, "peer handshake pending"))?;
        let sequence = self.tx_sequence.to_be_bytes();
        let sealed = aead::seal(
            key,
            &Nonce::chunk(&[0; 16], self.tx_sequence),
            bytes,
            &sequence,
        )?;
        self.tx_sequence = self.tx_sequence.checked_add(1).ok_or_else(|| {
            Error::new(ChurStatus::ResourceLimitExceeded, "peer sequence exhausted")
        })?;
        self.outgoing
            .extend_from_slice(&(sealed.len() as u32).to_be_bytes());
        self.outgoing.extend_from_slice(&sealed);
        Ok(())
    }
    /// Opens the next complete frame. Unauthenticated plaintext is never returned.
    fn open(&mut self) -> Result<Option<Zeroizing<Vec<u8>>>> {
        if self.tx_key.is_none() || self.incoming.len() < 4 {
            return Ok(None);
        }
        let size = frame_length(&self.incoming)?;
        ensure!(
            (16..=self.frame_max + 16).contains(&size),
            ResourceLimitExceeded,
            "peer frame length is invalid"
        );
        if self.incoming.len() < size + 4 {
            return Ok(None);
        }
        let key = self
            .rx_key
            .as_ref()
            .ok_or_else(|| Error::new(ChurStatus::AuthenticationFailed, "peer key absent"))?;
        let opened = aead::open(
            key,
            &Nonce::chunk(&[0; 16], self.rx_sequence),
            &self.incoming[4..4 + size],
            &self.rx_sequence.to_be_bytes(),
        )
        .map_err(|_| {
            Error::new(
                ChurStatus::AuthenticationFailed,
                "peer frame authentication failed",
            )
        })?;
        self.rx_sequence = self.rx_sequence.checked_add(1).ok_or_else(|| {
            Error::new(ChurStatus::ResourceLimitExceeded, "peer sequence exhausted")
        })?;
        self.incoming.drain(..size + 4);
        Ok(Some(opened))
    }
}
impl Drop for Channel {
    fn drop(&mut self) {
        let _ = self.stream.shutdown(Shutdown::Both);
    }
}
fn frame_length(incoming: &[u8]) -> Result<usize> {
    let header: [u8; 4] = incoming
        .get(..4)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| Error::new(ChurStatus::InvalidInput, "peer frame header"))?;
    Ok(u32::from_be_bytes(header) as usize)
}
fn network(_: std::io::Error) -> Error {
    Error::new(ChurStatus::NetworkFailure, "direct peer connection failed")
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use chur_sync_protocol::identity::DeviceIdentity;
    use std::net::Ipv4Addr;
    const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
    /// Device 2 listens, device 3 connects, and device 4 is another active member.
    const MEMBERS: [(u8, u8); 3] = [(2, 0x20), (3, 0x30), (4, 0x40)];
    fn id(byte: u8) -> Id {
        Id::new([byte; 16]).unwrap()
    }
    fn credential(device: u8, seed: u8) -> PeerCredential {
        let trusted = MEMBERS
            .iter()
            .map(|(device, seed)| {
                let identity = DeviceIdentity::from_seeds([*seed; 32], [*seed; 32]);
                (id(*device), identity.signing_public_key())
            })
            .collect();
        PeerCredential::new(
            id(1),
            id(device),
            DeviceIdentity::from_seeds([seed; 32], [seed; 32]),
            trusted,
        )
    }
    fn invitation() -> (Peer, u16, Key) {
        Peer::listen(LOOPBACK, credential(2, 0x20)).unwrap()
    }
    fn join(listener: &mut Peer, port: u16, secret: Key) -> Peer {
        let mut connector = Peer::connect(LOOPBACK, port, secret, credential(3, 0x30)).unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            assert!(Instant::now() < deadline, "direct handshake did not finish");
            let left = listener.poll().unwrap();
            let right = connector.poll().unwrap();
            if left && right {
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(listener.remote_device(), Some(&id(3)));
        assert_eq!(connector.remote_device(), Some(&id(2)));
        connector
    }
    fn connected() -> (Peer, Peer) {
        let (mut listener, port, secret) = invitation();
        let connector = join(&mut listener, port, secret);
        (listener, connector)
    }
    /// Polls the listener until it fails, while the connector side is pumped.
    fn listener_failure(listener: &mut Peer, mut connector: impl FnMut()) -> Error {
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            assert!(Instant::now() < deadline, "listener did not fail");
            connector();
            match listener.poll() {
                Err(error) => return error,
                Ok(ready) => assert!(!ready),
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    fn receive_sent(source: &mut Peer, target: &mut Peer) -> Result<Zeroizing<Vec<u8>>> {
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            assert!(Instant::now() < deadline, "direct frame did not finish");
            source.flush()?;
            if let Some(received) = target.receive()? {
                return Ok(received);
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    fn transfer(source: &mut Peer, target: &mut Peer, bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        source.send(bytes)?;
        receive_sent(source, target)
    }
    /// Polls the listener until it closed the given number of failed connections.
    fn await_failures(listener: &mut Peer, failures: u32, mut connector: impl FnMut()) {
        let deadline = Instant::now() + Duration::from_secs(3);
        while listener.failures < failures {
            assert!(
                Instant::now() < deadline,
                "failed connection was not closed"
            );
            connector();
            assert!(!listener.poll().unwrap());
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    #[test]
    fn real_tcp_exchanges_large_bounded_frames_in_both_directions() {
        let (mut left, mut right) = connected();
        let original: Vec<u8> = (0..2_000_000).map(|i| (i % 251) as u8).collect();
        assert_eq!(
            &*transfer(&mut left, &mut right, &original).unwrap(),
            &original
        );
        assert_eq!(
            &*transfer(&mut right, &mut left, b"acknowledged").unwrap(),
            b"acknowledged"
        );
        assert_eq!(
            &*transfer(&mut left, &mut right, b"next sequence").unwrap(),
            b"next sequence"
        );
        assert!(left.send(&vec![0; FRAME_MAX + 1]).is_err());
    }
    #[test]
    fn no_caller_frame_moves_before_the_remote_device_is_verified() {
        let (mut listener, port, secret) = invitation();
        let mut connector = Peer::connect(LOOPBACK, port, secret, credential(3, 0x30)).unwrap();
        assert_eq!(
            connector.send(b"early").unwrap_err().status(),
            ChurStatus::Conflict
        );
        assert!(connector.receive().unwrap().is_none());
        assert!(listener.receive().unwrap().is_none());
        assert!(listener.remote_device().is_none());
    }
    #[test]
    fn the_listener_binds_only_the_given_interface_address() {
        let (listener, _, _) = invitation();
        let bound = listener.listener.as_ref().unwrap().local_addr().unwrap();
        assert_eq!(bound.ip(), LOOPBACK);
        let unspecified = Peer::listen(IpAddr::V4(Ipv4Addr::UNSPECIFIED), credential(2, 0x20));
        assert_eq!(
            unspecified.err().unwrap().status(),
            ChurStatus::InvalidInput
        );
    }
    #[test]
    fn a_wrong_invitation_is_closed_and_the_invitation_stays_open() {
        let (mut listener, port, secret) = invitation();
        let mut wrong =
            Peer::connect(LOOPBACK, port, Key::new([0x55; 32]), credential(3, 0x30)).unwrap();
        await_failures(&mut listener, 1, || {
            let _ = wrong.poll();
        });
        assert!(listener.channel.is_none() && listener.listener.is_some());
        let mut right = join(&mut listener, port, secret);
        assert_eq!(
            &*transfer(&mut listener, &mut right, b"after").unwrap(),
            b"after"
        );
        // A proven connection closes the invitation for every later host.
        assert!(listener.listener.is_none());
    }
    #[test]
    fn idle_and_malformed_connections_do_not_take_the_invitation() {
        let (mut listener, port, secret) = invitation();
        let _idle = TcpStream::connect((LOOPBACK, port)).unwrap();
        let mut garbage = TcpStream::connect((LOOPBACK, port)).unwrap();
        garbage.write_all(&[0; HELLO_LEN]).unwrap();
        await_failures(&mut listener, 1, || {});
        let mut right = join(&mut listener, port, secret);
        assert_eq!(
            &*transfer(&mut right, &mut listener, b"proven").unwrap(),
            b"proven"
        );
    }
    #[test]
    fn failed_connections_and_the_invitation_deadline_are_bounded() {
        let (mut listener, port, _) = invitation();
        listener.failures = ATTEMPTS_MAX - 1;
        let mut garbage = TcpStream::connect((LOOPBACK, port)).unwrap();
        garbage.write_all(&[0; HELLO_LEN]).unwrap();
        let error = listener_failure(&mut listener, || {});
        assert_eq!(error.status(), ChurStatus::AuthenticationFailed);
        let (mut expired, _, _) = invitation();
        expired.deadline = Instant::now();
        assert_eq!(
            expired.poll().unwrap_err().status(),
            ChurStatus::NetworkFailure
        );
    }
    #[test]
    fn a_version_one_peer_is_refused_with_unsupported_version() {
        let raw = TcpListener::bind((LOOPBACK, 0)).unwrap();
        let port = raw.local_addr().unwrap().port();
        let mut connector =
            Peer::connect(LOOPBACK, port, Key::new([1; 32]), credential(3, 0x30)).unwrap();
        let (mut legacy, _) = raw.accept().unwrap();
        legacy.write_all(LEGACY_MAGIC).unwrap();
        legacy.write_all(&[7; 32]).unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        let error = loop {
            assert!(Instant::now() < deadline, "old hello was not refused");
            match connector.poll() {
                Err(error) => break error,
                Ok(ready) => assert!(!ready),
            }
            std::thread::sleep(Duration::from_millis(1));
        };
        assert_eq!(error.status(), ChurStatus::UnsupportedVersion);
        // A listener closes the old connection, stays open, and reports the version at expiry.
        let (mut listener, port, _) = invitation();
        let mut old = TcpStream::connect((LOOPBACK, port)).unwrap();
        old.write_all(LEGACY_MAGIC).unwrap();
        old.write_all(&[7; 32]).unwrap();
        await_failures(&mut listener, 1, || {});
        listener.deadline = Instant::now();
        assert_eq!(
            listener.poll().unwrap_err().status(),
            ChurStatus::UnsupportedVersion
        );
    }
    #[test]
    fn a_handshake_with_a_key_other_than_the_enrolled_device_key_fails() {
        // Device 3 is enrolled with seed 0x30; this connector signs with another key.
        let (mut listener, port, secret) = invitation();
        let mut connector = Peer::connect(LOOPBACK, port, secret, credential(3, 0x50)).unwrap();
        let error = listener_failure(&mut listener, || {
            let _ = connector.poll();
        });
        assert_eq!(error.status(), ChurStatus::AuthenticationFailed);
        assert!(listener.remote_device().is_none());
    }
    #[test]
    fn a_peer_that_asserts_another_member_or_an_unknown_device_fails() {
        // Device 3 claims active member 4, then an unenrolled identifier.
        for claimed in [4, 9] {
            let (mut listener, port, secret) = invitation();
            let mut connector =
                Peer::connect(LOOPBACK, port, secret, credential(claimed, 0x30)).unwrap();
            let error = listener_failure(&mut listener, || {
                let _ = connector.poll();
            });
            assert_eq!(error.status(), ChurStatus::AuthenticationFailed);
        }
        // The listener also fails when the listener signs with a key it does not own.
        let (mut listener, port, secret) = Peer::listen(LOOPBACK, credential(4, 0x20)).unwrap();
        let mut connector = Peer::connect(LOOPBACK, port, secret, credential(3, 0x30)).unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        let error = loop {
            assert!(Instant::now() < deadline, "connector did not fail");
            let _ = listener.poll();
            match connector.poll() {
                Err(error) => break error,
                Ok(ready) => assert!(!ready),
            }
            std::thread::sleep(Duration::from_millis(1));
        };
        assert_eq!(error.status(), ChurStatus::AuthenticationFailed);
    }
    #[test]
    fn a_replayed_signed_transcript_fails_in_a_new_session_for_the_same_invitation() {
        let (mut first, port, secret) = invitation();
        let connector = join(&mut first, port, secret.duplicate());
        let channel = connector.channel.as_ref().unwrap();
        let replay = connector.credential.sign(
            INITIATOR,
            &channel.transcript,
            channel.binding.as_ref().unwrap().expose(),
        );
        let (mut second, port, _) = invitation();
        second.secret = secret.duplicate();
        // A host that holds the invitation completes the handshake and sends the old record.
        let stream = TcpStream::connect((LOOPBACK, port)).unwrap();
        let mut replayer = Channel::create(stream, FRAME_MAX, IDLE_TIMEOUT).unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            assert!(Instant::now() < deadline, "replay handshake did not finish");
            assert!(!second.poll().unwrap());
            replayer.pump(true).unwrap();
            if replayer.handshake(&secret, true).unwrap() {
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_ne!(replayer.transcript, channel.transcript);
        replayer.seal(&replay).unwrap();
        let error = listener_failure(&mut second, || {
            let _ = replayer.pump(true);
        });
        assert_eq!(error.status(), ChurStatus::AuthenticationFailed);
    }
    #[test]
    fn two_sessions_for_the_same_invitation_derive_different_keys() {
        let (mut first, port, secret) = invitation();
        let _left = join(&mut first, port, secret.duplicate());
        let (mut second, port, _) = invitation();
        second.secret = secret.duplicate();
        let _right = join(&mut second, port, secret);
        let (first, second) = (first.channel.unwrap(), second.channel.unwrap());
        for (one, two) in [
            (&first.tx_key, &second.tx_key),
            (&first.rx_key, &second.rx_key),
            (&first.binding, &second.binding),
        ] {
            assert_ne!(
                one.as_ref().unwrap().expose(),
                two.as_ref().unwrap().expose()
            );
        }
    }
    #[test]
    fn a_truncated_frame_followed_by_disconnect_fails_without_waiting_for_idle_timeout() {
        let (mut left, mut right) = connected();
        let channel = left.channel.as_mut().unwrap();
        channel.outgoing.extend_from_slice(&100u32.to_be_bytes());
        channel.outgoing.extend_from_slice(&[0; 8]);
        while !left.flush().unwrap() {
            std::thread::sleep(Duration::from_millis(1));
        }
        drop(left);
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            assert!(
                Instant::now() < deadline,
                "a disconnected frame must not wait for idle timeout"
            );
            match right.receive() {
                Err(error) => {
                    assert_eq!(error.status(), ChurStatus::NetworkFailure);
                    break;
                }
                Ok(result) => assert!(result.is_none()),
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    #[test]
    fn replayed_encrypted_frames_and_tampered_bytes_fail_authentication() {
        let (mut left, mut right) = connected();
        left.send(b"one").unwrap();
        let replay = left.channel.as_ref().unwrap().outgoing.to_vec();
        assert_eq!(&*receive_sent(&mut left, &mut right).unwrap(), b"one");
        left.channel
            .as_mut()
            .unwrap()
            .outgoing
            .extend_from_slice(&replay);
        assert_eq!(
            receive_sent(&mut left, &mut right).unwrap_err().status(),
            ChurStatus::AuthenticationFailed
        );
        let (mut left, mut right) = connected();
        left.send(b"two").unwrap();
        *left.channel.as_mut().unwrap().outgoing.last_mut().unwrap() ^= 1;
        assert_eq!(
            receive_sent(&mut left, &mut right).unwrap_err().status(),
            ChurStatus::AuthenticationFailed
        );
    }
}
