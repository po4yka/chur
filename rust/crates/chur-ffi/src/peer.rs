//! Bounded foreground direct peer transport and signed history export.
use crate::api::{Status, borrow_bytes_mut, borrow_large, write_out};
use crate::panic::guard_status_for;
use crate::registry::{self, Entry, Handle, Kind};
use chur_core::{ChurStatus, Error, Result, ensure};
use chur_crypto::Key;
use chur_format::codec::{Reader, Writer};
use chur_media::peer_transport::{FRAME_MAX, Peer};

/// Operates one ephemeral connection owned by an unlocked vault session.
/// Commands: listen=1, connect=2, poll=3, send=4, receive=5, close=6, flush=7,
/// signed device history=8, authenticated device=9, pairing evidence=10,
/// object key for the peer=11, and object ciphertext range=12.
/// Frames, history, keys, and ciphertext move only after the peer proved its
/// enrolled device key, and each such command checks the current membership again.
/// Nothing is persisted by the transport.
/// # Safety
/// Input/output cover their declared non-overlapping ranges; written is writable and aligned.
#[unsafe(no_mangle)]
#[expect(unsafe_code, reason = "the peer C ABI borrows checked caller buffers")]
pub unsafe extern "C" fn chur_peer_call(
    owner: Handle,
    input: *const u8,
    length: u32,
    output: *mut u8,
    capacity: usize,
    written: *mut usize,
) -> Status {
    guard_status_for(owner, || {
        ensure!(
            length as usize <= FRAME_MAX + 256,
            ResourceLimitExceeded,
            "peer input exceeds limit"
        );
        // SAFETY: buffers cover their declared lengths, validated before access.
        let input = unsafe { borrow_large(input, length)? };
        ensure!(
            capacity
                >= match input.first() {
                    Some(1) => 34,
                    Some(3 | 7) => 1,
                    Some(5) => FRAME_MAX + 1,
                    Some(8) => FRAME_MAX / 8,
                    Some(9) if input.len() == 1 => 16,
                    Some(10) => 8192,
                    Some(11) => 346,
                    Some(12) => crate::sharing_publish::RANGE_MAX as usize,
                    _ => 0,
                },
            ResourceLimitExceeded,
            "peer output buffer is too small"
        );
        let destination = unsafe { borrow_bytes_mut(output, capacity)? };
        let entry = registry::get(owner, Kind::Session)?;
        let Entry::Session { session, peer, .. } = entry.as_ref() else {
            return Err(Error::new(
                ChurStatus::InvalidInput,
                "peer owner is not a session",
            ));
        };
        let mut guard = registry::lock(session);
        guard.root_secret()?;
        let bytes = zeroize::Zeroizing::new(call(&mut guard, &mut registry::lock(peer), input)?);
        ensure!(
            bytes.len() <= destination.len(),
            ResourceLimitExceeded,
            "peer response exceeds limit"
        );
        destination[..bytes.len()].copy_from_slice(&bytes);
        // SAFETY: written points to the caller's writable out-parameter.
        unsafe { write_out(written, bytes.len()) }
    })
}
/// Runs one command. A transport or authentication failure closes the connection. A
/// request-level failure after authentication (an absent or deleted object, an
/// offset past the end, a reused or stale key request, an invalid history range) is
/// returned and the connection stays open, so the caller can answer with an error.
fn call(
    session: &mut chur_catalog::vault::Session,
    state: &mut Option<Box<Peer>>,
    input: &[u8],
) -> Result<Vec<u8>> {
    let mut request_level = false;
    let result = dispatch(session, state, input, &mut request_level);
    if result.is_err() && !request_level {
        state.take();
    }
    result
}
fn dispatch(
    session: &mut chur_catalog::vault::Session,
    state: &mut Option<Box<Peer>>,
    input: &[u8],
    request_level: &mut bool,
) -> Result<Vec<u8>> {
    let mut reader = Reader::new(input, ChurStatus::InvalidInput);
    let command = reader.u8()?;
    let mut writer = Writer::new();
    match command {
        1 => {
            // The literal interface address is required; the listener never binds all interfaces.
            let address = reader.string(128)?.parse().map_err(|_| {
                Error::new(ChurStatus::InvalidInput, "enter this device's IP address")
            })?;
            reader.finish()?;
            ensure!(
                state.is_none(),
                Conflict,
                "a peer invitation already exists"
            );
            let (peer, port, secret) = Peer::listen(address, credential(session)?)?;
            writer.u16(port).fixed(secret.expose());
            *state = Some(Box::new(peer));
        }
        2 => {
            let address = reader
                .string(128)?
                .parse()
                .map_err(|_| Error::new(ChurStatus::InvalidInput, "enter a device IP address"))?;
            let port = reader.u16()?;
            let secret = Key::new(reader.fixed()?);
            reader.finish()?;
            ensure!(state.is_none(), Conflict, "a peer session already exists");
            *state = Some(Box::new(Peer::connect(
                address,
                port,
                secret,
                credential(session)?,
            )?));
        }
        3 | 5 | 7 => {
            reader.finish()?;
            let peer = state
                .as_mut()
                .ok_or_else(|| Error::new(ChurStatus::NotFound, "no peer connection"))?;
            // A ready session, a received frame, and flushed output each require that
            // the authenticated device is still active now.
            match command {
                3 => {
                    let ready = peer.poll()?;
                    if ready {
                        authenticated(session, state)?;
                    }
                    writer.u8(u8::from(ready));
                }
                7 => {
                    let flushed = peer.flush()?;
                    if state
                        .as_ref()
                        .is_some_and(|peer| peer.remote_device().is_some())
                    {
                        authenticated(session, state)?;
                    }
                    writer.u8(u8::from(flushed));
                }
                _ => match peer.receive()? {
                    None => {
                        writer.u8(0);
                    }
                    Some(bytes) => {
                        authenticated(session, state)?;
                        writer.u8(1).fixed(&bytes);
                    }
                },
            }
        }
        4 => {
            let bytes = reader.variable(FRAME_MAX as u32)?;
            reader.finish()?;
            authenticated(session, state)?;
            state
                .as_mut()
                .ok_or_else(|| Error::new(ChurStatus::NotFound, "no peer connection"))?
                .send(bytes)?;
        }
        6 => {
            reader.finish()?;
            *state = None;
        }
        8 => {
            let device = reader.id()?;
            let after = reader.u64()?;
            let until = reader.u64()?;
            reader.finish()?;
            authenticated(session, state)?;
            *request_level = true;
            ensure!(
                until >= after,
                InvalidInput,
                "peer history range is invalid"
            );
            let records =
                chur_catalog::sync_log::records_after(session.catalog_ref()?, &device, after)?;
            let mut size = 4;
            let mut page = Vec::new();
            for record in records {
                if page.len() == 256 {
                    break;
                }
                let sequence =
                    chur_sync_protocol::operation::Operation::decode(&record)?.device_sequence();
                if sequence > until {
                    break;
                }
                if size + 12 + record.len() > FRAME_MAX / 8 {
                    ensure!(
                        !page.is_empty(),
                        ResourceLimitExceeded,
                        "peer operation exceeds frame size"
                    );
                    break;
                }
                size += 12 + record.len();
                page.push((sequence, record));
            }
            writer.u32(page.len() as u32);
            for (sequence, record) in page {
                writer.u64(sequence).variable(&record)?;
            }
        }
        9 => {
            // The device comes from the verified signed transcript, never from the caller.
            // An earlier caller form names the device; it must equal the verified one.
            let claimed = if input.len() > 1 {
                Some(reader.id()?)
            } else {
                None
            };
            reader.finish()?;
            let device = authenticated(session, state)?;
            ensure!(
                claimed.is_none_or(|claimed| claimed == device),
                AuthenticationFailed,
                "peer device differs from the authenticated device"
            );
            if claimed.is_none() {
                writer.id(&device);
            }
        }
        10 => {
            reader.finish()?;
            let root = session.root_secret()?.duplicate();
            let vault = session.vault_id();
            if let Some(credentials) =
                chur_catalog::device_pairing::resume(session.catalog()?, &root, vault)?
            {
                writer
                    .u8(1)
                    .fixed(&crate::device_pairing::credentials_record(
                        vault,
                        &credentials,
                    )?);
            } else {
                writer.u8(0);
            }
        }
        11 => {
            // The grant recipient is the authenticated device, never a body device ID.
            let device = authenticated(session, state)?;
            *request_level = true;
            let prekey = chur_sync_protocol::object_grant::ObjectPrekey::decode(&input[1..])?;
            let vault = session.vault_id();
            ensure!(
                prekey.recipient_vault_id() == &vault && prekey.recipient_device_id() == &device,
                AuthenticationFailed,
                "object key request names another device than the authenticated peer"
            );
            let root = session.root_secret()?.duplicate();
            writer.fixed(
                &chur_catalog::object_grants::issue(session.catalog()?, &root, vault, &prekey)?
                    .encode(),
            );
        }
        12 => {
            let object = reader.id()?;
            let offset = reader.u64()?;
            let max_bytes = reader.u32()?;
            reader.finish()?;
            authenticated(session, state)?;
            *request_level = true;
            // Own devices sync only local collections, as object key issue (11) requires.
            let collection =
                chur_catalog::store::object(session.catalog_ref()?, &object)?.collection_id;
            ensure!(
                chur_catalog::own_sync::is_local_collection(session.catalog_ref()?, &collection)?,
                AuthenticationFailed,
                "peer range names an object outside the local collections"
            );
            writer.fixed(&crate::sharing_publish::object_range(
                session, &object, offset, max_bytes,
            )?);
        }
        _ => return Err(Error::new(ChurStatus::InvalidInput, "unknown peer command")),
    }
    Ok(writer.finish())
}

fn credential(
    session: &mut chur_catalog::vault::Session,
) -> Result<chur_sync_protocol::peer_auth::PeerCredential> {
    let root = session.root_secret()?.duplicate();
    let vault = session.vault_id();
    chur_catalog::device_pairing::peer_credential(session.catalog()?, &root, vault)
}
/// The verified remote device, still active in the membership that is trusted now.
fn authenticated(
    session: &chur_catalog::vault::Session,
    state: &Option<Box<Peer>>,
) -> Result<chur_core::Id> {
    let device = *state
        .as_ref()
        .and_then(|peer| peer.remote_device())
        .ok_or_else(|| {
            Error::new(
                ChurStatus::AuthenticationFailed,
                "peer device is not authenticated",
            )
        })?;
    chur_catalog::device_pairing::verify_peer(
        session.catalog_ref()?,
        session.root_secret()?,
        session.vault_id(),
        &device,
    )?;
    Ok(device)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use chur_catalog::{device_pairing, paths::VaultRoot, sync_receive, vault};
    use chur_media::{backup, progress::Uninterrupted};
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::{Duration, Instant};
    const PASSWORD: &[u8] = b"peer call test strong password";
    const NOW: u64 = 1_700_000_000_000;
    const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
    fn root() -> VaultRoot {
        let path = std::env::temp_dir().join(format!(
            "chur-peer-call-{}",
            chur_crypto::random::id().unwrap().to_hex()
        ));
        std::fs::create_dir_all(&path).unwrap();
        VaultRoot::new(path)
    }
    fn range_request(object: &chur_core::Id) -> Vec<u8> {
        let mut writer = Writer::new();
        writer.u8(12).fixed(object.as_bytes()).u64(0).u32(1024);
        writer.finish()
    }

    #[test]
    fn a_request_error_keeps_the_peer_and_a_revoked_peer_closes_it() {
        // S approves a restored device T; T signs with its approved identity.
        let source_root = root();
        let mut source = vault::create(&source_root, PASSWORD, NOW)
            .unwrap()
            .activate()
            .unwrap();
        let secret = source.root_secret().unwrap().duplicate();
        let vault_id = source.vault_id();
        sync_receive::provision_local_identity(source.catalog().unwrap(), &secret, vault_id)
            .unwrap();
        let mut package = std::io::Cursor::new(Vec::new());
        backup::create(&mut source, &mut package, NOW, &mut Uninterrupted).unwrap();
        package.set_position(0);
        let target_root = root();
        backup::restore(&target_root, &mut package, PASSWORD, &mut Uninterrupted).unwrap();
        let mut target = vault::unlock_with_password(&target_root, PASSWORD, NOW + 1).unwrap();
        let request =
            device_pairing::prepare_request(target.catalog().unwrap(), &secret, vault_id).unwrap();
        let approval = device_pairing::approve(
            source.catalog().unwrap(),
            &secret,
            vault_id,
            &request,
            NOW + 2,
        )
        .unwrap();
        device_pairing::accept_start(
            target.catalog().unwrap(),
            &secret,
            vault_id,
            &approval.approval,
        )
        .unwrap();
        let (listener, port, invitation) =
            Peer::listen(LOOPBACK, credential(&mut source).unwrap()).unwrap();
        let mut state = Some(Box::new(listener));
        let mut connector =
            Peer::connect(LOOPBACK, port, invitation, credential(&mut target).unwrap()).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            assert!(Instant::now() < deadline, "handshake did not finish");
            let left = call(&mut source, &mut state, &[3]).unwrap() == [1];
            if connector.poll().unwrap() && left {
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        // An absent object is a request error: the connection stays open and usable.
        let absent = chur_crypto::random::id().unwrap();
        let error = call(&mut source, &mut state, &range_request(&absent)).unwrap_err();
        assert_ne!(error.status(), ChurStatus::AuthenticationFailed);
        assert!(state.is_some(), "a request error must not close the peer");
        let mut frame = Writer::new();
        frame.u8(4).variable(b"after").unwrap();
        call(&mut source, &mut state, &frame.finish()).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        let received = loop {
            assert!(Instant::now() < deadline, "frame did not arrive");
            call(&mut source, &mut state, &[7]).unwrap();
            if let Some(bytes) = connector.receive().unwrap() {
                break bytes;
            }
            std::thread::sleep(Duration::from_millis(1));
        };
        assert_eq!(&*received, b"after");
        // A device revoked during the session fails authentication and closes it.
        device_pairing::prepare_revoke(
            source.catalog().unwrap(),
            &secret,
            vault_id,
            *request.device_id(),
            NOW + 3,
        )
        .unwrap();
        let error = call(&mut source, &mut state, &range_request(&absent)).unwrap_err();
        assert_eq!(error.status(), ChurStatus::AuthenticationFailed);
        assert!(
            state.is_none(),
            "an authentication failure must close the peer"
        );
    }
}
