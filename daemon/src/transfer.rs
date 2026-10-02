//! Resumable transfers, both directions.
//!
//! A transfer is identified by a sender-chosen `tid`. The receiver keeps a record (and the partial
//! file); when the sender reconnects with the same `tid` the receiver answers with the offset it
//! already holds, without asking the user again. Directories are streamed as `Entry` frames, so a
//! resume skips finished entries and continues the current file at its offset.
use crate::app::{local_ids, App, Incoming, Rec};
use crate::net::*;
use crate::proto::*;
use crate::tlsutil;
use crate::xfer::{self, Ctl, Owner};
use anyhow::{anyhow, bail, Result};
use ed25519_dalek::Signer;
use rustls::pki_types::ServerName;
use serde_json::json;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::oneshot;
use tokio::time::timeout;

const RETRY_WINDOW: Duration = Duration::from_secs(600);
const PEER_PAUSED_POLL: Duration = Duration::from_secs(3);

/// Fresh abort flag for a new attempt; replaces (and orphans) any previous one.
fn new_ctl(app: &App, tid: &str) -> Ctl {
    let cancel = Arc::new(AtomicBool::new(false));
    app.cancels.lock().unwrap().insert(tid.to_string(), cancel.clone());
    Ctl { bytes: Arc::new(AtomicU64::new(0)), cancel }
}

/// True if `ctl` is still the current attempt of `tid` (a newer attempt may have taken over).
fn release(app: &App, tid: &str, ctl: &Ctl) -> bool {
    let mut c = app.cancels.lock().unwrap();
    let mine = c.get(tid).map_or(false, |f| Arc::ptr_eq(f, &ctl.cancel));
    if mine {
        c.remove(tid);
    }
    mine
}

fn rec_state(app: &App, tid: &str) -> Option<String> {
    app.xfers.lock().unwrap().get(tid).map(|r| r.state.clone())
}

async fn answer_no(io: &mut BoxIo, reason: &str) -> Result<()> {
    write_msg(io, &Msg::Answer { accept: false, reason: Some(reason.into()), offset: 0, cur: None }).await?;
    Ok(())
}

// ================================================================== receiver

pub async fn handle_xfer(app: Arc<App>, mut tcp: tokio::net::TcpStream, id: String, jwt_s: String, c_enc: bool, nonce_c: String) -> Result<()> {
    let peer = app.peers.lock().unwrap().get(&id).cloned();
    let ok = peer.as_ref().map_or(false, |p| !p.blocked)
        && crate::jwt::verify(&app.sk.verifying_key(), &jwt_s).map_or(false, |c| c.iss == app.id && c.sub == id);
    if !ok {
        write_msg(&mut tcp, &Msg::HelloAck { ok: false, error: Some("not authorised".into()), enc: false, nonce: String::new(), sig: String::new() }).await?;
        bail!("rejected {}", &id[..8.min(id.len())]);
    }
    let peer = peer.unwrap();
    let enc = c_enc || app.settings.lock().unwrap().require_encryption;
    let nonce_s = rnd_hex();
    let sig = hex::encode(app.sk.sign(&sig_input(&id, &app.id, &nonce_c, &nonce_s, "server")).to_bytes());
    write_msg(&mut tcp, &Msg::HelloAck { ok: true, error: None, enc, nonce: nonce_s.clone(), sig }).await?;
    let mut io: BoxIo = if enc {
        let acc = tokio_rustls::TlsAcceptor::from(tlsutil::server_config(&app.cert, &app.key)?);
        Box::new(timeout(Duration::from_secs(15), acc.accept(tcp)).await??)
    } else {
        Box::new(tcp)
    };
    let Msg::Auth { sig } = timeout(Duration::from_secs(15), read_msg(&mut io)).await?? else { bail!("expected Auth") };
    if !verify_sig(&id, &sig_input(&id, &app.id, &nonce_c, &nonce_s, "client"), &sig) {
        write_msg(&mut io, &Msg::AuthOk { ok: false }).await?;
        bail!("bad client signature");
    }
    write_msg(&mut io, &Msg::AuthOk { ok: true }).await?;

    let Msg::Offer { tid, name, kind, size, mode, uid, gid } = timeout(Duration::from_secs(30), read_msg(&mut io)).await?? else { bail!("expected Offer") };
    if tid.is_empty() || tid.len() > 64 || !tid.chars().all(|c| c.is_ascii_alphanumeric()) || !(kind == "file" || kind == "dir") {
        bail!("bad offer");
    }
    let name = sanitize(&name);

    // Known transfer from this peer => resume, no prompt.
    let existing = app.xfers.lock().unwrap().get(&tid).filter(|r| !r.out && r.peer == id).cloned();
    let (dest, resumed, cur) = if let Some(r) = existing {
        match r.state.as_str() {
            "paused" => return answer_no(&mut io, "paused").await,
            "cancelled" => return answer_no(&mut io, "cancelled").await,
            "running" => {
                // The previous connection is probably dead but not noticed yet: preempt it.
                app.abort(&tid);
                for _ in 0..25 {
                    if rec_state(&app, &tid).as_deref() != Some("running") {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
                if rec_state(&app, &tid).as_deref() == Some("running") {
                    return answer_no(&mut io, "busy").await;
                }
            }
            _ => {}
        }
        let cur = app.xfers.lock().unwrap().get(&tid).and_then(|r| r.cur.clone());
        (r.path, true, cur)
    } else {
        let (tx, rx) = oneshot::channel();
        app.incoming.lock().unwrap().insert(tid.clone(), Incoming { peer: id.clone(), name: name.clone(), kind: kind.clone(), size, tx: Some(tx) });
        app.emit("incoming", json!({"xfer": tid, "peer": id, "peer_name": peer.info.name, "name": name, "kind": kind, "size": size, "encrypted": enc}));
        // Wait for the user's decision, or for the sender to hang up.
        let mut probe = [0u8; 1];
        let dest: Option<PathBuf> = tokio::select! {
            r = rx => r.ok().flatten(),
            _ = tokio::time::sleep(ACCEPT_TIMEOUT) => None,
            _ = io.read(&mut probe) => { app.incoming.lock().unwrap().remove(&tid); app.emit("incoming_cancelled", json!({"xfer": tid})); return Ok(()); }
        };
        app.incoming.lock().unwrap().remove(&tid);
        let Some(dest) = dest else {
            app.emit("done", json!({"xfer": tid, "dir": "in", "ok": false, "error": "declined"}));
            return answer_no(&mut io, "declined").await;
        };
        (dest, false, None)
    };

    // Where do we resume from?
    let len_of = |p: &Path| std::fs::metadata(p).map(|m| m.len()).unwrap_or(0);
    let offset = match (resumed, kind.as_str()) {
        (true, "file") => size.map_or(0, |s| len_of(&dest).min(s)),
        (true, _) => cur.as_deref().and_then(|c| xfer::safe_join(&dest, c)).map_or(0, |p| len_of(&p)),
        _ => 0,
    };
    let ctl = new_ctl(&app, &tid);
    app.xfers.lock().unwrap().insert(tid.clone(), Rec { tid: tid.clone(), out: false, peer: id.clone(), name: name.clone(), kind: kind.clone(), size, path: dest.clone(), state: "running".into(), cur: cur.clone() });
    app.set_state(&tid, "running", json!({"offset": offset, "resumed": resumed, "name": name, "peer_name": peer.info.name, "kind": kind, "size": size}));
    write_msg(&mut io, &Msg::Answer { accept: true, reason: None, offset, cur }).await?;

    let prog = spawn_progress(&app, tid.clone(), "in", ctl.clone(), size);
    let owner = Owner { uid_map: peer.uid_map.clone(), gid_map: peer.gid_map.clone() };
    let res = receive_payload(&app, &mut io, &tid, &kind, size, (mode, uid, gid), &dest, offset, &owner, &ctl).await;
    prog.abort();
    if !release(&app, &tid, &ctl) {
        return Ok(()); // superseded by a newer attempt
    }
    match res {
        Ok(()) => {
            let bytes = ctl.bytes.load(Ordering::Relaxed);
            app.xfers.lock().unwrap().remove(&tid);
            app.save_xfers();
            let _ = write_msg(&mut io, &Msg::Result { ok: true, bytes, error: None }).await;
            app.emit("done", json!({"xfer": tid, "dir": "in", "ok": true, "bytes": bytes}));
        }
        Err(e) => match rec_state(&app, &tid).as_deref() {
            // paused / cancelled by the user: the command already updated state and told the UI
            Some("running") => app.set_state(&tid, "interrupted", json!({"error": e.to_string()})),
            _ => {}
        },
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn receive_payload(app: &Arc<App>, io: &mut BoxIo, tid: &str, kind: &str, size: Option<u64>, meta: (Option<u32>, u32, u32), dest: &Path, offset: u64, owner: &Owner, ctl: &Ctl) -> std::io::Result<()> {
    use std::io::{Error, ErrorKind::InvalidData};
    use tokio::io::{AsyncReadExt as _, AsyncSeekExt};
    let open_at = |p: PathBuf, off: u64| async move {
        if off == 0 {
            return tokio::fs::File::create(&p).await;
        }
        let mut f = tokio::fs::OpenOptions::new().write(true).open(&p).await?;
        if f.metadata().await?.len() < off {
            return Err(Error::new(InvalidData, "partial file is shorter than the resume offset"));
        }
        f.set_len(off).await?;
        f.seek(std::io::SeekFrom::Start(off)).await?;
        Ok(f)
    };
    if kind == "file" {
        let f = open_at(dest.to_path_buf(), offset).await?;
        ctl.bytes.store(offset, Ordering::Relaxed);
        xfer::recv_into(io, f, size.map(|s| s.saturating_sub(offset)), ctl).await?;
        xfer::finish_file(dest, meta.0.unwrap_or(0o644), 0);
        owner.apply(dest, meta.1, meta.2);
        return Ok(());
    }
    tokio::fs::create_dir_all(dest).await?;
    let mut last_save = Instant::now();
    let mut rd = xfer::Rd::new(io);
    let mut done_acc = 0u64; // payload bytes of finished items (this and earlier attempts)
    while let Some(h) = rd.header().await? {
        if ctl.cancel.load(Ordering::Relaxed) {
            return Err(Error::new(std::io::ErrorKind::Interrupted, "aborted"));
        }
        let path = xfer::safe_join(dest, &h.p).ok_or_else(|| Error::new(InvalidData, "unsafe path in stream"))?;
        if h.dir {
            tokio::fs::create_dir_all(&path).await?;
            owner.apply(&path, h.uid, h.gid);
            continue;
        }
        let (off, base) = h.resume.unwrap_or((0, done_acc));
        done_acc = base;
        if let Some(r) = app.xfers.lock().unwrap().get_mut(tid) {
            r.cur = Some(h.p.clone());
        }
        if last_save.elapsed() > Duration::from_secs(2) {
            app.save_xfers();
            last_save = Instant::now();
        }
        if off == 0 && h.size <= xfer::SMALL {
            // header + content arrive together: one read, one blocking write
            let mut data = vec![0u8; h.size as usize];
            rd.read_exact(&mut data).await?;
            ctl.bytes.fetch_add(h.size, Ordering::Relaxed);
            let (p2, mode, mtime) = (path.clone(), h.mode, h.mtime);
            tokio::task::spawn_blocking(move || xfer::write_small(&p2, &data, mode, mtime)).await.map_err(Error::other)??;
        } else {
            if let Some(par) = path.parent() {
                tokio::fs::create_dir_all(par).await?;
            }
            let f = open_at(path.clone(), off).await?;
            ctl.bytes.store(done_acc + off, Ordering::Relaxed);
            xfer::recv_into(&mut rd, f, Some(h.size.saturating_sub(off)), ctl).await?;
            xfer::finish_file(&path, h.mode, h.mtime);
        }
        owner.apply(&path, h.uid, h.gid);
        done_acc += h.size;
    }
    Ok(())
}

// ================================================================== sender

enum Fail {
    /// Connection-level trouble: retry with backoff.
    Net(anyhow::Error),
    /// Retrying cannot help (bad auth, source changed, ...). Kept as "failed" for a manual retry.
    Fatal(String),
    /// The receiver said no for good (declined / cancelled).
    Declined(String),
    /// Receiver paused it; poll until it resumes.
    PeerPaused,
    /// pause/cancel requested locally.
    Aborted,
}
impl<E: Into<anyhow::Error>> From<E> for Fail {
    fn from(e: E) -> Self {
        Fail::Net(e.into())
    }
}
fn fatal<T>(m: impl Into<String>) -> Result<T, Fail> {
    Err(Fail::Fatal(m.into()))
}

pub fn start_send(app: &Arc<App>, peer: &str, path: PathBuf) -> Result<String> {
    let meta = std::fs::metadata(&path).map_err(|e| anyhow!("{}: {e}", path.display()))?;
    let is_dir = meta.is_dir();
    let tid = hex::encode(rand::random::<[u8; 8]>());
    let name = path.file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_else(|| "folder".into());
    let peer_name = app.peers.lock().unwrap().get(peer).map(|p| p.info.name.clone()).unwrap_or_default();
    let rec = Rec { tid: tid.clone(), out: true, peer: peer.into(), name: name.clone(), kind: if is_dir { "dir" } else { "file" }.into(), size: (!is_dir).then(|| meta.len()), path, state: "waiting".into(), cur: None };
    app.emit("xfer_start", json!({"xfer": tid, "dir": "out", "peer": peer, "peer_name": peer_name, "name": name, "kind": rec.kind, "size": rec.size}));
    app.xfers.lock().unwrap().insert(tid.clone(), rec);
    app.save_xfers();
    spawn_runner(app, &tid);
    Ok(tid)
}

fn spawn_runner(app: &Arc<App>, tid: &str) {
    if !app.runners.lock().unwrap().insert(tid.to_string()) {
        return; // a runner is alive and will notice the state change
    }
    let (app, tid) = (app.clone(), tid.to_string());
    tokio::spawn(async move {
        run_out(&app, &tid).await;
        app.runners.lock().unwrap().remove(&tid);
    });
}

async fn run_out(app: &Arc<App>, tid: &str) {
    let mut delay = Duration::from_secs(1);
    let mut first_fail: Option<Instant> = None;
    loop {
        match rec_state(app, tid).as_deref() {
            None => return app.emit("done", json!({"xfer": tid, "dir": "out", "ok": false, "error": "cancelled"})),
            Some("paused") => return,
            Some(s) if s != "waiting" => app.set_state(tid, "waiting", json!({})),
            _ => {}
        }
        let ctl = new_ctl(app, tid);
        let ran = AtomicBool::new(false);
        let r = attempt(app, tid, &ctl, &ran).await;
        release(app, tid, &ctl);
        let sleep = match r {
            Ok(bytes) => {
                app.xfers.lock().unwrap().remove(tid);
                app.save_xfers();
                return app.emit("done", json!({"xfer": tid, "dir": "out", "ok": true, "bytes": bytes}));
            }
            Err(Fail::Aborted) => continue, // top of loop decides: cancelled, paused, or resumed already
            Err(Fail::Declined(why)) => {
                app.xfers.lock().unwrap().remove(tid);
                app.save_xfers();
                return app.emit("done", json!({"xfer": tid, "dir": "out", "ok": false, "error": why}));
            }
            Err(Fail::Fatal(e)) => {
                app.set_state(tid, "failed", json!({"error": e}));
                return app.emit("done", json!({"xfer": tid, "dir": "out", "ok": false, "error": e}));
            }
            Err(Fail::PeerPaused) => {
                app.set_state(tid, "retrying", json!({"error": "paused by the receiver"}));
                PEER_PAUSED_POLL
            }
            Err(Fail::Net(e)) => {
                if ran.load(Ordering::Relaxed) {
                    first_fail = None;
                    delay = Duration::from_secs(1);
                }
                let since = *first_fail.get_or_insert_with(Instant::now);
                if since.elapsed() > RETRY_WINDOW {
                    let msg = format!("{e:#}");
                    app.set_state(tid, "failed", json!({"error": msg}));
                    return app.emit("done", json!({"xfer": tid, "dir": "out", "ok": false, "error": msg}));
                }
                app.set_state(tid, "retrying", json!({"error": format!("{e:#}"), "retry_in": delay.as_secs()}));
                let d = delay;
                delay = (delay * 2).min(Duration::from_secs(15));
                d
            }
        };
        // Sleep, but wake early when paused/cancelled.
        let end = Instant::now() + sleep;
        while Instant::now() < end && matches!(rec_state(app, tid).as_deref(), Some("retrying")) {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
}

async fn attempt(app: &Arc<App>, tid: &str, ctl: &Ctl, ran: &AtomicBool) -> Result<u64, Fail> {
    let Some(rec) = app.xfers.lock().unwrap().get(tid).cloned() else { return Err(Fail::Aborted) };
    let peer = app.peers.lock().unwrap().get(&rec.peer).cloned();
    let Some(peer) = peer else { return fatal("unknown peer") };
    if peer.blocked {
        return fatal("peer is blocked");
    }
    let is_dir = rec.kind == "dir";
    let items = if is_dir {
        let p = rec.path.clone();
        match tokio::task::spawn_blocking(move || xfer::scan_dir(&p)).await {
            Ok(Ok(v)) => Some(v),
            Ok(Err(e)) => return fatal(format!("{}: {e}", rec.path.display())),
            Err(e) => return Err(e.into()),
        }
    } else {
        None
    };
    let size = match &items {
        Some(v) => v.iter().map(|i| i.size).sum(),
        None => match tokio::fs::metadata(&rec.path).await {
            Ok(m) => m.len(),
            Err(e) => return fatal(format!("{}: {e}", rec.path.display())),
        },
    };
    match rec.size {
        Some(prev) if !is_dir && prev != size => return fatal("source file changed since the transfer started"),
        None => {
            if let Some(r) = app.xfers.lock().unwrap().get_mut(tid) {
                r.size = Some(size);
            }
            app.emit("xfer_start", json!({"xfer": tid, "dir": "out", "peer": rec.peer, "peer_name": peer.info.name, "name": rec.name, "kind": rec.kind, "size": size}));
        }
        _ => {}
    }
    #[cfg(unix)]
    let (mode, uid, gid) = {
        use std::os::unix::fs::MetadataExt;
        let m = std::fs::metadata(&rec.path)?;
        (Some(m.mode()), m.uid(), m.gid())
    };
    #[cfg(not(unix))]
    let (mode, uid, gid) = (None, local_ids().0, local_ids().1);
    let _ = local_ids;

    let Some(addr) = peer_addr(app, &rec.peer) else { return Err(Fail::Net(anyhow!("peer is not reachable (no known address)"))) };
    let mut tcp = connect(addr).await?;
    let my_enc = app.settings.lock().unwrap().require_encryption;
    let nonce_c = rnd_hex();
    write_msg(&mut tcp, &Msg::Hello { id: app.id.clone(), jwt: peer.jwt.clone(), enc: my_enc, nonce: nonce_c.clone() }).await?;
    let Msg::HelloAck { ok, error, enc, nonce: nonce_s, sig } = timeout(Duration::from_secs(15), read_msg(&mut tcp)).await?? else { return fatal("bad ack") };
    if !ok {
        return fatal(format!("refused by peer: {}", error.unwrap_or_default()));
    }
    if !verify_sig(&rec.peer, &sig_input(&app.id, &rec.peer, &nonce_c, &nonce_s, "server"), &sig) {
        return fatal("peer failed authentication");
    }
    if my_enc && !enc {
        return fatal("encryption required but peer answered in clear");
    }
    let mut io: BoxIo = if enc {
        let pk: [u8; 32] = hex::decode(&rec.peer)?.try_into().map_err(|_| anyhow!("bad id"))?;
        let conn = tokio_rustls::TlsConnector::from(tlsutil::client_config(pk)?);
        Box::new(timeout(Duration::from_secs(15), conn.connect(ServerName::try_from("lanshare").map_err(|e| anyhow!("{e}"))?, tcp)).await??)
    } else {
        Box::new(tcp)
    };
    let sig = hex::encode(app.sk.sign(&sig_input(&app.id, &rec.peer, &nonce_c, &nonce_s, "client")).to_bytes());
    write_msg(&mut io, &Msg::Auth { sig }).await?;
    let Msg::AuthOk { ok: true } = timeout(Duration::from_secs(15), read_msg(&mut io)).await?? else { return fatal("authentication rejected") };

    write_msg(&mut io, &Msg::Offer { tid: tid.into(), name: rec.name.clone(), kind: rec.kind.clone(), size: Some(size), mode, uid, gid }).await?;
    // Wait for the receiving user to accept (they pick the destination) unless aborted locally.
    let abort = ctl.cancel.clone();
    let answer = tokio::select! {
        a = timeout(ACCEPT_TIMEOUT + Duration::from_secs(5), read_msg(&mut io)) => a??,
        _ = async { while !abort.load(Ordering::Relaxed) { tokio::time::sleep(Duration::from_millis(100)).await } } => return Err(Fail::Aborted),
    };
    let (offset, cur) = match answer {
        Msg::Answer { accept: true, offset, cur, .. } => (offset, cur),
        Msg::Answer { reason, .. } => {
            return match reason.as_deref() {
                Some("paused") | Some("busy") => Err(Fail::PeerPaused),
                Some(r @ ("declined" | "cancelled")) => Err(Fail::Declined(if r == "declined" { "declined".into() } else { "cancelled by the receiver".into() })),
                other => fatal(other.unwrap_or("refused").to_string()),
            }
        }
        _ => return fatal("bad answer"),
    };
    ran.store(true, Ordering::Relaxed);
    app.set_state(tid, "running", json!({"offset": offset}));
    let prog = spawn_progress(app, tid.to_string(), "out", ctl.clone(), Some(size));

    let streamed: Result<(), Fail> = async {
        let io_err = |e: std::io::Error| if ctl.cancel.load(Ordering::Relaxed) { Fail::Aborted } else { Fail::Net(e.into()) };
        match &items {
            None => {
                if offset > size {
                    return fatal("receiver holds more data than the source file");
                }
                ctl.bytes.store(offset, Ordering::Relaxed);
                xfer::send_range(&mut io, &rec.path, offset, size - offset, ctl).await.map_err(io_err)?;
            }
            Some(items) => {
                let mut started = cur.is_none();
                let mut first = true;
                let mut done = 0u64;
                let mut out: Vec<u8> = Vec::with_capacity(xfer::CH + (256 << 10));
                for it in items {
                    if !started {
                        if Some(&it.rel) == cur.as_ref() {
                            started = true;
                        } else {
                            done += it.size;
                            continue;
                        }
                    }
                    if ctl.cancel.load(Ordering::Relaxed) {
                        return Err(Fail::Aborted);
                    }
                    let off = if cur.as_ref() == Some(&it.rel) { offset.min(it.size) } else { 0 };
                    let resume = (first && (off > 0 || done > 0)).then_some((off, done));
                    first = false;
                    xfer::Hdr { dir: it.dir, p: it.rel.clone(), size: it.size, mode: it.mode, uid: it.uid, gid: it.gid, mtime: it.mtime, resume }
                        .encode(&mut out)
                        .map_err(|e| Fail::Fatal(e.to_string()))?;
                    if !it.dir {
                        let len = it.size - off;
                        if len <= xfer::SMALL {
                            // batch header + content: no per-item syscall or TLS record
                            let (p2, o2) = (it.abs.clone(), off);
                            let data = tokio::task::spawn_blocking(move || xfer::read_small(&p2, o2, len)).await.map_err(|e| Fail::Net(e.into()))?.map_err(|e| Fail::Fatal(format!("{}: {e}", it.abs.display())))?;
                            out.extend_from_slice(&data);
                            ctl.bytes.fetch_add(len, Ordering::Relaxed);
                        } else {
                            io.write_all(&out).await.map_err(io_err)?;
                            out.clear();
                            ctl.bytes.store(done + off, Ordering::Relaxed);
                            xfer::send_range(&mut io, &it.abs, off, len, ctl).await.map_err(io_err)?;
                        }
                        done += it.size;
                    }
                    if out.len() >= xfer::CH {
                        io.write_all(&out).await.map_err(io_err)?;
                        out.clear();
                    }
                }
                if !started {
                    return fatal("source directory changed since the transfer started");
                }
                out.push(xfer::END);
                io.write_all(&out).await.map_err(io_err)?;
                io.flush().await.map_err(io_err)?;
            }
        }
        Ok(())
    }.await;
    prog.abort();
    streamed?;
    match timeout(Duration::from_secs(300), read_msg(&mut io)).await?? {
        Msg::Result { ok: true, bytes, .. } => Ok(bytes),
        Msg::Result { error, .. } => fatal(format!("receiver failed: {}", error.unwrap_or_default())),
        _ => fatal("bad result"),
    }
}

// ================================================================== user commands

pub fn pause(app: &Arc<App>, tid: &str) -> Result<(), String> {
    let st = rec_state(app, tid).ok_or("no such transfer")?;
    if matches!(st.as_str(), "cancelled" | "failed") {
        return Err(format!("cannot pause a {st} transfer"));
    }
    app.set_state(tid, "paused", json!({}));
    app.abort(tid);
    Ok(())
}

/// Resume / retry. Outgoing: reconnect now. Incoming: allow the sender's next attempt.
pub fn resume(app: &Arc<App>, tid: &str) -> Result<(), String> {
    let rec = app.xfers.lock().unwrap().get(tid).cloned().ok_or("no such transfer")?;
    if rec.out {
        if matches!(rec.state.as_str(), "paused" | "failed" | "interrupted" | "retrying") {
            app.set_state(tid, "waiting", json!({}));
            spawn_runner(app, tid);
        }
    } else if rec.state == "paused" {
        app.set_state(tid, "interrupted", json!({}));
    }
    Ok(())
}

pub fn cancel(app: &Arc<App>, tid: &str) -> Result<(), String> {
    let rec = app.xfers.lock().unwrap().get(tid).cloned().ok_or("no such transfer")?;
    if rec.out {
        app.xfers.lock().unwrap().remove(tid);
        app.save_xfers();
        app.abort(tid);
        if !app.runners.lock().unwrap().contains(tid) {
            app.emit("done", json!({"xfer": tid, "dir": "out", "ok": false, "error": "cancelled"}));
        }
    } else {
        // Tombstone: tells a sender that reconnects that this is final.
        app.set_state(tid, "cancelled", json!({}));
        app.abort(tid);
        if rec.kind == "file" {
            let _ = std::fs::remove_file(&rec.path);
        }
        app.emit("done", json!({"xfer": tid, "dir": "in", "ok": false, "error": "cancelled"}));
    }
    Ok(())
}
