//! TCP side: pairing, authenticated (optionally TLS) transfers, both directions.
use crate::app::{App, Peer};
use crate::jwt;
use crate::proto::*;
use crate::xfer::Ctl;
use anyhow::{anyhow, bail, Context, Result};
use ed25519_dalek::{Signature, Verifier};
use serde_json::json;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpSocket, TcpStream};
use tokio::time::timeout;

pub const SOCK_BUF: u32 = 4 << 20;
pub const ACCEPT_TIMEOUT: Duration = Duration::from_secs(600);

// ---------------------------------------------------------------- listener

pub fn apply_exchange(app: &Arc<App>) {
    let on = app.settings.lock().unwrap().exchange;
    let mut l = app.listener.lock().unwrap();
    if on && l.as_ref().map_or(false, |h| !h.is_finished()) {
        return;
    }
    if let Some(h) = l.take() {
        h.abort();
    }
    if on {
        let sock = (|| -> Result<tokio::net::TcpListener> {
            let s = TcpSocket::new_v4()?;
            s.set_reuseaddr(true)?;
            let _ = s.set_recv_buffer_size(SOCK_BUF);
            let _ = s.set_send_buffer_size(SOCK_BUF);
            s.bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, app.tcp_port)))?;
            Ok(s.listen(128)?)
        })();
        match sock {
            Ok(lst) => {
                let app = app.clone();
                *l = Some(tokio::spawn(async move {
                    loop {
                        let Ok((s, a)) = lst.accept().await else { continue };
                        let app = app.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_conn(app, s, a).await {
                                eprintln!("conn {a}: {e:#}");
                            }
                        });
                    }
                }));
            }
            Err(e) => app.emit("error", json!({"message": format!("cannot listen on tcp {}: {e}", app.tcp_port)})),
        }
    }
    drop(l);
    app.emit("state_changed", json!({}));
}

// ---------------------------------------------------------------- helpers

pub fn sig_input(id_c: &str, id_s: &str, nc: &str, ns: &str, role: &str) -> Vec<u8> {
    format!("lanshare/1|{role}|{id_c}|{id_s}|{nc}|{ns}").into_bytes()
}

pub fn verify_sig(peer_id: &str, msg: &[u8], sig_hex: &str) -> bool {
    let (Some(vk), Ok(raw)) = (App::peer_key(peer_id), hex::decode(sig_hex)) else { return false };
    Signature::from_slice(&raw).map(|s| vk.verify(msg, &s).is_ok()).unwrap_or(false)
}

pub fn rnd_hex() -> String {
    hex::encode(rand::random::<[u8; 16]>())
}

pub fn peer_addr(app: &App, id: &str) -> Option<SocketAddr> {
    if let Some(d) = app.discovered.lock().unwrap().get(id) {
        return Some(d.addr);
    }
    app.peers.lock().unwrap().get(id)?.last_addr.as_ref()?.parse().ok()
}

pub async fn connect(addr: SocketAddr) -> Result<TcpStream> {
    let s = TcpSocket::new_v4()?;
    let _ = s.set_recv_buffer_size(SOCK_BUF);
    let _ = s.set_send_buffer_size(SOCK_BUF);
    let t = timeout(Duration::from_secs(8), s.connect(addr)).await.context("connect timeout")??;
    t.set_nodelay(true)?;
    Ok(t)
}

pub fn spawn_progress(app: &Arc<App>, xfer: String, dir: &'static str, ctl: Ctl, total: Option<u64>) -> tokio::task::JoinHandle<()> {
    let app = app.clone();
    tokio::spawn(async move {
        let mut last = u64::MAX;
        loop {
            tokio::time::sleep(Duration::from_millis(200)).await;
            let b = ctl.bytes.load(Ordering::Relaxed);
            if b != last {
                last = b;
                app.emit("progress", json!({"xfer": xfer, "dir": dir, "bytes": b, "total": total}));
            }
        }
    })
}

// ---------------------------------------------------------------- server

async fn handle_conn(app: Arc<App>, mut tcp: TcpStream, _addr: SocketAddr) -> Result<()> {
    tcp.set_nodelay(true)?;
    match timeout(Duration::from_secs(15), read_msg(&mut tcp)).await?? {
        Msg::Pair { info, jwt } => handle_pair(&app, tcp, info, jwt).await,
        Msg::Hello { id, jwt, enc, nonce } => crate::transfer::handle_xfer(app, tcp, id, jwt, enc, nonce).await,
        _ => bail!("unexpected first message"),
    }
}

fn verify_token_from(peer: &PeerInfo, jwt_s: &str, my_id: &str) -> bool {
    App::peer_key(&peer.id)
        .and_then(|vk| jwt::verify(&vk, jwt_s))
        .map_or(false, |c| c.iss == peer.id && c.sub == my_id)
}

fn store_peer(app: &App, info: PeerInfo, jwt: String) {
    {
        let mut peers = app.peers.lock().unwrap();
        match peers.get_mut(&info.id) {
            Some(p) => {
                p.info = info.clone();
                p.jwt = jwt;
            }
            None => {
                peers.insert(info.id.clone(), Peer { info: info.clone(), jwt, blocked: false, uid_map: Default::default(), gid_map: Default::default(), last_addr: None });
            }
        }
    }
    app.intents.lock().unwrap().remove(&info.id);
    app.pending_pairs.lock().unwrap().remove(&info.id);
    app.save_peers();
    app.emit("paired", json!({"info": info}));
    app.emit("state_changed", json!({}));
}

async fn handle_pair(app: &Arc<App>, mut tcp: TcpStream, info: PeerInfo, jwt_s: String) -> Result<()> {
    let reply = |status: &str, jwt: Option<String>| Msg::PairReply { status: status.into(), info: app.my_info(), jwt };
    let blocked = app.peers.lock().unwrap().get(&info.id).map_or(false, |p| p.blocked);
    if blocked || !verify_token_from(&info, &jwt_s, &app.id) {
        write_msg(&mut tcp, &reply("refused", None)).await?;
        return Ok(());
    }
    let known = app.peers.lock().unwrap().contains_key(&info.id);
    let intent = app.intents.lock().unwrap().contains(&info.id);
    if intent || known {
        let mine = jwt::issue(&app.sk, &app.id, &info.id);
        if intent {
            store_peer(app, info, jwt_s);
        }
        write_msg(&mut tcp, &reply("accepted", Some(mine))).await?;
    } else {
        let full = {
            let mut p = app.pending_pairs.lock().unwrap();
            let full = p.len() >= 32 && !p.contains_key(&info.id);
            if !full {
                p.insert(info.id.clone(), (info.clone(), jwt_s));
            }
            full
        };
        if full {
            write_msg(&mut tcp, &reply("refused", None)).await?;
            return Ok(());
        }
        app.emit("pair_request", json!({"info": info}));
        write_msg(&mut tcp, &reply("pending", None)).await?;
    }
    Ok(())
}

pub fn sanitize(n: &str) -> String {
    let s: String = n.rsplit(|c| c == '/' || c == '\\').next().unwrap_or("").chars().filter(|c| !c.is_control() && !"<>:\"|?*".contains(*c)).collect();
    if s.is_empty() || s == "." || s == ".." { "received".into() } else { s }
}

// ---------------------------------------------------------------- pairing (client)

pub async fn pair_with(app: &Arc<App>, id: &str) -> Result<String> {
    if id == app.id || App::peer_key(id).is_none() {
        bail!("invalid id");
    }
    app.intents.lock().unwrap().insert(id.to_string());
    let addr = peer_addr(app, id).ok_or_else(|| anyhow!("peer not found on the network (run a search first)"))?;
    let mut tcp = connect(addr).await?;
    write_msg(&mut tcp, &Msg::Pair { info: app.my_info(), jwt: jwt::issue(&app.sk, &app.id, id) }).await?;
    let Msg::PairReply { status, info, jwt: theirs } = timeout(Duration::from_secs(15), read_msg(&mut tcp)).await?? else { bail!("bad reply") };
    if info.id != id {
        bail!("peer identity mismatch");
    }
    match status.as_str() {
        "accepted" => {
            let t = theirs.ok_or_else(|| anyhow!("missing token"))?;
            if !verify_token_from(&info, &t, &app.id) {
                bail!("invalid token from peer");
            }
            store_peer(app, info, t);
        }
        "pending" => app.emit("pair_pending", json!({"info": info})),
        _ => {
            app.intents.lock().unwrap().remove(id);
            bail!("peer refused the association");
        }
    }
    Ok(status)
}

