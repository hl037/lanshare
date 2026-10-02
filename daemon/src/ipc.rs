//! Local control channel for the UI: JSON lines over 127.0.0.1, token-authenticated.
use crate::app::{write_private, App};
use crate::{discovery, net, transfer};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Notify};

pub async fn start(app: Arc<App>, quit: Arc<Notify>) -> anyhow::Result<()> {
    let lst = TcpListener::bind("127.0.0.1:0").await?;
    let token = hex::encode(rand::random::<[u8; 24]>());
    let rt = json!({"port": lst.local_addr()?.port(), "token": token, "pid": std::process::id(), "tcp_port": app.tcp_port});
    write_private(&app.dir.join("runtime.json"), rt.to_string().as_bytes())?;
    tokio::spawn(async move {
        loop {
            let Ok((s, _)) = lst.accept().await else { continue };
            let (app, token, quit) = (app.clone(), token.clone(), quit.clone());
            tokio::spawn(async move {
                let _ = serve(app, s, token, quit).await;
            });
        }
    });
    Ok(())
}

async fn serve(app: Arc<App>, s: TcpStream, token: String, quit: Arc<Notify>) -> anyhow::Result<()> {
    let (rd, mut wr) = s.into_split();
    let mut lines = BufReader::new(rd).lines();
    let first: Value = serde_json::from_str(&lines.next_line().await?.unwrap_or_default())?;
    if first["cmd"] != "auth" || first["token"] != token.as_str() {
        return Ok(());
    }
    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<String>();
    let _ = out_tx.send(json!({"re": first["rid"], "ok": true}).to_string());
    let mut ev = app.events.subscribe();
    let w = tokio::spawn(async move {
        loop {
            let line = tokio::select! {
                l = out_rx.recv() => l,
                e = ev.recv() => match e { Ok(l) => Some(l), Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue, Err(_) => None },
            };
            let Some(l) = line else { break };
            if wr.write_all(l.as_bytes()).await.is_err() || wr.write_all(b"\n").await.is_err() {
                break;
            }
        }
    });
    while let Some(line) = lines.next_line().await? {
        let Ok(req) = serde_json::from_str::<Value>(&line) else { continue };
        let (app, tx, quit) = (app.clone(), out_tx.clone(), quit.clone());
        tokio::spawn(async move {
            let id = req["rid"].clone();
            let msg = match handle(&app, &req, &quit).await {
                Ok(d) => json!({"re": id, "ok": true, "data": d}),
                Err(e) => json!({"re": id, "ok": false, "error": e}),
            };
            let _ = tx.send(msg.to_string());
        });
    }
    w.abort();
    Ok(())
}

fn s<'a>(r: &'a Value, k: &str) -> Result<&'a str, String> {
    r[k].as_str().ok_or_else(|| format!("missing {k}"))
}

fn map_of(v: &Value) -> BTreeMap<u32, u32> {
    v.as_object()
        .map(|o| o.iter().filter_map(|(k, v)| Some((k.parse().ok()?, v.as_u64()? as u32))).collect())
        .unwrap_or_default()
}

async fn handle(app: &Arc<App>, r: &Value, quit: &Arc<Notify>) -> Result<Value, String> {
    match s(r, "cmd")? {
        "state" => Ok(app.state()),
        "set_settings" => {
            {
                let mut st = app.settings.lock().unwrap();
                if let Some(v) = r["name"].as_str().filter(|v| !v.trim().is_empty()) { st.name = v.trim().into(); }
                if let Some(v) = r["broadcast"].as_bool() { st.broadcast = v; }
                if let Some(v) = r["exchange"].as_bool() { st.exchange = v; }
                if let Some(v) = r["require_encryption"].as_bool() { st.require_encryption = v; }
            }
            app.save_settings();
            net::apply_exchange(app);
            Ok(json!({}))
        }
        "search" => {
            discovery::search(app).await;
            Ok(json!({}))
        }
        "pair_add" => net::pair_with(app, s(r, "id")?).await.map(|st| json!({"status": st})).map_err(|e| format!("{e:#}")),
        "pair_reject" => {
            app.pending_pairs.lock().unwrap().remove(s(r, "id")?);
            app.emit("state_changed", json!({}));
            Ok(json!({}))
        }
        "peer_remove" => {
            let id = s(r, "id")?;
            app.peers.lock().unwrap().remove(id);
            app.intents.lock().unwrap().remove(id);
            app.save_peers();
            app.emit("state_changed", json!({}));
            Ok(json!({}))
        }
        "peer_block" => {
            let blocked = r["blocked"].as_bool().unwrap_or(true);
            app.peers.lock().unwrap().get_mut(s(r, "id")?).ok_or("unknown peer")?.blocked = blocked;
            app.save_peers();
            app.emit("state_changed", json!({}));
            Ok(json!({}))
        }
        "peer_map" => {
            {
                let mut p = app.peers.lock().unwrap();
                let p = p.get_mut(s(r, "id")?).ok_or("unknown peer")?;
                p.uid_map = map_of(&r["uid_map"]);
                p.gid_map = map_of(&r["gid_map"]);
            }
            app.save_peers();
            app.emit("state_changed", json!({}));
            Ok(json!({}))
        }
        "send" => {
            let peer = s(r, "peer")?.to_string();
            if !app.peers.lock().unwrap().contains_key(&peer) {
                return Err("unknown peer".into());
            }
            let mut ids = vec![];
            for p in r["paths"].as_array().ok_or("missing paths")? {
                let path = PathBuf::from(p.as_str().ok_or("bad path")?);
                ids.push(transfer::start_send(app, &peer, path).map_err(|e| format!("{e:#}"))?);
            }
            Ok(json!({"xfers": ids}))
        }
        "accept" => {
            let x = s(r, "xfer")?;
            let dest = PathBuf::from(s(r, "dest")?);
            let tx = app.incoming.lock().unwrap().get_mut(x).and_then(|i| i.tx.take()).ok_or("no such pending transfer")?;
            let _ = tx.send(Some(dest));
            Ok(json!({}))
        }
        "reject" => {
            let x = s(r, "xfer")?;
            if let Some(tx) = app.incoming.lock().unwrap().get_mut(x).and_then(|i| i.tx.take()) {
                let _ = tx.send(None);
            }
            Ok(json!({}))
        }
        "cancel" => {
            let x = s(r, "xfer")?;
            if app.xfers.lock().unwrap().contains_key(x) {
                transfer::cancel(app, x)?;
            } else if let Some(tx) = app.incoming.lock().unwrap().get_mut(x).and_then(|i| i.tx.take()) {
                let _ = tx.send(None);
            }
            Ok(json!({}))
        }
        "pause" => transfer::pause(app, s(r, "xfer")?).map(|_| json!({})),
        "resume" => transfer::resume(app, s(r, "xfer")?).map(|_| json!({})),
        "quit" => {
            quit.notify_one();
            Ok(json!({}))
        }
        c => Err(format!("unknown command {c}")),
    }
}
