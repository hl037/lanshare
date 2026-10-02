//! UDP broadcast discovery: periodic announces, on-demand search.
use crate::app::{App, Discovered};
use crate::proto::PeerInfo;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;

#[derive(Serialize, Deserialize)]
struct Beacon {
    v: u8,
    t: String, // announce | search | reply
    info: PeerInfo,
    port: u16,
}

fn bind(port: u16) -> anyhow::Result<UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};
    let s = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    s.set_reuse_address(true)?;
    #[cfg(all(unix, not(target_os = "solaris"), not(target_os = "illumos")))]
    s.set_reuse_port(true)?;
    s.set_broadcast(true)?;
    s.set_nonblocking(true)?;
    s.bind(&SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)).into())?;
    Ok(UdpSocket::from_std(s.into())?)
}

fn targets(app: &App) -> Vec<SocketAddr> {
    let mut v = vec![SocketAddr::from((Ipv4Addr::BROADCAST, app.udp_port))];
    if let Ok(ifs) = if_addrs::get_if_addrs() {
        for i in ifs {
            if let if_addrs::IfAddr::V4(a) = i.addr {
                if let Some(b) = a.broadcast {
                    v.push(SocketAddr::from((b, app.udp_port)));
                }
            }
        }
    }
    v.extend(app.extra_bcast.iter().copied());
    v.sort();
    v.dedup();
    v
}

async fn send_beacon(app: &App, sock: &UdpSocket, t: &str, to: &[SocketAddr]) {
    let b = Beacon { v: 1, t: t.into(), info: app.my_info(), port: app.tcp_port };
    let data = serde_json::to_vec(&b).unwrap();
    for a in to {
        let _ = sock.send_to(&data, a).await;
    }
}

pub async fn search(app: &Arc<App>) {
    let sock = app.udp.lock().unwrap().clone();
    if let Some(sock) = sock {
        for _ in 0..3 {
            send_beacon(app, &sock, "search", &targets(app)).await;
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }
}

pub fn start(app: Arc<App>) -> anyhow::Result<()> {
    let sock = Arc::new(bind(app.udp_port)?);
    *app.udp.lock().unwrap() = Some(sock.clone());

    let (a, s) = (app.clone(), sock.clone());
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(3));
        loop {
            tick.tick().await;
            if a.settings.lock().unwrap().broadcast {
                send_beacon(&a, &s, "announce", &targets(&a)).await;
            }
        }
    });

    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            let Ok((n, src)) = sock.recv_from(&mut buf).await else { continue };
            let Ok(b) = serde_json::from_slice::<Beacon>(&buf[..n]) else { continue };
            let id = b.info.id.clone();
            if b.v != 1 || id == app.id || App::peer_key(&id).is_none() {
                continue;
            }
            let ip: IpAddr = src.ip();
            let addr = SocketAddr::new(ip, b.port);
            let new = {
                let mut d = app.discovered.lock().unwrap();
                let new = d.get(&id).map_or(true, |x| x.seen.elapsed().as_secs() >= 15);
                d.insert(id.clone(), Discovered { info: b.info.clone(), addr, seen: Instant::now() });
                new
            };
            if let Some(p) = app.peers.lock().unwrap().get_mut(&id) {
                p.last_addr = Some(addr.to_string());
            }
            let broadcasting = app.settings.lock().unwrap().broadcast;
            if b.t == "search" && broadcasting {
                // Someone is looking: answer, and propose to add them.
                send_beacon(&app, &sock, "reply", &[src]).await;
                if !app.peers.lock().unwrap().contains_key(&id) {
                    app.emit("pair_proposal", json!({"info": b.info, "addr": addr.to_string()}));
                }
            } else if new {
                app.emit("discovered", json!({"info": b.info, "addr": addr.to_string()}));
            }
        }
    });
    Ok(())
}
