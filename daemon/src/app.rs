//! Shared daemon state, persistence and event bus.
use crate::proto::PeerInfo;
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tokio::sync::{broadcast, oneshot};

pub fn os_name() -> &'static str {
    std::env::consts::OS
}

/// Local user ids. On Windows the user is always mapped to 1000:1000
/// (admin or not) so the protocol stays compatible with Unix peers.
pub fn local_ids() -> (u32, u32) {
    #[cfg(unix)]
    unsafe {
        (libc::getuid(), libc::getgid())
    }
    #[cfg(not(unix))]
    {
        (1000, 1000)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Settings {
    pub name: String,
    pub broadcast: bool,
    pub exchange: bool,
    pub require_encryption: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Peer {
    pub info: PeerInfo,
    /// Token issued BY the peer, presented to it when we connect.
    pub jwt: String,
    #[serde(default)]
    pub blocked: bool,
    #[serde(default)]
    pub uid_map: BTreeMap<u32, u32>,
    #[serde(default)]
    pub gid_map: BTreeMap<u32, u32>,
    #[serde(default)]
    pub last_addr: Option<String>,
}

#[derive(Clone, Debug)]
pub struct Discovered {
    pub info: PeerInfo,
    pub addr: SocketAddr, // tcp endpoint
    pub seen: Instant,
}

/// A transfer that can be paused/resumed; persisted in transfers.json.
/// state: waiting | running | retrying | paused | interrupted | failed | cancelled
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Rec {
    pub tid: String,
    pub out: bool,
    pub peer: String,
    pub name: String,
    pub kind: String,
    pub size: Option<u64>,
    /// Source path (outgoing) or destination (incoming).
    pub path: PathBuf,
    pub state: String,
    #[serde(default)]
    pub cur: Option<String>,
}

pub struct Incoming {
    pub peer: String,
    pub name: String,
    pub kind: String,
    pub size: Option<u64>,
    pub tx: Option<oneshot::Sender<Option<PathBuf>>>,
}

pub struct App {
    pub dir: PathBuf,
    pub sk: SigningKey,
    pub id: String,
    pub cert: Vec<u8>,
    pub key: Vec<u8>,
    pub tcp_port: u16,
    pub udp_port: u16,
    pub extra_bcast: Vec<SocketAddr>,
    pub settings: Mutex<Settings>,
    pub peers: Mutex<HashMap<String, Peer>>,
    pub intents: Mutex<HashSet<String>>,
    pub pending_pairs: Mutex<HashMap<String, (PeerInfo, String)>>,
    pub discovered: Mutex<HashMap<String, Discovered>>,
    pub incoming: Mutex<HashMap<String, Incoming>>,
    pub cancels: Mutex<HashMap<String, Arc<AtomicBool>>>,
    pub xfers: Mutex<HashMap<String, Rec>>,
    pub runners: Mutex<HashSet<String>>,
    pub events: broadcast::Sender<String>,
    pub listener: Mutex<Option<tokio::task::JoinHandle<()>>>,
    pub udp: Mutex<Option<Arc<tokio::net::UdpSocket>>>,
}

pub fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?;
        f.write_all(data)?;
    }
    // On Windows the per-user profile ACL (inherited from %APPDATA%) already restricts access.
    #[cfg(not(unix))]
    std::fs::write(&tmp, data)?;
    std::fs::rename(&tmp, path)
}

impl App {
    pub fn load(dir: PathBuf, tcp_port: u16, udp_port: u16, extra: Vec<SocketAddr>, name: Option<String>) -> anyhow::Result<Arc<App>> {
        std::fs::create_dir_all(&dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
        }
        let keyfile = dir.join("identity.key");
        let seed: [u8; 32] = match std::fs::read_to_string(&keyfile).ok().and_then(|s| hex::decode(s.trim()).ok()) {
            Some(b) if b.len() == 32 => b.try_into().unwrap(),
            _ => {
                let s = rand::random::<[u8; 32]>();
                write_private(&keyfile, hex::encode(s).as_bytes())?;
                s
            }
        };
        let sk = SigningKey::from_bytes(&seed);
        let id = hex::encode(sk.verifying_key().to_bytes());
        let (cert, key) = crate::tlsutil::make_cert(&seed)?;
        let mut settings: Settings = std::fs::read(dir.join("settings.json"))
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or(Settings {
                name: hostname::get().map(|h| h.to_string_lossy().into_owned()).unwrap_or_else(|_| "lanshare".into()),
                broadcast: false,
                exchange: true,
                require_encryption: false,
            });
        if let Some(n) = name {
            settings.name = n;
        }
        let peers: HashMap<String, Peer> = std::fs::read(dir.join("peers.json"))
            .ok()
            .and_then(|b| serde_json::from_slice::<Vec<Peer>>(&b).ok())
            .unwrap_or_default()
            .into_iter()
            .map(|p| (p.info.id.clone(), p))
            .collect();
        let xfers: HashMap<String, Rec> = std::fs::read(dir.join("transfers.json"))
            .ok()
            .and_then(|b| serde_json::from_slice::<Vec<Rec>>(&b).ok())
            .unwrap_or_default()
            .into_iter()
            .filter(|r| r.state != "cancelled")
            .map(|mut r| {
                // Nothing is running after a restart: everything resumable becomes "interrupted".
                if !matches!(r.state.as_str(), "paused" | "failed") {
                    r.state = "interrupted".into();
                }
                (r.tid.clone(), r)
            })
            .collect();
        let (events, _) = broadcast::channel(1024);
        Ok(Arc::new(App {
            dir, sk, id, cert, key, tcp_port, udp_port, extra_bcast: extra,
            settings: Mutex::new(settings),
            peers: Mutex::new(peers),
            intents: Default::default(),
            pending_pairs: Default::default(),
            discovered: Default::default(),
            incoming: Default::default(),
            cancels: Default::default(),
            xfers: Mutex::new(xfers),
            runners: Default::default(),
            events,
            listener: Mutex::new(None),
            udp: Mutex::new(None),
        }))
    }

    pub fn my_info(&self) -> PeerInfo {
        let (uid, gid) = local_ids();
        PeerInfo { id: self.id.clone(), name: self.settings.lock().unwrap().name.clone(), os: os_name().into(), uid, gid }
    }

    pub fn emit(&self, ev: &str, data: Value) {
        let mut v = data;
        v["event"] = json!(ev);
        let _ = self.events.send(v.to_string());
    }

    pub fn save_settings(&self) {
        let s = self.settings.lock().unwrap().clone();
        let _ = write_private(&self.dir.join("settings.json"), &serde_json::to_vec_pretty(&s).unwrap());
    }

    pub fn save_peers(&self) {
        let v: Vec<Peer> = self.peers.lock().unwrap().values().cloned().collect();
        let _ = write_private(&self.dir.join("peers.json"), &serde_json::to_vec_pretty(&v).unwrap());
    }

    pub fn save_xfers(&self) {
        let v: Vec<Rec> = self.xfers.lock().unwrap().values().cloned().collect();
        let _ = write_private(&self.dir.join("transfers.json"), &serde_json::to_vec_pretty(&v).unwrap());
    }

    /// Update a transfer's state, persist, and tell the UI.
    pub fn set_state(&self, tid: &str, state: &str, extra: Value) {
        if let Some(r) = self.xfers.lock().unwrap().get_mut(tid) {
            r.state = state.into();
        }
        self.save_xfers();
        let mut v = extra;
        v["xfer"] = json!(tid);
        v["state"] = json!(state);
        self.emit("xfer_state", v);
    }

    pub fn abort(&self, tid: &str) {
        if let Some(c) = self.cancels.lock().unwrap().get(tid) {
            c.store(true, Ordering::Relaxed);
        }
    }

    pub fn peer_key(id: &str) -> Option<VerifyingKey> {
        let b: [u8; 32] = hex::decode(id).ok()?.try_into().ok()?;
        VerifyingKey::from_bytes(&b).ok()
    }

    pub fn state(&self) -> Value {
        let now = Instant::now();
        let disc = self.discovered.lock().unwrap();
        let peers: Vec<Value> = self.peers.lock().unwrap().values().map(|p| {
            let d = disc.get(&p.info.id).filter(|d| now.duration_since(d.seen).as_secs() < 15);
            json!({"info": p.info, "blocked": p.blocked, "uid_map": p.uid_map, "gid_map": p.gid_map,
                   "online": d.is_some(), "addr": d.map(|d| d.addr.to_string()).or(p.last_addr.clone())})
        }).collect();
        let paired = self.peers.lock().unwrap();
        let discovered: Vec<Value> = disc.values()
            .filter(|d| now.duration_since(d.seen).as_secs() < 15)
            .map(|d| json!({"info": d.info, "addr": d.addr.to_string(), "paired": paired.contains_key(&d.info.id),
                            "intent": self.intents.lock().unwrap().contains(&d.info.id)}))
            .collect();
        let pending: Vec<Value> = self.pending_pairs.lock().unwrap().values().map(|(i, _)| json!(i)).collect();
        let incoming: Vec<Value> = self.incoming.lock().unwrap().iter().map(|(k, i)| {
            json!({"xfer": k, "peer": i.peer, "name": i.name, "kind": i.kind, "size": i.size})
        }).collect();
        let transfers: Vec<Rec> = self.xfers.lock().unwrap().values().filter(|r| r.state != "cancelled").cloned().collect();
        json!({"identity": self.my_info(), "transfers": transfers, "tcp_port": self.tcp_port,
               "settings": *self.settings.lock().unwrap(),
               "peers": peers, "discovered": discovered, "pending_pairs": pending, "incoming": incoming})
    }
}
