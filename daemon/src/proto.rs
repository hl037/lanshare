//! Wire protocol: u32-BE length-prefixed JSON frames, then raw payload bytes.
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const MAX_FRAME: usize = 1 << 20;

pub trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}
pub type BoxIo = Box<dyn Io>;

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct PeerInfo {
    pub id: String,
    pub name: String,
    pub os: String,
    pub uid: u32,
    pub gid: u32,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "t")]
pub enum Msg {
    /// Association request; `jwt` is a token issued by the sender for the receiver.
    Pair { info: PeerInfo, jwt: String },
    /// status: accepted | pending | refused
    PairReply { status: String, info: PeerInfo, #[serde(default)] jwt: Option<String> },
    Hello { id: String, jwt: String, enc: bool, nonce: String },
    HelloAck {
        ok: bool,
        #[serde(default)] error: Option<String>,
        #[serde(default)] enc: bool,
        #[serde(default)] nonce: String,
        #[serde(default)] sig: String,
    },
    Auth { sig: String },
    AuthOk { ok: bool },
    /// Transfer metadata. `size` is optional (unknown => payload runs until EOF).
    Offer {
        /// Stable transfer id chosen by the sender; re-sent verbatim to resume.
        tid: String,
        name: String,
        kind: String, // "file" | "dir"
        #[serde(default)] size: Option<u64>,
        #[serde(default)] mode: Option<u32>,
        #[serde(default)] uid: u32,
        #[serde(default)] gid: u32,
    },
    /// On resume: `offset` bytes of the file (or of entry `cur` for a directory) are already there.
    Answer {
        accept: bool,
        #[serde(default)] reason: Option<String>,
        #[serde(default)] offset: u64,
        #[serde(default)] cur: Option<String>,
    },
    Result { ok: bool, #[serde(default)] bytes: u64, #[serde(default)] error: Option<String> },
}

pub async fn write_msg<W: AsyncWrite + Unpin + ?Sized>(w: &mut W, m: &Msg) -> std::io::Result<()> {
    let body = serde_json::to_vec(m)?;
    let mut buf = Vec::with_capacity(4 + body.len());
    buf.extend_from_slice(&(body.len() as u32).to_be_bytes());
    buf.extend_from_slice(&body);
    w.write_all(&buf).await?;
    w.flush().await
}

pub async fn read_msg<R: AsyncRead + Unpin + ?Sized>(r: &mut R) -> std::io::Result<Msg> {
    read_json(r).await
}

async fn read_json<R: AsyncRead + Unpin + ?Sized, T: DeserializeOwned>(r: &mut R) -> std::io::Result<T> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len).await?;
    let n = u32::from_be_bytes(len) as usize;
    if n > MAX_FRAME {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "frame too large"));
    }
    let mut buf = vec![0u8; n];
    r.read_exact(&mut buf).await?;
    serde_json::from_slice(&buf).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}
