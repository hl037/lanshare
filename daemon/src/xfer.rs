//! Payload streaming: ranges of files (pipelined disk/net), directory scanning, safe paths.
use crate::proto::BoxIo;
use std::io::{self, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::sync::mpsc;

pub const CH: usize = 1 << 20;

#[derive(Clone)]
pub struct Ctl {
    pub bytes: Arc<AtomicU64>,
    pub cancel: Arc<AtomicBool>,
}

fn aborted() -> io::Error {
    io::Error::new(io::ErrorKind::Interrupted, "aborted")
}

/// Test knob: LANSHARE_THROTTLE=<bytes/s> slows the sender down.
fn throttle() -> Option<f64> {
    static T: OnceLock<Option<f64>> = OnceLock::new();
    *T.get_or_init(|| std::env::var("LANSHARE_THROTTLE").ok().and_then(|v| v.parse().ok()))
}

/// Fill `buf` fully unless EOF; returns bytes read.
async fn fill<R: tokio::io::AsyncRead + Unpin>(r: &mut R, buf: &mut [u8]) -> io::Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        let k = r.read(&mut buf[n..]).await?;
        if k == 0 {
            break;
        }
        n += k;
    }
    Ok(n)
}

/// Send `len` bytes of `path` starting at `off`.
pub async fn send_range(io: &mut BoxIo, path: &Path, off: u64, len: u64, ctl: &Ctl) -> io::Result<()> {
    let mut f = tokio::fs::File::open(path).await?;
    f.seek(SeekFrom::Start(off)).await?;
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(4);
    let reader = tokio::spawn(async move {
        let mut left = len;
        while left > 0 {
            let mut buf = vec![0u8; left.min(CH as u64) as usize];
            let n = fill(&mut f, &mut buf).await?;
            if n == 0 {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "file shrank during transfer"));
            }
            buf.truncate(n);
            left -= n as u64;
            if tx.send(buf).await.is_err() {
                break;
            }
        }
        Ok(())
    });
    let mut res = Ok(());
    while let Some(chunk) = rx.recv().await {
        if ctl.cancel.load(Ordering::Relaxed) {
            res = Err(aborted());
            break;
        }
        if let Err(e) = io.write_all(&chunk).await {
            res = Err(e);
            break;
        }
        ctl.bytes.fetch_add(chunk.len() as u64, Ordering::Relaxed);
        if let Some(bps) = throttle() {
            tokio::time::sleep(std::time::Duration::from_secs_f64(chunk.len() as f64 / bps)).await;
        }
    }
    drop(rx);
    reader.abort();
    res?;
    io.flush().await
}

/// Receive into an already-positioned file. `len == None` reads until EOF.
/// The partial file is left in place on error: its length is the resume offset.
pub async fn recv_into<R: tokio::io::AsyncRead + Unpin>(io: &mut R, f: tokio::fs::File, len: Option<u64>, ctl: &Ctl) -> io::Result<()> {
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(4);
    let mut f = f;
    let writer = tokio::spawn(async move {
        while let Some(c) = rx.recv().await {
            f.write_all(&c).await?;
        }
        f.flush().await
    });
    let mut left = len;
    let mut res = Ok(());
    loop {
        if ctl.cancel.load(Ordering::Relaxed) {
            res = Err(aborted());
            break;
        }
        let want = left.map_or(CH as u64, |l| l.min(CH as u64)) as usize;
        if want == 0 {
            break;
        }
        let mut buf = vec![0u8; want];
        match fill(io, &mut buf).await {
            Ok(0) => {
                if left.is_some() {
                    res = Err(io::Error::new(io::ErrorKind::UnexpectedEof, "connection closed early"));
                }
                break;
            }
            Ok(n) => {
                buf.truncate(n);
                ctl.bytes.fetch_add(n as u64, Ordering::Relaxed);
                if let Some(l) = left.as_mut() {
                    *l -= n as u64;
                }
                if tx.send(buf).await.is_err() {
                    break;
                }
            }
            Err(e) => {
                res = Err(e);
                break;
            }
        }
    }
    drop(tx);
    let wr = writer.await.map_err(io::Error::other)?;
    res.and(wr)
}

pub struct Item {
    pub rel: String, // "<root>/sub/file", always '/'-separated
    pub abs: PathBuf,
    pub dir: bool,
    pub size: u64,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub mtime: u64,
}

/// Deterministic (sorted) listing of a directory tree; symlinks and special files are skipped.
pub fn scan_dir(root: &Path) -> io::Result<Vec<Item>> {
    let base = root.file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_else(|| "folder".into());
    let mut out = vec![];
    for e in walkdir::WalkDir::new(root).follow_links(false).sort_by_file_name() {
        let e = e.map_err(io::Error::other)?;
        let ft = e.file_type();
        if !(ft.is_file() || ft.is_dir()) {
            continue;
        }
        let meta = e.metadata().map_err(io::Error::other)?;
        let mut rel = base.clone();
        for c in e.path().strip_prefix(root).unwrap().components() {
            rel.push('/');
            rel.push_str(&c.as_os_str().to_string_lossy());
        }
        #[cfg(unix)]
        let (mode, uid, gid) = {
            use std::os::unix::fs::MetadataExt;
            (meta.mode(), meta.uid(), meta.gid())
        };
        #[cfg(not(unix))]
        let (mode, uid, gid) = (if ft.is_dir() { 0o755 } else { 0o644 }, 1000, 1000);
        let mtime = meta.modified().ok().and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map_or(0, |d| d.as_secs());
        out.push(Item { rel, abs: e.path().to_path_buf(), dir: ft.is_dir(), size: if ft.is_file() { meta.len() } else { 0 }, mode, uid, gid, mtime });
    }
    Ok(out)
}

/// Join an untrusted relative path under `base`; rejects traversal, absolute paths, drive letters, ADS.
pub fn safe_join(base: &Path, rel: &str) -> Option<PathBuf> {
    let mut p = base.to_path_buf();
    let mut any = false;
    for c in rel.split('/') {
        if c.is_empty() || c == "." || c == ".." || c.chars().any(|ch| ch.is_control() || "\\:<>\"|?*".contains(ch)) {
            return None;
        }
        p.push(c);
        any = true;
    }
    any.then_some(p)
}

pub struct Owner {
    pub uid_map: std::collections::BTreeMap<u32, u32>,
    pub gid_map: std::collections::BTreeMap<u32, u32>,
}

impl Owner {
    /// Best-effort ownership remap (Unix only; needs privileges, silently ignored otherwise).
    pub fn apply(&self, _path: &Path, _uid: u32, _gid: u32) {
        #[cfg(unix)]
        {
            let u = self.uid_map.get(&_uid).copied();
            let g = self.gid_map.get(&_gid).copied();
            if u.is_some() || g.is_some() {
                let _ = std::os::unix::fs::chown(_path, u, g);
            }
        }
    }
}

/// Apply permission bits (setuid/setgid/sticky stripped) and mtime. Best effort.
pub fn finish_file(path: &Path, _mode: u32, mtime: u64) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(_mode & 0o777));
    }
    if mtime > 0 {
        if let Ok(f) = std::fs::OpenOptions::new().write(true).open(path) {
            let _ = f.set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(mtime));
        }
    }
}

// ------------------------------------------------------------------ compact directory stream
//
// After the Answer, a directory is a sequence of binary records, no per-item flush:
//   kind:u8 (0 = end, 1 = file, 2 = dir; |4 = resume info follows)
//   path_len:u16le, path (UTF-8, '/'-separated)
//   size, mode, uid, gid, mtime: LEB128 varints
//   [off, done: varints]  only on the first record of a resumed attempt
//   then `size - off` raw bytes for files.
// Typical overhead is ~30 bytes per item (tar: 512 + padding).

pub const END: u8 = 0;
/// Files up to this size are batched with their header into a single write / read.
pub const SMALL: u64 = 128 << 10;
const MAX_PATH: usize = 4096;

pub struct Hdr {
    pub dir: bool,
    pub p: String,
    pub size: u64,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub mtime: u64,
    /// (offset into this file already present, payload bytes of all previous items)
    pub resume: Option<(u64, u64)>,
}

fn put_varint(out: &mut Vec<u8>, mut v: u64) {
    while v >= 0x80 {
        out.push((v as u8) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

impl Hdr {
    pub fn encode(&self, out: &mut Vec<u8>) -> io::Result<()> {
        if self.p.len() > MAX_PATH {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "path too long"));
        }
        out.push(if self.dir { 2 } else { 1 } | if self.resume.is_some() { 4 } else { 0 });
        out.extend_from_slice(&(self.p.len() as u16).to_le_bytes());
        out.extend_from_slice(self.p.as_bytes());
        for v in [self.size, (self.mode & 0o7777) as u64, self.uid as u64, self.gid as u64, self.mtime] {
            put_varint(out, v);
        }
        if let Some((off, done)) = self.resume {
            put_varint(out, off);
            put_varint(out, done);
        }
        Ok(())
    }
}

/// Buffered reader for the header stream. Payload reads drain the buffer first, then bypass it,
/// so large files are read straight into the caller's buffer.
pub struct Rd<'a> {
    io: &'a mut BoxIo,
    buf: Vec<u8>,
    pos: usize,
    end: usize,
}

impl<'a> Rd<'a> {
    pub fn new(io: &'a mut BoxIo) -> Self {
        Rd { io, buf: vec![0; 64 << 10], pos: 0, end: 0 }
    }
    async fn ensure(&mut self, n: usize) -> io::Result<()> {
        if self.end - self.pos >= n {
            return Ok(());
        }
        if self.pos > 0 {
            self.buf.copy_within(self.pos..self.end, 0);
            self.end -= self.pos;
            self.pos = 0;
        }
        while self.end < n {
            let k = self.io.read(&mut self.buf[self.end..]).await?;
            if k == 0 {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "stream ended inside a header"));
            }
            self.end += k;
        }
        Ok(())
    }
    async fn byte(&mut self) -> io::Result<u8> {
        self.ensure(1).await?;
        self.pos += 1;
        Ok(self.buf[self.pos - 1])
    }
    async fn varint(&mut self) -> io::Result<u64> {
        let (mut v, mut shift) = (0u64, 0);
        loop {
            let b = self.byte().await?;
            v |= ((b & 0x7f) as u64) << shift;
            if b & 0x80 == 0 {
                return Ok(v);
            }
            shift += 7;
            if shift > 63 {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "bad varint"));
            }
        }
    }
    /// Next record; `None` marks the end of the directory stream.
    pub async fn header(&mut self) -> io::Result<Option<Hdr>> {
        let bad = |m: &'static str| io::Error::new(io::ErrorKind::InvalidData, m);
        let k = self.byte().await?;
        if k == END {
            return Ok(None);
        }
        if k & 3 == 0 || k & 3 == 3 || k > 7 {
            return Err(bad("bad record kind"));
        }
        self.ensure(2).await?;
        let n = u16::from_le_bytes([self.buf[self.pos], self.buf[self.pos + 1]]) as usize;
        self.pos += 2;
        if n == 0 || n > MAX_PATH {
            return Err(bad("bad path length"));
        }
        self.ensure(n).await?;
        let p = String::from_utf8(self.buf[self.pos..self.pos + n].to_vec()).map_err(|_| bad("path is not UTF-8"))?;
        self.pos += n;
        let (size, mode, uid, gid, mtime) = (self.varint().await?, self.varint().await?, self.varint().await?, self.varint().await?, self.varint().await?);
        let resume = if k & 4 != 0 { Some((self.varint().await?, self.varint().await?)) } else { None };
        Ok(Some(Hdr { dir: k & 3 == 2, p, size, mode: mode as u32, uid: uid as u32, gid: gid as u32, mtime, resume }))
    }
}

impl tokio::io::AsyncRead for Rd<'_> {
    fn poll_read(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>, out: &mut tokio::io::ReadBuf<'_>) -> std::task::Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.pos < this.end {
            let n = (this.end - this.pos).min(out.remaining());
            out.put_slice(&this.buf[this.pos..this.pos + n]);
            this.pos += n;
            return std::task::Poll::Ready(Ok(()));
        }
        std::pin::Pin::new(&mut *this.io).poll_read(cx, out)
    }
}

/// Read `len` bytes of a small file at `off` (blocking; call from spawn_blocking).
pub fn read_small(path: &Path, off: u64, len: u64) -> io::Result<Vec<u8>> {
    use std::io::{Read, Seek};
    let mut f = std::fs::File::open(path)?;
    f.seek(SeekFrom::Start(off))?;
    let mut v = vec![0u8; len as usize];
    f.read_exact(&mut v).map_err(|e| if e.kind() == io::ErrorKind::UnexpectedEof { io::Error::new(e.kind(), "file shrank during transfer") } else { e })?;
    Ok(v)
}

/// Create a small file in one go: parents, data, mtime, permissions (blocking).
pub fn write_small(path: &Path, data: &[u8], _mode: u32, mtime: u64) -> io::Result<()> {
    use std::io::Write;
    if let Some(par) = path.parent() {
        std::fs::create_dir_all(par)?;
    }
    let mut f = std::fs::File::create(path)?;
    f.write_all(data)?;
    if mtime > 0 {
        let _ = f.set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(mtime));
    }
    drop(f);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(_mode & 0o777));
    }
    Ok(())
}
