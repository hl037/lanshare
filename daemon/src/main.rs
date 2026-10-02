mod app;
mod discovery;
mod ipc;
mod jwt;
mod net;
mod proto;
mod transfer;
mod tlsutil;
mod xfer;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Notify;

fn config_dir() -> PathBuf {
    dirs::config_dir().unwrap_or_else(|| PathBuf::from(".")).join("lanshare")
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let (mut dir, mut tcp, mut udp, mut name) = (config_dir(), 47653u16, 47652u16, None);
    let mut extra: Vec<SocketAddr> = vec![];
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        let mut v = || it.next().ok_or_else(|| anyhow::anyhow!("{a} needs a value"));
        match a.as_str() {
            "--config-dir" => dir = v()?.into(),
            "--tcp-port" => tcp = v()?.parse()?,
            "--udp-port" => udp = v()?.parse()?,
            "--name" => name = Some(v()?),
            "--extra-bcast" => extra.push(v()?.parse()?),
            "--print-config-dir" => {
                println!("{}", dir.display());
                return Ok(());
            }
            _ => anyhow::bail!("unknown argument {a}"),
        }
    }
    let app = app::App::load(dir.clone(), tcp, udp, extra, name)?;
    if let Err(e) = discovery::start(app.clone()) {
        eprintln!("discovery disabled: {e:#}");
    }
    net::apply_exchange(&app);
    let quit = Arc::new(Notify::new());
    ipc::start(app.clone(), quit.clone()).await?;
    eprintln!("lanshared {} listening on tcp {tcp} / udp {udp}", &app.id[..8]);
    tokio::select! {
        _ = quit.notified() => {}
        _ = tokio::signal::ctrl_c() => {}
    }
    let _ = std::fs::remove_file(dir.join("runtime.json"));
    Ok(())
}
