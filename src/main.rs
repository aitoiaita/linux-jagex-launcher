use clap::Parser;
use client::{Client, ClientResult};
use daemon::DaemonStatus;
use sysinfo::{System, SystemExt, Pid, ProcessExt};
use tracing_subscriber::fmt::writer::MakeWriterExt;

use crate::{daemon::{launcher_client::LauncherClientSession, consent_client::ConsentClientSession}, xdg::XDGCredsState};

mod daemon;
mod xdg;
mod client;

const DEFAULT_DAEMON_PORT: u16 = 80;

#[derive(clap::Parser)]
struct ProgramArguments {
    #[arg(short, long, default_value_t=DEFAULT_DAEMON_PORT)]
    daemon_port: u16,

    #[arg(short, long, default_value_t=false)]
    kill_daemon: bool,

    #[arg(short, long, default_value_t=false)]
    clear_creds: bool,
}

fn kill_process(pid: usize) -> bool {
    let mut system = System::new();
    system.refresh_processes();
    match system.process(Pid::from(pid)) {
        Some(p) => p.kill(),
        None => false,
    }
}

fn main() -> ClientResult<()> {
    // setup logging
    let logfile = tracing_appender::rolling::daily(daemon::ensure_log_dir().unwrap(), "client");
    tracing_subscriber::fmt().with_writer(logfile.and(std::io::stdout)).init();

    tracing::info!("launching");
    if let Some(jagex_params) = std::env::args().nth(1).and_then(|s| s.strip_prefix("jagex:").map(|s| s.to_string() ) ) {
        // handle authorization callback invokation

        // parse port from env or default
        let port = std::env::var("LAUNCHER_DAEMON_PORT")
            .map(|s| u16::from_str_radix(&s, 10) )
            .unwrap_or(Ok(DEFAULT_DAEMON_PORT))
            .expect("Invalid port in env var");
        if port != DEFAULT_DAEMON_PORT {
            tracing::info!("Sending authorization code to daemon port {}", port);
        }
        // create client and authorize if the daemon is waiting for authorization
        let client = Client::new(port);
        match client.daemon_status() {
            Ok((DaemonStatus::AwaitAuthorization(_), _)) => { 
                let response = client.authorize(&jagex_params)?;
                tracing::debug!("Authorization response: {:?}", response);
             },
            Ok(_) => tracing::warn!("Daemon wasn't awaiting authorization"),
            Err(e) => tracing::error!("Couldn't fetch daemon status: {}", e),
        }
    } else {
        let args = ProgramArguments::parse();
        let client = Client::new(args.daemon_port);

        if args.clear_creds {
            if let Ok(path) = LauncherClientSession::ensure_creds_file_path(){
                if path.exists() {
                    std::fs::remove_file(path).expect("Couldn't remove launcher client credentials file");
                    tracing::info!("Cleared launcher client credentials");
                }
            }
            if let Ok(path) = ConsentClientSession::ensure_creds_file_path() {
                if path.exists() {
                    std::fs::remove_file(path).expect("Couldn't remove consent client credentials file");
                    tracing::info!("Cleared consent client credentials");
                }
            }
            tracing::info!("Done clearing credentials");
        } else if args.kill_daemon {
            // kill the daemon
            match client.daemon_status() {
                Ok((_, pid)) => match kill_process(pid.try_into().unwrap()) {
                    true => tracing::info!("Killed process with PID {}", pid),
                    false => tracing::warn!("Couldn't find/kill process with PID {}", pid),
                },
                Err(e) => tracing::warn!("Couldn't get daemon status: {}\nAre you sure it's an osrs-launcher daemon?", e),
            }
        } else {
            // make sure the daemon is running and run the client
            if let Err(e) = client.ensure_daemon_running() {
                tracing::error!("Couldn't ensure daemon was running\n{}", e);
            }
            if let Err(e) = client.run() {
                tracing::error!("{}", e);
            }
        }
    }

    Ok(())
}
