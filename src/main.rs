use std::net::{Ipv4Addr, Ipv6Addr};

use clap::Parser;
use client::{Client, ClientResult};
use daemon::{DaemonStatus, LauncherClientSession, ConsentClientSession};
use sysinfo::{System, SystemExt, Pid, ProcessExt};

mod daemon;
mod jagex_oauth;
mod game_session;
mod xdg;
mod client;

const LOCALHOST_V4: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);
const LOCALHOST_V6: Ipv6Addr = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1);

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
    if let Some(jagex_params) = std::env::args().nth(1).and_then(|s| s.strip_prefix("jagex:").map(|s| s.to_string() ) ) {
        // handle authorization callback invokation

        // parse port from env or default
        let port = std::env::var("LAUNCHER_DAEMON_PORT")
            .map(|s| u16::from_str_radix(&s, 10) )
            .unwrap_or(Ok(DEFAULT_DAEMON_PORT))
            .expect("Invalid port in env var");
        if port != DEFAULT_DAEMON_PORT {
            println!("Using daemon port {}", port);
        }
        // create client and authorize if the daemon is waiting for authorization
        let client = Client::new(port);
        match client.daemon_status() {
            Ok((DaemonStatus::AwaitAuthorization(_), _)) => { 
                let response = client.authorize(&jagex_params)?;
                println!("{:?}", response);
             },
            Ok(_) => eprintln!("Daemon wasn't awaiting authorization"),
            Err(e) => eprintln!("Couldn't fetch daemon status: {}", e),
        }
    } else {
        let args = ProgramArguments::parse();
        let client = Client::new(args.daemon_port);

        if args.clear_creds {
            if let Ok(path) = LauncherClientSession::ensure_state_file_path() {
                if path.exists() {
                    std::fs::remove_file(path).expect("Couldn't remove launcher client credentials file");
                    println!("Cleared launcher client credentials");
                }
            }
            if let Ok(path) = ConsentClientSession::ensure_state_file_path() {
                if path.exists() {
                    std::fs::remove_file(path).expect("Couldn't remove consent client credentials file");
                    println!("Cleared consent client credentials");
                }
            }
            println!("Done clearing credentials");
        } else if args.kill_daemon {
            // kill the daemon
            match client.daemon_status() {
                Ok((_, pid)) => match kill_process(pid.try_into().unwrap()) {
                    true => println!("Killed process with PID {}", pid),
                    false => eprintln!("Couldn't find/kill process with PID {}", pid),
                },
                Err(e) => eprintln!("Couldn't get daemon status: {}\nAre you sure it's an osrs-launcher daemon?", e),
            }
        } else {
            // make sure the daemon is running and run the client
            if let Err(e) = client.ensure_daemon_running() {
                panic!("Couldn't ensure daemon was running\n{}", e);
            }
            if let Err(e) = client.run() {
                panic!("{}", e);
            }
        }
    }

    Ok(())
}
