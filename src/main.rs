use std::net::{SocketAddr, SocketAddrV4, Ipv4Addr, Ipv6Addr, SocketAddrV6};

use daemon::{LauncherClientState, LauncherAuthorizationCode};
use oauth2::{AuthorizationCode, CsrfToken};
use reqwest::blocking::Response;

use crate::daemon::Daemon;

mod daemon;
mod jagex_oauth;
mod game_session;

const LOCALHOST_V4: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);
const LOCALHOST_V6: Ipv6Addr = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1);

#[derive(Debug)]
enum JagexURIForwarderError {
    InvalidParams(String),
    URIMissingCode,
    URIMissingState,
    URIMissingIntent,
    InvalidIntent(String),
    Reqwest(reqwest::Error),
}
type JagexURIForwarderResult<T> = Result<T, JagexURIForwarderError>;

fn handle_response(response: Response) {
    let status = response.status();
    let response_text = match response.text() {
        Ok(t) => t,
        Err(e) => panic!("HTTP Error: {}", e),
    };
    match status.as_u16() {
        200..=299 => println!("Success: {}", response_text),
        500..=599 => println!("Error: {}", response_text),
        i => println!("{}: {}", i, response_text)
    };
}

fn handle_jagex_uri(uri_arg_str: &str) -> JagexURIForwarderResult<()> {
    let params: Vec<(&str, &str)> = uri_arg_str.split(",")
        .map(|p| p.split_once("=").ok_or_else(||JagexURIForwarderError::InvalidParams(p.to_string())) )
        .collect::<Result<_,_>>()?;

    let auth_code_str = params.iter().find(|(k, _)| *k == "code" )
        .ok_or(JagexURIForwarderError::URIMissingCode)?.1;
    let state_str = params.iter().find(|(k, _)| *k == "state" )
        .ok_or(JagexURIForwarderError::URIMissingState)?.1;
    let intent = params.iter().find(|(k, _)| *k == "intent" )
        .ok_or(JagexURIForwarderError::URIMissingIntent)?.1.to_string();
    if intent != "social_auth" {
        return Err(JagexURIForwarderError::InvalidIntent(intent));
    }

    let code: LauncherAuthorizationCode = AuthorizationCode::new(auth_code_str.to_string()).into();
    let state: LauncherClientState = CsrfToken::new(state_str.to_string()).into();
    let http_client = reqwest::blocking::Client::new();
    let daemon_request = daemon::DaemonRequestType::AuthorizationCode { code, state, intent };
    let request = daemon_request.to_reqwest_request("http://localhost:80", &http_client).map_err(JagexURIForwarderError::Reqwest)?;
    let response = http_client.execute(request).map_err(JagexURIForwarderError::Reqwest)?;
    handle_response(response);
    Ok(())
}

#[derive(Debug)]
enum LaunchError {
    Reqwest(reqwest::Error),
}
type LaunchResult<T> = Result<T, LaunchError>;

fn launch(display_name: Option<&str>) -> LaunchResult<Response> {
    let http_client = reqwest::blocking::Client::new();
    let daemon_request = daemon::DaemonRequestType::Launch { display_name: display_name.map(|dn| dn.to_string() ) };
    let request = daemon_request.to_reqwest_request("http://localhost:80", &http_client).map_err(LaunchError::Reqwest)?;
    let response = http_client.execute(request).map_err(LaunchError::Reqwest)?;
    Ok(response)
}

fn handle_character_select(display_name: &str) -> LaunchResult<()> {
    handle_response(launch(Some(display_name))?);
    Ok(())
}

fn handle_ambiguous_launch() -> LaunchResult<()> {
    handle_response(launch(None)?);
    Ok(())
}

// Syntax: osrs-launcher --run-daemon [port] | jagex:<params> | [character display name]
fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("--run-daemon") => {

            let port = match args.get(2) {
                Some(p) => match u16::from_str_radix(p, 10) {
                    Ok(p) => p,
                    Err(e) => panic!("Couldn't parse port argument: {}", e),
                },
                None => 80
            };
            let listen_saddrs = vec![
                SocketAddr::V4(SocketAddrV4::new(LOCALHOST_V4, port)),
                SocketAddr::V6(SocketAddrV6::new(LOCALHOST_V6, port, 0, 0))
            ];
            println!("Running daemon HTTP server on 127.0.0.1:{}", port);
            let listen_address = tiny_http::ConfigListenAddr::IP(listen_saddrs);
            let mut daemon = match Daemon::new(listen_address) {
                Ok(d) => d,
                Err(e) => panic!("Couldn't create daemon: {}", e),
            };
            match daemon.run() {
                Ok(()) => (),
                Err(e) => panic!("Error running daemon: {}\nStopping", e),
            }
        }
        Some(arg) => {
            if let Some(uri_args) = arg.strip_prefix("jagex:") {
                if let Err(error) = handle_jagex_uri(uri_args) {
                    panic!("Error while handling Jagex URI\n{:?}", error);
                }
            } else {
                if let Err(error) = handle_character_select(arg) {
                    panic!("Error while launching client as character with display name \"{}\"\n{:?}", arg, error)
                }
            }
        },
        None => if let Err(error) = handle_ambiguous_launch() {
            panic!("Error launching client:\n{:?}", error);
        }
    };
}
