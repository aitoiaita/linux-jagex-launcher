use std::{fmt::Display, net::{SocketAddrV4, SocketAddr, SocketAddrV6}, time::Duration, io::{stdout, Write}};

use fork::Fork;
use oauth2::{AuthorizationCode, CsrfToken};
use sysinfo::{SystemExt, System, Pid, ProcessExt, Process, PidExt, ProcessStatus};
use url::Url;

use crate::{daemon::{DaemonRequest, DaemonResponse, DaemonStatus, Daemon, DaemonError, self}, xdg, LOCALHOST_V4, LOCALHOST_V6};

#[derive(Debug)]
pub enum ClientError {
    PrepareRequest(reqwest::Error),
    ExecuteRequest(reqwest::Error),
    ParseResponse(reqwest::Error),
    UnexpectedResponse(DaemonRequest, DaemonResponse),
    ErrorResponse(DaemonRequest, String),
    ForkError(i32),
    AuthURIMissingCode, AuthURIMissingState, AuthURIMissingIntent,
    AuthURIIntentInvalid(String),
    DaemonCrashed,
}
pub type ClientResult<T> = Result<T, ClientError>;

impl Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientError::PrepareRequest(e) => write!(f, "Couldn't prepare HTTP request to daemon: {}", e),
            ClientError::ExecuteRequest(e) => write!(f, "Couldn't send HTTP request to daemon: {}", e),
            ClientError::ParseResponse(e) => write!(f, "Couldn't parse JSON response from daemon: {}", e),
            ClientError::UnexpectedResponse(req, resp) => write!(f, "Unexpected response from {:?}: {:?}", req, resp),
            ClientError::ErrorResponse(req, e) => write!(f, "Error response from {:?}: {}", req, e),
            ClientError::ForkError(i) => write!(f, "Couldn't fork: returned {}", i),
            ClientError::AuthURIMissingCode => write!(f, "Authorization URI was missing code param"),
            ClientError::AuthURIMissingState => write!(f, "Authorization URI was missing state param"),
            ClientError::AuthURIMissingIntent => write!(f, "Authorization URI was missing intent param"),
            ClientError::AuthURIIntentInvalid(s) => write!(f, "Authorization URI intent param was an invalid value: {}", s),
            ClientError::DaemonCrashed => write!(f, "Spawned daemon, but then it crashed. Check daemon logs."),
        }
    }
}

pub struct Client {
    pub daemon_port: u16,
    http_client: reqwest::blocking::Client,
    url_base: String,
}

fn is_process_running_child_daemon(process: &Process) -> bool {
    let self_pid = std::process::id();
    let is_child_proc = process.parent()
        .map(|parent_id | parent_id.as_u32() == self_pid )
        .unwrap_or(false);
    if is_child_proc {
        return match process.status() {
            ProcessStatus::Zombie => false, // dead child :(
            _ => true,
        };
    }
    return false;
}

impl Client {
    pub fn new(daemon_port: u16) -> Self {
        Client {
            daemon_port,
            http_client: reqwest::blocking::Client::new(),
            url_base: format!("http://localhost:{}", daemon_port),
        }
    }

    fn execute_request(&self, daemon_request: &DaemonRequest) -> ClientResult<DaemonResponse> {
        let request = daemon_request.to_reqwest_request(&self.url_base, &self.http_client)
            .map_err(ClientError::PrepareRequest)?;
        let response = self.http_client.execute(request).map_err(ClientError::ExecuteRequest)?;
        let daemon_response: DaemonResponse = response.json().map_err(ClientError::ParseResponse)?;
        Ok(daemon_response)
    }

    pub fn authorize(&self, uri_arg_str: &str) -> ClientResult<DaemonResponse> {
        let params: Vec<(&str, &str)> = uri_arg_str.split(",")
            .map(|p| p.split_once("="))
            .filter(|po| po.is_some() ).map(|po| po.unwrap() )
            .collect();

        let auth_code_str = params.iter().find(|(k, _)| *k == "code" )
            .ok_or(ClientError::AuthURIMissingCode)?.1;
        let state_str = params.iter().find(|(k, _)| *k == "state" )
            .ok_or(ClientError::AuthURIMissingState)?.1;
        let intent = params.iter().find(|(k, _)| *k == "intent" )
            .ok_or(ClientError::AuthURIMissingIntent)?.1.to_string();
        if intent != "social_auth" {
            return Err(ClientError::AuthURIIntentInvalid(intent));
        }

        let daemon_request = DaemonRequest::AuthorizationCode {
            code: AuthorizationCode::new(auth_code_str.to_string()).into(),
            state: CsrfToken::new(state_str.to_string()).into(),
            intent,
        };
        let response = self.execute_request(&daemon_request)?;
        Ok(response)
    }

    fn launch_and_print_result(&self, display_name: Option<&str>) {
        let daemon_request = DaemonRequest::Launch { display_name: display_name.map(|s| s.to_string() ) };
        let response = match self.execute_request(&daemon_request) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("Couldn't launch: {}", e);
                return;
            },
        };
        match response {
            DaemonResponse::Launched(pid)  => tracing::info!("Launched game with PID {}", pid),
            DaemonResponse::ErrorStr(s) => tracing::warn!("Couldn't launch game due to error: {}", s),
            r => tracing::warn!("Received unexpected response to launch request: {:?}", r),
        };
    }

    fn open_url_and_print_err(&self, url_str: &str) {
        let open_result: Result<std::process::Child, String> = Url::parse(&url_str).map_err(|e| e.to_string() )
            .and_then(|url| xdg::open_http_url(url).map_err(|e| e.to_string() ) );
        if let Err(e) = open_result {
            tracing::warn!("Couldn't open url: {}", e);
        }
    }

    fn fetch_auth_url(&self, deauth: Option<bool>) -> ClientResult<String> {
        let request = DaemonRequest::AuthorizationURLRequest { deauth: deauth.unwrap_or(false) };
        let response = self.execute_request(&request)?;
        match response {
            DaemonResponse::AuthorizeUrl(s) => Ok(s),
            DaemonResponse::ErrorStr(s) => Err(ClientError::ErrorResponse(request, s)),
            e => Err(ClientError::UnexpectedResponse(request, e)),
        }
    }

    fn spawn_detached_daemon(&self) -> ClientResult<i32> {
        match fork::fork() {
            Ok(Fork::Parent(pid)) => Ok(pid),
            Ok(Fork::Child) => {
                let logdir = daemon::ensure_log_dir().unwrap();
                let logfile = tracing_appender::rolling::daily(logdir, "daemon");
                let log_collector = tracing_subscriber::fmt().with_writer(logfile).finish();
                tracing::subscriber::with_default(log_collector, || {
                    if let Err(i) = fork::setsid() {
                        tracing::error!("Couldn't setsid in daemon; returned {}", i);
                        panic!("Couldn't setsid in daemon");
                    }
                    if let Err(i) = fork::close_fd() {
                        tracing::error!("Can't close stdio fds in daemon; returned {}", i);
                        panic!("Can't close stdio fds in daemon");
                    }
                    let listen_saddrs = vec![
                        SocketAddr::V4(SocketAddrV4::new(LOCALHOST_V4, self.daemon_port)),
                        SocketAddr::V6(SocketAddrV6::new(LOCALHOST_V6, self.daemon_port, 0, 0))
                    ];
                    let listen_address = tiny_http::ConfigListenAddr::IP(listen_saddrs);
                    tracing::info!("Listening on port {}", self.daemon_port);
                    match Daemon::new(listen_address) {
                        Ok(mut d) => {
                            let r = d.run().map(|_| DaemonError::HTTPServerClosed ).unwrap_or_else(|e| e );
                            tracing::error!("Daemon encountered error: {}", r);
                            panic!("Daemon encountered error and stopped:\n{}", r)
                        },
                        Err(e) => {
                            tracing::error!("Couldn't run daemon: {}", e);
                            panic!("Couldn't create daemon: {}", e)
                        },
                    }
                })
            },
            Err(e) => Err(ClientError::ForkError(e)),
        }
    }

    const DAEMON_INIT_POLL_DELAY: u64 = 500;
    pub fn ensure_daemon_running(&self) -> ClientResult<(DaemonStatus, u32)> {
        let mut system = System::new();
        let mut spawned_pid = None;
        let mut last_status = None;
        while last_status.is_none() {
            last_status = match self.daemon_status() {
                Ok(s) => Some(s),
                Err(ClientError::ExecuteRequest(e)) if e.is_connect() => {
                    if let Some(pid) = spawned_pid {
                        system.refresh_process(pid);
                        let dproc_query = system.process(pid);
                        if let Some(daemon_process) = dproc_query {
                            if is_process_running_child_daemon(&daemon_process) {
                                tracing::info!("Waiting for daemon...");
                            } else {
                                return Err(ClientError::DaemonCrashed);
                            }
                        } else {
                            return Err(ClientError::DaemonCrashed);
                        } 
                    } else {
                        tracing::info!("Spawning daemon process");
                        let daemon_pid = usize::try_from(self.spawn_detached_daemon()?).unwrap();
                        spawned_pid = Some(Pid::from(daemon_pid));
                    }
                    std::thread::sleep(Duration::from_millis(Self::DAEMON_INIT_POLL_DELAY));
                    None
                }
                Err(e) => return Err(e),
            };
        }
        Ok(last_status.unwrap())
    }

    pub fn daemon_status(&self) -> ClientResult<(DaemonStatus, u32)> {
        match self.execute_request(&DaemonRequest::Status)? {
            DaemonResponse::Status(s, pid) => Ok((s, pid)),
            r => Err(ClientError::UnexpectedResponse(DaemonRequest::Status, r)),
        }
    }

    fn prompt_for_character(&self, choices: &[String]) {
        match choices.len() {
            0 => {
                println!("Press enter to launch");
                self.launch_and_print_result(None);
            },
            1 => {
                let display_name = choices.get(0).unwrap();
                println!("Press enter to launch as {}", display_name);
                self.launch_and_print_result(Some(&display_name));
            },
            _ => {
                // prompt for which character to launch as
                println!("Characters: ");
                for (display_name, idx) in choices.iter().zip(1..) {
                    println!(" {}) {}", idx, display_name);
                }
                print!("Select a character to launch\n >"); stdout().flush().unwrap();
                let mut line_buf = String::new();
                // if the line was read
                if std::io::stdin().read_line(&mut line_buf).is_ok() {
                    let line = line_buf.trim();
                    // try to find the character whose name matches the line
                    let char_by_name = choices.iter()
                        .find(|c| c.eq_ignore_ascii_case(&line) );
                    match char_by_name {
                        // if the input matches a character, launch as the character
                        Some(char) => self.launch_and_print_result(Some(&char)),
                        // if the input doesnt match a character, try to parse it as in an integer
                        None => if let Ok(idx) = usize::from_str_radix(&line, 10) {
                            // if the input was an integer, try to use the character indexed by the integer
                            match choices.get(idx - 1) {
                                // if there was a character at the input index, launch as the character
                                Some(char_by_idx) => self.launch_and_print_result(Some(&char_by_idx)),
                                None => eprintln!("There is no character at #{}", idx)
                            }
                        } else {
                            eprintln!("Invalid input");
                        }
                    };
                }
            }
        }
    }

    fn handle_daemon_status(&self, status: &DaemonStatus) -> ClientResult<DaemonLoopControl> {
        let control = match status {
            DaemonStatus::NeedAuthorization => {
                self.fetch_auth_url(None)?;
                DaemonLoopControl::WaitForChange
            },
            DaemonStatus::Launch(characters) => {
                self.prompt_for_character(characters.as_slice());
                DaemonLoopControl::Continue
            },
            DaemonStatus::AwaitAuthorization(auth_str) => {
                tracing::info!("Waiting for authorization...\n{}", auth_str);
                self.open_url_and_print_err(auth_str);
                DaemonLoopControl::WaitForChange
            },
            DaemonStatus::AwaitConsent(consent_str) => {
                tracing::info!("Waiting for consent...\n{}", consent_str);
                self.open_url_and_print_err(consent_str);
                DaemonLoopControl::WaitForChange
            },
        };
        Ok(control)
    }

    const LOOP_DELAY_MS: u64 = 350;
    pub fn run(&self) -> ClientResult<()> {
        let mut control = DaemonLoopControl::Continue;
        let mut last_status: Option<DaemonStatus> = None;
        loop {
            let (daemon_status, _) = self.daemon_status()?;
            control = match control {
                DaemonLoopControl::Continue => self.handle_daemon_status(&daemon_status)?,
                DaemonLoopControl::WaitForChange => {
                    let should_run = last_status.map(|ls| ls != daemon_status ).unwrap_or(true);
                    if should_run {
                        self.handle_daemon_status(&daemon_status)?
                    } else {
                        DaemonLoopControl::WaitForChange
                    }
                },
            };
            last_status = Some(daemon_status);
            std::thread::sleep(Duration::from_millis(Self::LOOP_DELAY_MS));
        }
    }
}

enum DaemonLoopControl {
    Continue,
    WaitForChange,
}