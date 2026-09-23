//! A verifier-owned loopback witness for the one exact harmless shell request.
//! A Codex message or process exit code cannot substitute for this observation.

use std::{
    io::{self, Read, Write},
    net::{TcpListener, TcpStream},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, anyhow};

const REQUEST_LIMIT: usize = 4096;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug, Default, Eq, PartialEq)]
pub struct Observation {
    pub exact_head_requests: usize,
    pub unexpected_requests: usize,
}

pub struct VerificationProbe {
    command: String,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<io::Result<Observation>>>,
}

impl VerificationProbe {
    pub fn start() -> Result<Self> {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .context("bind isolated loopback verification witness")?;
        listener
            .set_nonblocking(true)
            .context("configure verification witness")?;
        let port = listener.local_addr()?.port();
        let mut random = [0_u8; 16];
        getrandom::fill(&mut random).context("generate verification request nonce")?;
        let nonce: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
        let command = crate::compatibility::verification_probe_command(port, &nonce)
            .ok_or_else(|| anyhow!("invalid generated verification probe command"))?;
        let path = format!("/{nonce}");
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let worker = thread::Builder::new()
            .name("codex-autoapprover-verification-witness".into())
            .spawn(move || observe(listener, &path, &thread_stop))
            .context("start loopback verification witness")?;
        Ok(Self {
            command,
            stop,
            worker: Some(worker),
        })
    }

    pub fn command(&self) -> &str {
        &self.command
    }

    pub fn finish(mut self) -> Result<Observation> {
        self.stop.store(true, Ordering::Release);
        self.worker
            .take()
            .expect("verification witness worker")
            .join()
            .map_err(|_| anyhow!("loopback verification witness panicked"))?
            .context("loopback verification witness failed")
    }
}

impl Drop for VerificationProbe {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn observe(listener: TcpListener, path: &str, stop: &AtomicBool) -> io::Result<Observation> {
    let mut observation = Observation::default();
    while !stop.load(Ordering::Acquire) {
        match listener.accept() {
            Ok((mut stream, peer)) => {
                let exact = peer.ip().is_loopback() && receive_head(&mut stream, path)?;
                let response = if exact {
                    b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".as_slice()
                } else {
                    b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        .as_slice()
                };
                stream.set_write_timeout(Some(REQUEST_TIMEOUT))?;
                if stream.write_all(response).is_ok() && exact {
                    observation.exact_head_requests += 1;
                } else {
                    observation.unexpected_requests += 1;
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(error),
        }
    }
    Ok(observation)
}

fn receive_head(stream: &mut TcpStream, path: &str) -> io::Result<bool> {
    let deadline = Instant::now() + REQUEST_TIMEOUT;
    let mut request = Vec::with_capacity(256);
    let mut chunk = [0_u8; 256];
    while request.len() < REQUEST_LIMIT {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok(false);
        }
        stream.set_read_timeout(Some(remaining))?;
        let room = (REQUEST_LIMIT - request.len()).min(chunk.len());
        match stream.read(&mut chunk[..room]) {
            Ok(0) => return Ok(false),
            Ok(length) => {
                request.extend_from_slice(&chunk[..length]);
                if let Some(end) = request.windows(4).position(|window| window == b"\r\n\r\n") {
                    if end + 4 != request.len() {
                        return Ok(false);
                    }
                    let line_end = request.windows(2).position(|window| window == b"\r\n");
                    let Some(line_end) = line_end else {
                        return Ok(false);
                    };
                    return Ok(request[..line_end] == *format!("HEAD {path} HTTP/1.1").as_bytes());
                }
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                return Ok(false);
            }
            Err(error) => return Err(error),
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(target_os = "linux")]
    use std::process::Command;

    #[cfg(target_os = "linux")]
    #[test]
    fn exact_curl_probe_reaches_the_loopback_witness() {
        let probe = VerificationProbe::start().expect("start witness");
        let mut parts = probe.command().split_whitespace();
        let output = Command::new(parts.next().expect("curl executable"))
            .args(parts)
            .output()
            .expect("run exact local curl command");
        assert!(output.status.success());
        assert_eq!(
            probe.finish().expect("finish witness"),
            Observation {
                exact_head_requests: 1,
                unexpected_requests: 0,
            }
        );
    }

    #[test]
    fn witnesses_only_one_exact_head_to_the_generated_endpoint() {
        let probe = VerificationProbe::start().expect("start witness");
        let url = probe
            .command()
            .split_whitespace()
            .last()
            .expect("probe URL");
        let endpoint = url.strip_prefix("http://").expect("loopback URL");
        let (host, path) = endpoint.split_once('/').expect("probe path");
        let mut wrong = TcpStream::connect(host).expect("connect wrong request");
        wrong
            .write_all(b"HEAD /wrong HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
            .expect("send wrong request");
        let mut response = String::new();
        wrong.read_to_string(&mut response).expect("read denial");
        assert!(response.starts_with("HTTP/1.1 404"));

        let mut exact = TcpStream::connect(host).expect("connect exact request");
        exact
            .write_all(format!("HEAD /{path} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n").as_bytes())
            .expect("send exact request");
        response.clear();
        exact.read_to_string(&mut response).expect("read success");
        assert!(response.starts_with("HTTP/1.1 200"));
        assert_eq!(
            probe.finish().expect("finish witness"),
            Observation {
                exact_head_requests: 1,
                unexpected_requests: 1,
            }
        );
    }
}
