//! Blocking client for the control socket.

use crate::proto::*;
use anyhow::{Context, Result, anyhow, bail};
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::sync::mpsc::{Receiver, channel};
use std::time::Duration;

pub struct Client {
    stream: UnixStream,
    reader: BufReader<UnixStream>,
    next_id: u64,
}

fn connect_stream() -> Result<UnixStream> {
    let path = socket_path();
    UnixStream::connect(&path).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused => {
            anyhow!("the tattle daemon is not running ({path}).\n  Start it with: sudo systemctl enable --now tattle")
        }
        std::io::ErrorKind::PermissionDenied => {
            anyhow!("permission denied on {path}: your user must be in the 'wheel' group")
        }
        _ => anyhow!("connecting to {path}: {e}"),
    })
}

impl Client {
    pub fn connect() -> Result<Client> {
        let stream = connect_stream()?;
        stream.set_read_timeout(Some(Duration::from_secs(10)))?;
        let reader = BufReader::new(stream.try_clone()?);
        Ok(Client {
            stream,
            reader,
            next_id: 1,
        })
    }

    pub fn call(&mut self, req: Request) -> Result<Value> {
        let id = self.next_id;
        self.next_id += 1;
        let mut line = serde_json::to_string(&Envelope { id: Some(id), req })?;
        line.push('\n');
        self.stream
            .write_all(line.as_bytes())
            .context("sending request")?;
        loop {
            let mut buf = String::new();
            if self.reader.read_line(&mut buf).context("reading reply")? == 0 {
                bail!("daemon closed the connection");
            }
            match serde_json::from_str::<Incoming>(&buf) {
                Ok(Incoming::Reply(r)) if r.id == Some(id) || r.id.is_none() => {
                    if r.ok {
                        return Ok(r.data.unwrap_or(Value::Null));
                    }
                    bail!(r.error.unwrap_or_else(|| "request failed".into()));
                }
                _ => continue, // events or stale replies
            }
        }
    }

    pub fn get<T: DeserializeOwned>(&mut self, req: Request) -> Result<T> {
        Ok(serde_json::from_value(self.call(req)?)?)
    }
}

/// A subscription in a background thread: events arrive on the channel;
/// `None` means the daemon went away.
pub fn subscribe(
    alerts: bool,
    traffic: bool,
    connections: bool,
) -> Result<Receiver<Option<Event>>> {
    let mut stream = connect_stream()?;
    let mut line = serde_json::to_string(&Envelope {
        id: Some(1),
        req: Request::Subscribe {
            alerts,
            traffic,
            connections,
        },
    })?;
    line.push('\n');
    stream.write_all(line.as_bytes())?;
    let (tx, rx) = channel();
    std::thread::spawn(move || {
        let mut reader = BufReader::new(stream);
        let mut buf = String::new();
        loop {
            buf.clear();
            match reader.read_line(&mut buf) {
                Ok(0) | Err(_) => {
                    let _ = tx.send(None);
                    return;
                }
                Ok(_) => {
                    if let Ok(Incoming::Event(ev)) = serde_json::from_str::<Incoming>(&buf)
                        && tx.send(Some(ev)).is_err()
                    {
                        return;
                    }
                }
            }
        }
    });
    Ok(rx)
}
