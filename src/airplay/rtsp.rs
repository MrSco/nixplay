use super::hap::HapControlCipher;
use anyhow::{bail, Context, Result};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::debug;

#[derive(Debug, Clone)]
pub struct RtspResponse {
    pub status_code: u16,
    pub status_line: String,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

impl RtspResponse {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(&name.to_lowercase()).map(|s| s.as_str())
    }

    pub fn body_plist(&self) -> Result<plist::Value> {
        plist::from_bytes(&self.body).context("failed to decode binary plist body")
    }
}

/// Async RTSP/1.0 client supporting transparent mid-session upgrade to HAP ChaCha20-Poly1305 encryption.
pub struct RtspClient {
    stream: TcpStream,
    cseq: u32,
    dacp_id: String,
    active_remote: String,
    user_agent: String,
    cipher: Option<HapControlCipher>,
    plain_buf: Vec<u8>,
}

impl RtspClient {
    pub async fn connect(addr: SocketAddr) -> Result<Self> {
        let stream = timeout(Duration::from_secs(6), TcpStream::connect(addr))
            .await
            .context("RTSP connect timeout")?
            .with_context(|| format!("RTSP connect failed to {addr}"))?;
        let _ = stream.set_nodelay(true);

        let dacp_id = format!("{:016X}", rand::random::<u64>());
        let active_remote = format!("{}", rand::random::<u32>());

        Ok(Self {
            stream,
            cseq: 0,
            dacp_id,
            active_remote,
            user_agent: "AirPlay/700.0".to_string(),
            cipher: None,
            plain_buf: Vec::new(),
        })
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.stream.local_addr()?)
    }

    pub fn enable_encryption(&mut self, shared_secret: &[u8]) -> Result<()> {
        self.cipher = Some(HapControlCipher::from_shared_secret(shared_secret)?);
        Ok(())
    }

    pub async fn request(
        &mut self,
        method: &str,
        uri: &str,
        extra_headers: &[(&str, &str)],
        body: Option<(&str, &[u8])>,
    ) -> Result<RtspResponse> {
        self.request_with_proto("RTSP/1.0", method, uri, extra_headers, body)
            .await
    }

    pub async fn request_http(
        &mut self,
        method: &str,
        uri: &str,
        extra_headers: &[(&str, &str)],
        body: Option<(&str, &[u8])>,
    ) -> Result<RtspResponse> {
        self.request_with_proto("HTTP/1.1", method, uri, extra_headers, body)
            .await
    }

    pub async fn request_http_plist(
        &mut self,
        method: &str,
        uri: &str,
        extra_headers: &[(&str, &str)],
        value: &plist::Value,
    ) -> Result<RtspResponse> {
        let mut buf = Vec::new();
        plist::to_writer_binary(&mut buf, value).context("failed to encode binary plist")?;
        self.request_with_proto(
            "HTTP/1.1",
            method,
            uri,
            extra_headers,
            Some(("application/x-apple-binary-plist", &buf)),
        )
        .await
    }

    async fn request_with_proto(
        &mut self,
        proto: &str,
        method: &str,
        uri: &str,
        extra_headers: &[(&str, &str)],
        body: Option<(&str, &[u8])>,
    ) -> Result<RtspResponse> {
        let mut req = if proto == "RTSP/1.0" {
            self.cseq += 1;
            format!(
                "{method} {uri} RTSP/1.0\r\nCSeq: {}\r\nUser-Agent: {}\r\nDACP-ID: {}\r\nActive-Remote: {}\r\n",
                self.cseq, self.user_agent, self.dacp_id, self.active_remote
            )
        } else {
            format!("{method} {uri} {proto}\r\nUser-Agent: AirPlay/550.10\r\n")
        };

        for (k, v) in extra_headers {
            req.push_str(&format!("{k}: {v}\r\n"));
        }

        if let Some((ct, data)) = body {
            if !ct.is_empty() {
                req.push_str(&format!("Content-Type: {ct}\r\n"));
            }
            req.push_str(&format!("Content-Length: {}\r\n", data.len()));
        } else if proto == "HTTP/1.1" {
            req.push_str("Content-Length: 0\r\n");
        }
        req.push_str("\r\n");

        let mut wire = req.into_bytes();
        if let Some((_, data)) = body {
            wire.extend_from_slice(data);
        }

        debug!("{proto} >> {} {} ({} bytes)", method, uri, wire.len());

        let to_send = if let Some(ref mut cipher) = self.cipher {
            cipher.encrypt(&wire)?
        } else {
            wire
        };

        timeout(Duration::from_secs(6), self.stream.write_all(&to_send))
            .await
            .context("RTSP write timeout")?
            .context("RTSP write failed")?;

        self.read_response().await
    }

    pub async fn request_plist(
        &mut self,
        method: &str,
        uri: &str,
        extra_headers: &[(&str, &str)],
        value: &plist::Value,
    ) -> Result<RtspResponse> {
        let mut buf = Vec::new();
        plist::to_writer_binary(&mut buf, value).context("failed to encode binary plist")?;
        self.request(
            method,
            uri,
            extra_headers,
            Some(("application/x-apple-binary-plist", &buf)),
        )
        .await
    }

    async fn read_response(&mut self) -> Result<RtspResponse> {
        let mut tmp = [0u8; 4096];

        let (header_end, content_length) = loop {
            if let Some(pos) = find_double_crlf(&self.plain_buf) {
                let hdr_str = String::from_utf8_lossy(&self.plain_buf[..pos]);
                let cl = parse_content_length(&hdr_str);
                break (pos, cl);
            }
            self.read_more(&mut tmp).await?;
        };

        let total_needed = header_end + 4 + content_length;
        while self.plain_buf.len() < total_needed {
            self.read_more(&mut tmp).await?;
        }

        let hdr_bytes = self.plain_buf[..header_end].to_vec();
        let body = self.plain_buf[header_end + 4..total_needed].to_vec();
        self.plain_buf.drain(..total_needed);

        let hdr_str = String::from_utf8_lossy(&hdr_bytes);
        let mut lines = hdr_str.lines();
        let status_line = lines.next().unwrap_or("").trim().to_string();
        let status_code = status_line
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse::<u16>().ok())
            .unwrap_or(0);

        let mut headers = HashMap::new();
        for line in lines {
            if let Some((k, v)) = line.split_once(':') {
                headers.insert(k.trim().to_lowercase(), v.trim().to_string());
            }
        }

        debug!(
            "RTSP << {} ({} body bytes)",
            status_line,
            body.len()
        );

        Ok(RtspResponse {
            status_code,
            status_line,
            headers,
            body,
        })
    }

    async fn read_more(&mut self, tmp: &mut [u8]) -> Result<()> {
        let n = timeout(Duration::from_secs(8), self.stream.read(tmp))
            .await
            .context("RTSP read timeout")?
            .context("RTSP read failed")?;
        if n == 0 {
            bail!("RTSP peer closed connection");
        }
        if let Some(ref mut cipher) = self.cipher {
            let dec = cipher.feed_and_decrypt(&tmp[..n])?;
            self.plain_buf.extend_from_slice(&dec);
        } else {
            self.plain_buf.extend_from_slice(&tmp[..n]);
        }
        Ok(())
    }
}

fn find_double_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn parse_content_length(hdr: &str) -> usize {
    for line in hdr.lines() {
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case("content-length") {
                return v.trim().parse().unwrap_or(0);
            }
        }
    }
    0
}
