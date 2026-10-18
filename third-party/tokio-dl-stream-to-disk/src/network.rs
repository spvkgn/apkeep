//! Public-network HTTP policy. Initial URLs must pass `validate_public_url`.
use std::io::{Error, ErrorKind};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use reqwest::dns::{Addrs, Name, Resolve, Resolving};

fn denied() -> Error {
    Error::new(
        ErrorKind::PermissionDenied,
        "URL is not a public HTTP endpoint",
    )
}

/// Validate the scheme, authority and literal address of an initial URL.
/// DNS names are checked by the resolver at connection time, not looked up here.
/// Always call this before sending an initial request with the public builder:
/// reqwest does not call DNS resolvers for literal IP addresses.
pub fn validate_public_url(url: &reqwest::Url) -> Result<(), Error> {
    if !matches!(url.scheme(), "http" | "https")
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(denied());
    }
    let host = url.host_str().ok_or_else(denied)?;
    let literal = host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = literal.parse::<IpAddr>() {
        if !is_public_ip(ip) {
            return Err(denied());
        }
    } else if host.is_empty() {
        return Err(denied());
    }
    Ok(())
}

/// Public artifact URL policy for sources without authenticated content digests.
pub fn validate_public_https_url(url: &reqwest::Url) -> Result<(), Error> {
    if url.scheme() != "https" {
        return Err(denied());
    }
    validate_public_url(url)
}

/// HTTPS-only initial requests and redirects, plus the public-address policy.
pub fn public_https_client_builder() -> reqwest::ClientBuilder {
    public_http_client_builder()
        .https_only(true)
        .redirect(https_redirect_policy())
}

fn v4_in(ip: Ipv4Addr, network: [u8; 4], bits: u32) -> bool {
    let mask = u32::MAX << (32 - bits);
    u32::from(ip) & mask == u32::from(Ipv4Addr::from(network)) & mask
}

fn v6_in(ip: Ipv6Addr, network: [u16; 8], bits: u32) -> bool {
    let mask = u128::MAX << (128 - bits);
    u128::from(ip) & mask == u128::from(Ipv6Addr::from(network)) & mask
}

fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ![
            ([0, 0, 0, 0], 8),
            ([10, 0, 0, 0], 8),
            ([100, 64, 0, 0], 10),
            ([127, 0, 0, 0], 8),
            ([169, 254, 0, 0], 16),
            ([172, 16, 0, 0], 12),
            ([192, 0, 0, 0], 24),
            ([192, 0, 2, 0], 24),
            ([192, 31, 196, 0], 24),
            ([192, 52, 193, 0], 24),
            ([192, 88, 99, 0], 24),
            ([192, 168, 0, 0], 16),
            ([192, 175, 48, 0], 24),
            ([198, 18, 0, 0], 15),
            ([198, 51, 100, 0], 24),
            ([203, 0, 113, 0], 24),
            ([224, 0, 0, 0], 4),
            ([240, 0, 0, 0], 4),
        ]
        .iter()
        .any(|&(network, bits)| v4_in(ip, network, bits)),
        // Only global unicast; this also rejects mapped/compatible IPv4,
        // NAT64, local, multicast and unallocated/reserved address space.
        // Conservatively reject special-purpose blocks within global unicast.
        IpAddr::V6(ip) => {
            v6_in(ip, [0x2000, 0, 0, 0, 0, 0, 0, 0], 3)
                && !v6_in(ip, [0x2001, 0, 0, 0, 0, 0, 0, 0], 23)
                && !v6_in(ip, [0x2001, 0xdb8, 0, 0, 0, 0, 0, 0], 32)
                && !v6_in(ip, [0x2002, 0, 0, 0, 0, 0, 0, 0], 16)
                && !v6_in(ip, [0x2620, 0x4f, 0x8000, 0, 0, 0, 0, 0], 48)
                && !v6_in(ip, [0x3fff, 0, 0, 0, 0, 0, 0, 0], 20)
        }
    }
}

fn checked_addresses(addresses: impl Iterator<Item = SocketAddr>) -> Result<Addrs, Error> {
    let addresses: Vec<_> = addresses.collect();
    // Reject the entire answer, not just private members, before handing any
    // addresses to the connector. The connector uses this exact checked set.
    if addresses.is_empty() || addresses.iter().any(|addr| !is_public_ip(addr.ip())) {
        return Err(denied());
    }
    Ok(Box::new(addresses.into_iter()))
}

struct SystemResolver;
impl Resolve for SystemResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let host = name.as_str().to_owned();
        Box::pin(async move {
            let addresses: Vec<_> = tokio::net::lookup_host((host.as_str(), 0)).await?.collect();
            Ok(Box::new(addresses.into_iter()) as Addrs)
        })
    }
}

struct PublicResolver {
    inner: Arc<dyn Resolve>,
    timeout: Duration,
}
impl Resolve for PublicResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let resolving = self.inner.resolve(name);
        let timeout = self.timeout;
        Box::pin(async move {
            let addresses = tokio::time::timeout(timeout, resolving)
                .await
                .map_err(|_| Error::new(ErrorKind::TimedOut, "DNS deadline exceeded"))??;
            checked_addresses(addresses).map_err(Into::into)
        })
    }
}

fn redirect_policy() -> reqwest::redirect::Policy {
    redirect_policy_for(false)
}

pub(super) fn https_redirect_policy() -> reqwest::redirect::Policy {
    redirect_policy_for(true)
}

fn redirect_policy_for(https_only: bool) -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::custom(move |attempt| {
        if attempt.previous().len() > 10 {
            attempt.error("public HTTP redirect limit exceeded")
        } else if (https_only && attempt.url().scheme() != "https")
            || validate_public_url(attempt.url()).is_err()
        {
            attempt.error(denied())
        } else {
            attempt.follow()
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Answers {
        values: Vec<SocketAddr>,
        calls: Arc<AtomicUsize>,
        stall: bool,
    }
    impl Resolve for Answers {
        fn resolve(&self, _: Name) -> Resolving {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let values = self.values.clone();
            let stall = self.stall;
            Box::pin(async move {
                if stall {
                    std::future::pending::<()>().await;
                }
                Ok(Box::new(values.into_iter()) as Addrs)
            })
        }
    }

    #[tokio::test]
    async fn dns_rejects_entire_mixed_answer_and_returns_checked_set_once() {
        for values in [
            vec!["8.8.8.8:0", "127.0.0.1:0"],
            vec!["8.8.8.8:0", "10.0.0.1:0"],
            vec!["8.8.8.8:0", "[::ffff:127.0.0.1]:0"],
            vec!["127.0.0.1:0", "8.8.8.8:0"],
            vec![],
            vec!["8.8.8.8:0", "[2606:4700:4700::1111]:0"],
        ] {
            let calls = Arc::new(AtomicUsize::new(0));
            let values: Vec<SocketAddr> = values.into_iter().map(|v| v.parse().unwrap()).collect();
            let expected = values.clone();
            let public = !values.is_empty() && values.iter().all(|a| is_public_ip(a.ip()));
            let resolver = PublicResolver {
                inner: Arc::new(Answers {
                    values,
                    calls: calls.clone(),
                    stall: false,
                }),
                timeout: Duration::from_millis(30),
            };
            let result = resolver.resolve("fixture.invalid".parse().unwrap()).await;
            assert_eq!(result.is_ok(), public);
            if let Ok(addresses) = result {
                assert_eq!(addresses.collect::<Vec<_>>(), expected);
            }
            assert_eq!(
                calls.load(Ordering::SeqCst),
                1,
                "no validation/relookup race"
            );
        }
    }

    #[tokio::test]
    async fn dns_lookup_itself_has_a_deadline() {
        let resolver = PublicResolver {
            inner: Arc::new(Answers {
                values: vec![],
                calls: Arc::new(AtomicUsize::new(0)),
                stall: true,
            }),
            timeout: Duration::from_millis(30),
        };
        let result = tokio::time::timeout(
            Duration::from_millis(200),
            resolver.resolve("fixture.invalid".parse().unwrap()),
        )
        .await
        .expect("resolver must have its own finite deadline");
        assert!(result.is_err());
    }

    async fn redirect_fixture(location: String) -> (String, tokio::task::JoinHandle<()>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/source", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0; 4096];
            socket.read(&mut request).await.unwrap();
            let response = format!("HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            socket.write_all(response.as_bytes()).await.unwrap();
        });
        (url, task)
    }

    #[tokio::test]
    async fn redirects_reject_private_literals_userinfo_and_private_dns_before_target_io() {
        let target = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = target.local_addr().unwrap().port();
        for location in [
            format!("http://127.0.0.1:{port}/target"),
            format!("http://[::ffff:127.0.0.1]:{port}/target"),
            format!("http://private.fixture.invalid:{port}/target"),
            format!("http://u:p@public.fixture.invalid:{port}/target"),
            "http://169.254.169.254/target".to_owned(),
            "file:///etc/passwd".to_owned(),
        ] {
            let calls = Arc::new(AtomicUsize::new(0));
            let resolver = PublicResolver {
                inner: Arc::new(Answers {
                    values: vec![target.local_addr().unwrap()],
                    calls: calls.clone(),
                    stall: false,
                }),
                timeout: Duration::from_millis(50),
            };
            // Explicit fixture-only initial loopback request; redirect and DNS
            // enforcement are the exact production policies, not cfg bypasses.
            let client = reqwest::Client::builder()
                .no_proxy()
                .redirect(redirect_policy())
                .dns_resolver(Arc::new(resolver))
                .timeout(Duration::from_millis(300))
                .build()
                .unwrap();
            let (url, task) = redirect_fixture(location.clone()).await;
            let result = tokio::time::timeout(Duration::from_secs(1), client.get(url).send())
                .await
                .unwrap();
            if location.starts_with("file:") {
                // reqwest stops unsupported-scheme redirects before invoking
                // custom policy. No target request is made; it returns 302.
                assert_eq!(result.unwrap().status(), reqwest::StatusCode::FOUND);
            } else {
                assert!(result.is_err(), "redirect accepted: {location}");
            }
            task.await.unwrap();
            assert_eq!(
                calls.load(Ordering::SeqCst),
                usize::from(location.contains("private.fixture.invalid"))
            );
            assert!(
                tokio::time::timeout(Duration::from_millis(10), target.accept())
                    .await
                    .is_err()
            );
        }
    }

    #[tokio::test]
    async fn redirect_loops_have_a_finite_hop_limit() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let url = format!("http://loop.fixture.invalid:{}/source", address.port());
        let count = Arc::new(AtomicUsize::new(0));
        let requests = count.clone();
        let target_url = url.clone();
        let server = tokio::spawn(async move {
            loop {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut request = [0; 4096];
                socket.read(&mut request).await.unwrap();
                requests.fetch_add(1, Ordering::SeqCst);
                let response = format!("HTTP/1.1 302 Found\r\nLocation: {target_url}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                socket.write_all(response.as_bytes()).await.unwrap();
            }
        });
        // Only this test overrides DNS for a synthetic hostname to loopback.
        let client = public_http_client_builder()
            .resolve("loop.fixture.invalid", address)
            .timeout(Duration::from_secs(2))
            .build()
            .unwrap();
        validate_public_url(&reqwest::Url::parse(&url).unwrap()).unwrap();
        let error = client.get(url).send().await.unwrap_err();
        server.abort();
        let _ = server.await;
        assert!(error.is_redirect());
        assert_eq!(count.load(Ordering::SeqCst), 11);
    }

    #[tokio::test]
    async fn environment_proxy_is_not_used_by_public_client() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy = format!("http://{}", listener.local_addr().unwrap());
        let exe = std::env::current_exe().unwrap();
        let child = tokio::process::Command::new(exe)
            .arg("--exact")
            .arg("network::tests::environment_proxy_child")
            .env("DOWNLOADER_PROXY_CHILD", "1")
            .env("HTTP_PROXY", &proxy)
            .env("HTTPS_PROXY", &proxy)
            .env("ALL_PROXY", &proxy)
            .env("http_proxy", &proxy)
            .env("https_proxy", &proxy)
            .env("all_proxy", &proxy)
            .env("NO_PROXY", "")
            .env("no_proxy", "")
            .kill_on_drop(true)
            .output();
        let output = tokio::time::timeout(Duration::from_secs(5), child)
            .await
            .unwrap()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(20), listener.accept())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn environment_proxy_child() {
        if std::env::var_os("DOWNLOADER_PROXY_CHILD").is_none() {
            return;
        }
        let client = public_http_client_builder()
            .timeout(Duration::from_millis(300))
            .build()
            .unwrap();
        let url = reqwest::Url::parse("http://localhost:9/").unwrap();
        validate_public_url(&url).unwrap();
        let error = client.get(url).send().await.unwrap_err();
        assert!(
            error.is_dns(),
            "private DNS must fail before any proxy/target connection"
        );
    }
}

/// Build a direct public-network client with checked DNS and redirect targets.
/// Call `validate_public_url` for EVERY initial URL before sending a request.
/// Do not override DNS, proxy or redirect policy on production clients. This
/// returns reqwest's builder for configuring headers/timeouts, not a sandbox
/// against trusted Rust callers deliberately replacing its security policy.
pub fn public_http_client_builder() -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .no_proxy()
        .dns_resolver(Arc::new(PublicResolver {
            inner: Arc::new(SystemResolver),
            timeout: Duration::from_secs(15),
        }))
        .redirect(redirect_policy())
        .connect_timeout(Duration::from_secs(15))
        .read_timeout(Duration::from_secs(30))
        .timeout(Duration::from_secs(600))
}
