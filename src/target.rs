use std::fmt;
use std::net::SocketAddr;
use url::{Host, Url};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub host: Host<String>,
    pub port: Option<u16>,
}

impl Target {
    pub fn parse(input: &str) -> anyhow::Result<Self> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            anyhow::bail!("target cannot be empty");
        }

        // Accept both bare hostnames/IPs and full URLs. Using a URL parser gives
        // us correct handling of IPv6 brackets and explicit ports for free.
        let url = if trimmed.contains("://") {
            Url::parse(trimmed)
        } else if trimmed.parse::<std::net::Ipv6Addr>().is_ok() {
            // Bare IPv6 literal such as `::1` or `2001:db8::1`.
            Url::parse(&format!("http://[{}]/", trimmed))
        } else {
            Url::parse(&format!("http://{}/", trimmed))
        }
        .map_err(|e| anyhow::anyhow!("invalid target '{}': {}", trimmed, e))?;

        let host = url
            .host()
            .ok_or_else(|| anyhow::anyhow!("invalid target: no host"))?;
        // `Url::port()` hides the scheme's default port, so `https://host:443`
        // and `https://host` both yield `None`. Only keep explicit, non-default
        // ports so the scheme-specific defaults below stay correct.
        let port = url.port();
        if url.query().is_some() || url.fragment().is_some() {
            anyhow::bail!(
                "invalid target '{}': query strings and fragments are not supported",
                trimmed
            );
        }
        let path = url.path();
        if !path.is_empty() && path != "/" {
            anyhow::bail!(
                "invalid target '{}': paths are not supported (got '{}'). Provide a host or host:port.",
                trimmed,
                path
            );
        }

        Ok(Self {
            host: host.to_owned(),
            port,
        })
    }

    /// Raw host string, without brackets. Use this for DNS, nmap host arguments,
    /// and certificate SAN/CN matching.
    pub fn host(&self) -> String {
        match &self.host {
            Host::Domain(d) => d.clone(),
            Host::Ipv4(ip) => ip.to_string(),
            Host::Ipv6(ip) => ip.to_string(),
        }
    }

    /// Port to use for a service, falling back to `default` when the target did
    /// not specify one explicitly.
    pub fn port_or(&self, default: u16) -> u16 {
        self.port.unwrap_or(default)
    }

    /// `host:port` socket address string for a raw TCP connection, using
    /// `default_port` when the target has no explicit port. IPv6 hosts are
    /// bracketed so the result is always parseable by `ToSocketAddrs`.
    pub fn socket_address(&self, default_port: u16) -> String {
        let port = self.port_or(default_port);
        match &self.host {
            Host::Ipv6(ip) => format!("[{}]:{}", ip, port),
            _ => format!("{}:{}", self.host(), port),
        }
    }

    /// Resolve the target host to concrete socket addresses on `port`.
    /// IP-literal targets are returned without a DNS lookup.
    pub async fn resolve(&self, port: u16) -> anyhow::Result<Vec<SocketAddr>> {
        match &self.host {
            Host::Ipv4(ip) => Ok(vec![SocketAddr::new((*ip).into(), port)]),
            Host::Ipv6(ip) => Ok(vec![SocketAddr::new((*ip).into(), port)]),
            Host::Domain(d) => {
                let addrs: Vec<SocketAddr> = tokio::net::lookup_host((d.as_str(), port))
                    .await
                    .map_err(|e| anyhow::anyhow!("failed to resolve {}: {}", d, e))?
                    .collect();
                if addrs.is_empty() {
                    anyhow::bail!("{} did not resolve to any address", d);
                }
                Ok(addrs)
            }
        }
    }

    /// Host formatted for URLs and network addresses. IPv6 addresses are wrapped
    /// in brackets; the port is appended when present.
    pub fn address(&self) -> String {
        match &self.host {
            Host::Domain(d) => match self.port {
                Some(port) => format!("{}:{}", d, port),
                None => d.clone(),
            },
            Host::Ipv4(ip) => match self.port {
                Some(port) => format!("{}:{}", ip, port),
                None => ip.to_string(),
            },
            Host::Ipv6(ip) => match self.port {
                Some(port) => format!("[{}]:{}", ip, port),
                None => format!("[{}]", ip),
            },
        }
    }
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.address())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ip() {
        let t = Target::parse("127.0.0.1").unwrap();
        assert!(matches!(t.host, Host::Ipv4(_)));
        assert!(t.port.is_none());
        assert_eq!(t.host(), "127.0.0.1");
        assert_eq!(t.to_string(), "127.0.0.1");
    }

    #[test]
    fn parse_domain_with_port() {
        let t = Target::parse("example.com:8080").unwrap();
        assert!(matches!(t.host, Host::Domain(ref d) if d == "example.com"));
        assert_eq!(t.port, Some(8080));
        assert_eq!(t.address(), "example.com:8080");
        assert_eq!(t.to_string(), "example.com:8080");
    }

    #[test]
    fn parse_ip_with_port() {
        let t = Target::parse("127.0.0.1:3000").unwrap();
        assert!(matches!(t.host, Host::Ipv4(_)));
        assert_eq!(t.port, Some(3000));
        assert_eq!(t.address(), "127.0.0.1:3000");
    }

    #[test]
    fn parse_url_like_input() {
        let t = Target::parse("https://example.com:8443").unwrap();
        assert!(matches!(t.host, Host::Domain(ref d) if d == "example.com"));
        assert_eq!(t.port, Some(8443));
        assert_eq!(t.host(), "example.com");
        assert_eq!(t.address(), "example.com:8443");
    }

    #[test]
    fn rejects_url_with_path() {
        let err = Target::parse("https://example.com:8443/path").unwrap_err();
        assert!(err.to_string().contains("paths are not supported"));
    }

    #[test]
    fn parse_ipv6_with_port() {
        let t = Target::parse("[::1]:8080").unwrap();
        assert!(matches!(t.host, Host::Ipv6(_)));
        assert_eq!(t.port, Some(8080));
        assert_eq!(t.host(), "::1");
        assert_eq!(t.address(), "[::1]:8080");
        assert_eq!(t.to_string(), "[::1]:8080");
    }

    #[test]
    fn socket_address_applies_default_port() {
        let t = Target::parse("example.com").unwrap();
        assert_eq!(t.socket_address(443), "example.com:443");
        let t = Target::parse("example.com:8443").unwrap();
        assert_eq!(t.socket_address(443), "example.com:8443");
        let t = Target::parse("::1").unwrap();
        assert_eq!(t.socket_address(443), "[::1]:443");
    }

    #[test]
    fn rejects_query_strings() {
        assert!(Target::parse("https://example.com/?a=b").is_err());
    }

    #[tokio::test]
    async fn resolve_ip_literal_without_dns() {
        let t = Target::parse("127.0.0.1").unwrap();
        let addrs = t.resolve(80).await.unwrap();
        assert_eq!(addrs, vec!["127.0.0.1:80".parse().unwrap()]);
    }

    #[test]
    fn rejects_empty() {
        assert!(Target::parse("").is_err());
    }
}
