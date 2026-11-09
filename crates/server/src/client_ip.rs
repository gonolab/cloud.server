//! The client address of a request.
//!
//! Gono Cloud runs behind a reverse proxy. Forwarding headers (`Forwarded`, `X-Forwarded-For`)
//! are only believed when the TCP peer is one of `server.trusted_proxies`; otherwise anyone
//! could pick an address and evade the rate limiter. With a trusted peer, the forwarding chain
//! is walked from the right (the hop closest to us) and the first address that is not itself a
//! trusted proxy is the client.

use std::net::IpAddr;

use axum::http::HeaderMap;
use ipnet::IpNet;

/// Determines the client address of a request that arrived from `peer`.
pub fn client_ip(peer: IpAddr, headers: &HeaderMap, trusted_proxies: &[IpNet]) -> IpAddr {
    let trusted = |ip: &IpAddr| trusted_proxies.iter().any(|net| net.contains(ip));
    if !trusted(&peer) {
        return peer;
    }
    // Walk from the hop closest to us. An entry that is not an address (obfuscated or
    // garbage) ends the walk: everything left of it was written by someone we cannot vouch
    // for, so the last trusted hop is the best answer.
    let mut client = peer;
    for hop in forwarded_chain(headers).into_iter().rev() {
        match hop {
            Some(ip) => {
                client = ip;
                if !trusted(&ip) {
                    break;
                }
            }
            None => break,
        }
    }
    client
}

/// The entries of the forwarding chain, leftmost (original client) first; `None` for entries
/// that are not IP addresses.
///
/// RFC 7239 `Forwarded` takes precedence over `X-Forwarded-For`.
fn forwarded_chain(headers: &HeaderMap) -> Vec<Option<IpAddr>> {
    let forwarded: Vec<Option<IpAddr>> = headers
        .get_all("forwarded")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|element| {
            element.split(';').find_map(|pair| {
                let (name, value) = pair.trim().split_once('=')?;
                name.eq_ignore_ascii_case("for")
                    .then(|| parse_forwarded_node(value))
            })
        })
        .collect();
    if !forwarded.is_empty() {
        return forwarded;
    }
    headers
        .get_all("x-forwarded-for")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(|entry| entry.trim().parse().ok())
        .collect()
}

/// Parses a `Forwarded: for=` node: `192.0.2.1`, `"192.0.2.1:8080"`, `"[2001:db8::1]:443"`.
fn parse_forwarded_node(value: &str) -> Option<IpAddr> {
    let value = value.trim().trim_matches('"');
    if let Some(rest) = value.strip_prefix('[') {
        return rest.split_once(']')?.0.parse().ok();
    }
    if let Ok(ip) = value.parse() {
        return Some(ip);
    }
    value.rsplit_once(':')?.0.parse().ok()
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;

    use super::*;

    fn ip(value: &str) -> IpAddr {
        value.parse().unwrap()
    }

    fn headers(pairs: &[(&'static str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.append(*name, HeaderValue::from_str(value).unwrap());
        }
        map
    }

    fn proxies() -> Vec<IpNet> {
        vec![
            "127.0.0.1/32".parse().unwrap(),
            "10.0.0.0/8".parse().unwrap(),
        ]
    }

    #[test]
    fn untrusted_peers_keep_their_address() {
        let spoofed = headers(&[("x-forwarded-for", "203.0.113.9")]);
        assert_eq!(
            client_ip(ip("198.51.100.7"), &spoofed, &proxies()),
            ip("198.51.100.7")
        );
        assert_eq!(client_ip(ip("127.0.0.1"), &spoofed, &[]), ip("127.0.0.1"));
    }

    #[test]
    fn trusted_proxies_forward_the_client() {
        let xff = headers(&[("x-forwarded-for", "203.0.113.9, 10.1.2.3")]);
        assert_eq!(
            client_ip(ip("127.0.0.1"), &xff, &proxies()),
            ip("203.0.113.9")
        );
        // A client cannot hide behind addresses it prepends itself.
        let prepended = headers(&[("x-forwarded-for", "10.9.9.9, 198.51.100.4, 10.1.2.3")]);
        assert_eq!(
            client_ip(ip("127.0.0.1"), &prepended, &proxies()),
            ip("198.51.100.4")
        );
        assert_eq!(
            client_ip(ip("127.0.0.1"), &HeaderMap::new(), &proxies()),
            ip("127.0.0.1")
        );
    }

    #[test]
    fn forwarded_header_takes_precedence() {
        let both = headers(&[
            (
                "forwarded",
                "for=\"[2001:db8::5]:4711\";proto=https, for=10.0.0.2",
            ),
            ("x-forwarded-for", "203.0.113.9"),
        ]);
        assert_eq!(
            client_ip(ip("127.0.0.1"), &both, &proxies()),
            ip("2001:db8::5")
        );
        let with_port = headers(&[("forwarded", "for=\"192.0.2.60:8080\"")]);
        assert_eq!(
            client_ip(ip("127.0.0.1"), &with_port, &proxies()),
            ip("192.0.2.60")
        );
        let obfuscated = headers(&[("forwarded", "for=_hidden, for=10.0.0.2")]);
        assert_eq!(
            client_ip(ip("127.0.0.1"), &obfuscated, &proxies()),
            ip("10.0.0.2")
        );
    }

    #[test]
    fn garbage_cannot_truncate_the_chain() {
        let crafted = headers(&[("x-forwarded-for", "203.0.113.1, junk, 198.51.100.4")]);
        assert_eq!(
            client_ip(ip("127.0.0.1"), &crafted, &proxies()),
            ip("198.51.100.4")
        );
        let junk_last = headers(&[("x-forwarded-for", "203.0.113.1, junk")]);
        assert_eq!(
            client_ip(ip("10.0.0.1"), &junk_last, &proxies()),
            ip("10.0.0.1")
        );
    }
}
