//! The proxy jump chain (`-J`): the hops of an SSH3 connection dialed
//! through each other.
//!
//! Every hop is an ssh3 server; the QUIC packets of a hop travel as SSH3
//! datagrams of the UDP forwarding channel of the hop before it, so the
//! innermost connection is reached through the whole chain. The packet
//! budget follows the reference implementation: every level of the chain
//! eats [`TUNNEL_DATAGRAM_OVERHEAD`] bytes of the datagram budget of the
//! level below it, so the outermost connection takes a bigger initial
//! packet and the chain is refused when it no longer fits.

use std::net::SocketAddr;

/// The per-level cost of the datagram budget of a tunneled connection: the
/// QUIC packet overhead the transport reserves on every packet plus the
/// SSH3 datagram framing (the conversation id and the channel id varints),
/// rounded up - the `tunnelDatagramOverhead` of the reference.
pub const TUNNEL_DATAGRAM_OVERHEAD: usize = 48;

/// The QUIC minimum: a smaller Initial packet is refused by the protocol
/// (RFC 9000, section 14).
pub const MIN_QUIC_PACKET_SIZE: u16 = 1200;

/// The QUIC maximum packet size (the payload of a 1500-byte MTU path): the
/// outermost connection of a chain takes it at most, so its datagram budget
/// can carry the tunneled packets.
pub const MAX_QUIC_PACKET_SIZE: u16 = 1452;

/// One parsed `-J` destination: the `[user@]host[:port]` form of the ssh(1)
/// canon. IPv6 literals must be bracketed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JumpHop {
    /// The user of the hop, when the destination names one.
    pub user: Option<String>,
    /// The host of the hop.
    pub host: String,
    /// The port of the hop; the ssh3 default of the client (443) applies
    /// when the destination names none.
    pub port: Option<u16>,
}

/// Parses the ssh(1) `-J destination[,destination...]` syntax.
///
/// Every destination keeps its `[user@]host[:port]` form, exactly like the
/// `parseProxyJumpChain` of the reference; an empty destination or one with
/// whitespace is refused before a single packet is sent.
pub fn parse_jump_hops(spec: &str) -> Result<Vec<JumpHop>, String> {
    let mut hops = Vec::new();
    for hop in spec.split(',') {
        let hop = hop.trim();
        if hop.is_empty() {
            return Err(format!(
                "invalid -J specification {spec:?}: empty destination"
            ));
        }
        if hop.contains([' ', '\t']) {
            return Err(format!("invalid -J destination {hop:?} in {spec:?}"));
        }
        hops.push(parse_hop(hop, spec)?);
    }
    if hops.is_empty() {
        return Err(format!("invalid -J specification {spec:?}: no destination"));
    }
    Ok(hops)
}

/// Parses one `[user@]host[:port]` destination.
fn parse_hop(hop: &str, spec: &str) -> Result<JumpHop, String> {
    let (user, rest) = match hop.split_once('@') {
        Some((user, rest)) => (Some(user.to_string()), rest),
        None => (None, hop),
    };
    // A bracketed IPv6 literal carries no port separator of its own.
    if let Some(rest) = rest.strip_prefix('[') {
        let Some((host, port)) = rest.split_once(']') else {
            return Err(format!("invalid -J destination {hop:?} in {spec:?}"));
        };
        let port = match port.strip_prefix(':') {
            Some(port) => Some(
                port.parse::<u16>()
                    .map_err(|_| format!("invalid -J destination {hop:?} in {spec:?}"))?,
            ),
            None if port.is_empty() => None,
            None => return Err(format!("invalid -J destination {hop:?} in {spec:?}")),
        };
        return Ok(JumpHop {
            user,
            host: host.to_string(),
            port,
        });
    }
    // The last colon of a host without brackets separates the port; a host
    // that still contains a colon is a bare IPv6 literal.
    match rest.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') => Ok(JumpHop {
            user,
            host: host.to_string(),
            port: Some(
                port.parse::<u16>()
                    .map_err(|_| format!("invalid -J destination {hop:?} in {spec:?}"))?,
            ),
        }),
        _ => Ok(JumpHop {
            user,
            host: rest.to_string(),
            port: None,
        }),
    }
}

/// Returns the initial QUIC packet size of the outermost connection of a
/// chain of the given depth: every level eats its overhead of the datagram
/// budget of the level below, so the outermost connection takes a bigger
/// packet. The size is capped at the QUIC maximum, so a chain that does not
/// fit is refused instead of silently breaking - the `tunnelOuterSize` of
/// the reference.
pub fn tunnel_outer_size(base_size: u16, tunnel_depth: usize) -> u16 {
    let outer = base_size as usize + tunnel_depth * TUNNEL_DATAGRAM_OVERHEAD;
    outer.min(MAX_QUIC_PACKET_SIZE as usize) as u16
}

/// Returns the initial QUIC packet size of the connection at the given
/// level of the chain (level 0 is the outermost one, the level of the
/// destination is the number of hops) - the `tunneledPacketSize` of the
/// reference.
pub fn tunneled_packet_size(outer_size: u16, level: usize) -> Result<u16, String> {
    let size = outer_size as isize - level as isize * TUNNEL_DATAGRAM_OVERHEAD as isize;
    if size < MIN_QUIC_PACKET_SIZE as isize {
        return Err(format!(
            "the proxy jump chain is too long for the QUIC datagram budget: {level} levels need more than the {MIN_QUIC_PACKET_SIZE}-byte minimum packet size"
        ));
    }
    Ok(size as u16)
}

/// Resolves the address a hop of the chain is dialed at: the port defaults
/// to the ssh3 port of the client.
pub async fn resolve_hop_addr(host: &str, port: Option<u16>) -> std::io::Result<SocketAddr> {
    let port = port.unwrap_or(443);
    if let Ok(address) = host.parse::<SocketAddr>() {
        return Ok(address);
    }
    tokio::net::lookup_host((host, port))
        .await?
        .next()
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::AddrNotAvailable,
                "the hop did not resolve to an address",
            )
        })
}

#[cfg(test)]
mod tests {
    use super::{
        MAX_QUIC_PACKET_SIZE, TUNNEL_DATAGRAM_OVERHEAD, parse_jump_hops, tunnel_outer_size,
        tunneled_packet_size,
    };

    /// The chain parses the way the ssh(1) canon and the reference parser
    /// accept it (`TestParseProxyJumpChain` of the reference).
    #[test]
    fn the_chain_parses() {
        let hops = parse_jump_hops("jump.example.org").unwrap();
        assert_eq!(hops.len(), 1);
        assert_eq!(hops[0].host, "jump.example.org");
        assert_eq!(hops[0].user, None);
        assert_eq!(hops[0].port, None);

        let hops =
            parse_jump_hops("user@jump.example.org:443,hop2,alice@[2001:db8::5]:8443").unwrap();
        assert_eq!(hops.len(), 3);
        assert_eq!(hops[0].user.as_deref(), Some("user"));
        assert_eq!(hops[0].port, Some(443));
        assert_eq!(hops[1].host, "hop2");
        assert_eq!(hops[2].host, "2001:db8::5");
        assert_eq!(hops[2].port, Some(8443));

        // A bare IPv6 literal carries no port.
        let hops = parse_jump_hops("2001:db8::1").unwrap();
        assert_eq!(hops[0].host, "2001:db8::1");
        assert_eq!(hops[0].port, None);
    }

    /// A broken chain costs a process start and nothing else.
    #[test]
    fn a_broken_chain_is_refused() {
        assert!(parse_jump_hops("").is_err());
        assert!(parse_jump_hops("a,,b").is_err());
        assert!(parse_jump_hops("a b").is_err());
        assert!(parse_jump_hops("host:notaport").is_err());
        assert!(parse_jump_hops("[2001:db8::5").is_err());
    }

    /// The packet budget follows the reference: 48 bytes per level, capped
    /// at the QUIC maximum, refused under the QUIC minimum
    /// (`TestTunnelPacketBudget` of the reference).
    #[test]
    fn the_packet_budget_follows_the_reference() {
        assert_eq!(TUNNEL_DATAGRAM_OVERHEAD, 48);
        // The outer size grows by the overhead of every level, capped.
        assert_eq!(tunnel_outer_size(1200, 0), 1200);
        assert_eq!(tunnel_outer_size(1200, 1), 1200 + 48);
        assert_eq!(tunnel_outer_size(1200, 5), 1200 + 5 * 48);
        // A base at the maximum never grows.
        assert_eq!(tunnel_outer_size(1452, 3), 1452);

        // The level size shrinks by the overhead of the levels above it.
        assert_eq!(tunneled_packet_size(1296, 1).unwrap(), 1248);
        assert_eq!(tunneled_packet_size(1344, 3).unwrap(), 1200);
        // A chain that does not fit is refused.
        assert!(tunneled_packet_size(1248, 2).is_err());
        assert!(tunneled_packet_size(MAX_QUIC_PACKET_SIZE, 6).is_err());
        // The deepest working chain of the maximum outer size.
        assert_eq!(tunneled_packet_size(MAX_QUIC_PACKET_SIZE, 5).unwrap(), 1212);
    }
}
