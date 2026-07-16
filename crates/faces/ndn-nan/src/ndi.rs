//! The **NAN Data Interface** (NDI): the netdev a negotiated data path carries
//! traffic over.
//!
//! The M1–M4 handshake in `ndn-nan-core` settles *which addresses* a data path
//! uses — each side's data-interface MAC and the modified EUI-64 the peer forms
//! `fe80::<iid>` from. This module is what makes those addresses real: a TAP
//! device whose MAC **is** our NDI, so the kernel gives it exactly the link-local
//! address we advertised, and ordinary sockets can then talk over it.
//!
//! ```text
//!   application  ──socket──▶  nan0 (TAP, mac = our NDI, fe80::<our iid>)
//!                                │  Ethernet frames
//!                                ▼
//!                          [ this module ]
//!                                │  802.11 data frames (addr1 = peer NDI)
//!                                ▼
//!                          FrameIo (monitor radio)  ──▶ air
//! ```
//!
//! A kernel/firmware NAN stack does this conversion in the device. A userspace
//! monitor-mode stack has to do it here: on the air a data path is 802.11 data
//! frames between NDIs, and the kernel's IP stack wants Ethernet.

/// `dst(6) | src(6) | ethertype(2)`.
pub const ETHERNET_HEADER_LEN: usize = 14;
/// A non-QoS 802.11 data header: `fc(2) dur(2) addr1(6) addr2(6) addr3(6) seq(2)`.
const DOT11_HEADER_LEN: usize = 24;
/// QoS data frames carry two more bytes of QoS control.
const QOS_CONTROL_LEN: usize = 2;
/// `AA AA 03 00 00 00` then a 2-byte EtherType.
const LLC_SNAP_PREFIX: [u8; 6] = [0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00];
const LLC_SNAP_LEN: usize = 8;

/// 802.11 frame type 2 = Data.
const FRAME_TYPE_DATA: u8 = 2;

/// Is this the first byte of a data frame's frame-control field?
fn is_data(fc0: u8) -> bool {
    (fc0 >> 2) & 0x03 == FRAME_TYPE_DATA
}

/// Header length implied by the frame-control subtype (QoS data carries 2 more).
fn dot11_header_len(fc0: u8) -> usize {
    let subtype = (fc0 >> 4) & 0x0f;
    if subtype & 0x08 != 0 {
        DOT11_HEADER_LEN + QOS_CONTROL_LEN
    } else {
        DOT11_HEADER_LEN
    }
}

fn mac_at(buf: &[u8], off: usize) -> [u8; 6] {
    let mut m = [0u8; 6];
    m.copy_from_slice(&buf[off..off + 6]);
    m
}

/// An Ethernet frame off the NDI → the 802.11 data frame to put on the air.
///
/// The TAP's MAC is our NDI, so the Ethernet source already *is* our NDI and is
/// carried through as addr2. `addr3` is the cluster id — a data path lives inside
/// the cluster whose timeline it was negotiated on.
///
/// Returns `None` for a frame too short to be Ethernet.
pub fn eth_to_dot11(eth: &[u8], cluster_id: [u8; 6], seq: u16) -> Option<Vec<u8>> {
    if eth.len() < ETHERNET_HEADER_LEN {
        return None;
    }
    let dst = mac_at(eth, 0);
    let src = mac_at(eth, 6);
    let ethertype = &eth[12..14];
    let payload = &eth[ETHERNET_HEADER_LEN..];

    let mut out = Vec::with_capacity(DOT11_HEADER_LEN + LLC_SNAP_LEN + payload.len());
    out.extend_from_slice(&[0x08, 0x00]); // FC: type=Data, subtype=0, ToDS=FromDS=0
    out.extend_from_slice(&[0x00, 0x00]); // Duration
    out.extend_from_slice(&dst); // addr1 = receiver (the peer's NDI)
    out.extend_from_slice(&src); // addr2 = transmitter (our NDI)
    out.extend_from_slice(&cluster_id); // addr3 = BSSID (the NAN cluster)
    out.extend_from_slice(&(seq << 4).to_le_bytes()); // SeqCtrl (frag = 0)
    out.extend_from_slice(&LLC_SNAP_PREFIX);
    out.extend_from_slice(ethertype);
    out.extend_from_slice(payload);
    Some(out)
}

/// An 802.11 data frame off the air → the Ethernet frame to hand the NDI.
///
/// Returns `None` unless this is a data frame carrying LLC/SNAP and addressed to
/// `our_ndi` (or to a group) — a monitor radio hears the whole channel, so
/// everything else is another node's traffic and must not be injected into our
/// kernel's IP stack.
pub fn dot11_to_eth(frame: &[u8], our_ndi: [u8; 6]) -> Option<Vec<u8>> {
    if frame.len() < DOT11_HEADER_LEN || !is_data(frame[0]) {
        return None;
    }
    // ToDS/FromDS select a 4-address (mesh/AP-bridged) layout. A NAN data path is
    // neither, so anything with them set is not ours to interpret.
    if frame[1] & 0x03 != 0 {
        return None;
    }
    let hdr = dot11_header_len(frame[0]);
    if frame.len() < hdr + LLC_SNAP_LEN {
        return None;
    }
    let dst = mac_at(frame, 4); // addr1
    let src = mac_at(frame, 10); // addr2
    let is_group = dst[0] & 0x01 != 0;
    if dst != our_ndi && !is_group {
        return None;
    }
    // Frames we transmitted ourselves (a half-duplex radio's echo, or loopback).
    if src == our_ndi {
        return None;
    }
    if frame[hdr..hdr + 6] != LLC_SNAP_PREFIX {
        return None;
    }
    let ethertype = &frame[hdr + 6..hdr + LLC_SNAP_LEN];
    let payload = &frame[hdr + LLC_SNAP_LEN..];

    let mut out = Vec::with_capacity(ETHERNET_HEADER_LEN + payload.len());
    out.extend_from_slice(&dst);
    out.extend_from_slice(&src);
    out.extend_from_slice(ethertype);
    out.extend_from_slice(payload);
    Some(out)
}

/// The IPv6 link-local address the kernel will give an interface whose MAC is
/// `mac` — i.e. `fe80::<modified EUI-64>`. This must equal what NDPE advertised,
/// or the peer addresses a host that does not exist.
pub fn link_local_addr(iid: [u8; 8]) -> std::net::Ipv6Addr {
    let mut octets = [0u8; 16];
    octets[0] = 0xfe;
    octets[1] = 0x80;
    octets[8..].copy_from_slice(&iid);
    std::net::Ipv6Addr::from(octets)
}

#[cfg(target_os = "linux")]
pub use linux::NdiInterface;

/// Creating a netdev and setting its hardware address is `ioctl` work: there is
/// no safe Rust API for `TUNSETIFF` / `SIOCSIFHWADDR`, and no crate wraps them in
/// the shape this needs (a TAP whose MAC we choose *before* the link comes up).
/// The workspace denies `unsafe_code` precisely so an OS-I/O leaf like this opts
/// back in deliberately, scoped to the syscalls and nothing else.
///
/// Linux-only: macOS has no TAP without a kext, and this is the same platform the
/// rest of the monitor-mode stack (AF_PACKET, the USB drivers) targets.
#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
mod linux {
    use super::*;
    use ndn_transport::FaceError;
    use std::os::unix::io::RawFd;

    /// `ioctl`'s request argument is `c_int` on musl but `c_ulong` on glibc, and
    /// this stack ships static musl binaries to the test rigs while building
    /// against glibc elsewhere. Naming the type once keeps both honest.
    #[cfg(target_env = "musl")]
    type IoctlReq = libc::c_int;
    #[cfg(not(target_env = "musl"))]
    type IoctlReq = libc::c_ulong;

    const IFF_TAP: libc::c_short = 0x0002;
    /// Hand us bare Ethernet frames — no 4-byte packet-info prefix.
    const IFF_NO_PI: libc::c_short = 0x1000;
    const TUNSETIFF: IoctlReq = 0x4004_54ca;
    const SIOCSIFHWADDR: IoctlReq = 0x8924;
    const SIOCGIFFLAGS: IoctlReq = 0x8913;
    const SIOCSIFFLAGS: IoctlReq = 0x8914;
    const ARPHRD_ETHER: libc::c_ushort = 1;

    /// Generate the IPv6 link-local from the MAC (RFC 4291 modified EUI-64).
    ///
    /// The kernel default is often `stable_privacy`, which would give the
    /// interface a *random-looking* link-local — not the EUI-64 one we advertised
    /// in NDPE. The peer would then send to an address we never had, and the data
    /// path would silently carry nothing.
    const ADDR_GEN_MODE_EUI64: &str = "0";

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct IfReq {
        name: [libc::c_char; libc::IFNAMSIZ],
        union_data: [u8; 24],
    }

    impl IfReq {
        fn new(name: &str) -> Result<Self, FaceError> {
            let mut req = Self {
                name: [0; libc::IFNAMSIZ],
                union_data: [0; 24],
            };
            if name.len() >= libc::IFNAMSIZ {
                return Err(err(format!("interface name '{name}' too long")));
            }
            for (i, b) in name.as_bytes().iter().enumerate() {
                req.name[i] = *b as libc::c_char;
            }
            Ok(req)
        }
    }

    fn err(msg: String) -> FaceError {
        FaceError::Io(std::io::Error::other(msg))
    }

    fn last_err(what: &str) -> FaceError {
        FaceError::Io(std::io::Error::new(
            std::io::Error::last_os_error().kind(),
            format!("{what}: {}", std::io::Error::last_os_error()),
        ))
    }

    /// A TAP device standing in for a NAN Data Interface.
    ///
    /// Needs `CAP_NET_ADMIN` (run as root): it creates a netdev and sets its MAC.
    pub struct NdiInterface {
        fd: RawFd,
        name: String,
        mac: [u8; 6],
    }

    impl NdiInterface {
        /// Create `name` as a TAP device with hardware address `mac` (our NDI) and
        /// bring it up.
        ///
        /// Order matters: the MAC and the address-generation mode must both be set
        /// *before* the link comes up, because that is when the kernel derives the
        /// IPv6 link-local address from them.
        pub fn open(name: &str, mac: [u8; 6]) -> Result<Self, FaceError> {
            let fd = unsafe { libc::open(c"/dev/net/tun".as_ptr(), libc::O_RDWR) };
            if fd < 0 {
                return Err(last_err("open /dev/net/tun (is the tun module loaded?)"));
            }
            let me = Self {
                fd,
                name: name.to_string(),
                mac,
            };

            let mut req = IfReq::new(name)?;
            let flags = (IFF_TAP | IFF_NO_PI).to_ne_bytes();
            req.union_data[..2].copy_from_slice(&flags);
            if unsafe { libc::ioctl(fd, TUNSETIFF, &mut req) } < 0 {
                return Err(last_err("TUNSETIFF (need CAP_NET_ADMIN)"));
            }

            me.set_mac(mac)?;
            // Before `up`: the link-local is generated at that moment.
            me.set_addr_gen_mode_eui64()?;
            me.set_up()?;
            Ok(me)
        }

        /// A control socket for the SIOC* ioctls (they need a socket, not the TAP).
        fn ctl_socket() -> Result<RawFd, FaceError> {
            let s = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
            if s < 0 {
                return Err(last_err("socket(AF_INET) for interface control"));
            }
            Ok(s)
        }

        fn set_mac(&self, mac: [u8; 6]) -> Result<(), FaceError> {
            let s = Self::ctl_socket()?;
            let mut req = IfReq::new(&self.name)?;
            // struct sockaddr: family(2) then the address bytes.
            req.union_data[..2].copy_from_slice(&ARPHRD_ETHER.to_ne_bytes());
            req.union_data[2..8].copy_from_slice(&mac);
            let rc = unsafe { libc::ioctl(s, SIOCSIFHWADDR, &mut req) };
            unsafe { libc::close(s) };
            if rc < 0 {
                return Err(last_err("SIOCSIFHWADDR (set NDI mac)"));
            }
            Ok(())
        }

        fn set_addr_gen_mode_eui64(&self) -> Result<(), FaceError> {
            let path = format!("/proc/sys/net/ipv6/conf/{}/addr_gen_mode", self.name);
            std::fs::write(&path, ADDR_GEN_MODE_EUI64).map_err(|e| {
                err(format!(
                    "write {path}: {e} — without EUI-64 generation the kernel's \
                     link-local will not match the interface identifier NDPE advertised"
                ))
            })
        }

        fn set_up(&self) -> Result<(), FaceError> {
            let s = Self::ctl_socket()?;
            let mut req = IfReq::new(&self.name)?;
            if unsafe { libc::ioctl(s, SIOCGIFFLAGS, &mut req) } < 0 {
                unsafe { libc::close(s) };
                return Err(last_err("SIOCGIFFLAGS"));
            }
            let mut flags = libc::c_short::from_ne_bytes([req.union_data[0], req.union_data[1]]);
            flags |= libc::IFF_UP as libc::c_short | libc::IFF_RUNNING as libc::c_short;
            req.union_data[..2].copy_from_slice(&flags.to_ne_bytes());
            let rc = unsafe { libc::ioctl(s, SIOCSIFFLAGS, &mut req) };
            unsafe { libc::close(s) };
            if rc < 0 {
                return Err(last_err("SIOCSIFFLAGS (bring NDI up)"));
            }
            Ok(())
        }

        pub fn name(&self) -> &str {
            &self.name
        }

        pub fn mac(&self) -> [u8; 6] {
            self.mac
        }

        /// The link-local address the kernel derived — what a peer reaches us at.
        pub fn link_local(&self) -> std::net::Ipv6Addr {
            link_local_addr(ndn_nan_core::eui64_iid(self.mac))
        }

        pub fn as_raw_fd(&self) -> RawFd {
            self.fd
        }

        /// Read one Ethernet frame from the interface (blocking).
        pub fn read_frame(&self, buf: &mut [u8]) -> std::io::Result<usize> {
            let n = unsafe { libc::read(self.fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
            if n < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(n as usize)
        }

        /// Write one Ethernet frame to the interface.
        pub fn write_frame(&self, buf: &[u8]) -> std::io::Result<usize> {
            let n = unsafe { libc::write(self.fd, buf.as_ptr() as *const libc::c_void, buf.len()) };
            if n < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(n as usize)
        }
    }

    impl Drop for NdiInterface {
        fn drop(&mut self) {
            // The netdev disappears with its last fd.
            unsafe { libc::close(self.fd) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OUR_NDI: [u8; 6] = [0x02, 0xaa, 0xaa, 0x00, 0x00, 0x01];
    const PEER_NDI: [u8; 6] = [0x02, 0xbb, 0xbb, 0x00, 0x00, 0x02];
    const CLUSTER: [u8; 6] = [0x50, 0x6f, 0x9a, 0x01, 0x00, 0x00];
    const IPV6: [u8; 2] = [0x86, 0xdd];

    fn eth(dst: [u8; 6], src: [u8; 6], payload: &[u8]) -> Vec<u8> {
        let mut e = Vec::new();
        e.extend_from_slice(&dst);
        e.extend_from_slice(&src);
        e.extend_from_slice(&IPV6);
        e.extend_from_slice(payload);
        e
    }

    /// A frame the kernel hands us must come back off the air unchanged — this is
    /// the whole job of the interface.
    #[test]
    fn ethernet_survives_a_round_trip_through_the_air() {
        let out = eth(PEER_NDI, OUR_NDI, b"an ipv6 packet");
        let air = eth_to_dot11(&out, CLUSTER, 3).unwrap();

        // Addressing the peer must actually pick out the peer.
        assert_eq!(&air[4..10], &PEER_NDI, "addr1 = the peer's NDI");
        assert_eq!(&air[10..16], &OUR_NDI, "addr2 = our NDI");
        assert_eq!(&air[16..22], &CLUSTER, "addr3 = the cluster, not the peer");
        assert!(is_data(air[0]));

        // The peer's side converts it back to exactly what we sent.
        let back = dot11_to_eth(&air, PEER_NDI).unwrap();
        assert_eq!(back, out);
    }

    /// A monitor radio hears the whole channel. Handing another node's traffic to
    /// our kernel would be both wrong and a way to leak frames between nodes.
    #[test]
    fn traffic_for_other_hosts_is_not_delivered() {
        const OTHER: [u8; 6] = [0x02, 0xcc, 0xcc, 0x00, 0x00, 0x03];
        let air = eth_to_dot11(&eth(OTHER, PEER_NDI, b"not yours"), CLUSTER, 1).unwrap();
        assert!(dot11_to_eth(&air, OUR_NDI).is_none());

        // But a group address is for everyone (IPv6 relies on multicast for ND).
        let mcast = [0x33, 0x33, 0x00, 0x00, 0x00, 0x01];
        let air = eth_to_dot11(&eth(mcast, PEER_NDI, b"hello all"), CLUSTER, 1).unwrap();
        assert!(dot11_to_eth(&air, OUR_NDI).is_some());
    }

    /// Our own transmissions come back on a half-duplex radio / loopback bus.
    /// Delivering them would make the kernel see its own packets arriving.
    #[test]
    fn our_own_echo_is_not_delivered() {
        let air = eth_to_dot11(&eth(PEER_NDI, OUR_NDI, b"mine"), CLUSTER, 1).unwrap();
        assert!(dot11_to_eth(&air, OUR_NDI).is_none());
    }

    #[test]
    fn non_data_and_malformed_frames_are_rejected() {
        // A NAN action frame (management) is not data-path traffic.
        let mut mgmt = eth_to_dot11(&eth(PEER_NDI, OUR_NDI, b"x"), CLUSTER, 1).unwrap();
        mgmt[0] = 0xd0; // management/action
        assert!(dot11_to_eth(&mgmt, PEER_NDI).is_none());

        // Truncated.
        assert!(dot11_to_eth(&[0x08, 0x00], PEER_NDI).is_none());
        assert!(eth_to_dot11(&[0u8; 4], CLUSTER, 0).is_none());

        // Data, addressed to us, but not LLC/SNAP — not something we can hand up.
        let mut no_snap = eth_to_dot11(&eth(PEER_NDI, OUR_NDI, b"x"), CLUSTER, 1).unwrap();
        no_snap[24] = 0x00;
        assert!(dot11_to_eth(&no_snap, PEER_NDI).is_none());

        // A 4-address (ToDS/FromDS) layout is a different frame shape entirely.
        let mut four_addr = eth_to_dot11(&eth(PEER_NDI, OUR_NDI, b"x"), CLUSTER, 1).unwrap();
        four_addr[1] |= 0x03;
        assert!(dot11_to_eth(&four_addr, PEER_NDI).is_none());
    }

    /// QoS data carries two extra header bytes; missing that shifts the payload.
    #[test]
    fn qos_data_frames_are_parsed_at_the_right_offset() {
        let plain = eth_to_dot11(&eth(PEER_NDI, OUR_NDI, b"payload"), CLUSTER, 1).unwrap();
        let mut qos = Vec::new();
        qos.extend_from_slice(&plain[..24]);
        qos[0] = 0x88; // QoS data
        qos.extend_from_slice(&[0x00, 0x00]); // QoS control
        qos.extend_from_slice(&plain[24..]);

        let back = dot11_to_eth(&qos, PEER_NDI).unwrap();
        assert_eq!(back, eth(PEER_NDI, OUR_NDI, b"payload"));
    }

    /// The address a peer computes from our advertised IID must be the address the
    /// kernel actually assigns our interface.
    #[test]
    fn link_local_is_fe80_plus_the_advertised_iid() {
        let iid = ndn_nan_core::eui64_iid(OUR_NDI);
        assert_eq!(
            link_local_addr(iid),
            "fe80::aa:aaff:fe00:1".parse::<std::net::Ipv6Addr>().unwrap()
        );
    }
}
