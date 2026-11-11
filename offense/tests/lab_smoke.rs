//! Real-lab smoke tests for the offense eBPF object.
//!
//! All tests here are `#[ignore]`d and run through `scripts/offense_smoke.sh`
//! in a privileged, disposable environment. They exercise what the passive
//! defense smoke tests deliberately avoid: loading offensive probes, attaching
//! them to real kernel hooks, pushing crafted traffic through the kernel
//! networking datapath, and decoding events from the real BPF ring buffer.
//! No radio hardware or RF transmission is involved; every packet stays on a
//! cabled-free veth pair inside the host.

use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{ensure, Context, Result};
use aya::maps::{Array, HashMap, RingBuf};
use aya::programs::XdpFlags;
use common::{
    EventHeader, GtpTunnelState, EVENT_GTP_TUNNEL_HIJACK, EVENT_PROTOCOL_DOWNGRADE,
    EVENT_RRC_REDIRECT,
};
use staticzero_offense::decode_event;

const TEID: u32 = 0x1122_3344;
const ETH_P_ALL: u16 = 0x0003;

fn object_path() -> PathBuf {
    std::env::var_os("STATICZERO_BPF_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../target/bpfel-unknown-none/release/staticzero-offense")
        })
}

async fn collect(
    ring: &mut RingBuf<aya::maps::MapData>,
    duration: Duration,
) -> Result<Vec<EventHeader>> {
    let deadline = Instant::now() + duration;
    let mut events = Vec::new();
    loop {
        while let Some(item) = ring.next() {
            events.push(decode_event(&item)?);
        }
        if Instant::now() >= deadline {
            return Ok(events);
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

fn temp_dir() -> Result<PathBuf> {
    let base = if Path::new("/tmp/opencode").is_dir() {
        PathBuf::from("/tmp/opencode")
    } else {
        std::env::temp_dir()
    };
    let dir = base.join(format!(
        "sz-offense-{}-{}",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
    ));
    std::fs::create_dir(&dir)?;
    Ok(dir)
}

// ─────────────────────────────────────────────────────────────────────────────
// Offensive kprobe smoke test
//
// `shadow_rrc_redirect` treats kprobe arg0 as a configured redirect target
// (ARFCN) and consults the DOWNGRADE_TARGETS map. `fd_install(unsigned int fd,
// struct file *)` takes the file descriptor as arg0, so programming the map
// with a predictable fd and opening a file gives a deterministic, SMAP-safe
// kernel-resident trigger: no user-memory reads are involved.
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
#[ignore = "requires the offense eBPF object, kprobe PMU, and BPF/perf privileges in an isolated VM"]
async fn privileged_offense_kprobe_smoke() -> Result<()> {
    let dir = temp_dir()?;
    let mut bpf = aya::BpfLoader::new().load_file(object_path())?;
    let mut ring = RingBuf::try_from(bpf.take_map("EVENTS").context("EVENTS map missing")?)?;

    // Predict which fd the next open() will install: occupy it, release it,
    // and the kernel hands the same number to the next allocation.
    let probe_file = dir.join("fd-probe");
    std::fs::write(&probe_file, b"fd probe")?;
    let taken = std::fs::File::open(&probe_file)?;
    let predicted_fd = AsRawFd::as_raw_fd(&taken) as u32;
    drop(taken);

    HashMap::<_, u32, u8>::try_from(
        bpf.map_mut("DOWNGRADE_TARGETS")
            .context("DOWNGRADE_TARGETS map missing")?,
    )?
    .insert(predicted_fd, 1, 0)?;

    // Negative control first: a documented hook point that is not a mainline
    // kernel symbol must fail to attach rather than silently succeed.
    let missing = staticzero_offense::attach_kprobe_all_cpus(
        &mut bpf,
        "shadow_at_cmd_inject",
        "sdr_rx_callback",
    );
    ensure!(
        missing.is_err(),
        "attach to nonexistent symbol sdr_rx_callback unexpectedly succeeded"
    );

    let attachment =
        staticzero_offense::attach_kprobe_all_cpus(&mut bpf, "shadow_rrc_redirect", "fd_install")
            .context("attaching shadow_rrc_redirect to fd_install")?;
    ensure!(!attachment.is_empty(), "no per-CPU perf events attached");

    // Trigger: any open() installs the predicted fd via fd_install.
    let trigger = std::fs::File::create(dir.join("trigger"))?;
    drop(trigger);

    let events = collect(&mut ring, Duration::from_secs(1)).await?;
    let matching: Vec<_> = events
        .iter()
        .filter(|event| {
            event.event_type == EVENT_RRC_REDIRECT
                && event.pid == std::process::id()
                && event.context == predicted_fd as u64
        })
        .collect();
    ensure!(
        matching.len() == 1,
        "expected exactly one EVENT_RRC_REDIRECT (pid={}, context={}), got {} of {} event(s)",
        std::process::id(),
        predicted_fd,
        matching.len(),
        events.len()
    );
    ensure!(matching[0].timestamp_ns > 0);

    drop(attachment);
    drop(ring);
    drop(bpf);
    std::fs::remove_dir_all(&dir).ok();
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Traffic-path (XDP + TC) smoke test
//
// A veth pair carries a crafted GTP-U packet (UDP/2152, known TEID) from one
// end to the other. shadow_gtp_hijack (XDP, ingress) must emit an event with
// the tunnel TEID, shadow_protocol_downgrade (TC clsact ingress) must fire on
// the same packet, and an AF_PACKET socket on the receiving side proves the
// XDP verdict was XDP_PASS: the frame is still delivered.
// ─────────────────────────────────────────────────────────────────────────────

struct Veth {
    tx: String,
    rx: String,
}

impl Veth {
    fn new() -> Result<Self> {
        let suffix = std::process::id() % 100_000;
        let tx = format!("sztx{suffix}");
        let rx = format!("szrx{suffix}");
        run_ip(&["link", "del", &tx]).ok(); // stale leftovers from a failed run

        run_ip(&[
            "link", "add", "name", &tx, "type", "veth", "peer", "name", &rx,
        ])?;
        // Suppress interface-local IPv6 noise (router solicitations would
        // traverse the TC classifier and add unrelated events).
        for iface in [&tx, &rx] {
            let _ = Command::new("sysctl")
                .args(["-q", "-w", &format!("net.ipv6.conf.{iface}.disable_ipv6=1")])
                .status();
        }
        run_ip(&["link", "set", "dev", &tx, "up"])?;
        run_ip(&["link", "set", "dev", &rx, "up"])?;
        run_ip(&["link", "set", "dev", &rx, "promisc", "on"])?;
        // 192.0.2.0/24 and 198.51.100.0/24 are TEST-NET ranges (RFC 5737).
        run_ip(&["addr", "add", "192.0.2.1/30", "dev", &tx])?;
        run_ip(&["route", "add", "198.51.100.0/30", "dev", &tx])?;
        Ok(Self { tx, rx })
    }
}

impl Drop for Veth {
    fn drop(&mut self) {
        run_ip(&["link", "del", &self.tx]).ok();
    }
}

fn run_ip(args: &[&str]) -> Result<()> {
    let status = Command::new("ip")
        .args(args)
        .status()
        .with_context(|| format!("failed to execute ip {}", args.join(" ")))?;
    ensure!(
        status.success(),
        "ip {} failed with {status}",
        args.join(" ")
    );
    Ok(())
}

fn interface_mac(name: &str) -> Result<[u8; 6]> {
    let text = std::fs::read_to_string(format!("/sys/class/net/{name}/address"))
        .with_context(|| format!("reading MAC of {name}"))?;
    let octets: Result<Vec<u8>> = text
        .trim()
        .split(':')
        .map(|part| u8::from_str_radix(part, 16).with_context(|| format!("bad MAC {text:?}")))
        .collect();
    let octets = octets?;
    ensure!(octets.len() == 6, "bad MAC {text:?}");
    Ok(octets.try_into().unwrap())
}

fn if_index(name: &str) -> Result<libc::c_int> {
    let c_name = std::ffi::CString::new(name)?;
    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    for (i, b) in c_name.as_bytes().iter().enumerate() {
        ifr.ifr_name[i] = *b as libc::c_char;
    }
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    ensure!(fd >= 0, "socket for SIOCGIFINDEX failed");
    let rc = unsafe { libc::ioctl(fd, libc::SIOCGIFINDEX, &ifr) };
    let index = unsafe { ifr.ifr_ifru.ifru_ifindex };
    unsafe { libc::close(fd) };
    ensure!(rc == 0, "SIOCGIFINDEX for {name} failed");
    Ok(index)
}

fn packet_socket() -> Result<libc::c_int> {
    let fd = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW,
            ETH_P_ALL.to_be() as libc::c_int,
        )
    };
    ensure!(
        fd >= 0,
        "AF_PACKET socket failed: {}",
        std::io::Error::last_os_error()
    );
    Ok(fd)
}

fn bind_packet_socket(fd: libc::c_int, ifindex: libc::c_int) -> Result<()> {
    let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    addr.sll_family = libc::AF_PACKET as u16;
    addr.sll_protocol = ETH_P_ALL.to_be();
    addr.sll_ifindex = ifindex;
    let rc = unsafe {
        libc::bind(
            fd,
            &addr as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    };
    ensure!(
        rc == 0,
        "bind AF_PACKET failed: {}",
        std::io::Error::last_os_error()
    );
    Ok(())
}

fn set_recv_timeout(fd: libc::c_int, seconds: libc::time_t) -> Result<()> {
    let tv = libc::timeval {
        tv_sec: seconds,
        tv_usec: 0,
    };
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &tv as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        )
    };
    ensure!(rc == 0, "SO_RCVTIMEO failed");
    Ok(())
}

fn ip_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for chunk in header.as_chunks::<2>().0 {
        sum += u16::from_be_bytes(*chunk) as u32;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// Ethernet + IPv4 + UDP(2152) + GTP-U header carrying the test TEID, plus a
/// recognizable payload tail.
fn build_gtp_frame(dst_mac: [u8; 6], src_mac: [u8; 6]) -> Vec<u8> {
    const GTP_PAYLOAD: [u8; 16] = [0xA5; 16];
    let udp_len = 8 + 8 + GTP_PAYLOAD.len();
    let ip_len = 20 + udp_len;

    let mut frame = Vec::with_capacity(14 + ip_len);
    frame.extend_from_slice(&dst_mac);
    frame.extend_from_slice(&src_mac);
    frame.extend_from_slice(&[0x08, 0x00]); // EtherType: IPv4

    let mut ip = vec![0u8; 20];
    ip[0] = 0x45; // IPv4, IHL 5
    ip[2..4].copy_from_slice(&(ip_len as u16).to_be_bytes());
    ip[4..6].copy_from_slice(&0x1234u16.to_be_bytes());
    ip[8] = 64; // TTL
    ip[9] = 17; // UDP
    ip[12..16].copy_from_slice(&[192, 0, 2, 1]);
    ip[16..20].copy_from_slice(&[198, 51, 100, 1]);
    let checksum = ip_checksum(&ip).to_be_bytes();
    ip[10..12].copy_from_slice(&checksum);
    frame.extend_from_slice(&ip);

    frame.extend_from_slice(&50123u16.to_be_bytes()); // source port
    frame.extend_from_slice(&2152u16.to_be_bytes()); // GTP-U
    frame.extend_from_slice(&(udp_len as u16).to_be_bytes());
    frame.extend_from_slice(&[0, 0]); // UDP checksum 0 (legal)

    frame.extend_from_slice(&[0x30, 0xFF]); // GTP flags, message type
    frame.extend_from_slice(&(GTP_PAYLOAD.len() as u16).to_be_bytes());
    frame.extend_from_slice(&TEID.to_be_bytes());
    frame.extend_from_slice(&GTP_PAYLOAD);
    frame
}

fn send_frame(fd: libc::c_int, ifindex: libc::c_int, dst_mac: [u8; 6], frame: &[u8]) -> Result<()> {
    let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    addr.sll_family = libc::AF_PACKET as u16;
    addr.sll_protocol = ETH_P_ALL.to_be();
    addr.sll_ifindex = ifindex;
    addr.sll_halen = 6;
    addr.sll_addr[..6].copy_from_slice(&dst_mac);
    let sent = unsafe {
        libc::sendto(
            fd,
            frame.as_ptr() as *const libc::c_void,
            frame.len(),
            0,
            &addr as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    };
    ensure!(
        sent == frame.len() as libc::ssize_t,
        "sendto sent {sent} of {} bytes: {}",
        frame.len(),
        std::io::Error::last_os_error()
    );
    Ok(())
}

fn recv_frame(fd: libc::c_int, buffer: &mut [u8]) -> Result<usize> {
    let received = unsafe {
        libc::recv(
            fd,
            buffer.as_mut_ptr() as *mut libc::c_void,
            buffer.len(),
            0,
        )
    };
    ensure!(
        received >= 0,
        "recv failed: {}",
        std::io::Error::last_os_error()
    );
    Ok(received as usize)
}

/// Newtype so the test can satisfy aya's `Pod` bound for map values.
/// `GtpTunnelState` is `#[repr(C)]` `Clone + Copy` with only integer fields;
/// every byte pattern (including internal alignment padding) is valid.
#[repr(C)]
#[derive(Clone, Copy)]
struct GtpTunnelStateValue(GtpTunnelState);

// SAFETY: see above — the type is plain old data with no validity invariants.
unsafe impl aya::Pod for GtpTunnelStateValue {}

#[tokio::test]
#[ignore = "requires the offense eBPF object, root for veth/clsact, and BPF privileges in an isolated VM"]
async fn privileged_offense_xdp_tc_smoke() -> Result<()> {
    let mut bpf = aya::BpfLoader::new().load_file(object_path())?;
    let mut ring = RingBuf::try_from(bpf.take_map("EVENTS").context("EVENTS map missing")?)?;

    // Program the tunnel table with the TEID the crafted packet carries, and
    // arm the downgrade classifier.
    HashMap::<_, u32, GtpTunnelStateValue>::try_from(
        bpf.map_mut("GTP_TUNNEL_STATE")
            .context("GTP_TUNNEL_STATE map missing")?,
    )?
    .insert(
        TEID,
        GtpTunnelStateValue(GtpTunnelState {
            teid_in: TEID,
            teid_out: 0x5566_7788,
            peer_ip: u32::from_be_bytes([192, 0, 2, 2]),
            local_ip: u32::from_be_bytes([198, 51, 100, 1]),
            qfi: 1,
            state: 1,
            _pad: [0; 2],
            byte_count: 0,
        }),
        0,
    )?;
    Array::<_, u32>::try_from(
        bpf.map_mut("TELECOM_STATE")
            .context("TELECOM_STATE map missing")?,
    )?
    .set(0, 1, 0)?;

    let veth = Veth::new()?;

    let xdp: &mut aya::programs::Xdp = bpf
        .program_mut("shadow_gtp_hijack")
        .context("shadow_gtp_hijack missing from object")?
        .try_into()?;
    xdp.load().context("verifier rejected shadow_gtp_hijack")?;
    xdp.attach(&veth.rx, XdpFlags::SKB_MODE)
        .context("XDP attach failed")?;

    aya::programs::tc::qdisc_add_clsact(&veth.rx).context("adding clsact qdisc failed")?;
    let classifier: &mut aya::programs::SchedClassifier = bpf
        .program_mut("shadow_protocol_downgrade")
        .context("shadow_protocol_downgrade missing from object")?
        .try_into()?;
    classifier
        .load()
        .context("verifier rejected shadow_protocol_downgrade")?;
    classifier
        .attach(&veth.rx, aya::programs::TcAttachType::Ingress)
        .context("TC attach failed")?;

    let rx_index = if_index(&veth.rx)?;
    let tx_index = if_index(&veth.tx)?;
    let tx_socket = packet_socket()?;
    let rx_socket = packet_socket()?;
    bind_packet_socket(rx_socket, rx_index)?;
    set_recv_timeout(rx_socket, 2)?;

    let frame = build_gtp_frame(interface_mac(&veth.rx)?, interface_mac(&veth.tx)?);
    send_frame(tx_socket, tx_index, interface_mac(&veth.rx)?, &frame)?;

    let events = collect(&mut ring, Duration::from_secs(1)).await?;
    let gtp_events: Vec<_> = events
        .iter()
        .filter(|event| event.event_type == EVENT_GTP_TUNNEL_HIJACK)
        .collect();
    ensure!(
        gtp_events.len() == 1,
        "expected exactly one EVENT_GTP_TUNNEL_HIJACK, got {} of {} event(s)",
        gtp_events.len(),
        events.len()
    );
    ensure!(
        gtp_events[0].context == TEID as u64,
        "GTP event carried TEID {:#x}, expected {TEID:#x}",
        gtp_events[0].context
    );
    ensure!(
        events
            .iter()
            .any(|event| event.event_type == EVENT_PROTOCOL_DOWNGRADE),
        "TC classifier did not emit EVENT_PROTOCOL_DOWNGRADE"
    );

    // Delivery proof: XDP_PASS must leave the frame observable on the peer.
    let mut buffer = [0u8; 1500];
    let received = recv_frame(rx_socket, &mut buffer)?;
    ensure!(
        received == frame.len(),
        "received {received} bytes, expected {}",
        frame.len()
    );
    let teid_offset = 14 + 20 + 8 + 4; // eth + IPv4 + UDP + GTP flags/length
    ensure!(
        received >= teid_offset + 4
            && u32::from_be_bytes(buffer[teid_offset..teid_offset + 4].try_into()?) == TEID,
        "delivered frame does not carry the crafted TEID"
    );

    unsafe {
        libc::close(tx_socket);
        libc::close(rx_socket);
    }
    drop(ring);
    drop(bpf); // Detaches TC and XDP before the veth pair is removed.
    drop(veth);
    Ok(())
}
