//! End-to-end test: a real TCP client -> stack A (egress) -> IP packets -> stack
//! B (ingress) -> a real echo server, all over loopback with no privileges and
//! no kernel network interface.
//!
//! Two netstacks are wired back-to-back at the IP layer: every packet A emits
//! is fed to B and vice versa. This exercises the full smoltcp TCP path through
//! the crate in both directions.

use std::ffi::{c_void, CString};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Mutex;
use std::time::Duration;

use lemonade_virtual_netstack::*;

/// Bridges packets emitted by one stack into another stack's inbound queue.
struct Wiring {
    peer: Mutex<Option<*mut NsHandle>>,
}
unsafe impl Send for Wiring {}
unsafe impl Sync for Wiring {}

unsafe extern "C" fn forward_to_peer(ctx: *mut c_void, pkt: *const u8, len: usize) {
    let wiring = &*(ctx as *const Wiring);
    if let Some(peer) = *wiring.peer.lock().unwrap() {
        ns_feed_inbound(peer, pkt, len);
    }
}

fn cs(s: &str) -> CString {
    CString::new(s).unwrap()
}

#[test]
fn tcp_request_response_through_two_stacks() {
    // Real echo server the ingress side bridges to.
    let echo = TcpListener::bind("127.0.0.1:0").unwrap();
    let echo_addr = echo.local_addr().unwrap();
    std::thread::spawn(move || {
        for stream in echo.incoming() {
            let mut stream = match stream {
                Ok(s) => s,
                Err(_) => break,
            };
            std::thread::spawn(move || {
                let mut buf = [0u8; 4096];
                loop {
                    match stream.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            // Echo back uppercased so we can tell it round-tripped.
                            let upper: Vec<u8> =
                                buf[..n].iter().map(|b| b.to_ascii_uppercase()).collect();
                            if stream.write_all(&upper).is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });

    let wiring_a = Box::into_raw(Box::new(Wiring { peer: Mutex::new(None) }));
    let wiring_b = Box::into_raw(Box::new(Wiring { peer: Mutex::new(None) }));

    let stack_a = unsafe { ns_create(1420, 65536, forward_to_peer, wiring_a as *mut c_void) };
    let stack_b = unsafe { ns_create(1420, 65536, forward_to_peer, wiring_b as *mut c_void) };
    assert!(!stack_a.is_null());
    assert!(!stack_b.is_null());

    // Cross-wire: A emits -> B feeds, B emits -> A feeds.
    unsafe {
        *(*wiring_a).peer.lock().unwrap() = Some(stack_b);
        *(*wiring_b).peer.lock().unwrap() = Some(stack_a);
    }

    // Both planes on a shared /8 so each address is on-link to the other.
    let a_ip = cs("10.0.0.1/8");
    let b_ip = cs("10.0.0.2/8");
    unsafe {
        assert_eq!(ns_add_local_ip(stack_a, a_ip.as_ptr()), 0);
        assert_eq!(ns_add_local_ip(stack_b, b_ip.as_ptr()), 0);
    }

    // Ingress on B: virtual 10.0.0.2:80 -> real echo server.
    let target = cs(&format!("tcp:{echo_addr}"));
    let b_vip = cs("10.0.0.2");
    unsafe {
        assert_eq!(ns_add_tcp_forward(stack_b, b_vip.as_ptr(), 80, target.as_ptr()), 0);
    }

    // Egress on A: real loopback listener -> virtual connect to 10.0.0.2:80,
    // sourced from A's own virtual IP.
    let dst_ip = cs("10.0.0.2");
    let src_ip = cs("10.0.0.1");
    let loopback_port = unsafe { ns_add_tcp_egress(stack_a, dst_ip.as_ptr(), 80, src_ip.as_ptr()) };
    assert_ne!(loopback_port, 0, "egress listener failed to bind");

    // Drive a real TCP client through the whole path.
    std::thread::sleep(Duration::from_millis(100));
    let mut client = TcpStream::connect(("127.0.0.1", loopback_port)).unwrap();
    client.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    client.write_all(b"hello virtual world").unwrap();

    let mut response = Vec::new();
    let mut buf = [0u8; 1024];
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while response.len() < b"hello virtual world".len() && std::time::Instant::now() < deadline {
        match client.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => response.extend_from_slice(&buf[..n]),
            Err(_) => break,
        }
    }

    assert_eq!(
        String::from_utf8_lossy(&response),
        "HELLO VIRTUAL WORLD",
        "data did not round-trip through both virtual stacks"
    );

    // Half-close propagation: dropping the client should tear down cleanly.
    drop(client);
    std::thread::sleep(Duration::from_millis(100));

    unsafe {
        ns_destroy(stack_a);
        ns_destroy(stack_b);
        drop(Box::from_raw(wiring_a));
        drop(Box::from_raw(wiring_b));
    }
}

/// A second, larger transfer to exercise multi-segment streaming and the
/// connection lifecycle a few times in a row.
#[test]
fn repeated_connections_and_larger_payload() {
    let echo = TcpListener::bind("127.0.0.1:0").unwrap();
    let echo_addr = echo.local_addr().unwrap();
    std::thread::spawn(move || {
        for stream in echo.incoming() {
            let mut stream = match stream { Ok(s) => s, Err(_) => break };
            std::thread::spawn(move || {
                let mut buf = [0u8; 8192];
                loop {
                    match stream.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => { if stream.write_all(&buf[..n]).is_err() { break; } }
                    }
                }
            });
        }
    });

    let wiring_a = Box::into_raw(Box::new(Wiring { peer: Mutex::new(None) }));
    let wiring_b = Box::into_raw(Box::new(Wiring { peer: Mutex::new(None) }));
    let stack_a = unsafe { ns_create(1420, 65536, forward_to_peer, wiring_a as *mut c_void) };
    let stack_b = unsafe { ns_create(1420, 65536, forward_to_peer, wiring_b as *mut c_void) };
    unsafe {
        *(*wiring_a).peer.lock().unwrap() = Some(stack_b);
        *(*wiring_b).peer.lock().unwrap() = Some(stack_a);
        let a_ip = cs("10.0.0.1/8");
        let b_ip = cs("10.0.0.2/8");
        ns_add_local_ip(stack_a, a_ip.as_ptr());
        ns_add_local_ip(stack_b, b_ip.as_ptr());
        let target = cs(&format!("tcp:{echo_addr}"));
        let b_vip = cs("10.0.0.2");
        ns_add_tcp_forward(stack_b, b_vip.as_ptr(), 80, target.as_ptr());
    }
    let dst_ip = cs("10.0.0.2");
    let src_ip = cs("10.0.0.1");
    let port = unsafe { ns_add_tcp_egress(stack_a, dst_ip.as_ptr(), 80, src_ip.as_ptr()) };
    assert_ne!(port, 0);
    std::thread::sleep(Duration::from_millis(100));

    let payload = vec![b'x'; 200 * 1024]; // exceeds socket buffers -> multi-segment
    for _ in 0..3 {
        let mut client = TcpStream::connect(("127.0.0.1", port)).unwrap();
        client.set_read_timeout(Some(Duration::from_secs(15))).unwrap();
        let writer = {
            let payload = payload.clone();
            let mut c = client.try_clone().unwrap();
            std::thread::spawn(move || {
                c.write_all(&payload).unwrap();
                c.shutdown(std::net::Shutdown::Write).unwrap();
            })
        };
        let mut got = Vec::new();
        let mut buf = [0u8; 16384];
        loop {
            match client.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => got.extend_from_slice(&buf[..n]),
            }
        }
        writer.join().unwrap();
        assert_eq!(got.len(), payload.len(), "echoed payload truncated");
    }

    unsafe {
        ns_destroy(stack_a);
        ns_destroy(stack_b);
        drop(Box::from_raw(wiring_a));
        drop(Box::from_raw(wiring_b));
    }
}

unsafe extern "C" fn discard_packets(_: *mut c_void, _: *const u8, _: usize) {}

/// (vport, bridge port, source ip, source port, opened) as reported.
type IngressEvents = Mutex<Vec<(u16, u16, u32, u16, i32)>>;

unsafe extern "C" fn record_ingress(
    ctx: *mut c_void,
    vport: u16,
    bridge_port: u16,
    src_ip: u32,
    src_port: u16,
    opened: i32,
) {
    let events = &*(ctx as *const IngressEvents);
    events.lock().unwrap().push((vport, bridge_port, src_ip, src_port, opened));
}

// An observed ingress forward reports each accepted connection's virtual
// source, keyed by the loopback port the target sees, before the first byte
// arrives at the target, and reports the connection closed afterwards.
#[test]
fn observed_forward_reports_the_virtual_source_of_each_connection() {
    // The target records the remote port of each connection it accepts and
    // echoes the data back.
    let target = TcpListener::bind("127.0.0.1:0").unwrap();
    let target_addr = target.local_addr().unwrap();
    let accepted: &'static Mutex<Vec<u16>> = Box::leak(Box::new(Mutex::new(Vec::new())));
    std::thread::spawn(move || {
        for stream in target.incoming() {
            let mut stream = match stream { Ok(s) => s, Err(_) => break };
            accepted.lock().unwrap().push(stream.peer_addr().unwrap().port());
            std::thread::spawn(move || {
                let mut buf = [0u8; 4096];
                loop {
                    match stream.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => { if stream.write_all(&buf[..n]).is_err() { break; } }
                    }
                }
            });
        }
    });

    let events = Box::into_raw(Box::new(IngressEvents::new(Vec::new())));
    let wiring_a = Box::into_raw(Box::new(Wiring { peer: Mutex::new(None) }));
    let wiring_b = Box::into_raw(Box::new(Wiring { peer: Mutex::new(None) }));
    let stack_a = unsafe { ns_create(1420, 65536, forward_to_peer, wiring_a as *mut c_void) };
    let stack_b = unsafe { ns_create(1420, 65536, forward_to_peer, wiring_b as *mut c_void) };
    assert!(!stack_a.is_null() && !stack_b.is_null());
    unsafe {
        *(*wiring_a).peer.lock().unwrap() = Some(stack_b);
        *(*wiring_b).peer.lock().unwrap() = Some(stack_a);
        let a_ip = cs("10.0.0.1/8");
        let b_ip = cs("10.0.0.2/8");
        assert_eq!(ns_add_local_ip(stack_a, a_ip.as_ptr()), 0);
        assert_eq!(ns_add_local_ip(stack_b, b_ip.as_ptr()), 0);
        let spec = cs(&format!("tcp:{target_addr}"));
        let b_vip = cs("10.0.0.2");
        assert_eq!(
            ns_add_tcp_forward_observed(stack_b, b_vip.as_ptr(), 80, spec.as_ptr(),
                                        record_ingress, events as *mut c_void),
            0
        );
        assert_eq!(
            ns_add_tcp_forward_observed(std::ptr::null_mut(), b_vip.as_ptr(), 80, spec.as_ptr(),
                                        record_ingress, events as *mut c_void),
            -1
        );
    }
    let dst_ip = cs("10.0.0.2");
    let src_ip = cs("10.0.0.1");
    let port = unsafe { ns_add_tcp_egress(stack_a, dst_ip.as_ptr(), 80, src_ip.as_ptr()) };
    assert_ne!(port, 0);
    std::thread::sleep(Duration::from_millis(100));

    let mut client = TcpStream::connect(("127.0.0.1", port)).unwrap();
    client.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    client.write_all(b"attributed").unwrap();
    let mut got = [0u8; 10];
    client.read_exact(&mut got).unwrap();
    assert_eq!(&got, b"attributed");

    let opened: Vec<_> = unsafe { (*events).lock().unwrap().clone() };
    assert_eq!(opened.len(), 1, "one opened event before the first byte: {opened:?}");
    let (vport, bridge_port, ip, src_port, flag) = opened[0];
    assert_eq!(vport, 80);
    assert_eq!(flag, 1);
    assert_eq!(ip, 0x0A00_0001, "the virtual source is stack A's address");
    assert_ne!(src_port, 0);
    assert_ne!(bridge_port, 0);
    assert_eq!(accepted.lock().unwrap().as_slice(), &[bridge_port],
               "the target sees the reported bridge port as the remote port");

    drop(client);
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let events: Vec<_> = unsafe { (*events).lock().unwrap().clone() };
        if events.len() == 2 {
            assert_eq!(events[1], (80, bridge_port, 0x0A00_0001, src_port, 0));
            break;
        }
        assert!(std::time::Instant::now() < deadline, "no closed event: {events:?}");
        std::thread::sleep(Duration::from_millis(20));
    }

    unsafe {
        ns_destroy(stack_a);
        ns_destroy(stack_b);
        drop(Box::from_raw(wiring_a));
        drop(Box::from_raw(wiring_b));
        drop(Box::from_raw(events));
    }
}

// Removing one egress closes that loopback listener and leaves the others
// serving: a removed or re-addressed peer must not stay reachable through a
// stale port.
#[test]
fn removing_egress_closes_only_its_loopback_listener() {
    let stack = unsafe { ns_create(1420, 65536, discard_packets, std::ptr::null_mut()) };
    assert!(!stack.is_null());
    let src = cs("10.0.0.1");
    let first = cs("10.0.0.2");
    let second = cs("10.0.0.3");
    let port_a = unsafe { ns_add_tcp_egress(stack, first.as_ptr(), 80, src.as_ptr()) };
    let port_b = unsafe { ns_add_tcp_egress(stack, second.as_ptr(), 80, src.as_ptr()) };
    assert!(port_a > 0 && port_b > 0);
    assert_eq!(unsafe { ns_remove_tcp_egress(stack, first.as_ptr(), 80) }, 0);
    let mut closed = false;
    for _ in 0..100 {
        if TcpStream::connect(("127.0.0.1", port_a)).is_err() {
            closed = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(closed, "the removed egress listener still accepts connections");
    assert!(TcpStream::connect(("127.0.0.1", port_b)).is_ok());
    assert_eq!(unsafe { ns_remove_tcp_egress(std::ptr::null_mut(), first.as_ptr(), 80) }, -1);
    unsafe { ns_destroy(stack) };
}

// An egress connection toward a peer that never answers (every packet is
// dropped, as on a path that is not up) ends within EGRESS_CONNECT_TIMEOUT
// instead of holding the loopback client until its own read timeout.
#[test]
fn an_egress_connect_that_gets_no_answer_ends_within_the_connect_timeout() {
    let stack = unsafe { ns_create(1420, 65536, discard_packets, std::ptr::null_mut()) };
    assert!(!stack.is_null());
    let local = cs("10.0.0.1/8");
    let src = cs("10.0.0.1");
    let dst = cs("10.0.0.2");
    unsafe {
        assert_eq!(ns_add_local_ip(stack, local.as_ptr()), 0);
    }
    let port = unsafe { ns_add_tcp_egress(stack, dst.as_ptr(), 80, src.as_ptr()) };
    assert_ne!(port, 0, "egress listener failed to bind");
    std::thread::sleep(Duration::from_millis(100));

    let started = std::time::Instant::now();
    let mut client = TcpStream::connect(("127.0.0.1", port)).unwrap();
    let mut buf = [0u8; 16];
    // Well inside the bound the connection is still open: a read only waits.
    client.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
    match client.read(&mut buf) {
        Err(e) if matches!(
            e.kind(),
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
        ) => {}
        other => panic!("the connection ended before the connect timeout: {other:?}"),
    }
    // Then the stack gives up and the loopback side sees EOF or a reset.
    client.set_read_timeout(Some(EGRESS_CONNECT_TIMEOUT * 2)).unwrap();
    let ended = match client.read(&mut buf) {
        Ok(0) => true,
        Ok(_) => false,
        Err(e) => !matches!(
            e.kind(),
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
        ),
    };
    let elapsed = started.elapsed();
    assert!(ended, "the loopback side stayed open past the connect timeout ({elapsed:?})");
    assert!(
        elapsed < EGRESS_CONNECT_TIMEOUT + Duration::from_secs(10),
        "the connection ended only after {elapsed:?}"
    );
    unsafe { ns_destroy(stack) };
}

// A stack that cannot start must not hand back a handle. Before this check,
// ns_create returned a non-null handle whose stack thread had already exited.
#[test]
fn create_returns_null_when_the_stack_cannot_start() {
    // 67 is one byte below the IPv4 minimum MTU (RFC 791).
    for mtu in [0u32, 20, 67] {
        let stack = unsafe { ns_create(mtu, 65536, discard_packets, std::ptr::null_mut()) };
        assert!(stack.is_null(), "ns_create({mtu}) returned a handle");
    }
    let stack = unsafe { ns_create(68, 65536, discard_packets, std::ptr::null_mut()) };
    assert!(!stack.is_null());
    unsafe { ns_destroy(stack) };
}

/// Wiring with a one-way delay: each packet reaches the peer after `delay`,
/// in order, so the stacks see a real round-trip time.
struct DelayedWiring {
    queue: std::sync::mpsc::Sender<(std::time::Instant, Vec<u8>)>,
}

impl DelayedWiring {
    /// The peer handle arrives through the returned sender, as an address,
    /// once both stacks exist.
    fn new() -> (*mut DelayedWiring, std::sync::mpsc::Sender<usize>) {
        let (queue, packets) = std::sync::mpsc::channel::<(std::time::Instant, Vec<u8>)>();
        let (peer_tx, peer_rx) = std::sync::mpsc::channel::<usize>();
        std::thread::spawn(move || {
            let peer = match peer_rx.recv() {
                Ok(p) => p,
                Err(_) => return,
            };
            for (due, pkt) in packets {
                let now = std::time::Instant::now();
                if due > now {
                    std::thread::sleep(due - now);
                }
                unsafe { ns_feed_inbound(peer as *mut NsHandle, pkt.as_ptr(), pkt.len()) };
            }
        });
        (Box::into_raw(Box::new(DelayedWiring { queue })), peer_tx)
    }
}

static ONE_WAY_DELAY: Mutex<Duration> = Mutex::new(Duration::from_millis(0));

unsafe extern "C" fn forward_delayed(ctx: *mut c_void, pkt: *const u8, len: usize) {
    let wiring = &*(ctx as *const DelayedWiring);
    let delay = *ONE_WAY_DELAY.lock().unwrap();
    let data = std::slice::from_raw_parts(pkt, len).to_vec();
    let _ = wiring.queue.send((std::time::Instant::now() + delay, data));
}

/// A server that counts the bytes it receives on each connection and
/// reports the total through `counted`.
fn byte_sink(counted: &'static std::sync::atomic::AtomicUsize, hold: Duration) -> std::net::SocketAddr {
    let sink = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = sink.local_addr().unwrap();
    std::thread::spawn(move || {
        for stream in sink.incoming() {
            let mut stream = match stream { Ok(s) => s, Err(_) => break };
            std::thread::spawn(move || {
                std::thread::sleep(hold);
                let mut buf = vec![0u8; 1 << 16];
                loop {
                    match stream.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => { counted.fetch_add(n, std::sync::atomic::Ordering::Relaxed); }
                    }
                }
            });
        }
    });
    addr
}

struct Pair {
    a: *mut NsHandle,
    b: *mut NsHandle,
    port: u16,
    wiring: [*mut DelayedWiring; 2],
}

/// Two stacks with `tcp_buffer` bytes per socket, delayed wiring, an
/// ingress on B to `sink` and an egress on A toward it.
fn delayed_pair(tcp_buffer: u32, one_way: Duration, sink: std::net::SocketAddr) -> Pair {
    *ONE_WAY_DELAY.lock().unwrap() = one_way;
    let (wiring_a, peer_of_a) = DelayedWiring::new();
    let (wiring_b, peer_of_b) = DelayedWiring::new();
    let a = unsafe { ns_create(1420, tcp_buffer, forward_delayed, wiring_a as *mut c_void) };
    let b = unsafe { ns_create(1420, tcp_buffer, forward_delayed, wiring_b as *mut c_void) };
    assert!(!a.is_null() && !b.is_null());
    peer_of_a.send(b as usize).unwrap();
    peer_of_b.send(a as usize).unwrap();
    let a_ip = cs("10.0.0.1/8");
    let b_ip = cs("10.0.0.2/8");
    let target = cs(&format!("tcp:{sink}"));
    let b_vip = cs("10.0.0.2");
    let dst_ip = cs("10.0.0.2");
    let src_ip = cs("10.0.0.1");
    let port = unsafe {
        assert_eq!(ns_add_local_ip(a, a_ip.as_ptr()), 0);
        assert_eq!(ns_add_local_ip(b, b_ip.as_ptr()), 0);
        assert_eq!(ns_add_tcp_forward(b, b_vip.as_ptr(), 80, target.as_ptr()), 0);
        ns_add_tcp_egress(a, dst_ip.as_ptr(), 80, src_ip.as_ptr())
    };
    assert_ne!(port, 0);
    std::thread::sleep(Duration::from_millis(100));
    Pair { a, b, port, wiring: [wiring_a, wiring_b] }
}

fn destroy_pair(pair: Pair) {
    unsafe {
        ns_destroy(pair.a);
        ns_destroy(pair.b);
        for w in pair.wiring {
            drop(Box::from_raw(w));
        }
    }
}

/// Write `payload` through the egress and wait until the sink counted it
/// all. Returns the time the transfer took.
fn transfer(port: u16, payload: &[u8], counted: &std::sync::atomic::AtomicUsize, deadline: Duration) -> Duration {
    let start = std::time::Instant::now();
    let mut client = TcpStream::connect(("127.0.0.1", port)).unwrap();
    let before = counted.load(std::sync::atomic::Ordering::Relaxed);
    client.write_all(payload).unwrap();
    client.shutdown(std::net::Shutdown::Write).unwrap();
    while counted.load(std::sync::atomic::Ordering::Relaxed) - before < payload.len() {
        assert!(start.elapsed() < deadline,
                "sink has {} of {} bytes after {:?}",
                counted.load(std::sync::atomic::Ordering::Relaxed) - before, payload.len(), deadline);
        std::thread::sleep(Duration::from_millis(5));
    }
    start.elapsed()
}

// The TCP buffer sets the bytes one connection keeps in flight per round
// trip. Over a link with a 50 ms round trip, an 8 MiB transfer needs at
// least 128 round trips (6.4 s) with the one unscaled 64 KiB window the
// earlier release had; a 1 MiB buffer scales the window and finishes in a
// fraction of that.
#[test]
fn a_larger_tcp_buffer_carries_a_transfer_over_a_delayed_link() {
    static COUNTED: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let sink = byte_sink(&COUNTED, Duration::ZERO);
    let pair = delayed_pair(1 << 20, Duration::from_millis(25), sink);
    let payload = vec![0x5au8; 8 << 20];
    let took = transfer(pair.port, &payload, &COUNTED, Duration::from_secs(20));
    eprintln!("8 MiB over a 50 ms round trip: {took:?}");
    assert!(took < Duration::from_secs(3),
            "8 MiB over a 50 ms round trip took {took:?}; the window is not scaled");
    destroy_pair(pair);
}

// Bytes a slow bridge target does not read stay in the sender's socket
// instead of in the stack's staging buffers: the writer is held back and
// nothing is lost once the target reads.
#[test]
fn a_slow_bridge_reader_holds_the_writer_back() {
    static COUNTED: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let sink = byte_sink(&COUNTED, Duration::from_secs(4));
    let pair = delayed_pair(1 << 20, Duration::ZERO, sink);
    let payload: &'static [u8] = Box::leak(vec![0xa5u8; 128 << 20].into_boxed_slice());
    static WRITTEN: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

    let mut client = TcpStream::connect(("127.0.0.1", pair.port)).unwrap();
    let writer = {
        let mut c = client.try_clone().unwrap();
        std::thread::spawn(move || {
            let mut off = 0;
            while off < payload.len() {
                let n = c.write(&payload[off..]).unwrap();
                off += n;
                WRITTEN.store(off, std::sync::atomic::Ordering::Relaxed);
            }
            c.shutdown(std::net::Shutdown::Write).unwrap();
        })
    };
    std::thread::sleep(Duration::from_secs(3));
    let accepted = WRITTEN.load(std::sync::atomic::Ordering::Relaxed);
    assert!(accepted < 64 << 20,
            "the stacks absorbed {accepted} bytes while the target read nothing");

    let start = std::time::Instant::now();
    while COUNTED.load(std::sync::atomic::Ordering::Relaxed) < payload.len() {
        assert!(start.elapsed() < Duration::from_secs(60), "transfer stalled");
        std::thread::sleep(Duration::from_millis(20));
    }
    writer.join().unwrap();
    let mut end = [0u8; 1];
    assert_eq!(client.read(&mut end).unwrap_or(0), 0);
    destroy_pair(pair);
}

// A TCP buffer below one unscaled window is refused like a bad MTU.
#[test]
fn create_returns_null_for_a_tcp_buffer_below_the_minimum() {
    for buffer in [0u32, 4096, 65535] {
        let stack = unsafe { ns_create(1420, buffer, discard_packets, std::ptr::null_mut()) };
        assert!(stack.is_null(), "ns_create with tcp_buffer {buffer} returned a handle");
    }
    let stack = unsafe { ns_create(1420, 65536, discard_packets, std::ptr::null_mut()) };
    assert!(!stack.is_null());
    unsafe { ns_destroy(stack) };
}
