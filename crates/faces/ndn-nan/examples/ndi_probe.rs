//! Bring up a NAN Data Interface and bind the socket a data path would use.
fn main() {
    #[cfg(target_os = "linux")]
    {
        use ndn_nan::ndi::{DataInterface, NdiInterface, link_local_addr};
        const NDI: [u8; 6] = [0x02, 0xaa, 0xaa, 0x00, 0x00, 0x01];
        const PEER_NDI: [u8; 6] = [0x02, 0xbb, 0xbb, 0x00, 0x00, 0x02];

        let want = link_local_addr(ndn_nan_core::eui64_iid(NDI));
        println!("advertising iid -> {want}");
        let n = match NdiInterface::open("nan0", NDI) {
            Ok(n) => n,
            Err(e) => {
                println!("open failed: {e}");
                return;
            }
        };
        println!(
            "NDI up: {} mac={:02x?} link_local={}",
            n.name(),
            n.mac(),
            n.link_local()
        );
        let scope = DataInterface::index(&n);
        println!("ifindex (link-local scope) = {scope}");
        assert_ne!(scope, 0, "a scope of 0 would make the address unroutable");

        // Exactly what request_ndp does once the handshake settles.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let local = std::net::SocketAddrV6::new(n.link_local(), 6363, 0, scope);
            match tokio::net::UdpSocket::bind(local).await {
                Ok(s) => println!("bound our end: {}", s.local_addr().unwrap()),
                Err(e) => println!("BIND FAILED {local}: {e}"),
            }
            let peer = std::net::SocketAddrV6::new(
                link_local_addr(ndn_nan_core::eui64_iid(PEER_NDI)),
                6363,
                0,
                scope,
            );
            println!("peer would be: {peer}");
        });
    }
}
