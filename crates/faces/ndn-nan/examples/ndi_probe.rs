//! Bring up a NAN Data Interface and show what the kernel made of it.
fn main() {
    #[cfg(target_os = "linux")]
    {
        const NDI: [u8; 6] = [0x02, 0xaa, 0xaa, 0x00, 0x00, 0x01];
        let want = ndn_nan::ndi::link_local_addr(ndn_nan_core::eui64_iid(NDI));
        println!("advertising iid -> {want}");
        match ndn_nan::ndi::NdiInterface::open("nan0", NDI) {
            Ok(n) => {
                println!("NDI up: {} mac={:02x?} link_local={}", n.name(), n.mac(), n.link_local());
                std::thread::sleep(std::time::Duration::from_secs(3));
                println!("(holding the fd; the netdev exists while this runs)");
            }
            Err(e) => println!("open failed: {e}"),
        }
    }
}
