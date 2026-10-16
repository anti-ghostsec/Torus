//! Guards the vendored `saturating-time` fix (see the workspace `[patch]`).
//! Without it this call never returns on Windows, and neither does Tor's
//! reading of the network directory.

use std::sync::mpsc;
use std::time::{Duration, SystemTime};

use saturating_time::SaturatingTime;

#[test]
fn the_largest_system_time_can_be_found() {
    let (done, wait) = mpsc::channel();
    std::thread::spawn(move || {
        let max = SystemTime::max_value();
        let min = SystemTime::min_value();
        let _ = done.send(max > SystemTime::now() && min < SystemTime::UNIX_EPOCH);
    });
    let sane = wait.recv_timeout(Duration::from_secs(10)).expect("the search for the largest time never finished");
    assert!(sane);
}

/// The editor makes keys with `torus-onion-key`; Tor must agree on what
/// address each one stands for, or a site would publish somewhere unexpected.
#[test]
fn editor_made_keys_mean_the_same_address_to_tor() {
    for _ in 0..20 {
        let identity = torus_onion_key::new_identity().unwrap();
        assert_eq!(torus_onion_key::address(&identity), torus_tor::address(&identity).unwrap());
        let from_tor = torus_tor::new_identity().unwrap();
        assert_eq!(torus_onion_key::address(&from_tor), torus_tor::address(&from_tor).unwrap());
    }
}

/// A mined vanity key means, to Tor, exactly the address it was mined for.
#[test]
fn mined_keys_mean_the_same_address_to_tor() {
    use std::sync::atomic::{AtomicBool, AtomicU64};
    let prefix = torus_onion_key::Prefix::new("to").unwrap();
    for _ in 0..5 {
        let identity = torus_onion_key::mine(&prefix, &AtomicBool::new(false), &AtomicU64::new(0)).unwrap();
        let address = torus_tor::address(&identity).unwrap();
        assert!(address.starts_with("to"), "{address}");
        assert_eq!(torus_onion_key::address(&identity), address);
    }
}
