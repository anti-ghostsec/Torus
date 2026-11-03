//! The host program: serves one site as told by the editor over standard
//! input, or, started in the other role, converts that site's videos.

fn main() {
    // Before anything else, and before a single byte is read from anyone:
    // the editor's instructions for confining this process are in its
    // environment, and everything after this runs confined.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let isolation = torus_host_api::confine_from_surroundings();
        // The converter reads what anonymous visitors upload. Unless it can
        // neither open the owner's files nor reach the network, it does not
        // run at all: a video it was handed by an attacker could otherwise
        // carry the owner's files, or their address, back out.
        if std::env::var_os(torus_host_api::CONFINE_OFFLINE).is_some() && !isolation.is_some_and(|i| i.files && i.syscalls) {
            eprintln!("torus-host: this system cannot confine the video converter, so it does not run");
            std::process::exit(78);
        }
    }
    torus_host_api::no_crash_dumps();
    // Started as a converter, this program serves nothing and has no network.
    if let Some(code) = torus_host::media::serve_if_converter() {
        std::process::exit(code);
    }
    let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build().expect("tokio runtime");
    let code = runtime.block_on(torus_host::run(tokio::io::stdin(), tokio::io::stdout()));
    // Exit directly: a thread may still be blocked reading standard input.
    std::process::exit(code);
}
