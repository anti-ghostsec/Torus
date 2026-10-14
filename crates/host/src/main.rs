//! The host program: serves one site as told by the editor over standard
//! input, or, started in the other role, converts that site's videos.

fn main() {
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
