//! How the wallet reaches its Monero node: through whatever passes its
//! requests on. In the app that is the relay, a sandboxed process that
//! sends them through Tor; the wallet itself never touches the network.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use monero_daemon_rpc::prelude::InterfaceError;
use monero_daemon_rpc::HttpTransport;

/// The largest answer accepted when the caller sets no limit.
pub const DEFAULT_LIMIT: usize = 64 << 20;

type Fetch = dyn Fn(String, Vec<u8>, usize) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, String>> + Send>> + Send + Sync;

/// Passes each request to a function that returns the node's answer.
#[derive(Clone)]
pub struct Fetcher(Arc<Fetch>);

impl Fetcher {
    pub fn new<F, Fut>(fetch: F) -> Fetcher
    where
        F: Fn(String, Vec<u8>, usize) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Vec<u8>, String>> + Send + 'static,
    {
        Fetcher(Arc::new(move |route, body, limit| Box::pin(fetch(route, body, limit))))
    }
}

impl HttpTransport for Fetcher {
    fn post(&self, route: &str, body: Vec<u8>, limit: Option<usize>) -> impl Send + Future<Output = Result<Vec<u8>, InterfaceError>> {
        let answer = (self.0)(route.to_owned(), body, limit.unwrap_or(DEFAULT_LIMIT));
        async move { answer.await.map_err(InterfaceError::InterfaceError) }
    }
}
