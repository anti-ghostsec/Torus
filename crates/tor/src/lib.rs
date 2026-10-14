//! Publishes [`Live`] sites as Tor v3 onion services.
//!
//! Tor runs inside this process (Arti), so there is no listening socket at
//! all: visitors' streams arrive from the Tor network and are handed straight
//! to the HTTP server. Arti's keystore is kept in RAM; the only long-lived
//! secret, the service's identity key, is passed in and out as bytes so the
//! caller can keep it in the encrypted vault.

use std::fmt;
use std::collections::HashSet;
use std::path::Path;
use std::sync::{Arc, Mutex};

use arti_client::config::onion_service::OnionServiceConfigBuilder;
use arti_client::config::TorClientConfigBuilder;
use arti_client::TorClient;
use tor_rtcompat::PreferredRuntime;
use torus_runtime::{serve_connection, Live};
use futures::StreamExt;
use safelog::DisplayRedacted;
use tokio::task::JoinHandle;
use tor_cell::relaycell::msg::{Connected, End};
use tor_config::ExplicitOrAuto;
use tor_hscrypto::pk::{HsIdKey, HsIdKeypair};
use tor_hsservice::status::State;
use tor_hsservice::{handle_rend_requests, RunningOnionService};
use tor_keymgr::config::ArtiKeystoreKind;
use tor_llcrypto::pk::ed25519;
use tor_proto::stream::IncomingStreamRequest;
use zeroize::Zeroizing;

/// The service's secret identity: an expanded Ed25519 key. Whoever holds
/// these bytes owns the onion address.
pub type Identity = Zeroizing<[u8; 64]>;

#[derive(Debug)]
pub struct Error(String);

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

/// Arti's errors keep their real cause several layers down, so spell out the whole chain.
fn err(context: &str, cause: impl std::error::Error) -> Error {
    let mut message = format!("{context}: {cause}");
    let mut source = cause.source();
    while let Some(inner) = source {
        message.push_str(&format!(": {inner}"));
        source = inner.source();
    }
    Error(message)
}

pub fn new_identity() -> Result<Identity, Error> {
    let mut seed = Zeroizing::new([0u8; 32]);
    getrandom::getrandom(seed.as_mut()).map_err(|e| err("no secure randomness", e))?;
    let expanded = ed25519::ExpandedKeypair::from(&ed25519::Keypair::from_bytes(&seed));
    Ok(Zeroizing::new(expanded.to_secret_key_bytes()))
}

fn keypair(identity: &Identity) -> Result<HsIdKeypair, Error> {
    ed25519::ExpandedKeypair::from_secret_key_bytes(**identity)
        .map(HsIdKeypair::from)
        .ok_or_else(|| Error("the stored onion identity key is not valid".into()))
}

/// The `.onion` address an identity publishes at.
pub fn address(identity: &Identity) -> Result<String, Error> {
    Ok(HsIdKey::from(&keypair(identity)?).id().display_unredacted().to_string())
}

/// A running onion service. Dropping it takes the site off the network.
pub struct Onion {
    address: String,
    service: Arc<RunningOnionService>,
    task: JoinHandle<()>,
}

impl Onion {
    pub fn address(&self) -> &str {
        &self.address
    }

    /// Whether visitors can reach the site yet. Announcing a new service to
    /// the network takes a little while after launch.
    pub fn reachable(&self) -> bool {
        self.service.status().state().is_fully_reachable()
    }

    /// The service's own description of its state, for diagnostics.
    pub fn state(&self) -> String {
        format!("{:?}", self.service.status().state())
    }

    /// True once the service has failed in a way it will not recover from.
    pub fn broken(&self) -> bool {
        matches!(self.service.status().state(), State::Broken) || self.task.is_finished()
    }
}

impl Drop for Onion {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// A connection to the Tor network, shared by every site this app hosts.
pub struct Tor {
    client: Arc<TorClient<PreferredRuntime>>,
    // Services whose identity key is already in the in-memory keystore.
    known: Mutex<HashSet<String>>,
}

impl Tor {
    /// Connects to Tor.
    ///
    /// `state_dir` and `cache_dir` hold Tor's own bookkeeping (its copy of the
    /// network directory and its choice of entry relays). No key is written there.
    pub async fn connect(state_dir: &Path, cache_dir: &Path) -> Result<Self, Error> {
        // rustls needs its cryptography chosen once per process; a second call is harmless.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut config = TorClientConfigBuilder::from_directories(state_dir, cache_dir);
        config.storage().keystore().primary().kind(ExplicitOrAuto::Explicit(ArtiKeystoreKind::Ephemeral));
        // Arti normally inspects the permissions of every folder above its
        // own. On Windows that check verifies nothing, and inside the sandbox
        // those folders cannot even be looked at, so it only gets in the way.
        #[cfg(windows)]
        config.storage().permissions().dangerously_trust_everyone();
        let config = config.build().map_err(|e| err("invalid Tor configuration", e))?;
        let client = TorClient::create_bootstrapped(config).await.map_err(|e| err("could not connect to Tor", e))?;
        Ok(Self { client, known: Mutex::default() })
    }

    /// Starts serving `live` at the address of `identity`. `name` tells this
    /// app's services apart and never leaves the machine; it must stay paired
    /// with the same identity for as long as this connection lives.
    pub fn launch(&self, name: &str, identity: &Identity, live: Live) -> Result<Onion, Error> {
        let service_config = OnionServiceConfigBuilder::default()
            .nickname(name.parse().map_err(|e| err("invalid service name", e))?)
            // Makes visitors solve a puzzle when the service is being flooded.
            .enable_pow(true)
            .build()
            .map_err(|e| err("invalid onion service configuration", e))?;
        let address = address(identity)?;

        // The keystore refuses to take the same key twice, so a service that
        // was taken offline and comes back reuses the key it already holds.
        let mut known = self.known.lock().unwrap_or_else(|e| e.into_inner());
        let launched = if known.contains(name) {
            self.client.launch_onion_service(service_config).map(|o| o.map(|(s, r)| (s, r.boxed())))
        } else {
            self.client
                .launch_onion_service_with_hsid(service_config, keypair(identity)?)
                .map(|o| o.map(|(s, r)| (s, r.boxed())))
        };
        let (service, requests) = launched
            .map_err(|e| err("could not start the onion service", e))?
            .ok_or_else(|| Error("the onion service is disabled".into()))?;
        known.insert(name.to_owned());
        drop(known);

        let task = tokio::spawn(async move {
            let mut streams = std::pin::pin!(handle_rend_requests(requests));
            while let Some(request) = streams.next().await {
                let is_http = matches!(request.request(), IncomingStreamRequest::Begin(begin) if begin.port() == 80);
                let live = live.clone();
                tokio::spawn(async move {
                    if !is_http {
                        let _ = request.reject(End::new_misc()).await;
                    } else if let Ok(stream) = request.accept(Connected::new_empty()).await {
                        serve_connection(stream, live).await;
                    }
                });
            }
        });
        Ok(Onion { address, service, task })
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identities_are_distinct_and_map_to_stable_v3_addresses() {
        let a = new_identity().unwrap();
        let b = new_identity().unwrap();
        let address_a = address(&a).unwrap();
        assert_ne!(address_a, address(&b).unwrap());
        assert_eq!(address_a, address(&a).unwrap());
        assert_eq!(address_a.len(), 56 + ".onion".len());
        assert!(address_a.ends_with(".onion"));
    }
}
