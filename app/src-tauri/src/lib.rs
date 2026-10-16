mod backend;

use backend::{Backend, Failure, Listed, OnionStatus, View};
use tauri::{Manager, State};
use torus_core::Site;

// Each command only forwards to the backend, which is tested on its own.

#[tauri::command]
fn vault_exists(backend: State<'_, Backend>) -> Result<bool, Failure> {
    backend.vault_exists()
}

#[tauri::command(async)]
fn create_vault(backend: State<'_, Backend>, passphrase: String, site: Site) -> Result<Vec<Listed>, Failure> {
    backend.create_vault(passphrase, site)
}

#[tauri::command(async)]
fn unlock(backend: State<'_, Backend>, passphrase: String) -> Result<Vec<Listed>, Failure> {
    backend.unlock(passphrase)
}

/// Forgets the vault's key and everything decrypted with it. Sites that
/// are online stay online: their hosts hold what they need already.
#[tauri::command]
fn lock(backend: State<'_, Backend>) {
    backend.lock();
}

#[tauri::command(async)]
fn save(backend: State<'_, Backend>, id: u32, site: Site) -> Result<(), Failure> {
    backend.save(id, site)
}

#[tauri::command(async)]
fn add_site(backend: State<'_, Backend>, site: Site) -> Result<u32, Failure> {
    backend.add_site(site)
}

#[tauri::command]
async fn delete_site(backend: State<'_, Backend>, id: u32) -> Result<(), Failure> {
    backend.delete_site(id).await
}

#[tauri::command]
fn starter(backend: State<'_, Backend>, kind: String) -> Result<Site, Failure> {
    backend.starter(&kind)
}

#[tauri::command]
fn canvas(backend: State<'_, Backend>, site: Site, slug: String) -> View {
    backend.canvas(&site, &slug)
}

#[tauri::command]
async fn publish_local(backend: State<'_, Backend>, id: u32, site: Site) -> Result<String, Failure> {
    backend.publish_local(id, site).await
}

#[tauri::command]
async fn publish_onion(backend: State<'_, Backend>, id: u32, site: Site) -> Result<String, Failure> {
    backend.publish_onion(id, site).await
}

#[tauri::command]
async fn records(backend: State<'_, Backend>, id: u32, collection: String) -> Result<Vec<torus_core::Record>, Failure> {
    backend.records(id, collection).await
}

#[tauri::command]
async fn remove_record(backend: State<'_, Backend>, id: u32, collection: String, record: String) -> Result<bool, Failure> {
    backend.remove_record(id, collection, record).await
}

#[tauri::command]
async fn approve_record(backend: State<'_, Backend>, id: u32, collection: String, record: String) -> Result<bool, Failure> {
    backend.approve_record(id, collection, record).await
}

#[tauri::command]
async fn moderators(backend: State<'_, Backend>, id: u32) -> Result<Vec<String>, Failure> {
    backend.moderators(id).await
}

#[tauri::command]
async fn set_moderator(backend: State<'_, Backend>, id: u32, account: String, on: bool) -> Result<Vec<String>, Failure> {
    backend.set_moderator(id, account, on).await
}

#[tauri::command]
fn onion_status(backend: State<'_, Backend>) -> Vec<OnionStatus> {
    backend.onion_status()
}

#[tauri::command]
async fn stop(backend: State<'_, Backend>, id: u32) -> Result<(), ()> {
    backend.stop(id).await;
    Ok(())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    torus_host_api::no_crash_dumps();
    tauri::Builder::default()
        .setup(|app| {
            let paths = app.path();
            app.manage(Backend::new(
                paths.app_data_dir()?,
                paths.app_local_data_dir()?.join("tor"),
                torus_host_api::host_program()?,
            ));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            vault_exists,
            create_vault,
            unlock,
            lock,
            save,
            add_site,
            delete_site,
            canvas,
            starter,
            publish_local,
            publish_onion,
            records,
            remove_record,
            approve_record,
            moderators,
            set_moderator,
            onion_status,
            stop
        ])
        .build(tauri::generate_context!())
        .expect("error while building tauri application")
        .run(|app, event| {
            // Closing the app takes every site offline, packs Tor's
            // bookkeeping away encrypted and forgets the vault's key: with
            // the app closed, nothing can be read without the passphrase.
            if let tauri::RunEvent::Exit = event {
                if let Some(backend) = app.try_state::<Backend>() {
                    tauri::async_runtime::block_on(backend.shutdown());
                }
            }
        });
}
