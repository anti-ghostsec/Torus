mod backend;

use backend::{Backend, Failure, Listed, MineStatus, OnionStatus, View};
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

#[tauri::command]
fn in_decoy(backend: State<'_, Backend>) -> bool {
    backend.in_decoy()
}

#[tauri::command]
async fn set_decoy(backend: State<'_, Backend>, passphrase: String) -> Result<(), Failure> {
    backend.set_decoy(passphrase).await
}

#[tauri::command]
async fn export_backup(backend: State<'_, Backend>, file: std::path::PathBuf) -> Result<(), Failure> {
    backend.export_backup(file).await
}

#[tauri::command]
async fn export_site(
    backend: State<'_, Backend>,
    id: u32,
    file: std::path::PathBuf,
    passphrase: String,
    content: bool,
    address: bool,
) -> Result<(), Failure> {
    backend.export_site(id, file, passphrase, content, address).await
}

#[tauri::command]
async fn import_site(backend: State<'_, Backend>, file: std::path::PathBuf, passphrase: String) -> Result<Listed, Failure> {
    backend.import_site(file, passphrase).await
}

#[tauri::command]
fn import_backup(backend: State<'_, Backend>, file: std::path::PathBuf) -> Result<(), Failure> {
    backend.import_backup(file)
}

#[tauri::command]
fn auto_lock_minutes(backend: State<'_, Backend>) -> u32 {
    backend.auto_lock_minutes()
}

#[tauri::command]
fn set_auto_lock_minutes(backend: State<'_, Backend>, minutes: u32) -> Result<(), Failure> {
    backend.set_auto_lock_minutes(minutes)
}

/// Takes every site offline, locks the vault, then closes the app.
#[tauri::command]
async fn panic(app: tauri::AppHandle, backend: State<'_, Backend>) -> Result<(), ()> {
    backend.panic().await;
    app.exit(0);
    Ok(())
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
fn mine_start(backend: State<'_, Backend>, id: u32, prefix: String) -> Result<MineStatus, Failure> {
    backend.mine_start(id, &prefix)
}

#[tauri::command]
fn mine_status(backend: State<'_, Backend>) -> Option<MineStatus> {
    backend.mine_status()
}

#[tauri::command]
fn mine_stop(backend: State<'_, Backend>) {
    backend.mine_stop();
}

#[tauri::command]
async fn mine_use(backend: State<'_, Backend>, id: u32, replace: bool) -> Result<String, Failure> {
    backend.mine_use(id, replace).await
}

#[tauri::command]
fn mine_save(backend: State<'_, Backend>) -> Result<String, Failure> {
    backend.mine_save()
}

#[tauri::command]
fn saved_addresses(backend: State<'_, Backend>) -> Result<Vec<String>, Failure> {
    backend.saved_addresses()
}

#[tauri::command]
async fn use_saved(backend: State<'_, Backend>, id: u32, address: String, replace: bool) -> Result<String, Failure> {
    backend.use_saved(id, address, replace).await
}

#[tauri::command]
fn forget_saved(backend: State<'_, Backend>, address: String) -> Result<(), Failure> {
    backend.forget_saved(address)
}

#[tauri::command]
async fn export_key(backend: State<'_, Backend>, address: String, file: std::path::PathBuf, passphrase: String) -> Result<(), Failure> {
    backend.export_key(address, file, passphrase).await
}

#[tauri::command]
async fn import_key(backend: State<'_, Backend>, file: std::path::PathBuf, passphrase: String) -> Result<String, Failure> {
    backend.import_key(file, passphrase).await
}

#[tauri::command]
async fn stop(backend: State<'_, Backend>, id: u32) -> Result<(), ()> {
    backend.stop(id).await;
    Ok(())
}

/// The folder the window's browser engine keeps its files in.
struct Engine(std::path::PathBuf);

/// Where everything this app keeps lives. On a computer that is one folder,
/// `TorusData`, beside the program itself, so the app is portable and
/// leaves nothing in the user's profile or anywhere else. On Android, the
/// app's private storage, which only it can reach.
fn data_root(app: &tauri::App) -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    #[cfg(mobile)]
    {
        Ok(app.path().app_data_dir()?)
    }
    #[cfg(desktop)]
    {
        let _ = app;
        let program = std::env::current_exe()?;
        let beside = program.parent().ok_or("the program has no folder")?;
        let root = beside.join("TorusData");
        std::fs::create_dir_all(&root)
            .map_err(|e| format!("Torus keeps everything in {}, and cannot write there: {e}", root.display()))?;
        Ok(root)
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    torus_host_api::no_crash_dumps();
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            let root = data_root(app)?;
            let backend = Backend::new(root.clone(), root.join("sites"), torus_host_api::host_program()?);

            // The window's browser engine keeps its own files in the app's
            // folder too, never in the user's profile. Its session is private
            // and left behind by an earlier run is erased.
            let engine = root.join("webview");
            let _ = torus_vault::folder::erase(&engine);
            app.manage(Engine(engine.clone()));
            let builder = tauri::WebviewWindowBuilder::new(app, "main", tauri::WebviewUrl::default())
                .data_directory(engine)
                .incognito(true)
                .disable_drag_drop_handler();
            #[cfg(desktop)]
            let builder = builder.title("Torus").inner_size(1280.0, 800.0).min_inner_size(960.0, 600.0);
            builder.build()?;
            app.manage(backend);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            vault_exists,
            create_vault,
            unlock,
            lock,
            auto_lock_minutes,
            set_auto_lock_minutes,
            export_backup,
            import_backup,
            export_site,
            import_site,
            in_decoy,
            set_decoy,
            panic,
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
            mine_start,
            mine_status,
            mine_stop,
            mine_use,
            mine_save,
            saved_addresses,
            use_saved,
            forget_saved,
            export_key,
            import_key,
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
                // The window's browser engine kept a private session, but its
                // folder is erased too, once its own processes have let go.
                if let Some(Engine(folder)) = app.try_state::<Engine>().map(|e| Engine(e.0.clone())) {
                    for _ in 0..20 {
                        if torus_vault::folder::erase(&folder).is_ok() {
                            break;
                        }
                        std::thread::sleep(std::time::Duration::from_millis(250));
                    }
                }
            }
        });
}
