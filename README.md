# Torus

Build a website and host it as a Tor onion service, from your own Windows PC or Android phone. No server, no domain, no hosting company, and no account anywhere.

## What you can make

Start from a ready-made site and change it in the editor:

- **Video site**: uploads of up to 10 GB, each one re-encoded before anyone can watch it, so it carries no traces of the camera or app that made it.
- **Board** and **microblog**: posts, feeds and view counts.
- **Wiki** and **pastebin**.

Sites can have **member accounts**, with moderation (blocked words, approving new accounts) and picture puzzles to keep bots out. A **Monero wallet** kept in the vault lets a site take payments: each site gets an account of its own and each of its users gets a separate address, so nobody looking at the chain can link them.

Pages are plain HTML and CSS, with no scripts and no third-party requests. A built-in checker refuses to publish a page that would leak.

You can also mine a **vanity onion address** that starts with letters you choose.

## How it keeps you safe

- **Everything is in one encrypted vault.** Sites, keys, visitor data and the wallet are encrypted with Argon2id and XChaCha20-Poly1305. Nothing is readable on disk without your passphrase.
- **The network-facing part is sandboxed.** Each site runs in its own host process that gets finished pages and its one onion key, and nothing else: never the vault, your passphrase or other sites. On Windows it runs in an AppContainer. On Linux and Android it runs under Landlock and seccomp.
- **Visitors' submissions are sealed.** What visitors send to a sealed collection is encrypted to a key that only the vault holds, using a hybrid of a classical and a post-quantum key agreement. Someone who seizes or breaks into the host can't read it.
- **Tor runs inside the app** (Arti), so there's no listening socket at all. Tor's own state is kept encrypted too.
- **Nothing about your machine reaches visitors.** Responses carry a small, fixed set of headers, with no clocks, software versions or file times.
- **Under pressure:** auto-lock, a panic action, and a decoy passphrase that opens a separate, empty vault.
- **Backups:** encrypted backup and restore of everything, or export and import of a single site.

## Get it

Download from [Releases](https://github.com/anti-ghostsec/Torus/releases) and check it against `SHA256SUMS.txt`.

| On | Download |
|---|---|
| **Windows 10 or 11** | `Torus_*_windows_portable.zip`: unzip anywhere on an NTFS drive and run `Torus\torus.exe`. Nothing is installed or written outside that folder. |
| **Android (64-bit ARM)** | `Torus_*_arm64.apk` |

The builds aren't code-signed yet, so Windows SmartScreen warns the first time you run it: choose "More info", then "Run anyway".

## Known limits

- Torus hasn't been audited by an independent security firm. Don't rely on it alone if being identified could put you in danger.
- On Android systems without Landlock, a site's files can't be confined. The editor tells you when this happens.
- Your device has to stay on and online for your sites to be reachable.
- Hosting from home can be traced by timing. Someone who can watch your internet connection, or who already suspects you, can compare when your site goes offline or gets busy with when your connection does. Torus turns on Tor's defences against locating a service (vanguards), which make this harder, not impossible; power cuts and restarts that take the site down with your connection are the usual giveaway.

## Layout

| Crate | What it does |
|---|---|
| `crates/core` | The site model, the no-script HTML compiler and the leak checker |
| `crates/runtime` | Serves a site: pages, records, files and accounts |
| `crates/host`, `crates/host-api` | The sandboxed process that faces the network, and how the editor talks to it |
| `crates/tor` | Publishes sites as onion services with Arti |
| `crates/onion-key` | Makes onion keys and derives their addresses, with no networking code |
| `crates/vault` | The encrypted single-file vault |
| `crates/seal` | Post-quantum hybrid encryption for visitor submissions |
| `crates/wallet` | The Monero wallet |
| `crates/gateway` | `torus-gateway`: publishes any web app already running on the machine as an onion service, and mines vanity addresses from the command line |
| `app/` | The Tauri editor app |
| `patches/` | Patched copies of `wry`, `fs-mistrust` and `saturating-time` |

Building it yourself is covered in [BUILDING.md](BUILDING.md).

## Publishing another web app

The editor can put a web app that already runs on this computer online at an onion
address of its own: **Apps on this computer**, in the site settings. Give it a name and
the port the app listens on, pick a new or saved address (mined, or imported from an
address file or from Tor's own `hs_ed25519_secret_key`), and publish it. It runs in a
confined host of its own, with its own Tor bookkeeping, like a site's.

The same works without the editor: `torus-gateway` puts the app online as an onion
service, with Tor inside the process and nothing listening for visitors:

```sh
cargo build --release -p torus-gateway
torus-gateway address --key onion.key                 # prints the address (makes a key if needed)
torus-gateway mine --key onion.key PREFIX...          # vanity address; --replace to overwrite
torus-gateway serve --key onion.key --data tor --to 127.0.0.1:3000   # --with-parent: exit when stdin closes
```

The key file holds the service's secret identity (64 bytes, the same as the part of
Tor's `hs_ed25519_secret_key` after its 32-byte header). Like Tor, the gateway refuses
a key file other users of the machine could read. Only one gateway runs per Tor folder,
and with `--with-parent` it never outlives the program that started it.

Either way, Torus only carries visitors' connections: the app behind it is not confined
or checked for leaks, so it must be safe to put online itself and listen on 127.0.0.1
only. Each circuit may hold 64 streams at once and each service 1024; a forwarded stream
silent for two minutes is closed.

## License

MIT or Apache-2.0, at your choice.
