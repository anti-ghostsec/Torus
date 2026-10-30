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

### Passing visitors to an app you run yourself

A site can instead pass its visitors straight to a web app already running on your computer, such as one with its own server and database. Turn it on under the site's settings and give the app's port on `127.0.0.1`. Torus still provides the onion address, its key in the vault, and Tor.

**This carries more risk than a site Torus builds.** Torus doesn't build or check that app's pages, and the app runs outside the sandbox and the vault. It can leak scripts, outside requests, or details about your computer to visitors. Any sites it contacts itself see your real IP address unless it goes through Tor. The editor shows these risks before you can turn it on, and keeps showing them while it's on. This isn't available on Windows yet, because Windows keeps sandboxed programs from reaching the computer's own addresses.

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
| `app/` | The Tauri editor app |
| `patches/` | Patched copies of `wry`, `fs-mistrust` and `saturating-time` |

Building it yourself is covered in [BUILDING.md](BUILDING.md).

## License

MIT or Apache-2.0, at your choice.
