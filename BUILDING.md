# Building Torus

Builds from a Linux machine (tested on Ubuntu 24.04).

## Requirements

- Rust (stable)
- Node 22 and `npm install` in `app/`
- Linux: `pkg-config`, `libwebkit2gtk-4.1-dev`, `libgtk-3-dev`, `libayatana-appindicator3-dev`, `librsvg2-dev`
- Windows: `mingw-w64` and `nsis` (with rust target `x86_64-pc-windows-gnu`)
- Android: the Android SDK (platform `android-37.0`, build-tools 37) and NDK 29, with
  `ANDROID_HOME` and `ANDROID_NDK_HOME` set, and Java 17+ (with rust target `aarch64-linux-android`)
- Video converter: `git` or `curl`, `make`, `nasm`/`yasm`, `pkg-config`

## The video converter

Every uploaded video is encoded afresh by FFmpeg in a sandbox before anyone can
watch it. Build the static, LGPL-only FFmpeg the app ships (VP9/Opus, no network
code) once per target:

```sh
tools/ffmpeg/build.sh linux     # -> tools/ffmpeg/linux/ffmpeg
tools/ffmpeg/build.sh windows   # -> tools/ffmpeg/windows/ffmpeg.exe
ANDROID_NDK_HOME=... tools/ffmpeg/build.sh android   # -> tools/ffmpeg/android/ffmpeg
```

## Linux

```sh
cd app && npm run portable:linux
```

This makes `target/portable/Torus_<version>_linux_portable.tar.gz`: a `Torus`
folder with `torus`, `torus-host` and `ffmpeg`. Nothing is installed.
Everything the app keeps, encrypted, goes in a `TorusData` folder beside
`torus`. The sandbox confines each site using Linux Landlock and seccomp.

(`npm run bundle:linux` makes `.deb` and `.AppImage` packages.)

## Windows

```sh
cd app && npm run portable:windows
```

This makes `target/portable/Torus_<version>_windows_portable.zip`: a `Torus`
folder with `torus.exe`, `torus-host.exe`, `ffmpeg.exe` and `WebView2Loader.dll`.
Nothing is installed. Everything the app keeps, encrypted, goes in a `TorusData`
folder beside `torus.exe`: the vault, each site's folder, the encrypted copies of
Tor's bookkeeping, and the window's browser-engine files. Nothing is written to
AppData or anywhere else; the one exception is a Windows Error Reporting setting
in the registry that keeps crash dumps (copies of memory) from being written to
disk at all. The sandbox needs the folder on an NTFS drive.

(`npm run bundle:windows` still makes an installer, for those who want one.)

## Android

```sh
cd app && npm run bundle:android
```

The host program and the converter are packaged as `libtorus_host.so` and
`libffmpeg.so`, the one place Android lets an app keep programs it can start.
Each site's host then runs as a separate, confined process. The APK lands in
`app/src-tauri/gen/android/app/build/outputs/apk/`. A release APK must be signed
before it installs:

```sh
keytool -genkeypair -keystore torus.jks -alias torus -keyalg RSA -keysize 4096 -validity 10000
$ANDROID_HOME/build-tools/37.0.0/zipalign -p 4 app-universal-release-unsigned.apk aligned.apk
$ANDROID_HOME/build-tools/37.0.0/apksigner sign --ks torus.jks --out torus.apk aligned.apk
```

## How the parts are confined

| Platform | Host (faces the network) | Converter (decodes videos) |
|---|---|---|
| Windows | AppContainer (never registered, so no profile folder) with only outbound internet, given its site's folder inside `TorusData`; a job object (one process, 4 GB) | AppContainer with no capabilities and an empty folder; 6 GB |
| Linux, Android | Landlock to its own folder; seccomp; no new privileges | Landlock to nothing; seccomp with no sockets |

The editor checks the sandbox from outside on every start, by asking the host to
open the vault. Where it can, the site is not put online. The one exception is
Android systems without Landlock: the site goes online, and the editor says that
files are not confined there.
