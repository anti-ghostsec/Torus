# Building Torus

Both targets build from a Linux machine (tested on Ubuntu 24.04).

## Requirements

- Rust (stable) with the targets `x86_64-pc-windows-gnu` and `aarch64-linux-android`
- Node 22 and `npm install` in `app/`
- Windows: `mingw-w64` and `nsis`
- Android: the Android SDK (platform `android-37.0`, build-tools 37) and NDK 29, with
  `ANDROID_HOME` and `ANDROID_NDK_HOME` set, and Java 17+
- Video converter: `git`, `curl`, `make`, `nasm`/`yasm`, `pkg-config`

## The video converter

Every uploaded video is encoded afresh by FFmpeg in a sandbox before anyone can
watch it. Build the static, LGPL-only FFmpeg the app ships (VP9/Opus, no network
code) once per target:

```sh
tools/ffmpeg/build.sh windows   # -> tools/ffmpeg/windows/ffmpeg.exe
ANDROID_NDK_HOME=... tools/ffmpeg/build.sh android   # -> tools/ffmpeg/android/ffmpeg
```

## Windows

```sh
cd app && npm run bundle:windows
```

The installer lands in `target/x86_64-pc-windows-gnu/release/bundle/nsis/`.

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
| Windows | AppContainer with only outbound internet; a job object (one process, 4 GB) | AppContainer with no capabilities; 6 GB |
| Linux, Android | Landlock to its own folder; seccomp; no new privileges | Landlock to nothing; seccomp with no sockets |

The editor checks the sandbox from outside on every start, by asking the host to
open the vault. Where it can, the site is not put online. The one exception is
Android systems without Landlock: the site goes online, and the editor says that
files are not confined there.
