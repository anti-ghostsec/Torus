// Puts the programs the Android app starts among its native libraries, the
// one place Android lets an app keep programs it can run: the host program
// (libtorus_host.so) and the video converter (libffmpeg.so). Each site's
// host then runs as a process of its own, confined, apart from the editor.
//
//   ANDROID_NDK_HOME=... node scripts/prepare-android.mjs
import { execFileSync } from "node:child_process";
import { copyFileSync, existsSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const ndk = process.env.ANDROID_NDK_HOME ?? process.env.NDK_HOME;
if (!ndk) throw new Error("Set ANDROID_NDK_HOME to the Android NDK.");
const tools = join(ndk, "toolchains", "llvm", "prebuilt", "linux-x86_64", "bin");

// Only 64-bit ARM: every phone sold for years, and what the converter is built for.
const triple = "aarch64-linux-android";
const abi = "arm64-v8a";
const clang = join(tools, `${triple}24-clang`);
const env = {
  ...process.env,
  CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER: clang,
  CC_aarch64_linux_android: clang,
  AR_aarch64_linux_android: join(tools, "llvm-ar"),
};
execFileSync("cargo", ["build", "--release", "-p", "torus-host", "--target", triple], { cwd: root, stdio: "inherit", env });
const metadata = JSON.parse(
  execFileSync("cargo", ["metadata", "--format-version", "1", "--no-deps"], { cwd: root, encoding: "utf8", maxBuffer: 1 << 26 }),
);

const libs = join(root, "app", "src-tauri", "gen", "android", "app", "src", "main", "jniLibs", abi);
mkdirSync(libs, { recursive: true });
copyFileSync(join(metadata.target_directory, triple, "release", "torus-host"), join(libs, "libtorus_host.so"));
const converter = join(root, "tools", "ffmpeg", "android", "ffmpeg");
if (!existsSync(converter)) throw new Error("The video converter is missing: run tools/ffmpeg/build.sh android");
copyFileSync(converter, join(libs, "libffmpeg.so"));
console.log(`Prepared ${libs}`);
