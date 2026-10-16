// Puts the programs the installer ships beside the app where the bundler
// looks for them: the host program, built for release, and the video converter.
//
//   node scripts/prepare-bundle.mjs                         # for this computer
//   node scripts/prepare-bundle.mjs x86_64-pc-windows-gnu   # for Windows, from Linux
import { execFileSync } from "node:child_process";
import { copyFileSync, existsSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const host = /host: (\S+)/.exec(execFileSync("rustc", ["-vV"], { encoding: "utf8" }))[1];
const triple = process.argv[2] ?? host;
const exe = triple.includes("windows") ? ".exe" : "";

const cross = triple === host ? [] : ["--target", triple];
execFileSync("cargo", ["build", "--release", "-p", "torus-host", ...cross], { cwd: root, stdio: "inherit" });
const metadata = JSON.parse(
  execFileSync("cargo", ["metadata", "--format-version", "1", "--no-deps"], { cwd: root, encoding: "utf8", maxBuffer: 1 << 26 }),
);
const built = join(metadata.target_directory, ...(triple === host ? [] : [triple]), "release", `torus-host${exe}`);

const binaries = join(root, "app", "src-tauri", "binaries");
mkdirSync(binaries, { recursive: true });
copyFileSync(built, join(binaries, `torus-host-${triple}${exe}`));

// Built by tools/ffmpeg/build.sh windows, or put in place by hand.
const converter = [join(root, "tools", "ffmpeg", "windows", `ffmpeg${exe}`), join(root, "tools", "ffmpeg", `ffmpeg${exe}`)].find(existsSync);
if (!converter) {
  throw new Error("The video converter is missing: run tools/ffmpeg/build.sh windows");
}
copyFileSync(converter, join(binaries, `ffmpeg-${triple}${exe}`));
console.log(`Prepared ${binaries}`);
