// Puts the programs the installer ships beside the app where the bundler
// looks for them: the host program, built for release, and the video converter.
import { execFileSync } from "node:child_process";
import { copyFileSync, existsSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const triple = /host: (\S+)/.exec(execFileSync("rustc", ["-vV"], { encoding: "utf8" }))[1];
const exe = triple.includes("windows") ? ".exe" : "";

execFileSync("cargo", ["build", "--release", "-p", "torus-host"], { cwd: root, stdio: "inherit" });
const metadata = JSON.parse(
  execFileSync("cargo", ["metadata", "--format-version", "1", "--no-deps"], { cwd: root, encoding: "utf8", maxBuffer: 1 << 26 }),
);

const binaries = join(root, "app", "src-tauri", "binaries");
mkdirSync(binaries, { recursive: true });
copyFileSync(join(metadata.target_directory, "release", `torus-host${exe}`), join(binaries, `torus-host-${triple}${exe}`));

const converter = join(root, "tools", "ffmpeg", `ffmpeg${exe}`);
if (!existsSync(converter)) {
  throw new Error(`The video converter is missing: ${converter}`);
}
copyFileSync(converter, join(binaries, `ffmpeg-${triple}${exe}`));
console.log(`Prepared ${binaries}`);
