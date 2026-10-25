// Builds the portable Linux app: one folder holding the editor, the host
// program and the video converter. It needs no installer and keeps everything
// it stores in a TorusData folder beside itself.
//
//   node scripts/package-portable-linux.mjs
import { execFileSync } from "node:child_process";
import { chmodSync, copyFileSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const host = /host: (\S+)/.exec(execFileSync("rustc", ["-vV"], { encoding: "utf8" }))[1];
const triple = process.argv[2] ?? host;
const version = JSON.parse(readFileSync(join(root, "app", "src-tauri", "tauri.conf.json"), "utf8")).version;

// The host program and the converter, as the installer would ship them.
execFileSync("node", [join(root, "app", "scripts", "prepare-bundle.mjs"), triple], { stdio: "inherit" });
const targetFlag = triple === host ? [] : ["--target", triple];
execFileSync("npx", ["tauri", "build", ...targetFlag, "--no-bundle"], { cwd: join(root, "app"), stdio: "inherit" });

const metadata = JSON.parse(
  execFileSync("cargo", ["metadata", "--format-version", "1", "--no-deps"], { cwd: root, encoding: "utf8", maxBuffer: 1 << 26 }),
);
const release = join(metadata.target_directory, ...(triple === host ? [] : [triple]), "release");
const name = `Torus_${version}_linux_portable`;
const out = join(metadata.target_directory, "portable");
const folder = join(out, "Torus");
rmSync(out, { recursive: true, force: true });
mkdirSync(join(folder, "licenses"), { recursive: true });

const binaries = join(root, "app", "src-tauri", "binaries");
copyFileSync(join(release, "torus"), join(folder, "torus"));
chmodSync(join(folder, "torus"), 0o755);

copyFileSync(join(binaries, `torus-host-${triple}`), join(folder, "torus-host"));
chmodSync(join(folder, "torus-host"), 0o755);

copyFileSync(join(binaries, `ffmpeg-${triple}`), join(folder, "ffmpeg"));
chmodSync(join(folder, "ffmpeg"), 0o755);

const license = [
  join(root, "tools", "ffmpeg", "linux", "LICENSE.md"),
  join(root, "tools", "ffmpeg", "windows", "LICENSE.md"),
  join(root, "tools", "ffmpeg", "LICENSE.txt"),
].find(existsSync);
if (license) copyFileSync(license, join(folder, "licenses", "FFmpeg-LICENSE.txt"));

writeFileSync(
  join(folder, "README.txt"),
  [
    "Torus, portable.",
    "",
    "Run ./torus. Nothing is installed: everything Torus keeps, encrypted, is in the",
    "TorusData folder it makes beside itself. Move the whole Torus folder to take your",
    "sites with you; delete it to remove every trace of them.",
    "",
    "Each site's host process runs in a Linux Landlock and seccomp sandbox,",
    "and video conversions run in an isolated offline process.",
    "",
  ].join("\n"),
);

execFileSync("tar", ["-czf", `${name}.tar.gz`, "Torus"], { cwd: out, stdio: "inherit" });
try {
  execFileSync("zip", ["-r", "-9", `${name}.zip`, "Torus"], { cwd: out, stdio: "inherit" });
} catch {}
console.log(`Built ${join(out, `${name}.tar.gz`)}`);
