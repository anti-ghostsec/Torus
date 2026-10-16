// Builds the portable Windows app: one folder, zipped, holding the editor,
// the host program and the video converter. It needs no installer and keeps
// everything it stores in a TorusData folder beside itself.
//
//   node scripts/package-portable.mjs   # from Linux, with mingw-w64
import { execFileSync } from "node:child_process";
import { copyFileSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const triple = "x86_64-pc-windows-gnu";
const version = JSON.parse(readFileSync(join(root, "app", "src-tauri", "tauri.conf.json"), "utf8")).version;

// The host program and the converter, as the installer would ship them.
execFileSync("node", [join(root, "app", "scripts", "prepare-bundle.mjs"), triple], { stdio: "inherit" });
execFileSync("npx", ["tauri", "build", "--target", triple, "--no-bundle"], { cwd: join(root, "app"), stdio: "inherit" });

const metadata = JSON.parse(
  execFileSync("cargo", ["metadata", "--format-version", "1", "--no-deps"], { cwd: root, encoding: "utf8", maxBuffer: 1 << 26 }),
);
const release = join(metadata.target_directory, triple, "release");
const name = `Torus_${version}_windows_portable`;
const out = join(metadata.target_directory, "portable");
const folder = join(out, "Torus");
rmSync(out, { recursive: true, force: true });
mkdirSync(join(folder, "licenses"), { recursive: true });

const binaries = join(root, "app", "src-tauri", "binaries");
copyFileSync(join(release, "torus.exe"), join(folder, "torus.exe"));
copyFileSync(join(binaries, `torus-host-${triple}.exe`), join(folder, "torus-host.exe"));
copyFileSync(join(binaries, `ffmpeg-${triple}.exe`), join(folder, "ffmpeg.exe"));
// The browser engine's loader, where the build produced one beside the app.
if (existsSync(join(release, "WebView2Loader.dll"))) copyFileSync(join(release, "WebView2Loader.dll"), join(folder, "WebView2Loader.dll"));
const license = [join(root, "tools", "ffmpeg", "windows", "LICENSE.md"), join(root, "tools", "ffmpeg", "LICENSE.txt")].find(existsSync);
if (license) copyFileSync(license, join(folder, "licenses", "FFmpeg-LICENSE.md"));
writeFileSync(
  join(folder, "README.txt"),
  [
    "Torus, portable.",
    "",
    "Run torus.exe. Nothing is installed: everything Torus keeps, encrypted, is in the",
    "TorusData folder it makes beside itself. Move the whole Torus folder to take your",
    "sites with you; delete it to remove every trace of them.",
    "",
    "Keep the folder on an NTFS drive (any Windows disk, or a USB drive formatted NTFS):",
    "the sandbox that confines each site relies on NTFS permissions, and Torus refuses",
    "to put a site online where it cannot hold.",
    "",
  ].join("\r\n"),
);
execFileSync("zip", ["-r", "-9", `${name}.zip`, "Torus"], { cwd: out, stdio: "inherit" });
console.log(`Built ${join(out, `${name}.zip`)}`);
