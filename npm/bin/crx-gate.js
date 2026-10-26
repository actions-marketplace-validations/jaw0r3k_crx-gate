#!/usr/bin/env node

const { spawnSync } = require("child_process");
const fs = require("fs");
const path = require("path");
const os = require("os");
const https = require("https");

const VERSION = "0.1.0";
const REPO = "jaw0r3k/crx-gate";

function getBinaryName() {
  const platform = os.platform();
  const arch = os.arch();

  let targetArch = arch === "x64" ? "x86_64" : arch === "arm64" ? "aarch64" : null;
  if (!targetArch) {
    console.error(`crx-gate error: Unsupported CPU architecture '${arch}'.`);
    process.exit(1);
  }

  if (platform === "linux") {
    return {
      artifact: `crx-gate-${targetArch}-unknown-linux-gnu.tar.gz`,
      binaryName: "crx-gate",
      isZip: false,
    };
  } else if (platform === "darwin") {
    return {
      artifact: `crx-gate-${targetArch}-apple-darwin.tar.gz`,
      binaryName: "crx-gate",
      isZip: false,
    };
  } else if (platform === "win32") {
    return {
      artifact: `crx-gate-x86_64-pc-windows-msvc.zip`,
      binaryName: "crx-gate.exe",
      isZip: true,
    };
  } else {
    console.error(`crx-gate error: Unsupported OS '${platform}'.`);
    process.exit(1);
  }
}

function getLocalBinaryPath() {
  // Check local release build first if developing locally
  const localTarget = path.join(__dirname, "..", "..", "target", "release", process.platform === "win32" ? "crx-gate.exe" : "crx-gate");
  if (fs.existsSync(localTarget)) {
    return localTarget;
  }

  const { binaryName } = getBinaryName();
  const cacheDir = path.join(os.homedir(), ".crx-gate", `v${VERSION}`);
  return path.join(cacheDir, binaryName);
}

function runBinary(binPath, args) {
  const result = spawnSync(binPath, args, { stdio: "inherit" });
  if (result.error) {
    console.error("Execution error:", result.error);
    process.exit(1);
  }
  process.exit(result.status !== null ? result.status : 0);
}

function downloadBinary(url, dest, cb) {
  https.get(url, (res) => {
    if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
      downloadBinary(res.headers.location, dest, cb);
      return;
    }
    if (res.statusCode !== 200) {
      cb(new Error(`Failed to download binary: HTTP ${res.statusCode}`));
      return;
    }
    const file = fs.createWriteStream(dest);
    res.pipe(file);
    file.on("finish", () => {
      file.close(() => cb(null));
    });
  }).on("error", (err) => {
    cb(err);
  });
}

function main() {
  const args = process.argv.slice(2);
  const binPath = getLocalBinaryPath();

  if (fs.existsSync(binPath)) {
    runBinary(binPath, args);
    return;
  }

  const { artifact, binaryName, isZip } = getBinaryName();
  const cacheDir = path.join(os.homedir(), ".crx-gate", `v${VERSION}`);
  fs.mkdirSync(cacheDir, { recursive: true });

  const archivePath = path.join(cacheDir, artifact);
  const downloadUrl = `https://github.com/${REPO}/releases/download/v${VERSION}/${artifact}`;

  console.log(`crx-gate: Fetching pre-compiled release binary (v${VERSION})...`);
  downloadBinary(downloadUrl, archivePath, (err) => {
    if (!err) {
      try {
        if (isZip) {
          spawnSync("powershell", ["-Command", `Expand-Archive -Path '${archivePath}' -DestinationPath '${cacheDir}' -Force`]);
        } else {
          spawnSync("tar", ["-xzf", archivePath, "-C", cacheDir]);
        }
        if (fs.existsSync(binPath)) {
          if (process.platform !== "win32") {
            fs.chmodSync(binPath, 0o755);
          }
          try { fs.unlinkSync(archivePath); } catch (_) {}
          runBinary(binPath, args);
          return;
        }
      } catch (_) {}
    }

    // Fallback to cargo run if developing in repo
    const cargoRun = spawnSync("cargo", ["run", "--release", "--quiet", "--", ...args], {
      stdio: "inherit",
      cwd: path.join(__dirname, "..", ".."),
    });

    if (cargoRun.status === 0) {
      process.exit(0);
    }

    console.error(`crx-gate error: Could not run or download binary. Please install via cargo: 'cargo install crx-gate'`);
    process.exit(1);
  });
}

main();
