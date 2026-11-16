// Sets the app version everywhere it is written down.
//   node scripts/set-version.mjs 0.2.0      (from apps/desktop)
// The release workflow refuses a tag that does not match these files.
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const version = process.argv[2];
// Plain MAJOR.MINOR.PATCH: the updater compares versions as semver, and the
// NSIS installer needs a numeric version.
if (!/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/.test(version ?? "")) {
  console.error("Kullanım: node scripts/set-version.mjs 1.2.3");
  process.exit(1);
}

const root = join(dirname(fileURLToPath(import.meta.url)), "..");

function edit(rel, fn) {
  const file = join(root, rel);
  const before = readFileSync(file, "utf8");
  const after = fn(before);
  if (after === before) throw new Error(`${rel}: sürüm alanı bulunamadı ya da zaten ${version}`);
  writeFileSync(file, after);
  console.log(`${rel}: ${version}`);
}

// The first `"version": "..."` lines of each file (formatting kept as is):
// the app's own version, then for package-lock.json the root package's.
const firstVersions = (n) => (text) => {
  let left = n;
  return text.replace(/^(\s*"version": )"[^"]*"/gm, (m, head) =>
    left-- > 0 ? `${head}"${version}"` : m,
  );
};

edit("package.json", firstVersions(1));
edit("package-lock.json", firstVersions(2));
edit("src-tauri/tauri.conf.json", firstVersions(1));
edit("src-tauri/Cargo.toml", (t) =>
  t.replace(/^(name = "lockalperen-desktop"\r?\nversion = )"[^"]*"/m, `$1"${version}"`),
);
edit("src-tauri/Cargo.lock", (t) =>
  t.replace(/(name = "lockalperen-desktop"\r?\nversion = )"[^"]*"/, `$1"${version}"`),
);
