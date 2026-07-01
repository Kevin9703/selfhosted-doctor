import fs from "node:fs";
import path from "node:path";
import fg from "fast-glob";
import type { LoadedFile } from "./model";

export interface LoadedInputs {
  target: string;
  files: LoadedFile[];
}

type Kind = LoadedFile["kind"];

function basename(p: string): string {
  return path.basename(p);
}

/** Decide the kind for a given file path by filename/location. */
function classify(p: string): Kind | undefined {
  const name = basename(p);
  const lower = name.toLowerCase();

  // compose: {docker-compose,compose}*.{yml,yaml}
  if (/^(docker-compose|compose).*\.(ya?ml)$/i.test(name)) {
    return "compose";
  }

  // env: .env, .env.*, *.env
  if (lower === ".env" || lower.startsWith(".env.") || lower.endsWith(".env")) {
    return "env";
  }

  // cloudflared: config.{yml,yaml} OR any yml/yaml under a cloudflared/ directory
  if (/^config\.(ya?ml)$/i.test(name)) {
    return "cloudflared";
  }
  if (/\.(ya?ml)$/i.test(name) && /(^|[\\/])cloudflared([\\/])/i.test(p)) {
    return "cloudflared";
  }

  return undefined;
}

function readLoadedFile(resolvedPath: string, displayPath: string): LoadedFile | undefined {
  const kind = classify(displayPath) ?? classify(resolvedPath);
  if (!kind) return undefined;
  let content: string;
  try {
    content = fs.readFileSync(resolvedPath, "utf8");
  } catch {
    return undefined;
  }
  return { path: displayPath, kind, content };
}

const KIND_ORDER: Record<Kind, number> = {
  compose: 0,
  env: 1,
  cloudflared: 2,
};

function sortFiles(files: LoadedFile[]): LoadedFile[] {
  return [...files].sort((a, b) => {
    const ka = KIND_ORDER[a.kind];
    const kb = KIND_ORDER[b.kind];
    if (ka !== kb) return ka - kb;
    return a.path < b.path ? -1 : a.path > b.path ? 1 : 0;
  });
}

export function loadInputs(inputPath: string): LoadedInputs {
  let stat: fs.Stats;
  try {
    stat = fs.statSync(inputPath);
  } catch {
    throw new Error(`Input path does not exist: ${inputPath}`);
  }

  // Prefer cwd-relative paths when the input was relative, else absolute.
  const inputIsRelative = !path.isAbsolute(inputPath);
  const cwd = process.cwd();
  const display = (resolved: string): string => {
    if (inputIsRelative) {
      const rel = path.relative(cwd, resolved);
      if (rel && !rel.startsWith("..") && !path.isAbsolute(rel)) return rel;
    }
    return resolved;
  };

  // Map from resolved absolute path -> LoadedFile (dedupe by resolved path).
  const byResolved = new Map<string, LoadedFile>();

  const add = (resolvedPath: string): void => {
    const absolute = path.resolve(resolvedPath);
    if (byResolved.has(absolute)) return;
    const loaded = readLoadedFile(absolute, display(resolvedPath));
    if (loaded) byResolved.set(absolute, loaded);
  };

  if (stat.isFile()) {
    // Treat the file itself as a compose file regardless of its name.
    const absolute = path.resolve(inputPath);
    let content: string | undefined;
    try {
      content = fs.readFileSync(absolute, "utf8");
    } catch {
      content = undefined;
    }
    if (content !== undefined) {
      byResolved.set(absolute, { path: display(inputPath), kind: "compose", content });
    }

    // Also scan its containing directory (non-recursive) for siblings.
    const dir = path.dirname(inputPath);
    let entries: fs.Dirent[] = [];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      entries = [];
    }
    for (const entry of entries) {
      if (!entry.isFile()) continue;
      const siblingResolved = path.join(dir, entry.name);
      const siblingAbs = path.resolve(siblingResolved);
      if (byResolved.has(siblingAbs)) continue;
      const kind = classify(entry.name);
      if (kind === "env" || kind === "cloudflared") {
        add(siblingResolved);
      }
    }
  } else if (stat.isDirectory()) {
    const patterns = [
      "**/{docker-compose,compose}*.{yml,yaml}",
      "**/.env",
      "**/.env.*",
      "**/*.env",
      "**/config.{yml,yaml}",
      "**/cloudflared/**/*.{yml,yaml}",
    ];
    let matches: string[] = [];
    try {
      matches = fg.sync(patterns, {
        cwd: inputPath,
        dot: true,
        deep: 5,
        onlyFiles: true,
        ignore: ["**/node_modules/**", "**/.git/**"],
        absolute: false,
      });
    } catch {
      matches = [];
    }
    for (const rel of matches) {
      add(path.join(inputPath, rel));
    }
  } else {
    throw new Error(`Input path is neither a file nor a directory: ${inputPath}`);
  }

  return {
    target: inputPath,
    files: sortFiles([...byResolved.values()]),
  };
}
