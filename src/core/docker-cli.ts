/**
 * Read-only bridge to the local Docker CLI for `--running`.
 *
 * We shell out to ONLY `docker ps` and `docker inspect` — both strictly
 * read-only. We NEVER run anything that creates, starts, stops, removes, or
 * otherwise mutates containers, images, networks, or configuration. This upholds
 * the tool's core promise: it can now read live container config, but it still
 * changes nothing.
 *
 * If the Docker CLI is missing or the daemon isn't reachable, we throw a
 * friendly Error (no stack trace) that points the user at the offline
 * `docker inspect > file.json` export flow, which they can scan the same way.
 */
import { execFileSync } from "node:child_process";
import { looksLikeDockerInspect, type DockerInspectContainer } from "./docker-inspect";

/** Label used as the report `target` when scanning live containers. */
export const RUNNING_TARGET = "running containers (docker inspect)";

const EXPORT_HINT =
  "Tip: if this machine can't reach the Docker daemon, run this on the host and scan the file:\n" +
  "  docker inspect $(docker ps -q) > containers.json\n" +
  "  selfhosted-doctor expose containers.json";

interface ExecError extends NodeJS.ErrnoException {
  stderr?: Buffer | string;
  status?: number;
}

function runDocker(args: string[]): string {
  try {
    return execFileSync("docker", args, {
      encoding: "utf8",
      maxBuffer: 64 * 1024 * 1024,
      stdio: ["ignore", "pipe", "pipe"],
    });
  } catch (err) {
    const e = err as ExecError;
    if (e.code === "ENOENT") {
      throw new Error(
        `Docker CLI not found on PATH, so --running can't inspect live containers.\n${EXPORT_HINT}`,
      );
    }
    const stderr = typeof e.stderr === "string" ? e.stderr : (e.stderr?.toString() ?? "");
    const firstLine = stderr.trim().split("\n")[0] ?? "";
    throw new Error(
      `Couldn't talk to the Docker daemon (\`docker ${args[0]}\` failed${firstLine ? `: ${firstLine}` : ""}).\n` +
        `Make sure Docker is running and your user can access it.\n${EXPORT_HINT}`,
    );
  }
}

/**
 * Collect running containers via read-only `docker ps -q` + `docker inspect`.
 * Returns an empty array when there are no running containers. Throws a friendly
 * Error when Docker is unavailable.
 */
export function collectRunningContainers(): DockerInspectContainer[] {
  const psOut = runDocker(["ps", "-q"]);
  const ids = psOut
    .split(/\r?\n/)
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
  if (ids.length === 0) return [];

  const inspectOut = runDocker(["inspect", ...ids]);
  let parsed: unknown;
  try {
    parsed = JSON.parse(inspectOut);
  } catch {
    throw new Error("Could not parse `docker inspect` output as JSON.");
  }
  if (looksLikeDockerInspect(parsed)) return parsed;
  if (Array.isArray(parsed) && parsed.length === 0) return [];
  throw new Error("`docker inspect` returned an unexpected shape; nothing to scan.");
}
