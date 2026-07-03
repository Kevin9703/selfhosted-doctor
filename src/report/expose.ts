/**
 * Terminal renderer for the `expose` command.
 *
 * Where `scan` dumps a score and every finding, `expose` answers one question —
 * "can I open this to the internet?" — as a decision with a short, prioritized
 * to-do list. The heavy lifting (what's a blocker vs. hygiene) lives in
 * core/verdict.ts; this file only formats an ExposeAssessment for a terminal.
 */
import pc from "picocolors";
import type { ExposeAssessment, Verdict } from "../core/verdict";

type Colors = ReturnType<typeof pc.createColors>;

interface VerdictStyle {
  icon: string;
  label: string;
  paint: (c: Colors, s: string) => string;
}

const VERDICT_STYLE: Record<Verdict, VerdictStyle> = {
  "dont-expose": {
    icon: "⛔",
    label: "DON'T EXPOSE YET",
    paint: (c, s) => c.bold(c.red(s)),
  },
  "behind-access": {
    icon: "🔒",
    label: "EXPOSE ONLY BEHIND ACCESS",
    paint: (c, s) => c.bold(c.yellow(s)),
  },
  "check-manually": {
    icon: "❓",
    label: "CHECK MANUALLY",
    paint: (c, s) => c.bold(c.yellow(s)),
  },
  "looks-ok": {
    icon: "✅",
    label: "LOOKS OK TO EXPOSE",
    paint: (c, s) => c.bold(c.green(s)),
  },
};

/** "nginx 80/443, plugin_daemon 5003 (+1 variable port)" from the entry points. */
function entryPointsPhrase(a: ExposeAssessment): string {
  return a.entryPoints
    .map((p) => {
      const resolved = p.ports.join("/");
      const variable =
        p.variablePorts && p.variablePorts.length > 0
          ? `${resolved ? " " : ""}+${p.variablePorts.length} variable`
          : "";
      const detail = `${resolved}${variable}`.trim();
      return detail ? `${p.service} ${detail}` : p.service;
    })
    .join(", ");
}

/** The top "mirror" line: what is reachable from the internet. */
function topLine(c: Colors, a: ExposeAssessment): string {
  const n = a.entryPoints.length;
  const parts: string[] = [];
  if (n > 0) {
    parts.push(`${n} entry point${n === 1 ? "" : "s"} reachable from the internet (${entryPointsPhrase(a)})`);
  }
  if (a.hasTunnel) {
    parts.push(n > 0 ? "plus a Cloudflare Tunnel" : "reachable via a Cloudflare Tunnel");
  }
  if (parts.length === 0) {
    parts.push("no ports published to 0.0.0.0 in this file");
  }
  return `${c.bold(a.stackLabel)} · ${parts.join(", ")}`;
}

export function renderExpose(a: ExposeAssessment, opts?: { color?: boolean }): string {
  const c: Colors = opts?.color === false ? pc.createColors(false) : pc;
  const lines: string[] = [];
  const pad = "  ";

  lines.push("");
  lines.push(pad + topLine(c, a));
  lines.push(
    pad + c.dim("(reachable if this host has a public IP or a forwarded port — inferred from your config, not probed)"),
  );

  // Verdict banner.
  const style = VERDICT_STYLE[a.verdict];
  lines.push("");
  lines.push(pad + style.paint(c, `${style.icon}  ${style.label}`));

  // Blockers — the genuinely dangerous list.
  if (a.blockers.length > 0) {
    const total = a.blockers.length + a.blockerOverflow;
    lines.push("");
    lines.push(pad + c.bold(`Genuinely dangerous — ${total} thing${total === 1 ? "" : "s"}:`));
    for (const b of a.blockers) {
      lines.push(pad + `${c.red("●")}  ${b.headline}`);
      if (b.why) lines.push(pad + `   ${c.dim(b.why)}`);
      if (b.fixes && b.fixes.length > 0) {
        for (const fx of b.fixes) lines.push(pad + `   Fix:  ${c.cyan(fx)}`);
      } else if (b.fix) {
        lines.push(pad + `   Fix:  ${c.cyan(b.fix)}`);
      }
    }
    if (a.blockerOverflow > 0) {
      lines.push(
        pad +
          c.dim(`   +${a.blockerOverflow} more blocker${a.blockerOverflow === 1 ? "" : "s"} — run \`scan\` for the full list.`),
      );
    }
  }

  // Check-manually explanation.
  if (a.verdict === "check-manually" && a.unresolvedPorts.length > 0) {
    lines.push("");
    lines.push(pad + c.bold("Couldn't decide — dynamic ports this tool can't resolve:"));
    for (const u of a.unresolvedPorts) {
      lines.push(pad + `${c.yellow("?")}  ${u.service}: ${u.raw}`);
    }
    lines.push(pad + `   ${c.dim("Resolve these values (e.g. check your .env), then run expose again.")}`);
  }

  // Secondary: access + change-before-public.
  const secondary = [...a.access, ...a.changeBeforePublic];
  if (secondary.length > 0) {
    lines.push("");
    lines.push(pad + c.bold("Also handle before going public:"));
    for (const item of secondary) {
      lines.push(pad + `${c.yellow("○")}  ${item.headline}`);
      if (item.why) lines.push(pad + `   ${c.dim(item.why)}`);
      if (item.action) lines.push(pad + `   → ${item.action}`);
      if (item.fix) lines.push(pad + `   Fix:  ${c.cyan(item.fix)}`);
    }
  }

  // Hygiene, collapsed to a single line.
  if (a.hygieneCount > 0) {
    lines.push("");
    lines.push(
      pad +
        c.dim(
          `${a.hygieneCount} hygiene item${a.hygieneCount === 1 ? "" : "s"} (healthchecks, unpinned images, restart policies) won't get you hacked — run \`scan\` for the full list.`,
        ),
    );
  }

  // Conditional (profile-gated) note.
  const condTotal = a.conditionalHigh + a.conditionalMedium;
  if (condTotal > 0) {
    const sevParts: string[] = [];
    if (a.conditionalHigh > 0) sevParts.push(`${a.conditionalHigh} high`);
    if (a.conditionalMedium > 0) sevParts.push(`${a.conditionalMedium} medium`);
    const profiles = a.conditionalProfiles.slice(0, 5).join(", ");
    const more = a.conditionalProfiles.length > 5 ? ", …" : "";
    const profileNote = profiles ? ` if you enable optional profiles (${profiles}${more})` : ` if you enable optional profiles`;
    lines.push("");
    lines.push(pad + c.dim(`${condTotal} more issue${condTotal === 1 ? "" : "s"} (${sevParts.join(", ")}) appear${profileNote}.`));
  }

  for (const note of a.notes) {
    lines.push("");
    lines.push(pad + c.yellow(`Note: ${note}`));
  }

  // Closing call to action.
  lines.push("");
  lines.push(pad + c.dim(closingLine(a.verdict)));
  lines.push("");

  return lines.join("\n");
}

function closingLine(verdict: Verdict): string {
  switch (verdict) {
    case "dont-expose":
      return "Fix the items above, then run `expose` again.";
    case "behind-access":
      return "Put the public surface behind access control, handle the items above, then run `expose` again.";
    case "check-manually":
      return "Resolve the items above manually, then run `expose` again to get a verdict.";
    case "looks-ok":
      return "No active blockers. Keep the items above in mind and re-run `expose` after any change.";
    default: {
      const exhaustive: never = verdict;
      return String(exhaustive);
    }
  }
}
