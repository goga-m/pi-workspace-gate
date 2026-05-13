import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { isToolCallEventType } from "@earendil-works/pi-coding-agent";
import { resolve, toNamespacedPath, sep } from "node:path";
import { realpathSync } from "node:fs";
import { platform, homedir } from "node:os";

const FILE_TOOLS = ["read", "write", "edit", "grep", "find", "ls"] as const;

// Files that always require confirmation, regardless of location
// Use [\\/] to match both forward and backward slashes on all platforms
const SENSITIVE_PATTERNS = [
  /\.env$/i,
  /\.npmrc$/i,
  /\.pypirc$/i,
  /\.netrc$/i,
  /id_rsa$/i,
  /id_ed25519$/i,
  /\.ssh[\\/]/i,
  /\.aws[\\/]credentials/i,
  /\.gnupg/i,
  /\.docker[\\/]config\.json/i,
  /token/i,
  /secret/i,
  /credential/i,
  /\.key$/i,
  /\.pem$/i,
];

// Bash: file copy commands
const FILE_COPY_PATTERNS = [
  /\bcp\s+/i,
  /\bscp\s+/i,
  /\brsync\s+/i,
];

// Bash: package manager installs
const PACKAGE_INSTALL_PATTERNS = [
  /npm\s+install\b/i,
  /yarn\s+add\b/i,
  /pnpm\s+add\b/i,
  /pip\s+install\b/i,
  /cargo\s+install\b/i,
  /go\s+install\b/i,
  /gem\s+install\b/i,
  /composer\s+require\b/i,
];

// Bash: system modifications
const SYSTEM_MOD_PATTERNS = [
  /apt\s+(get\s+)?install\b/i,
  /brew\s+install\b/i,
  /yum\s+install\b/i,
  /dnf\s+install\b/i,
  /apk\s+add\b/i,
  /snap\s+install\b/i,
  /chmod\s+[^\s]+\s+[^\/]/,  // chmod on absolute path outside workspace
  /chown\s+[^\s]+\s+[^\/]/,   // chown on absolute path outside workspace
];

/**
 * Expand leading ~/ or ~\ to the user's home directory.
 */
function expandTilde(path: string): string {
  const home = homedir();
  if (path === "~") {
    return home;
  } else if (path.startsWith("~/") || path.startsWith("~\\")) {
    return home + path.slice(1);
  }
  return path;
}

/**
 * Extract file paths from a bash command.
 * Matches absolute paths (/...), tilde paths (~/...), and relative paths with ../ that escape the workspace.
 */
function extractPathsFromCommand(cmd: string): string[] {
  const paths: string[] = [];
  // Match absolute paths — / must be at start of string or after whitespace/quote (not after . or word chars)
  const absoluteMatches = cmd.match(/(?:^|(?<=[\s"'`(]))\/[^\s"'`)]+/g);
  if (absoluteMatches) paths.push(...absoluteMatches);
  // Match tilde paths (~...)
  const tildeMatches = cmd.match(/~\\?[^\s"'`)]+/g);
  if (tildeMatches) {
    paths.push(...tildeMatches.map(expandTilde));
  }
  // Match relative paths with ../ (potential workspace escape)
  const relativeMatches = cmd.match(/\.\.\/[^\s"'`)]+/g);
  if (relativeMatches) paths.push(...relativeMatches);
  return paths;
}

/**
 * Normalize a path for consistent comparison across platforms.
 * - Uses platform-native separator
 * - Lowercases on Windows (case-insensitive filesystem)
 */
function normalizePath(path: string): string {
  const normalized = toNamespacedPath(path);
  return platform() === "win32" ? normalized.toLowerCase() : normalized;
}

/**
 * Check if a path is inside the workspace.
 */
function isInsideWorkspace(path: string, cwd: string): boolean {
  const normPath = normalizePath(path);
  const normCwd = normalizePath(cwd);
  return normPath === normCwd || normPath.startsWith(normCwd + sep);
}

/**
 * Check if any path in the command escapes the workspace.
 */
function hasPathsOutsideWorkspace(cmd: string, cwd: string): boolean {
  const paths = extractPathsFromCommand(cmd);

  for (const path of paths) {
    const absolute = resolve(cwd, path);
    let real: string;
    try {
      real = realpathSync(absolute);
    } catch {
      real = absolute;
    }

    // Allow /dev/* device files (e.g., /dev/null, /dev/zero)
    const normalized = toNamespacedPath(real);
    if (normalized === "/dev" || normalized.startsWith("/dev/")) continue;

    if (!isInsideWorkspace(real, cwd)) {
      return true;
    }
  }
  return false;
}

export default function (pi: ExtensionAPI) {
  pi.on("tool_call", async (event, ctx) => {
    const toolName = event.toolName;

    // --- Bash: gate dangerous commands ---
    if (isToolCallEventType("bash", event)) {
      const cmd = event.input.command;
      const dangerousPatterns = [
        /rm\s+(-rf?|-fr)/,       // rm -rf, rm -r, rm -f
        /sudo\b/,                 // sudo anything
        /mkfs\b/,                 // format filesystem
        /dd\s+if=/,              // dd with input file
        /chmod\s+[0-7]*[7]\d{2}\s/, // chmod with world-writable
      ];

      if (dangerousPatterns.some(re => re.test(cmd))) {
        const allowed = await ctx.ui.confirm(
          "Dangerous command",
          `Allow: ${cmd}?`,
        );
        if (!allowed) return { block: true, reason: "Blocked by user" };
      }

      // Package manager installs
      if (PACKAGE_INSTALL_PATTERNS.some(re => re.test(cmd))) {
        const allowed = await ctx.ui.confirm(
          "Package install",
          `Allow: ${cmd}?`,
        );
        if (!allowed) return { block: true, reason: "Blocked by user" };
      }

      // System modifications
      if (SYSTEM_MOD_PATTERNS.some(re => re.test(cmd))) {
        const allowed = await ctx.ui.confirm(
          "System modification",
          `Allow: ${cmd}?`,
        );
        if (!allowed) return { block: true, reason: "Blocked by user" };
      }

      // File copy commands
      if (FILE_COPY_PATTERNS.some(re => re.test(cmd))) {
        const allowed = await ctx.ui.confirm(
          "File copy",
          `Allow: ${cmd}?`,
        );
        if (!allowed) return { block: true, reason: "Blocked by user" };
      }

      // Any command with paths outside workspace (catches redirections, touch, etc.)
      if (hasPathsOutsideWorkspace(cmd, ctx.cwd)) {
        const allowed = await ctx.ui.confirm(
          "Path outside workspace",
          `Allow: ${cmd}?`,
        );
        if (!allowed) return { block: true, reason: "Blocked by user" };
      }

      return;
    }

    // --- File tools: gate paths outside workspace ---
    if (!FILE_TOOLS.includes(toolName as any)) return;

    // Extract the path argument
    let targetPath: string | undefined;

    if (isToolCallEventType("read", event)) targetPath = event.input.path;
    else if (isToolCallEventType("write", event)) targetPath = event.input.path;
    else if (isToolCallEventType("edit", event)) targetPath = event.input.path;
    else if (isToolCallEventType("grep", event)) targetPath = event.input.path;
    else if (isToolCallEventType("find", event)) targetPath = event.input.path;
    else if (isToolCallEventType("ls", event)) targetPath = event.input.path;

    if (!targetPath) return;

    // Expand ~ before resolving
    const expandedTarget = expandTilde(targetPath);

    // Resolve relative paths against cwd, then follow symlinks
    const absolute = resolve(ctx.cwd, expandedTarget);
    let real: string;
    try {
      real = realpathSync(absolute);
    } catch {
      real = absolute; // File doesn't exist yet (e.g. write) — use resolved path
    }

    // Normalize for consistent comparison
    const normalized = toNamespacedPath(real);

    // Sensitive files — always prompt, even inside workspace
    if (SENSITIVE_PATTERNS.some(re => re.test(normalized))) {
      const allowed = await ctx.ui.confirm(
        "Sensitive file",
        `Allow ${toolName} on ${normalized}?`,
      );
      if (!allowed) return { block: true, reason: "Blocked by user — sensitive file" };
      return;
    }

    // Inside workspace — allow silently
    if (isInsideWorkspace(real, ctx.cwd)) return;

    // Outside workspace — ask for permission
    const allowed = await ctx.ui.confirm(
      "Outside workspace",
      `Allow ${toolName} on ${real}?`,
    );

    if (!allowed) {
      return { block: true, reason: "Blocked by user — path is outside the workspace" };
    }
  });
}
