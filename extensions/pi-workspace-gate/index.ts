import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { isToolCallEventType } from "@earendil-works/pi-coding-agent";
import { resolve, toNamespacedPath, sep, join } from "node:path";
import { realpathSync } from "node:fs";
import { platform, homedir, tmpdir } from "node:os";

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
 * Directories treated as disposable scratch space.
 *
 * pi writes here constantly — truncated bash output (`pi-bash-*.log`), the
 * external-editor buffer (`pi-editor-*`), share staging (`pi-share-*`),
 * clipboard images and TUI crash logs. Gating those paths makes the extension
 * prompt on almost every turn, so they are allowed silently.
 *
 * Note pi uses `os.tmpdir()`, which on macOS is `/var/folders/…/T` (NOT `/tmp`).
 * Literal `/tmp` and `/var/tmp` are included as well, plus the `$TMPDIR`/`$TMP`/
 * `$TEMP` overrides, so the allowlist matches both what pi does and what users
 * typically type.
 */
let tempRootsCache: string[] | null = null;

/** Strip a trailing separator so `root + sep` comparisons stay clean. */
function stripTrailingSep(path: string): string {
  return path.length > 1 && (path.endsWith(sep) || path.endsWith("/"))
    ? path.slice(0, -1)
    : path;
}

/**
 * Expand one candidate temp root into the forms it should be matched against:
 * the literal resolved path *and* its symlink target. On macOS `/tmp` is a
 * symlink to `/private/tmp`, and `os.tmpdir()` returns `/var/folders/…/T`
 * whose real path is `/private/var/folders/…/T` — both forms are needed
 * because a path that does not exist yet cannot be realpath'd by the caller.
 */
function tempRootVariants(candidate: string | undefined): string[] {
  if (!candidate) return [];
  let absolute: string;
  try {
    absolute = resolve(expandTilde(candidate));
  } catch {
    return [];
  }
  const variants = [stripTrailingSep(normalizePath(absolute))];
  try {
    const real = realpathSync(absolute);
    if (real !== absolute) variants.push(stripTrailingSep(normalizePath(real)));
  } catch {
    // Root doesn't exist yet — the literal form is enough.
  }
  return variants;
}

function getTempRoots(): string[] {
  if (tempRootsCache) return tempRootsCache;

  const candidates: (string | undefined)[] = [
    tmpdir(),
    process.env.TMPDIR,
    process.env.TMP,
    process.env.TEMP,
  ];
  if (platform() === "win32") {
    candidates.push(
      process.env.SYSTEMROOT ? join(process.env.SYSTEMROOT, "Temp") : "C:\\Windows\\Temp",
    );
  } else {
    candidates.push("/tmp", "/var/tmp");
  }

  const roots = new Set<string>();
  for (const candidate of candidates) {
    for (const variant of tempRootVariants(candidate)) {
      if (variant) roots.add(variant);
    }
  }
  tempRootsCache = [...roots];
  return tempRootsCache;
}

/** Check a resolved path against the temp roots (symlinks already followed). */
function isInsideTempDir(path: string): boolean {
  const normalized = stripTrailingSep(normalizePath(path));
  for (const root of getTempRoots()) {
    if (normalized === root || normalized.startsWith(root + sep)) return true;
  }
  return false;
}

/**
 * True when a path is disposable scratch space: a `/dev/*` device file or
 * anything under a temp root.
 *
 * Both the unresolved and symlink-resolved forms are tested so that writing a
 * brand-new file into `/tmp` still matches (realpathSync falls back to the
 * unresolved path when the target does not exist yet). A symlink *inside* a
 * temp dir that points elsewhere still resolves outside the roots and is
 * therefore not treated as scratch — no symlink bypass.
 */
function isScratchPath(absolute: string, real: string): boolean {
  for (const candidate of [absolute, real]) {
    const normalized = toNamespacedPath(candidate);
    if (normalized === "/dev" || normalized.startsWith("/dev/")) return true;
    if (isInsideTempDir(candidate)) return true;
  }
  return false;
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

    // Allow /dev/* device files and temp dirs (pi writes there constantly)
    if (isScratchPath(absolute, real)) continue;

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

    // Sensitive files — always prompt, even inside workspace or a temp dir
    if (SENSITIVE_PATTERNS.some(re => re.test(normalized))) {
      const allowed = await ctx.ui.confirm(
        "Sensitive file",
        `Allow ${toolName} on ${normalized}?`,
      );
      if (!allowed) return { block: true, reason: "Blocked by user — sensitive file" };
      return;
    }

    // Disposable scratch space (/tmp, /var/tmp, os.tmpdir()) — allow silently
    if (isScratchPath(absolute, real)) return;

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
