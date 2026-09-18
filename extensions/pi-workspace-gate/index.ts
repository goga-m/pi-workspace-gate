import type {
  ExtensionAPI,
  ExtensionContext,
  ToolCallEventResult,
} from "@earendil-works/pi-coding-agent";
import { isToolCallEventType } from "@earendil-works/pi-coding-agent";
import { resolve, toNamespacedPath, sep, join } from "node:path";
import { realpathSync } from "node:fs";
import { platform, homedir, tmpdir } from "node:os";

const IS_WINDOWS = platform() === "win32";

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

// Basename-only forms, used for bare command tokens (`cat .env`). The full
// SENSITIVE_PATTERNS include loose word matches (`/token/i`, `/secret/i`) that
// would fire on ordinary prose if applied to every shell token.
const SENSITIVE_BASENAME_PATTERNS = [
  /^\.env$/i,
  /^\.npmrc$/i,
  /^\.pypirc$/i,
  /^\.netrc$/i,
  /^id_rsa$/i,
  /^id_ed25519$/i,
  /\.pem$/i,
  /\.key$/i,
];

// Bash: file copy commands (`cp` is also the PowerShell Copy-Item alias)
const FILE_COPY_PATTERNS = [
  /\bcp\s+/i,
  /\bscp\s+/i,
  /\brsync\s+/i,
  /\bCopy-Item\b/i,
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
  /\bwinget\s+install\b/i,
  /\bchoco\s+install\b/i,
  /\bscoop\s+install\b/i,
  /\bInstall-(Module|Package|Script)\b/i,
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
  /\bSet-ExecutionPolicy\b/i,
  /\breg\s+(add|delete)\b/i,
  /\bnetsh\b/i,
  /\bNew-Service\b/i,
];

// Shell: destructive commands. Covers POSIX shells and PowerShell/cmd, where
// `rm`, `del`, `rd` and `erase` are all Remove-Item aliases.
const DANGEROUS_COMMAND_PATTERNS = [
  /rm\s+(-rf?|-fr)/,              // rm -rf, rm -r, rm -f
  /sudo\b/,                       // sudo anything
  /mkfs\b/,                       // format filesystem
  /dd\s+if=/,                     // dd with input file
  /chmod\s+[0-7]*[7]\d{2}\s/,     // chmod with world-writable
  /\b(?:Remove-Item|del|erase|rd|rmdir|rm)\b[^\n;|&]*\s-(?:Recurse|Force)\b/i,
  /\bRemove-Item\b[^\n;|&]*\s\/(?:s|q)\b/i,
  /\bFormat-Volume\b|\bClear-Disk\b/i,
  /\bClear-RecycleBin\b/i,
  /\b(?:Stop-Computer|Restart-Computer)\b/i,
  /\bSet-MpPreference\b[^\n;|&]*Disable/i,
  /\b(?:Invoke-Expression|\biex)\b/i,
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
 * Rewrite Git Bash / Cygwin POSIX paths as native Windows paths.
 *
 * pi uses Git Bash by default on Windows, so the model emits `/c/Users/you/x`
 * and `/cygdrive/c/Users/you/x`. Node's `path.win32.resolve` treats a leading
 * `/` as drive-relative, which turns `/c/Users/x` into `C:\c\Users\x` — the
 * drive letter becomes a directory and every comparison against the real
 * workspace and temp roots fails. Without this, MSYS paths are misclassified
 * (in-workspace paths look external, and `%TEMP%` never matches the scratch
 * allowlist).
 *
 * Only applies on Windows: on POSIX hosts `/c/...` is a genuine absolute path.
 */
function fromShellPath(path: string): string {
  if (!IS_WINDOWS) return path;

  const drive = /^\/(?:cygdrive\/)?([a-zA-Z])(?:\/(.*))?\/?$/.exec(path);
  if (drive) {
    const rest = (drive[2] ?? "").replace(/\//g, sep);
    return `${drive[1].toUpperCase()}:${sep}${rest}`;
  }

  // Git Bash mounts %TEMP% at /tmp via its /etc/fstab.
  if (path === "/tmp" || path.startsWith("/tmp/")) {
    return join(tmpdir(), path.slice("/tmp".length));
  }

  return path;
}

interface ResolvedPath {
  /** Shell form after tilde + MSYS rewriting, before resolving against cwd. */
  expanded: string;
  /** Resolved against cwd, symlinks untouched. */
  absolute: string;
  /** Symlinks followed; falls back to `absolute` when the target is missing. */
  real: string;
}

/**
 * Expand `~`, rewrite MSYS paths, resolve against cwd and follow symlinks.
 */
function resolvePath(rawPath: string, cwd: string): ResolvedPath {
  const expanded = fromShellPath(expandTilde(rawPath));
  const absolute = resolve(cwd, expanded);
  let real: string;
  try {
    real = realpathSync(absolute);
  } catch {
    real = absolute; // Doesn't exist yet (e.g. write) — use the resolved path
  }
  return { expanded, absolute, real };
}

/**
 * Extract file paths from a bash command.
 *
 * Recognises POSIX absolute paths, Windows drive paths (`C:\x`, `c:/x`), UNC
 * shares (`\\server\share`), tilde paths and `../` relative paths that escape
 * the workspace. Git Bash drive paths (`/c/x`) come through the POSIX pattern
 * and are rewritten later by `fromShellPath`.
 */
function extractPathsFromCommand(cmd: string): string[] {
  const paths: string[] = [];

  // POSIX absolute paths — / must be at start of string or after a token
  // boundary (not after . or word chars, so URLs like https://x/y are skipped)
  const absoluteMatches = cmd.match(/(?:^|(?<=[\s"'`(=,;]))\/[^\s"'`)]+/g);
  if (absoluteMatches) paths.push(...absoluteMatches);

  // Windows drive paths: C:\Users\you, c:/Windows/win.ini
  const driveMatches = cmd.match(/(?:^|(?<=[\s"'`(=,;]))[a-zA-Z]:[\\/][^\s"'`)]+/g);
  if (driveMatches) paths.push(...driveMatches);

  // UNC shares: \\server\share\file
  const uncMatches = cmd.match(/(?:^|(?<=[\s"'`(=,;]))\\\\[^\s"'`)]+/g);
  if (uncMatches) paths.push(...uncMatches);

  // Tilde paths (~... and ~\...)
  const tildeMatches = cmd.match(/~\\?[^\s"'`)]+/g);
  if (tildeMatches) {
    paths.push(...tildeMatches.map(expandTilde));
  }

  // Relative paths with ../ or ..\ (potential workspace escape)
  const relativeMatches = cmd.match(/\.\.[\\/][^\s"'`)]+/g);
  if (relativeMatches) paths.push(...relativeMatches);

  return paths;
}

/**
 * Split a command into rough argument tokens for basename-level checks.
 */
function tokenizeCommand(cmd: string): string[] {
  return cmd.split(/[\s"'`;|&()<>]+/).filter(Boolean);
}

/**
 * Find a sensitive file referenced by a shell command — either as a path-like
 * token (matched with the same patterns the file tools use) or as a bare
 * credential filename such as `cat .env`.
 */
function findSensitiveToken(cmd: string): string | undefined {
  for (const token of tokenizeCommand(cmd)) {
    // URLs are not files: `curl https://host/token` must not read as token.pem
    if (/^[a-z][a-z0-9+.-]*:\/\//i.test(token)) continue;
    const isPathLike =
      token.includes("/") || token.includes("\\") || token.startsWith("~");
    if (isPathLike && SENSITIVE_PATTERNS.some(re => re.test(token))) return token;
    if (SENSITIVE_BASENAME_PATTERNS.some(re => re.test(token))) return token;
  }
  return undefined;
}

/**
 * Normalize a path for consistent comparison across platforms.
 * - Uses platform-native separator
 * - Lowercases on Windows (case-insensitive filesystem)
 */
function normalizePath(path: string): string {
  const normalized = toNamespacedPath(path);
  return IS_WINDOWS ? normalized.toLowerCase() : normalized;
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
 * True for `/dev/*` device files.
 *
 * Tested against the *shell* form as well as the resolved one: in Git Bash
 * `/dev/null` is the null device, but `path.win32.resolve` turns it into
 * `C:\dev\null`, which would otherwise prompt on every `2>/dev/null`.
 */
function isDevicePath(candidate: string): boolean {
  const slashForm = candidate.replace(/\\/g, "/");
  return slashForm === "/dev" || slashForm.startsWith("/dev/");
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
  if (IS_WINDOWS) {
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
function isScratchPath(path: ResolvedPath): boolean {
  if (isDevicePath(path.expanded) || isDevicePath(path.absolute)) return true;
  for (const candidate of [path.absolute, path.real]) {
    if (isInsideTempDir(candidate)) return true;
  }
  return false;
}

/**
 * Check if any path in the command escapes the workspace.
 */
function hasPathsOutsideWorkspace(cmd: string, cwd: string): boolean {
  for (const path of extractPathsFromCommand(cmd)) {
    const resolved = resolvePath(path, cwd);

    // Allow /dev/* device files and temp dirs (pi writes there constantly)
    if (isScratchPath(resolved)) continue;

    if (!isInsideWorkspace(resolved.real, cwd)) {
      return true;
    }
  }
  return false;
}

/** Prompt the user; return a block result when they decline. */
async function ask(
  ctx: ExtensionContext,
  title: string,
  detail: string,
  reason = "Blocked by user",
): Promise<ToolCallEventResult | undefined> {
  const allowed = await ctx.ui.confirm(title, detail);
  return allowed ? undefined : { block: true, reason };
}

/**
 * Gate a shell command string. Shared by the `bash` and `powershell` tools —
 * pi's PowerShell tool is a shell tool with the same `{ command }` input, and
 * on Windows pi's own docs suggest swapping `bash` for it, so it must not be
 * left unguarded.
 */
async function gateShellCommand(
  command: string,
  ctx: ExtensionContext,
): Promise<ToolCallEventResult | undefined> {
  if (DANGEROUS_COMMAND_PATTERNS.some(re => re.test(command))) {
    const blocked = await ask(ctx, "Dangerous command", `Allow: ${command}?`);
    if (blocked) return blocked;
  }

  // Package manager installs
  if (PACKAGE_INSTALL_PATTERNS.some(re => re.test(command))) {
    const blocked = await ask(ctx, "Package install", `Allow: ${command}?`);
    if (blocked) return blocked;
  }

  // System modifications
  if (SYSTEM_MOD_PATTERNS.some(re => re.test(command))) {
    const blocked = await ask(ctx, "System modification", `Allow: ${command}?`);
    if (blocked) return blocked;
  }

  // File copy commands
  if (FILE_COPY_PATTERNS.some(re => re.test(command))) {
    const blocked = await ask(ctx, "File copy", `Allow: ${command}?`);
    if (blocked) return blocked;
  }

  // Sensitive files referenced in the command (`cat .env`, `type C:\...\.ssh\id_rsa`)
  const sensitive = findSensitiveToken(command);
  if (sensitive) {
    const blocked = await ask(
      ctx,
      "Sensitive file",
      `Allow command touching ${sensitive}?`,
      "Blocked by user — sensitive file",
    );
    if (blocked) return blocked;
  }

  // Any command with paths outside workspace (catches redirections, touch, etc.)
  if (hasPathsOutsideWorkspace(command, ctx.cwd)) {
    const blocked = await ask(ctx, "Path outside workspace", `Allow: ${command}?`);
    if (blocked) return blocked;
  }

  return undefined;
}

export default function (pi: ExtensionAPI) {
  pi.on("tool_call", async (event, ctx) => {
    const toolName = event.toolName;

    // --- Shell tools: gate dangerous commands ---
    if (isToolCallEventType("bash", event) || isToolCallEventType("powershell", event)) {
      return gateShellCommand(event.input.command, ctx);
    }

    // --- File tools: gate paths outside workspace ---
    if (!FILE_TOOLS.includes(toolName as (typeof FILE_TOOLS)[number])) return;

    // Extract the path argument
    let targetPath: string | undefined;

    if (isToolCallEventType("read", event)) targetPath = event.input.path;
    else if (isToolCallEventType("write", event)) targetPath = event.input.path;
    else if (isToolCallEventType("edit", event)) targetPath = event.input.path;
    else if (isToolCallEventType("grep", event)) targetPath = event.input.path;
    else if (isToolCallEventType("find", event)) targetPath = event.input.path;
    else if (isToolCallEventType("ls", event)) targetPath = event.input.path;

    if (!targetPath) return;

    // Expand ~, rewrite MSYS paths, resolve against cwd, follow symlinks
    const resolved = resolvePath(targetPath, ctx.cwd);

    // Sensitive files — always prompt, even inside workspace or a temp dir
    if (SENSITIVE_PATTERNS.some(re => re.test(resolved.real))) {
      return ask(
        ctx,
        "Sensitive file",
        `Allow ${toolName} on ${resolved.real}?`,
        "Blocked by user — sensitive file",
      );
    }

    // Disposable scratch space (/tmp, /var/tmp, os.tmpdir()) — allow silently
    if (isScratchPath(resolved)) return;

    // Inside workspace — allow silently
    if (isInsideWorkspace(resolved.real, ctx.cwd)) return;

    // Outside workspace — ask for permission
    return ask(
      ctx,
      "Outside workspace",
      `Allow ${toolName} on ${resolved.real}?`,
      "Blocked by user — path is outside the workspace",
    );
  });
}