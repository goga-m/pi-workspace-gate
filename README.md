# pi-workspace-gate

A security extension for [pi](https://github.com/mariozechner/pi-coding-agent) that intercepts tool calls and prompts for user confirmation before allowing potentially dangerous operations.

Both shell tools are gated — `bash` **and** `powershell` — so swapping one for the other (pi's own recommendation on Windows) does not bypass the gate.

## What It Guards

| Category | Examples |
|----------|----------|
| 🔴 **Dangerous commands** | `rm -rf`, `sudo`, `mkfs`, `dd if=`, `chmod 777`, `Remove-Item -Recurse -Force`, `Format-Volume`, `Invoke-Expression` |
| 📦 **Package installs** | `npm install`, `yarn add`, `pip install`, `cargo install`, `winget install`, `choco install`, `Install-Module` |
| 🖥️ **System modifications** | `apt install`, `brew install`, `yum install`, `dnf install`, `Set-ExecutionPolicy`, `reg add` |
| 📋 **File copies** | `cp`, `scp`, `rsync`, `Copy-Item` |
| 🚪 **Paths outside workspace** | Any command or file tool targeting paths outside the CWD (except [scratch directories](#scratch-directories)) |
| 🔑 **Sensitive files** | `.env`, `.npmrc`, SSH keys, tokens, `.pem`, `.key` |

## Install

```bash
# From this repo
pi install https://github.com/goga-m/pi-workspace-gate

# Try without installing
pi -e /path/to/Workspace-Gate
```

## Configuration

No configuration needed — it works out of the box. The extension uses pattern matching to detect potentially dangerous operations and prompts you before allowing them.

### Scratch directories

Temp directories are **never** gated for path checks. pi writes there constantly — truncated bash output (`pi-bash-*.log`), the external-editor buffer (`pi-editor-*`), share staging (`pi-share-*`) and clipboard images — so prompting on those paths would mean a confirmation on nearly every turn.

Auto-allowed roots:

| Source | Example |
|--------|---------|
| `os.tmpdir()` / `$TMPDIR` | `/var/folders/hr/…/T` (macOS), `/tmp` (Linux), `%TEMP%` (Windows) |
| `$TMP`, `$TEMP` | whatever you set |
| `/tmp`, `/var/tmp` | including their macOS `/private/…` symlink targets |
| `%SYSTEMROOT%\Temp` | `C:\Windows\Temp` |
| `/dev/*` | `/dev/null`, `/dev/zero` — also in Git Bash form, where `2>/dev/null` would otherwise resolve to `C:\dev\null` |
| `/tmp` under Git Bash | rewritten to `%TEMP%`, which is where Git Bash's `/etc/fstab` actually mounts it |

The allowlist covers the **path** checks only. Everything else still prompts, even when the paths are in `/tmp`:

```bash
rm -rf /tmp/x            # still prompts — dangerous command
sudo ls /tmp             # still prompts — sudo
cp README.md /tmp/x.md   # still prompts — file copy
npm install              # still prompts — package install
```

And these still prompt:

- `read`/`write`/`edit` on a sensitive file inside a temp dir (e.g. `/tmp/api_token.json`)
- any temp path that is a **symlink to somewhere outside** the temp roots
- a command mixing temp and non-temp paths — `cat /tmp/a /etc/passwd` prompts

### Sensitive file patterns

The following patterns always trigger a confirmation prompt, even inside the workspace:

- `.env`, `.npmrc`, `.pypirc`, `.netrc`
- `id_rsa`, `id_ed25519`, `.ssh/`, `.aws/credentials`
- `.gnupg`, `.docker/config.json`
- Files containing `token`, `secret`, `credential`
- `.key`, `.pem`

These apply to shell commands too, not just the file tools — otherwise `cat .env`
would slip past a gate that `read .env` triggers. Path-like command tokens are
matched with the same patterns the file tools use; bare tokens are matched
against a narrower basename list, so `cat .env` prompts while
`echo "the secret plan"` does not.

## Windows

pi uses **Git Bash** by default on Windows, so the model emits MSYS paths such
as `/c/Users/you/project/src/index.ts`. Node's `path.win32.resolve` treats a
leading `/` as drive-relative and rewrites that to
`C:\c\Users\you\project\src\index.ts` — the drive letter becomes a directory.
Left alone, every MSYS path looks external, so in-workspace edits prompt and
`%TEMP%` never matches the scratch allowlist.

The extension rewrites `/c/…` and `/cygdrive/c/…` back to `C:\…` before
resolving, on Windows only (on POSIX hosts `/c/…` is a genuine absolute path).

Paths written in native form are extracted from shell commands as well:
`C:\Users\you\x`, `c:/Users/you/x`, `..\..\x` and UNC `\\server\share`. Without
this, `cat C:\Users\you\Desktop\notes.txt` was invisible to the path check.

## How It Works

The extension subscribes to pi's `tool_call` event and checks:

1. **Shell commands** (`bash` and `powershell`) against dangerous patterns (rm, sudo, installs, etc.)
2. **File tool paths** against the workspace boundary and sensitive file patterns
3. **Symlinks** are resolved — no bypassing via symlink tricks
4. **Scratch paths** (`/tmp`, `/var/tmp`, `os.tmpdir()`, `/dev/*`) skip the workspace-boundary check — see [Scratch directories](#scratch-directories)
5. **Shell paths** are extracted in POSIX, MSYS, drive-letter and UNC forms before the boundary check

## Testing

```bash
npm test            # both platforms
npm test -- win     # simulated win32 only
npm run test:load   # load the extension in a real pi session
```

`test/run.mjs` needs no dependencies: pi is stubbed (`test/pi-stub.mjs`) and
win32 `path` is shimmed via `module.registerHooks` (`test/win32-path.mjs`),
since `node:path` picks its implementation at process boot and cannot be faked
by overriding `process.platform` alone. Requires Node >= 22.15.

For anything that matches a pattern, a confirmation dialog appears. Deny it and the call is blocked.

## License

MIT
