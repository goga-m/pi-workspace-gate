# pi-workspace-gate

A security extension for [pi](https://github.com/mariozechner/pi-coding-agent) that intercepts tool calls and prompts for user confirmation before allowing potentially dangerous operations.

## What It Guards

| Category | Examples |
|----------|----------|
| 🔴 **Dangerous commands** | `rm -rf`, `sudo`, `mkfs`, `dd if=`, `chmod 777` |
| 📦 **Package installs** | `npm install`, `yarn add`, `pip install`, `cargo install` |
| 🖥️ **System modifications** | `apt install`, `brew install`, `yum install`, `dnf install` |
| 📋 **File copies** | `cp`, `scp`, `rsync` |
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
| `/dev/*` | `/dev/null`, `/dev/zero` |

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

## How It Works

The extension subscribes to pi's `tool_call` event and checks:

1. **Bash commands** against dangerous patterns (rm, sudo, installs, etc.)
2. **File tool paths** against the workspace boundary and sensitive file patterns
3. **Symlinks** are resolved — no bypassing via symlink tricks
4. **Scratch paths** (`/tmp`, `/var/tmp`, `os.tmpdir()`, `/dev/*`) skip the workspace-boundary check — see [Scratch directories](#scratch-directories)

For anything that matches a pattern, a confirmation dialog appears. Deny it and the call is blocked.

## License

MIT
