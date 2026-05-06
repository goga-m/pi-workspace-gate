# pi-workspace-gate

A security extension for [pi](https://github.com/mariozechner/pi-coding-agent) that intercepts tool calls and prompts for user confirmation before allowing potentially dangerous operations.

## What It Guards

| Category | Examples |
|----------|----------|
| 🔴 **Dangerous commands** | `rm -rf`, `sudo`, `mkfs`, `dd if=`, `chmod 777` |
| 📦 **Package installs** | `npm install`, `yarn add`, `pip install`, `cargo install` |
| 🖥️ **System modifications** | `apt install`, `brew install`, `yum install`, `dnf install` |
| 📋 **File copies** | `cp`, `scp`, `rsync` |
| 🚪 **Paths outside workspace** | Any command or file tool targeting paths outside the CWD |
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

For anything that matches a pattern, a confirmation dialog appears. Deny it and the call is blocked.

## License

MIT
