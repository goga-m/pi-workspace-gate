// Regression tests for the workspace gate.
//
//   node test/run.mjs          # runs both platforms
//   node test/run.mjs posix    # real platform
//   node test/run.mjs win      # simulated win32
//
// No dependencies: pi itself is stubbed (test/pi-stub.mjs) and win32 `path` is
// shimmed (test/win32-path.mjs). Requires Node >= 22.15 for module.registerHooks.
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const MODE = process.argv[2];

if (!MODE) {
  let failed = 0;
  for (const mode of ["posix", "win"]) {
    const child = spawn(process.execPath, [fileURLToPath(import.meta.url), mode], {
      stdio: "inherit",
    });
    const code = await new Promise((res) => child.on("exit", res));
    if (code !== 0) failed++;
  }
  console.log(failed ? `\n${failed} mode(s) failed` : "\nall modes passed");
  process.exit(failed ? 1 : 0);
}

if (MODE !== "posix" && MODE !== "win") {
  console.error(`unknown mode: ${MODE}`);
  process.exit(2);
}

const here = new URL(".", import.meta.url);
const EXTENSION = new URL("../extensions/pi-workspace-gate/index.ts", here);

const { registerHooks } = await import("node:module");
const redirects = {
  "@earendil-works/pi-coding-agent": new URL("./pi-stub.mjs", here).href,
};
if (MODE === "win") {
  Object.defineProperty(process, "platform", { value: "win32" });
  const HOME = "C:\\Users\\testuser";
  const TEMP = "C:\\Users\\testuser\\AppData\\Local\\Temp";
  Object.assign(process.env, {
    HOME,
    USERPROFILE: HOME,
    TMPDIR: TEMP,
    TMP: TEMP,
    TEMP,
    SYSTEMROOT: "C:\\Windows",
  });
  redirects["node:path"] = new URL("./win32-path.mjs", here).href;
}
registerHooks({
  resolve(specifier, context, next) {
    const target = redirects[specifier];
    // Never redirect the shim's own lookup, or it cycles on itself.
    if (target && context.parentURL !== target) {
      return { url: target, shortCircuit: true };
    }
    return next(specifier, context);
  },
});

const { default: extension } = await import(EXTENSION.href);

let handler = null;
extension({ on: (event, h) => { if (event === "tool_call") handler = h; } });

const CWD = MODE === "win" ? "C:\\Users\\testuser\\Projects\\app" : "/Users/testuser/Projects/app";

const cases = [];
const sh = (command, expect, why) => cases.push({ tool: "bash", input: { command }, expect, why });
const pwsh = (command, expect, why) => cases.push({ tool: "powershell", input: { command }, expect, why });
const file = (tool, path, expect, why) => cases.push({ tool, input: { path }, expect, why });

if (MODE === "win") {
  // --- Git Bash / MSYS drive paths ---
  sh("cat /c/Users/testuser/Desktop/a.txt", "prompt", "MSYS path outside workspace");
  sh("cat /c/Users/testuser/Projects/app/src/index.ts", "allow", "MSYS path inside workspace");
  sh("cat /C/Users/testuser/Projects/app/src/index.ts", "allow", "MSYS path, uppercase drive letter");
  sh("cat /cygdrive/c/Users/testuser/Projects/app/src/index.ts", "allow", "cygdrive form inside workspace");
  sh("cat /cygdrive/c/Users/testuser/Desktop/a.txt", "prompt", "cygdrive form outside workspace");
  sh("cat /d/Downloads/foo.zip", "prompt", "MSYS path on another drive");

  // --- Scratch space ---
  sh("cat /c/Users/testuser/AppData/Local/Temp/pi-bash-123.log", "allow", "pi scratch log, MSYS form");
  sh("cat C:\\Users\\testuser\\AppData\\Local\\Temp\\pi-bash-123.log", "allow", "pi scratch log, native form");
  sh("echo hi > /tmp/pi-editor-1.txt", "allow", "Git Bash /tmp maps to %TEMP%");
  sh("echo hi 2>/dev/null", "allow", "/dev/null (win32 resolve would say C:\\dev\\null)");

  // --- Native Windows paths ---
  sh("cat C:\\Users\\testuser\\Desktop\\a.txt", "prompt", "native backslash path outside workspace");
  sh("cat c:/Users/testuser/Desktop/a.txt", "prompt", "forward-slash drive path");
  sh("del D:\\secrets\\notes.txt", "prompt", "del on another drive");
  sh("cat \\\\fileserv\\share\\a.txt", "prompt", "UNC share");
  sh("cat --file=C:\\Users\\testuser\\Desktop\\a.txt", "prompt", "path after an `=` separator");
  sh("cat C:\\Users\\testuser\\Projects\\app\\src\\index.ts", "allow", "native path inside workspace");
  sh("cat ..\\..\\Users\\testuser\\Desktop\\a.txt", "prompt", "..\\ escape with backslashes");

  // --- Sensitive files reached through the shell ---
  sh("cat .env", "prompt", "bare .env (file tools already gated this)");
  sh("type C:\\Users\\testuser\\.ssh\\id_rsa", "prompt", "ssh key via native path");
  sh("echo \"the secret plan is secret\"", "allow", "prose must not false-positive");
  sh("curl https://api.example.com/token", "allow", "URL is not a file");
  sh("ls src", "allow", "plain in-workspace command");
  sh("git status", "allow", "plain command");

  // --- The powershell tool must be gated like bash ---
  pwsh("Remove-Item -Recurse -Force C:\\Users\\testuser\\Projects\\app", "prompt", "PS recursive delete");
  pwsh("rm -Force C:\\Users\\testuser\\Projects\\app\\x", "prompt", "PS rm alias with -Force");
  pwsh("Get-Content src\\index.ts", "allow", "PS read inside workspace");
  pwsh("winget install 7zip.7zip", "prompt", "PS package install");
  pwsh("Set-ExecutionPolicy Bypass", "prompt", "PS system modification");
  pwsh("Invoke-Expression (Get-Content install.ps1)", "prompt", "IEX");

  // --- File tools with MSYS / native paths ---
  file("read", "/c/Users/testuser/Projects/app/src/index.ts", "allow", "read MSYS in-workspace");
  file("read", "/c/Users/testuser/Desktop/x.txt", "prompt", "read MSYS outside workspace");
  file("read", "C:\\Users\\testuser\\Desktop\\x.txt", "prompt", "read native outside workspace");
  file("read", "src\\index.ts", "allow", "read native inside workspace");
  file("write", "/c/Users/testuser/AppData/Local/Temp/pi-share-x/out.txt", "allow", "write to scratch via MSYS");
  file("read", "/c/Users/testuser/Projects/app/.env", "prompt", "sensitive file in workspace via MSYS");
} else {
  sh("cat /etc/passwd", "prompt", "POSIX absolute outside workspace");
  sh("cat /c/Users/testuser/Desktop/a.txt", "prompt", "/c/... is a real POSIX path, must not be drive-rewritten");
  sh("cat ./src/index.ts", "allow", "relative in workspace");
  sh("cat /tmp/pi-bash-1.log", "allow", "POSIX /tmp scratch");
  sh("echo hi 2>/dev/null", "allow", "/dev/null");
  sh("cat .env", "prompt", "bare .env");
  sh("cat ./secrets/notes.md", "prompt", "workspace path containing 'secret'");
  sh("echo \"the secret plan is secret\"", "allow", "prose must not false-positive");
  sh("rm -rf node_modules", "prompt", "dangerous rm");
  sh("rm README.md", "allow", "plain rm is not -rf");
  sh("npm install left-pad", "prompt", "package install");
  sh("cp a.txt b.txt", "prompt", "file copy");
  sh("cat C:\\Users\\testuser\\Desktop\\a.txt", "allow", "Windows path is a relative token on POSIX");
  sh("cat https://example.com/api/v1", "allow", "URL must not be read as an absolute path");
  sh("curl https://api.example.com/token", "allow", "URL path segment must not read as a sensitive file");
  sh("ls ../other-repo", "prompt", "../ escape");
  file("read", "/etc/passwd", "prompt", "read outside workspace");
  file("read", "src/index.ts", "allow", "read inside workspace");
  file("read", "/tmp/x.txt", "allow", "read scratch");
  file("read", ".env", "prompt", "sensitive in workspace");
}

let pass = 0;
let fail = 0;
for (const c of cases) {
  const prompts = [];
  const ctx = {
    cwd: CWD,
    // Deny everything so every prompt is observable as a block.
    ui: { confirm: async (title) => { prompts.push(title); return false; } },
  };

  let result;
  try {
    result = await handler({ toolName: c.tool, input: c.input }, ctx);
  } catch (err) {
    console.log(`ERROR  ${c.tool} ${JSON.stringify(c.input)} -> ${err.stack}`);
    fail++;
    continue;
  }

  const ok = c.expect === "allow" ? prompts.length === 0 : prompts.length > 0;
  const got = prompts.length ? `prompt[${prompts.join(",")}]` : "allow";
  if (ok) pass++; else fail++;

  console.log(
    `${ok ? "ok  " : "FAIL"} ${got.padEnd(34)} ` +
    `${JSON.stringify(c.input.command ?? c.input.path).padEnd(60)} ${c.why}`
  );
}

console.log(`\n${MODE}: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);