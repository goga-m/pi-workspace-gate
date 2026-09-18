// Stand-in for `node:path` when the tests simulate win32.
//
// The real `node:path` picks its win32-vs-posix implementation once, at process
// boot, so overriding `process.platform` afterwards is not enough. The test
// runner redirects every `node:path` import here instead.
//
// createRequire is used deliberately: a plain `import "node:path"` would be
// redirected back to this file by the resolve hook and self-cycle.
import { createRequire } from "node:module";

const real = createRequire(import.meta.url)("node:path");
const w = real.win32;

export const resolve = w.resolve;
export const toNamespacedPath = w.toNamespacedPath;
export const join = w.join;
export const dirname = w.dirname;
export const basename = w.basename;
export const extname = w.extname;
export const isAbsolute = w.isAbsolute;
export const relative = w.relative;
export const normalize = w.normalize;
export const parse = w.parse;
export const format = w.format;
export const sep = "\\";
export const delimiter = w.delimiter;
export const posix = real.posix;
export const win32 = w;
export default w;