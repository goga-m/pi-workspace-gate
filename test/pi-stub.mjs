// Minimal stand-in for @earendil-works/pi-coding-agent so the tests run without
// installing pi. `import type` specifiers are erased by Node's type stripping,
// so only the runtime helper is needed.
export function isToolCallEventType(toolName, event) {
  return event?.toolName === toolName;
}