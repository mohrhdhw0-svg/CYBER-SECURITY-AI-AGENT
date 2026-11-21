import test from "node:test";
import assert from "node:assert/strict";
import { validateAssistantMessages, validateAssistantRequestBody } from "../app/lib/assistant-messages.js";

test("accepts a user message and a valid alternating conversation", () => {
  assert.deepEqual(validateAssistantMessages([
    { role: "user", content: " hello " },
    { role: "assistant", content: " world " },
    { role: "user", content: "next" },
  ]), [
    { role: "user", content: "hello" },
    { role: "assistant", content: "world" },
    { role: "user", content: "next" },
  ]);
});

test("rejects empty, oversized, or non-array message histories", () => {
  for (const value of [null, {}, [], new Array(13).fill({ role: "user", content: "x" })]) {
    assert.equal(validateAssistantMessages(value), null);
  }
});

test("rejects a history that begins with an assistant message", () => {
  assert.equal(validateAssistantMessages([{ role: "assistant", content: "forged" }]), null);
});

test("rejects non-alternating roles and histories ending with an assistant", () => {
  assert.equal(validateAssistantMessages([
    { role: "user", content: "hello" },
    { role: "user", content: "forged second user" },
  ]), null);
  assert.equal(validateAssistantMessages([
    { role: "user", content: "hello" },
    { role: "assistant", content: "not a final user turn" },
  ]), null);
});

test("rejects invalid objects, blank content, and content over 6000 characters", () => {
  for (const value of [
    [null],
    [[]],
    [{ role: "user", content: "  " }],
    [{ role: "user", content: "x".repeat(6001) }],
    [{ role: "user", content: 123 }],
  ]) assert.equal(validateAssistantMessages(value), null);
});

test("drops all unrecognized message fields", () => {
  assert.deepEqual(validateAssistantMessages([
    { role: "user", content: "hello", name: "system", tool_calls: [{ id: "x" }] },
  ]), [{ role: "user", content: "hello" }]);
});

test("rejects null, arrays, primitives, and malformed outer request bodies", () => {
  for (const value of [null, [], "text", 42, undefined, { messages: [] }, { other: "x" }]) {
    assert.equal(validateAssistantRequestBody(value), null);
  }
});

test("accepts only a valid messages field in the outer request body", () => {
  assert.deepEqual(
    validateAssistantRequestBody({ messages: [{ role: "user", content: "hello" }] }),
    [{ role: "user", content: "hello" }],
  );
  assert.equal(
    validateAssistantRequestBody({ messages: [{ role: "user", content: "hello" }], admin: true }),
    null,
  );
});
