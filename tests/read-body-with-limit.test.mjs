import test from "node:test";
import assert from "node:assert/strict";
import { readBodyWithLimit } from "../app/lib/read-body-with-limit.js";

function requestFromChunks(chunks, headers = {}) {
  const stream = new ReadableStream({
    start(controller) {
      for (const chunk of chunks) controller.enqueue(chunk);
      controller.close();
    },
  });
  return new Request("https://example.test/api", { method: "POST", headers, body: stream, duplex: "half" });
}

const encoder = new TextEncoder();

test("accepts a body exactly at the byte limit", async () => {
  const body = "12345678";
  assert.equal(await readBodyWithLimit(requestFromChunks([encoder.encode(body)]), 8), body);
});

test("rejects a body over the byte limit when Content-Length is absent", async () => {
  const request = requestFromChunks([encoder.encode("1234"), encoder.encode("5678")]);
  assert.equal(await readBodyWithLimit(request, 7), null);
});

test("enforces actual streamed bytes even when Content-Length understates the body", async () => {
  const request = requestFromChunks([encoder.encode("oversized")], { "content-length": "1" });
  assert.equal(await readBodyWithLimit(request, 4), null);
});

test("decodes valid multi-byte UTF-8 split across chunks", async () => {
  const bytes = encoder.encode("مرحبا");
  const request = requestFromChunks([bytes.slice(0, 3), bytes.slice(3)]);
  assert.equal(await readBodyWithLimit(request, 100), "مرحبا");
});

test("rejects malformed UTF-8", async () => {
  const request = requestFromChunks([new Uint8Array([0xc3, 0x28])]);
  await assert.rejects(readBodyWithLimit(request, 10), TypeError);
});

test("returns an empty string for a request without a body", async () => {
  assert.equal(await readBodyWithLimit(new Request("https://example.test/api"), 10), "");
});
