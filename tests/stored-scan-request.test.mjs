import test from "node:test";
import assert from "node:assert/strict";
import { parseStoredRequest } from "../app/lib/stored-scan-request.js";

const id = "a".repeat(36);
const base = {
  id,
  ip: "8.8.8.8",
  status: "pending",
  createdAt: "2026-11-21T00:00:00.000Z",
  ticketProof: "b".repeat(64),
};

test("accepts a valid stored scan request", () => {
  assert.deepEqual(parseStoredRequest(JSON.stringify(base), id), base);
});

test("accepts supported lifecycle states and optional metadata", () => {
  const item = {
    ...base,
    status: "scanning",
    expiresAt: "2026-11-22T00:00:00.000Z",
    decisionAt: "2026-11-21T01:00:00.000Z",
    authorizationReference: "admin-approved:" + id,
    result: { findings: [] },
  };
  assert.deepEqual(parseStoredRequest(JSON.stringify(item), id), item);
});

test("rejects malformed JSON, non-object records, and mismatched identifiers", () => {
  for (const value of ["{", "null", "[]", JSON.stringify({ ...base, id: "c".repeat(36) })]) {
    assert.throws(() => parseStoredRequest(value, id));
  }
});

test("rejects non-public or malformed IP addresses", () => {
  for (const ip of ["127.0.0.1", "10.0.0.1", "192.0.2.1", "not-an-ip"]) {
    assert.throws(() => parseStoredRequest(JSON.stringify({ ...base, ip }), id));
  }
});

test("rejects unknown statuses and invalid timestamps", () => {
  assert.throws(() => parseStoredRequest(JSON.stringify({ ...base, status: "queued" }), id));
  assert.throws(() => parseStoredRequest(JSON.stringify({ ...base, createdAt: "yesterday" }), id));
  assert.throws(() => parseStoredRequest(JSON.stringify({ ...base, expiresAt: "never" }), id));
  assert.throws(() => parseStoredRequest(JSON.stringify({ ...base, decisionAt: "later" }), id));
});

test("rejects malformed proof and oversized optional text fields", () => {
  assert.throws(() => parseStoredRequest(JSON.stringify({ ...base, ticketProof: "bad" }), id));
  assert.throws(() => parseStoredRequest(JSON.stringify({ ...base, authorizationReference: "x".repeat(2_001) }), id));
  assert.throws(() => parseStoredRequest(JSON.stringify({ ...base, error: "x".repeat(1_001) }), id));
});

test("rejects unexpected stored fields", () => {
  assert.throws(() => parseStoredRequest(JSON.stringify({ ...base, internalAdminToken: "secret" }), id));
});

test("rejects invalid expected identifiers and non-text values", () => {
  assert.throws(() => parseStoredRequest(JSON.stringify(base), "invalid"));
  assert.throws(() => parseStoredRequest({ ...base }, id));
});
