import test from "node:test";
import assert from "node:assert/strict";
import { parseStoredRequest, validScanResult } from "../app/lib/stored-scan-request.js";

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
    status: "completed",
    expiresAt: "2026-11-22T00:00:00.000Z",
    decisionAt: "2026-11-21T01:00:00.000Z",
    authorizationReference: "admin-approved:" + id,
    result: {
  status: "completed",
  target: "8.8.8.8",
  authorization_reference: "admin-approved:" + id,
  profile: "approved-public-ip-intelligence",
  passive: { warnings: [] },
  ports: [{ port: "443", protocol: "tcp", state: "open", service: "https", product: null, version: null }],
  summary: { ports_observed: 1, open_ports: 1 },
  limitations: ["Bounded test report"],
}
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

test("rejects malformed or target-mismatched scan results", () => {
  const validResult = {
  status: "completed",
  target: "8.8.8.8",
  authorization_reference: "admin-approved:" + id,
  profile: "approved-public-ip-intelligence",
  passive: { warnings: [] },
  ports: [{ port: "443", protocol: "tcp", state: "open", service: "https", product: null, version: null }],
  summary: { ports_observed: 1, open_ports: 1 },
  limitations: ["Bounded test report"],
};
  const invalidResults = [
    "completed",
    { ...validResult, status: "running" },
    { ...validResult, target: "1.1.1.1" },
    { ...validResult, authorization_reference: "" },
    { ...validResult, ports: Array(101).fill(validResult.ports[0]) },
    { ...validResult, ports: [{ ...validResult.ports[0], port: "70000" }] },
    { ...validResult, ports: [{ ...validResult.ports[0], protocol: "udp" }] },
    { ...validResult, summary: { ports_observed: 2, open_ports: 1 } },
    { ...validResult, summary: { ports_observed: 1, open_ports: 0 } },
    { ...validResult, limitations: ["x".repeat(501)] },
    { ...validResult, passive: [] },
  ];
  for (const result of invalidResults) {
    assert.throws(() => parseStoredRequest(JSON.stringify({ ...base, status: "completed", authorizationReference: "admin-approved:" + id, result }), id));
  }
  assert.throws(() => parseStoredRequest(JSON.stringify({ ...base, status: "scanning", authorizationReference: "admin-approved:" + id, result: validResult }), id));
  assert.throws(() => parseStoredRequest(JSON.stringify({ ...base, status: "completed", authorizationReference: "different-reference", result: validResult }), id));
});


test("validates engine results against the exact approved target and reference", () => {
  const result = {
    status: "completed",
    target: "8.8.8.8",
    authorization_reference: "admin-approved:" + id,
    profile: "approved-public-ip-intelligence",
    passive: { warnings: [] },
    ports: [{ port: "443", protocol: "tcp", state: "open", service: "https", product: null, version: null }],
    summary: { ports_observed: 1, open_ports: 1 },
    limitations: ["Bounded test report"],
  };
  assert.equal(validScanResult(result, "8.8.8.8", "admin-approved:" + id), true);
  assert.equal(validScanResult(result, "1.1.1.1", "admin-approved:" + id), false);
  assert.equal(validScanResult(result, "8.8.8.8", "admin-approved:" + "c".repeat(36)), false);
  assert.equal(validScanResult({ ...result, summary: null }, "8.8.8.8", "admin-approved:" + id), false);
});
