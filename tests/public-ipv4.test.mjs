import test from "node:test";
import assert from "node:assert/strict";
import { isPublicIPv4 } from "../app/lib/public-ipv4.js";

test("accepts ordinary public IPv4 addresses", () => {
  assert.equal(isPublicIPv4("8.8.8.8"), true);
  assert.equal(isPublicIPv4("1.1.1.1"), true);
  assert.equal(isPublicIPv4("203.0.114.1"), true);
});

test("rejects malformed and non-string input", () => {
  for (const value of ["", "localhost", "999.1.1.1", "1.2.3", "1.2.3.4.5", 1234, null]) {
    assert.equal(isPublicIPv4(value), false);
  }
});

test("rejects private, loopback, link-local, and shared address space", () => {
  for (const value of [
    "10.0.0.1",
    "127.0.0.1",
    "169.254.1.1",
    "172.16.0.1",
    "172.31.255.254",
    "192.168.1.1",
    "100.64.0.1",
    "100.127.255.254",
    "0.1.2.3",
  ]) {
    assert.equal(isPublicIPv4(value), false, value);
  }
});

test("rejects documentation, benchmarking, multicast, and reserved ranges", () => {
  for (const value of [
    "192.0.0.8",
    "192.0.2.1",
    "192.88.99.1",
    "198.18.0.1",
    "198.19.255.254",
    "198.51.100.1",
    "203.0.113.1",
    "224.0.0.1",
    "240.0.0.1",
    "255.255.255.255",
  ]) {
    assert.equal(isPublicIPv4(value), false, value);
  }
});
