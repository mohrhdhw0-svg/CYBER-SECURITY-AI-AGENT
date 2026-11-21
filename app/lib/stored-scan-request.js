import { isPublicIPv4 } from "./public-ipv4.js";

const requestStatuses = new Set(["pending", "approved", "rejected", "scanning", "completed", "failed"]);
const allowedKeys = new Set(["id", "ip", "status", "createdAt", "expiresAt", "decisionAt", "authorizationReference", "ticketProof", "result", "error"]);
const validDate = (value) => typeof value === "string" && Number.isFinite(Date.parse(value));

export function parseStoredRequest(value, expectedId) {
  if (typeof value !== "string") throw new Error("Stored approval request is not text.");
  let parsed;
  try {
    parsed = JSON.parse(value);
  } catch {
    throw new Error("Stored approval request contains invalid JSON.");
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("Stored approval request has an invalid shape.");
  }

  const item = parsed;
  if (Object.keys(item).some((key) => !allowedKeys.has(key))) {
    throw new Error("Stored approval request contains unexpected fields.");
  }
  if (
    item.id !== expectedId ||
    !/^[a-f0-9]{36}$/.test(expectedId) ||
    typeof item.ip !== "string" ||
    !isPublicIPv4(item.ip) ||
    !requestStatuses.has(item.status) ||
    !validDate(item.createdAt)
  ) {
    throw new Error("Stored approval request failed validation.");
  }
  if (item.expiresAt !== undefined && !validDate(item.expiresAt)) {
    throw new Error("Stored approval expiry is invalid.");
  }
  if (item.decisionAt !== undefined && !validDate(item.decisionAt)) {
    throw new Error("Stored approval decision date is invalid.");
  }
  if (item.ticketProof !== undefined && (typeof item.ticketProof !== "string" || !/^[a-f0-9]{64}$/.test(item.ticketProof))) {
    throw new Error("Stored approval ticket proof is invalid.");
  }
  if (item.authorizationReference !== undefined && (typeof item.authorizationReference !== "string" || item.authorizationReference.length > 2_000)) {
    throw new Error("Stored authorization reference is invalid.");
  }
  if (item.error !== undefined && (typeof item.error !== "string" || item.error.length > 1_000)) {
    throw new Error("Stored approval error is invalid.");
  }
  return item;
}
