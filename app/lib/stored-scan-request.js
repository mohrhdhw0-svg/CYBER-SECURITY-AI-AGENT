import { isPublicIPv4 } from "./public-ipv4.js";

const requestStatuses = new Set(["pending", "approved", "rejected", "scanning", "completed", "failed"]);
const allowedKeys = new Set(["id", "ip", "status", "createdAt", "expiresAt", "decisionAt", "authorizationReference", "ticketProof", "result", "error"]);
const validDate = (value) => typeof value === "string" && Number.isFinite(Date.parse(value));

const isRecord = (value) => !!value && typeof value === "object" && !Array.isArray(value);
export function validScanResult(result, expectedIp, expectedAuthorizationReference) {
  if (!isRecord(result) || result.status !== "completed" || result.target !== expectedIp) return false;
  if (typeof result.authorization_reference !== "string" || result.authorization_reference.length < 4 || result.authorization_reference.length > 120 || result.authorization_reference !== expectedAuthorizationReference) return false;
  if (typeof result.profile !== "string" || result.profile.length > 120) return false;
  if (!Array.isArray(result.ports) || result.ports.length > 100) return false;
  const validPorts = result.ports.every((port) =>
    isRecord(port) &&
    typeof port.port === "string" &&
    /^\d{1,5}$/.test(port.port) &&
    Number(port.port) >= 1 &&
    Number(port.port) <= 65535 &&
    port.protocol === "tcp" &&
    typeof port.state === "string" &&
    port.state.length <= 32 &&
    typeof port.service === "string" &&
    port.service.length <= 128 &&
    (port.product === undefined || port.product === null || (typeof port.product === "string" && port.product.length <= 256)) &&
    (port.version === undefined || port.version === null || (typeof port.version === "string" && port.version.length <= 256))
  );
  if (!validPorts || !isRecord(result.summary)) return false;
  const { ports_observed: observed, open_ports: open } = result.summary;
  if (!Number.isSafeInteger(observed) || observed !== result.ports.length || observed > 100) return false;
  if (!Number.isSafeInteger(open) || open < 0 || open > observed) return false;
  if (open !== result.ports.filter((port) => port.state === "open").length) return false;
  if (!Array.isArray(result.limitations) || result.limitations.length > 20 ||
      !result.limitations.every((entry) => typeof entry === "string" && entry.length <= 500)) return false;
  if (result.passive !== undefined && !isRecord(result.passive)) return false;
  try {
    return Buffer.byteLength(JSON.stringify(result), "utf8") <= 1_000_000;
  } catch {
    return false;
  }
}

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
  if ((item.result !== undefined && item.status !== "completed") || (item.status === "completed" && item.result === undefined)) {
    throw new Error("Stored request status and scan result are inconsistent.");
  }
  if (item.result !== undefined && !validScanResult(item.result, item.ip, item.authorizationReference)) {
    throw new Error("Stored scan result failed validation.");
  }
  return item;
}
