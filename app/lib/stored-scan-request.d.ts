import type { ScanRequest } from "./approval-store";
export function parseStoredRequest(value: unknown, expectedId: string): ScanRequest;
export function validScanResult(result: unknown, expectedIp: string, expectedAuthorizationReference: string): boolean;
