/**
 * Read a Fetch API request or response body without buffering more than the
 * configured byte limit. Returns null when the limit is exceeded.
 * @param {{ body: ReadableStream<Uint8Array> | null }} source
 * @param {number} maxBytes
 * @returns {Promise<string | null>}
 */
export async function readBodyWithLimit(source, maxBytes) {
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 0) {
    throw new TypeError("maxBytes must be a non-negative safe integer.");
  }
  if (!source.body) return "";
  const reader = source.body.getReader();
  const chunks = [];
  let totalBytes = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      totalBytes += value.byteLength;
      if (totalBytes > maxBytes) {
        await reader.cancel();
        return null;
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }

  const body = new Uint8Array(totalBytes);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder("utf-8", { fatal: true }).decode(body);
}
