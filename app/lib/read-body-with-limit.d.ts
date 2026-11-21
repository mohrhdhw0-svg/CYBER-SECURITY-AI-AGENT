type FetchBodySource = {
  body: ReadableStream<Uint8Array> | null;
};

export function readBodyWithLimit(
  source: FetchBodySource,
  maxBytes: number,
): Promise<string | null>;
