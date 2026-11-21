/**
 * Call an OpenAI-compatible chat completion endpoint with bounded response
 * memory use. The API key is only sent in the server-side Authorization header.
 *
 * @param {{ endpoint: URL, apiKey: string, model: string, messages: Array<{role: string, content: string}>, systemPrompt: string, timeoutMs?: number }} options
 * @returns {Promise<{ok: true, answer: string} | {ok: false, status: number, reason: string}>}
 */
export async function fetchAssistantCompletion({
  endpoint,
  apiKey,
  model,
  messages,
  systemPrompt,
  timeoutMs = 45_000,
}) {
  try {
    const response = await fetch(endpoint, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${apiKey}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        model,
        messages: [{ role: "system", content: systemPrompt }, ...messages],
        temperature: 0.25,
        max_tokens: 1200,
        stream: false,
      }),
      cache: "no-store",
      redirect: "error",
      signal: AbortSignal.timeout(timeoutMs),
    });

    if (!response.ok) {
      await response.body?.cancel().catch(() => {});
      return { ok: false, status: 502, reason: response.status === 429 ? "rate_limited" : "provider_error" };
    }

    const declaredLength = Number(response.headers.get("content-length") || 0);
    if (Number.isFinite(declaredLength) && declaredLength > 1_000_000) {
      await response.body?.cancel().catch(() => {});
      return { ok: false, status: 502, reason: "response_too_large" };
    }
    if (!response.body) return { ok: false, status: 502, reason: "empty_response" };

    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let totalBytes = 0;
    let responseText = "";
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        totalBytes += value.byteLength;
        if (totalBytes > 1_000_000) {
          await reader.cancel();
          return { ok: false, status: 502, reason: "response_too_large" };
        }
        responseText += decoder.decode(value, { stream: true });
      }
      responseText += decoder.decode();
    } finally {
      reader.releaseLock();
    }

    let data;
    try {
      data = JSON.parse(responseText);
    } catch {
      return { ok: false, status: 502, reason: "invalid_provider_json" };
    }

    const raw = data?.choices?.[0]?.message?.content;
    const answer = typeof raw === "string"
      ? raw.trim()
      : Array.isArray(raw)
        ? raw.filter((part) => part?.type === "text").map((part) => typeof part.text === "string" ? part.text : "").join("\n").trim()
        : "";

    if (!answer) return { ok: false, status: 502, reason: "empty_answer" };
    return { ok: true, answer };
  } catch (error) {
    return {
      ok: false,
      status: 504,
      reason: error?.name === "TimeoutError" || error?.name === "AbortError" ? "timeout" : "connection_error",
    };
  }
}
