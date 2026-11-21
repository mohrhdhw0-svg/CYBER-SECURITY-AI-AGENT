export function fetchAssistantCompletion(options: {
  endpoint: URL;
  apiKey: string;
  model: string;
  messages: Array<{ role: string; content: string }>;
  systemPrompt: string;
  timeoutMs?: number;
}): Promise<
  | { ok: true; answer: string }
  | { ok: false; status: number; reason: string }
>;
