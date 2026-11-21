export type AssistantMessage = {
  role: "user" | "assistant";
  content: string;
};

export function validateAssistantMessages(input: unknown): AssistantMessage[] | null;
export function validateAssistantRequestBody(input: unknown): AssistantMessage[] | null;
