/**
 * Validate untrusted chat history and return only the supported message fields.
 * Messages must alternate user/assistant, begin with user, and end with user.
 * @param {unknown} input
 * @returns {Array<{role: "user" | "assistant", content: string}> | null}
 */
export function validateAssistantMessages(input) {
  if (!Array.isArray(input) || input.length < 1 || input.length > 12) return null;

  const safeMessages = [];
  for (const [index, item] of input.entries()) {
    if (!item || typeof item !== "object" || Array.isArray(item)) return null;
    const expectedRole = index % 2 === 0 ? "user" : "assistant";
    if (
      item.role !== expectedRole ||
      typeof item.content !== "string" ||
      !item.content.trim() ||
      item.content.length > 6000
    ) return null;

    safeMessages.push({ role: expectedRole, content: item.content.trim() });
  }

  return safeMessages[safeMessages.length - 1]?.role === "user" ? safeMessages : null;
}

/**
 * Validate the outer JSON payload before reading its messages property.
 * @param {unknown} input
 * @returns {Array<{role: "user" | "assistant", content: string}> | null}
 */
export function validateAssistantRequestBody(input) {
  if (!input || typeof input !== "object" || Array.isArray(input)) return null;
  if (Object.keys(input).some((key) => key !== "messages")) return null;
  return validateAssistantMessages(input.messages);
}
