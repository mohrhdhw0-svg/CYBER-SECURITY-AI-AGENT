export function checkAssistantRateLimit(clientKey: string): Promise<{ allowed: boolean; remaining: number }>;
