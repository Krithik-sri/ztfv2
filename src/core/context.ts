import { IContext } from './interfaces.js';

/**
 * Builds contextual information from an incoming request.
 *
 * Framework-agnostic: accepts any object with `ip`, `headers`, and `socket` properties.
 * The Express/Fastify/Koa/Hono adapters pass their native request objects directly.
 */
export class ContextEvaluator {
  /**
   * Build an IContext from a generic request-like object.
   *
   * @param req - An object with optional ip, headers, and socket properties
   * @param extraData - Additional context fields (userId, roles, metadata)
   * @returns A fully populated IContext
   */
  public static async buildContext(
    req: {
      ip?: string;
      headers?: Record<string, string | string[] | undefined>;
      socket?: { remoteAddress?: string };
    },
    extraData: Partial<IContext> = {},
  ): Promise<IContext> {
    const context: IContext = {
      timestamp: new Date(),
      ip: req.ip ?? req.socket?.remoteAddress ?? 'unknown',
      userAgent: Array.isArray(req.headers?.['user-agent'])
        ? req.headers['user-agent'][0]
        : req.headers?.['user-agent'],
      ...extraData,
    };

    return context;
  }
}
