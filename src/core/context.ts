import { IContext } from './interfaces';

export class ContextEvaluator {
    // Generic context builder.
    // In a real app, this would extract from an Express/Fastify request object.
    // We'll define a generic interface for the input request to keep it framework-agnostic where possible,
    // but for now, we'll assume it receives an object with headers, ip, etc.

    public static async buildContext(req: any, extraData: any = {}): Promise<IContext> {
        const context: IContext = {
            timestamp: new Date(),
            ip: req.ip || req.socket?.remoteAddress || 'unknown',
            userAgent: req.headers?.['user-agent'],
            ...extraData,
        };

        return context;
    }
}
