export interface IContext {
    ip: string;
    userAgent?: string;
    timestamp: Date;
    userId?: string;
    roles?: string[];
    [key: string]: any;
}

export interface IRequest {
    subject: string; // The user or service making the request
    action: string;  // e.g., 'read', 'write', 'delete'
    resource: string; // e.g., 'database', 'file', 'api-endpoint'
    context: IContext;
}

export enum Decision {
    ALLOW = 'ALLOW',
    DENY = 'DENY',
}

export interface IPolicy {
    id: string;
    description?: string;
    // A function that evaluates the request and returns a boolean (true = allow) or a Decision
    evaluate(request: IRequest): Promise<Decision> | Decision;
}

export interface IPolicyEngine {
    evaluate(request: IRequest): Promise<Decision>;
    addPolicy(policy: IPolicy): void;
    removePolicy(policyId: string): void;
}
