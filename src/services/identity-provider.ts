import { Request } from 'express';

export interface UserIdentity {
    id: string;
    username: string;
    role: 'admin' | 'user' | 'guest';
    department: string;
}

export class IdentityProvider {
    /**
     * Mocks verifying a token from the request header.
     * In a real app, this would verify a JWT or session.
     */
    static async verify(req: Request): Promise<UserIdentity | null> {
        const authHeader = req.headers['authorization'];

        // SIMULATION: 
        // If header is "Bearer admin-token", return admin
        // If header is "Bearer user-token", return user
        // Else return null

        if (authHeader === 'Bearer admin-token') {
            return { id: 'u-1', username: 'alice_admin', role: 'admin', department: 'IT' };
        }

        if (authHeader === 'Bearer user-token') {
            return { id: 'u-2', username: 'bob_user', role: 'user', department: 'Sales' };
        }

        return null;
    }
}
