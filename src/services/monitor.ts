export interface AccessEvent {
    id: string;
    timestamp: string;
    user: string;
    action: string;
    resource: string;
    trustScore: number;
    status: 'ALLOW' | 'BLOCK' | 'CHALLENGE';
    riskFactors: string[];
}

class MonitorService {
    private events: AccessEvent[] = [];
    private readonly MAX_EVENTS = 50;

    logEvent(event: AccessEvent) {
        this.events.unshift(event);
        if (this.events.length > this.MAX_EVENTS) {
            this.events.pop();
        }
    }

    getEvents(): AccessEvent[] {
        return this.events;
    }
}

export const monitor = new MonitorService();
