const feedContent = document.getElementById('feed-content');
const totalReqsEl = document.getElementById('total-reqs');
const avgTrustEl = document.getElementById('avg-trust');
const blockedReqsEl = document.getElementById('blocked-reqs');

let seenIds = new Set();
let stats = { total: 0, blocked: 0, trustSum: 0 };

async function fetchEvents() {
    try {
        const response = await fetch('/api/monitor/events');
        const events = await response.json();
        
        // Reset stats for simplicity or calculate from fetched batch
        // Real app would have persistent stats endpoint
        
        // For visual feed, we just prepend new ones
        renderEvents(events);
    } catch (error) {
        console.error('Error fetching events:', error);
    }
}

function renderEvents(events) {
    // We'll just rebuild the specific view for simplicity in this demo
    feedContent.innerHTML = '';
    
    // Recalculate stats from the window of events we get
    let currentTotal = events.length;
    let currentBlocked = 0;
    let currentTrustSum = 0;

    events.forEach(event => {
        if (event.status === 'BLOCK' || event.status === 'CHALLENGE') currentBlocked++;
        currentTrustSum += event.trustScore;

        const row = document.createElement('div');
        row.className = 'feed-item';
        
        const time = new Date(event.timestamp).toLocaleTimeString();
        
        // Trust bar color
        let riskColor = '#4caf50';
        if (event.trustScore < 70) riskColor = '#ff9800';
        if (event.trustScore < 40) riskColor = '#f44336';

        const statusClass = `status-${event.status.toLowerCase()}`;

        row.innerHTML = `
            <div style="font-size: 0.8em; color: #888;">${time}</div>
            <div style="font-weight: 500;">${event.user}</div>
            <div><span style="background: #333; padding: 2px 6px; border-radius: 4px; font-size: 0.8em;">${event.action}</span></div>
            <div style="font-family: monospace; color: #aaa;">${event.resource}</div>
            <div>
                <div class="risk-bar">
                    <div class="risk-fill" style="width: ${event.trustScore}%; background: ${riskColor};"></div>
                </div>
                <div style="font-size: 0.7em; text-align: right; margin-top: 2px;">${event.trustScore}%</div>
            </div>
            <div class="${statusClass}">${event.status}</div>
        `;
        
        if (event.riskFactors.length > 0) {
            row.title = "Risk Factors: " + event.riskFactors.join(', ');
        }

        feedContent.appendChild(row);
    });

    // Update Stats
    totalReqsEl.textContent = currentTotal;
    blockedReqsEl.textContent = currentBlocked;
    const avg = currentTotal > 0 ? Math.round(currentTrustSum / currentTotal) : 100;
    avgTrustEl.textContent = avg + '%';
    
    // Color code the stats
    avgTrustEl.style.color = avg > 80 ? '#4caf50' : (avg > 50 ? '#ff9800' : '#f44336');
}

// Poll every 1 second
setInterval(fetchEvents, 1000);
fetchEvents();
