import React from 'react';

const StatCard = ({ label, value, color, icon }) => (
    <div className="card-panel" style={{ padding: '1.5rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'start' }}>
            <div>
                <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>{label}</div>
                <div style={{ fontSize: '2.5rem', fontWeight: 'bold', color: 'var(--text-primary)', marginTop: '0.5rem', fontFamily: 'var(--font-mono)' }}>
                    {value}
                </div>
            </div>
            <div style={{ color: color, opacity: 0.8, fontSize: '1.5rem' }}>{icon}</div>
        </div>
    </div>
);

const StatGrid = ({ events, status }) => {
    // Check if event is meaningful (failed attempts > 0)
    const activeEvents = events.filter(e => {
        const loginMatch = e.message.match(/(?:reported|Detected)\s+(\d+)\s+(?:failed login attempts|Failed Login Attempts)/i);
        if (loginMatch) {
            return parseInt(loginMatch[1]) > 0;
        }
        return true; // Keep other types
    });

    const threatCount = events.filter(e => e.severity === 'critical').length;
    const activeAgents = new Set(events.map(e => e.agent)).size;

    return (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '1.5rem', marginBottom: '2rem' }}>
            <StatCard
                label="Total Activity"
                value={activeEvents.length}
                color="var(--accent-cyan)"
                icon="≣"
            />
            <StatCard
                label="Active Threats"
                value={threatCount}
                color={threatCount > 0 ? "var(--status-danger)" : "var(--status-safe)"}
                icon="⚠"
            />
            <StatCard
                label="Active Agents"
                value={activeAgents}
                color="var(--accent-blue)"
                icon="◈"
            />
            <StatCard
                label="System Status"
                value={status === 'danger' ? 'CRIT' : status === 'warning' ? 'WARN' : 'OK'}
                color={status === 'danger' ? 'var(--status-danger)' : status === 'warning' ? 'var(--status-warning)' : 'var(--status-safe)'}
                icon="⚡"
            />
        </div>
    );
};

export default StatGrid;
