import React from 'react';

const ActivityChart = ({ events }) => {
    // Simple aggregation: count events per 'slice' (simulated time buckets)
    // For demo, we just randomize a bit or take last 20 events relative severity

    const bars = Array.from({ length: 40 }).map((_, i) => {
        // Fake some data visual
        const height = Math.random() * 80 + 20;
        const isThreat = Math.random() > 0.9;

        return (
            <div key={i} style={{
                height: `${height}%`,
                width: '8px',
                backgroundColor: isThreat ? 'var(--status-danger)' : 'var(--accent-cyan)',
                opacity: Math.random() * 0.5 + 0.5,
                borderRadius: '2px'
            }}></div>
        );
    });

    return (
        <div className="card-panel" style={{ padding: '1.5rem', marginBottom: '2rem' }}>
            <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '1rem' }}>
                Network Activity Spectrum
            </div>
            <div style={{ height: '100px', display: 'flex', alignItems: 'flex-end', gap: '4px', overflow: 'hidden' }}>
                {bars}
            </div>
        </div>
    );
};

export default ActivityChart;
