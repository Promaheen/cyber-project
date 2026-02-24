import React from 'react';

const BlockedList = ({ blockedIps, setBlockedIps }) => {
    const handleUnblock = async (ip) => {
        if (!confirm(`Unblock IP ${ip}?`)) return;

        // Optimistic Update: Remove from UI immediately
        if (setBlockedIps) {
            setBlockedIps(prev => prev.filter(item => item.ip_address !== ip));
        }

        try {
            await fetch('http://localhost:5000/api/unblock', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ip })
            });
        } catch (err) {
            console.error("Failed to unblock:", err);
            // Optional: Revert state if failed
        }
    };

    return (
        <div className="card-panel" style={{ height: '100%' }}>
            <div style={{ padding: '1.5rem', borderBottom: '1px solid var(--border-glass)' }}>
                <h3 style={{ margin: 0, fontSize: '1rem', color: 'var(--status-danger)' }}>
                    ⛔ ACTIVE BLOCKS ({blockedIps.length})
                </h3>
            </div>
            <div style={{ maxHeight: '400px', overflowY: 'auto' }}>
                {blockedIps.length === 0 ? (
                    <div style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-muted)', fontSize: '0.9rem' }}>
                        No active blocks. Network is clear.
                    </div>
                ) : (
                    <table className="event-table">
                        <thead>
                            <tr>
                                <th>IP ADDRESS</th>
                                <th>REASON</th>
                                <th>ACTION</th>
                            </tr>
                        </thead>
                        <tbody>
                            {blockedIps.map(item => (
                                <tr key={item.id}>
                                    <td style={{ color: 'var(--text-primary)', fontFamily: 'var(--font-mono)' }}>{item.ip_address}</td>
                                    <td style={{ color: 'var(--text-secondary)' }}>{item.reason}</td>
                                    <td>
                                        <button
                                            onClick={() => handleUnblock(item.ip_address)}
                                            style={{
                                                background: 'rgba(6, 182, 212, 0.1)',
                                                border: '1px solid var(--accent-cyan)',
                                                color: 'var(--accent-cyan)',
                                                cursor: 'pointer',
                                                padding: '2px 8px',
                                                borderRadius: '4px',
                                                fontSize: '0.75rem'
                                            }}>
                                            UNBLOCK
                                        </button>
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                )}
            </div>
        </div>
    );
};
export default BlockedList;
