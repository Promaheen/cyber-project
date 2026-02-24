import React from 'react';

const EventLog = ({ events, selectedAgent }) => {

    const formatDate = (isoString) => {
        const date = new Date(isoString + 'Z');
        return date.toLocaleString('en-IN', {
            timeZone: 'Asia/Kolkata',
            day: '2-digit',
            month: 'short',
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit',
            hour12: true
        });
    };

    const formatMessage = (msg, severity) => {
        // New format: "Failed Login: 3/5 attempts from 10.134.225.98 [Escalating]"
        const progressMatch = msg.match(/Failed Login:\s+(\d+)\/(\d+)\s+attempts from\s+([\d.]+(?::[\w]+)?)\s*(?:\[(.+?)\])?/);

        if (progressMatch) {
            const count = parseInt(progressMatch[1]);
            const threshold = parseInt(progressMatch[2]);
            const ip = progressMatch[3];
            const tag = progressMatch[4] || '';
            const progress = Math.min((count / threshold) * 100, 100);

            const barColor = severity === 'critical' ? 'var(--status-danger)' :
                severity === 'warning' ? 'var(--status-warning)' : 'var(--neon-primary)';

            return (
                <span style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
                    <span style={{
                        background: 'rgba(255,255,255,0.05)',
                        padding: '2px 8px',
                        borderRadius: '4px',
                        fontFamily: 'var(--font-mono)',
                        fontSize: '0.85em',
                        border: '1px solid rgba(255,255,255,0.1)'
                    }}>{ip}</span>
                    <span style={{ display: 'flex', alignItems: 'center', gap: '6px', minWidth: '120px' }}>
                        <span style={{
                            width: '60px', height: '6px', borderRadius: '3px',
                            background: 'rgba(255,255,255,0.1)', display: 'inline-block', position: 'relative', overflow: 'hidden'
                        }}>
                            <span style={{
                                width: `${progress}%`, height: '100%', borderRadius: '3px',
                                background: barColor, display: 'block',
                                transition: 'width 0.3s ease'
                            }} />
                        </span>
                        <strong style={{
                            color: barColor,
                            fontSize: '1.05em',
                            fontFamily: 'var(--font-mono)'
                        }}>{count}/{threshold}</strong>
                    </span>
                    {tag && <span style={{
                        fontSize: '0.75em',
                        background: severity === 'critical' ? 'var(--status-danger)' : 'rgba(255,165,0,0.2)',
                        color: severity === 'critical' ? 'white' : 'var(--status-warning)',
                        padding: '2px 6px',
                        borderRadius: '4px',
                        fontWeight: 600
                    }}>{tag}</span>}
                </span>
            );
        }

        // Legacy format: "Detected N Failed Login Attempts"
        const loginMatch = msg.match(/(?:reported|Detected)\s+(\d+)\s+(?:failed login attempts|Failed Login Attempts)/i);

        if (loginMatch) {
            const count = parseInt(loginMatch[1]);
            if (count === 0) return <span style={{ opacity: 0.6 }}>System Check: Normal</span>;

            return (
                <span>
                    Detected <strong style={{
                        color: severity === 'critical' ? 'var(--status-danger)' :
                            severity === 'warning' ? 'var(--status-warning)' : 'inherit',
                        fontSize: '1.1em'
                    }}>{count}</strong> Failed Login Attempts
                    {(msg.includes("AI DETECTED") || msg.includes("AI THREAT")) && <span style={{ marginLeft: '10px', fontSize: '0.8em', background: 'var(--status-danger)', color: 'white', padding: '2px 6px', borderRadius: '4px' }}>THREAT</span>}
                </span>
            );
        }

        // Suspicious login
        if (msg.includes("SUSPICIOUS LOGIN")) {
            return <span style={{ color: 'var(--status-danger)', fontWeight: 600 }}>{msg}</span>;
        }

        // DDoS / Flood format: "SYN Flood: 60/50 pkt/sec from 10.x.x.x [FLOOD DETECTED]"
        const ddosMatch = msg.match(/(.+?):\s+(\d+)\/(\d+)\s+pkt\/sec from\s+([\d.]+(?::[\w]+)?)\s*(?:\[(.+?)\])?/);
        if (ddosMatch) {
            const attackType = ddosMatch[1];
            const count = parseInt(ddosMatch[2]);
            const threshold = parseInt(ddosMatch[3]);
            const ip = ddosMatch[4];
            const tag = ddosMatch[5] || '';
            const progress = Math.min((count / threshold) * 100, 100);

            const barColor = severity === 'critical' ? 'var(--status-danger)' :
                severity === 'warning' ? 'var(--status-warning)' : 'var(--neon-primary)';

            return (
                <span style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
                    <span style={{
                        fontSize: '0.8em', fontWeight: 600,
                        background: 'rgba(255,100,100,0.15)', color: 'var(--status-danger)',
                        padding: '2px 6px', borderRadius: '4px'
                    }}>{attackType}</span>
                    <span style={{
                        background: 'rgba(255,255,255,0.05)', padding: '2px 8px', borderRadius: '4px',
                        fontFamily: 'var(--font-mono)', fontSize: '0.85em',
                        border: '1px solid rgba(255,255,255,0.1)'
                    }}>{ip}</span>
                    <span style={{ display: 'flex', alignItems: 'center', gap: '6px', minWidth: '120px' }}>
                        <span style={{
                            width: '60px', height: '6px', borderRadius: '3px',
                            background: 'rgba(255,255,255,0.1)', display: 'inline-block', overflow: 'hidden'
                        }}>
                            <span style={{
                                width: `${progress}%`, height: '100%', borderRadius: '3px',
                                background: barColor, display: 'block', transition: 'width 0.3s ease'
                            }} />
                        </span>
                        <strong style={{ color: barColor, fontFamily: 'var(--font-mono)', fontSize: '1.05em' }}>
                            {count}/{threshold}
                        </strong>
                        <span style={{ fontSize: '0.7em', color: 'var(--text-muted)' }}>pkt/s</span>
                    </span>
                    {tag && <span style={{
                        fontSize: '0.75em', fontWeight: 600, padding: '2px 6px', borderRadius: '4px',
                        background: severity === 'critical' ? 'var(--status-danger)' : 'rgba(255,165,0,0.2)',
                        color: severity === 'critical' ? 'white' : 'var(--status-warning)'
                    }}>{tag}</span>}
                </span>
            );
        }

        return msg;
    };

    // Filter out "System Check: Normal" (0 failures)
    const filteredEvents = events.filter(event => {
        const loginMatch = event.message.match(/(?:reported|Detected)\s+(\d+)\s+(?:failed login attempts|Failed Login Attempts)/i);
        if (loginMatch) {
            return parseInt(loginMatch[1]) > 0;
        }
        return true;
    });

    const handleClearEvents = async () => {
        const confirmMsg = selectedAgent
            ? `Are you sure you want to CLEAR the event log for ${selectedAgent}?`
            : "Are you sure you want to CLEAR the entire event log?";

        if (!confirm(confirmMsg)) return;

        try {
            const url = selectedAgent
                ? `http://localhost:5000/api/events?agent=${encodeURIComponent(selectedAgent)}`
                : 'http://localhost:5000/api/events';
            await fetch(url, { method: 'DELETE' });
            // The App.jsx polling will automatically refresh the list to empty
        } catch (err) {
            console.error("Failed to clear events:", err);
        }
    };

    return (
        <div className="card event-log-card">
            <div className="card-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div>
                    <h2 className="card-title">Live Security Events</h2>
                    <span className="event-count">{filteredEvents.length} threats detected</span>
                </div>
                <button
                    onClick={handleClearEvents}
                    style={{
                        background: 'transparent',
                        border: '1px solid var(--status-danger)',
                        color: 'var(--status-danger)',
                        padding: '4px 8px',
                        borderRadius: '4px',
                        cursor: 'pointer',
                        fontSize: '0.8rem',
                        fontFamily: 'var(--font-mono)'
                    }}
                    onMouseOver={(e) => e.target.style.background = 'rgba(239, 68, 68, 0.1)'}
                    onMouseOut={(e) => e.target.style.background = 'transparent'}
                >
                    CLEAR LOG
                </button>
            </div>
            <div className="table-container">
                <table className="event-table">
                    <thead>
                        <tr>
                            <th width="20%">TIME (IST)</th>
                            <th width="15%">AGENT</th>
                            <th width="10%">STATUS</th>
                            <th>ACTIVITY DETAIL</th>
                        </tr>
                    </thead>
                    <tbody>
                        {filteredEvents.map((event) => (
                            <tr key={event.id} className={`severity-${event.severity}`}>
                                <td className="timestamp" style={{ color: 'var(--text-muted)' }}>
                                    {formatDate(event.timestamp)}
                                </td>
                                <td className="agent" style={{ fontFamily: 'var(--font-mono)' }}>{event.agent}</td>
                                <td>
                                    <span className={`badge badge-${event.severity}`}>
                                        {event.severity === 'critical' ? 'THREAT' :
                                            event.severity === 'warning' ? 'WARN' : 'SAFE'}
                                    </span>
                                </td>
                                <td className="message">{formatMessage(event.message, event.severity)}</td>
                            </tr>
                        ))}
                        {filteredEvents.length === 0 && (
                            <tr>
                                <td colSpan="4" className="empty-state">
                                    No threats detected. Monitoring safe activity...
                                </td>
                            </tr>
                        )}
                    </tbody>
                </table>
            </div>
        </div>
    );
};

export default EventLog;
