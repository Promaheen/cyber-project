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
        // Regex to extract key info: Supports both old "reported <N>" and new "Detected <N>" formats
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

        return msg;
    };

    // Filter out "System Check: Normal" (0 failures)
    const filteredEvents = events.filter(event => {
        // Match both old and new formats
        const loginMatch = event.message.match(/(?:reported|Detected)\s+(\d+)\s+(?:failed login attempts|Failed Login Attempts)/i);
        if (loginMatch) {
            return parseInt(loginMatch[1]) > 0;
        }
        return true; // Keep other types of events
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
