import React from 'react';

const Sidebar = ({ agents = [], selectedAgent, setSelectedAgent }) => {
    return (
        <aside style={{
            width: '260px',
            height: '100vh',
            position: 'fixed',
            left: 0,
            top: 0,
            background: 'var(--bg-panel)',
            borderRight: '1px solid var(--border-glass)',
            display: 'flex',
            flexDirection: 'column',
            zIndex: 100
        }}>
            <div style={{ padding: '2rem', borderBottom: '1px solid var(--border-glass)' }}>
                <h1 style={{ margin: 0, fontSize: '1.2rem', letterSpacing: '0.1em', color: 'var(--text-primary)' }}>
                    CYBER<span className="text-neon">SHIELD</span>
                </h1>
                <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginTop: '0.5rem' }}>
                    INTELLIGENT SOC v1.0
                </div>
            </div>

            <nav style={{ flex: 1, paddingTop: '2rem', overflowY: 'auto' }}>
                <a href="#"
                    className={`nav-link ${!selectedAgent ? 'active' : ''}`}
                    onClick={(e) => { e.preventDefault(); setSelectedAgent(null); }}
                >
                    <span style={{ marginRight: '1rem' }}>▣</span> Dashboard
                </a>

                <div style={{ padding: '1.5rem 2rem 0.5rem', fontSize: '0.7rem', color: 'var(--text-muted)', letterSpacing: '0.1em' }}>
                    AGENTS ({agents.length})
                </div>

                {agents.map(agent => (
                    <a
                        key={agent}
                        href="#"
                        className={`nav-link ${selectedAgent === agent ? 'active' : ''}`}
                        onClick={(e) => { e.preventDefault(); setSelectedAgent(agent); }}
                    >
                        <span style={{ marginRight: '1rem' }}>◩</span> {agent}
                    </a>
                ))}
            </nav>

            <div style={{ padding: '2rem', borderTop: '1px solid var(--border-glass)' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.8rem' }}>
                    <div style={{ width: '8px', height: '8px', background: 'var(--status-safe)', borderRadius: '50%', boxShadow: '0 0 10px var(--status-safe)' }}></div>
                    <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>System Online</span>
                </div>
            </div>
        </aside>
    );
};

export default Sidebar;
