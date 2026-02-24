import React from 'react';
import Sidebar from './Sidebar';

const Layout = ({ children, agents = [], selectedAgent, setSelectedAgent }) => {
    return (
        <div className="layout">
            <div className="bg-grid"></div>
            <div className="scanlines"></div>

            <Sidebar agents={agents} selectedAgent={selectedAgent} setSelectedAgent={setSelectedAgent} />

            <main style={{
                marginLeft: '260px',
                padding: '2rem',
                minHeight: '100vh',
                position: 'relative',
                zIndex: 1
            }}>
                <div style={{ maxWidth: '1400px', margin: '0 auto' }}>
                    {children}
                </div>
            </main>
        </div>
    );
};

export default Layout;
