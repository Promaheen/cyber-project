import React, { useState, useEffect } from 'react';
import Layout from './components/Layout';
import StatGrid from './components/StatGrid';
import EventLog from './components/EventLog';
import ActivityChart from './components/ActivityChart';
import BlockedList from './components/BlockedList';

function App() {
  // State for all security events
  const [events, setEvents] = useState([]);

  // Real active agents tracked via heartbeat
  const [activeAgents, setActiveAgents] = useState([]);

  const [blockedIps, setBlockedIps] = useState([]);
  const [status, setStatus] = useState('safe');
  const [selectedAgent, setSelectedAgent] = useState(null);

  const fetchData = async () => {
    try {
      // 1. Fetch Log Events
      const logRes = await fetch('http://localhost:5000/api/events');
      let newLogEvents = [];
      if (logRes.ok) {
        newLogEvents = await logRes.json();
      }

      // 2. Sort Events by id (preserves exact insertion order)
      const allEvents = [...newLogEvents].sort((a, b) => b.id - a.id);
      setEvents(allEvents);

      // 3. Determine System Status
      const recentCritical = allEvents.some(e => e.severity === 'critical' || e.severity === 'HIGH');
      if (recentCritical) setStatus('danger');
      else if (allEvents.some(e => e.severity === 'warning')) setStatus('warning');
      else setStatus('safe');

      // 4. Fetch Blocked IPs
      const blockedRes = await fetch('http://localhost:5000/api/blocked-ips');
      if (blockedRes.ok) {
        setBlockedIps(await blockedRes.json());
      }

      // 5. Fetch Active Agents
      const agentsRes = await fetch('http://localhost:5000/api/agents');
      if (agentsRes.ok) {
        const data = await agentsRes.json();
        setActiveAgents(data.active_agents || []);
      }

    } catch (error) {
      console.error("Failed to fetch data:", error);
    }
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 2000); // Poll every 2 seconds
    return () => clearInterval(interval);
  }, []);

  // Filter events based on selection
  const filteredEvents = selectedAgent
    ? events.filter(e => e.agent === selectedAgent)
    : events;

  // Filter blocked IPs based on selection
  const filteredBlockedIps = selectedAgent
    ? blockedIps.filter(ip => ip.agent === selectedAgent)
    : blockedIps;

  return (
    <Layout agents={activeAgents} selectedAgent={selectedAgent} setSelectedAgent={setSelectedAgent}>
      <header style={{ marginBottom: '2rem', borderBottom: '1px solid var(--border-glass)', paddingBottom: '1rem', display: 'flex', justifyContent: 'space-between', alignItems: 'end' }}>
        <div>
          {!selectedAgent && <div className="text-neon" style={{ fontSize: '0.9rem', marginBottom: '0.5rem' }}>// DASHBOARD</div>}
          <h2 className="animate-flicker" style={{ margin: 0, fontSize: '2rem', fontWeight: '300' }}>
            {selectedAgent ? `AGENT: ${selectedAgent}` : 'OVERVIEW'}
          </h2>
        </div>
        <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.9rem', color: 'var(--text-muted)' }}>
          LINK_STATUS: <span style={{ color: 'var(--status-safe)' }}>CONNECTED</span>
        </div>
      </header>

      {selectedAgent ? (
        <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: '2rem' }}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '2rem' }}>
            <div>
              <h3 style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', marginBottom: '1rem' }}>AGENT EVENTS</h3>
              <EventLog events={filteredEvents} selectedAgent={selectedAgent} />
            </div>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '2rem' }}>
            <div>
              <h3 style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', marginBottom: '1rem' }}>BLOCKED IPS</h3>
              <BlockedList blockedIps={filteredBlockedIps} setBlockedIps={setBlockedIps} />
            </div>
          </div>
        </div>
      ) : (
        <>
          <StatGrid events={filteredEvents} status={status} />

          <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: '2rem' }}>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '2rem' }}>
              <div>
                <h3 style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', marginBottom: '1rem' }}>LIVE EVENT FEED</h3>
                <EventLog events={filteredEvents} selectedAgent={selectedAgent} />
              </div>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '2rem' }}>
              <div>
                <h3 style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', marginBottom: '1rem' }}>METRICS & ANALYSIS</h3>
                <ActivityChart events={filteredEvents} />
              </div>
              <div>
                <BlockedList blockedIps={filteredBlockedIps} setBlockedIps={setBlockedIps} />
              </div>
            </div>
          </div>
        </>
      )}
    </Layout>
  );
}

export default App;
