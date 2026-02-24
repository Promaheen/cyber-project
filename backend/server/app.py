import os
import sqlite3
import json
import sys

# Add backend directory to sys.path to allow imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from backend.shared import config
from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

# Global store for active agents
# Format: {"Agent Name": timestamp_of_last_heartbeat}
import time
active_agents_store = {}

# Configuration
DB_PATH = config.DB_PATH


def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({"status": "healthy"}), 200

@app.route('/api/events', methods=['GET'])
def get_events():
    conn = get_db_connection()
    events = conn.execute('SELECT * FROM events ORDER BY timestamp DESC LIMIT 100').fetchall()
    conn.close()
    return jsonify([dict(ix) for ix in events])

@app.route('/api/blocked-ips', methods=['GET'])
def get_blocked_ips():
    conn = get_db_connection()
    ips = conn.execute('SELECT * FROM blocked_ips ORDER BY timestamp DESC').fetchall()
    conn.close()
    return jsonify([dict(ix) for ix in ips])

@app.route('/api/unblock', methods=['POST'])
def unblock_ip():
    data = request.json
    ip = data.get('ip')
    # Defaulting to agent-001 since we only have one for now. 
    # In a real system, we'd know which agent blocked it.
    agent_id = "Log Agent" 
    
    try:
        conn = get_db_connection()
        # 1. Remove from blocked_ips visual list
        conn.execute('DELETE FROM blocked_ips WHERE ip_address = ?', (ip,))
        
        # 2. Queue command for Agent
        conn.execute('INSERT INTO agent_commands (agent_id, command, params, status) VALUES (?, ?, ?, ?)',
                     (agent_id, 'UNBLOCK_IP', ip, 'pending'))
        
        conn.commit()
        conn.close()
        return jsonify({"status": "success", "message": f"Unblock command queued for {ip}"}), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/agent/commands', methods=['GET'])
def get_agent_commands():
    agent_id = request.args.get('agent_id')
    try:
        conn = get_db_connection()
        # Get pending commands for this agent
        cmds = conn.execute('SELECT * FROM agent_commands WHERE agent_id = ? AND status = ?', 
                          (agent_id, 'pending')).fetchall()
        
        # Mark them as 'sent' (or keep pending until ack? simpler to mark sent)
        # For this demo, let's assume agent performs them immediately.
        conn.execute('UPDATE agent_commands SET status = ? WHERE agent_id = ? AND status = ?',
                     ('sent', agent_id, 'pending'))
        conn.commit()
        conn.close()
        
        return jsonify([dict(ix) for ix in cmds])
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/events', methods=['DELETE'])
def clear_events():
    agent_id = request.args.get('agent')
    try:
        conn = get_db_connection()
        if agent_id:
            conn.execute('DELETE FROM events WHERE agent = ?', (agent_id,))
            msg = f"All events cleared for {agent_id}"
        else:
            conn.execute('DELETE FROM events')
            msg = "All events cleared"
            
        # Optional: Also clear blocked IPs? Or keep them?
        # User asked for "event clear", usually implies the log list.
        # Let's keep blocked IPs for safety unless asked.
        conn.commit()
        conn.close()
        return jsonify({"status": "success", "message": msg}), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/agents', methods=['GET'])
def get_active_agents():
    """Returns a list of agents that have sent a heartbeat in the last 2 minutes."""
    current_time = time.time()
    active_timeout_seconds = 120
    
    # Filter agents whose last heartbeat was within the timeout window
    active_list = [
        agent_id for agent_id, last_seen 
        in active_agents_store.items() 
        if (current_time - last_seen) < active_timeout_seconds
    ]
    
    return jsonify({"active_agents": active_list}), 200

@app.route('/api/events', methods=['POST'])
def receive_event():
    data = request.json
    agent_id = data.get('agent_id')
    event_type = data.get('event_type')
    details = data.get('details', {})
    
    severity = "info"
    message = f"Event received from {agent_id}: {event_type}"
    
    # Ignore heartbeats from polluting the timeline, but update the active agents store
    if event_type == "heartbeat":
        active_agents_store[agent_id] = time.time()
        return jsonify({"status": "success", "message": "Heartbeat received"}), 200

    # Handle IP Block Event
    if event_type == "ip_blocked":
        ip = details.get('ip')
        reason = details.get('reason')
        severity = "critical"
        message = f"ACTIVE RESPONSE: Blocked IP {ip}. Reason: {reason}"
        
        # Store in Blocked List
        try:
            conn = get_db_connection()
            conn.execute('INSERT OR IGNORE INTO blocked_ips (ip_address, reason, agent) VALUES (?, ?, ?)',
                         (ip, reason, agent_id))
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"Error storing blocked IP: {e}")

    # Handle IP Unblock Event (Auto-cooldown)
    elif event_type == "ip_unblocked":
        ip = details.get('ip')
        reason = details.get('reason')
        severity = "info"
        message = f"RESOLVED: IP {ip} unblocked. Reason: {reason}"
        
        # Remove from Blocked List
        try:
            conn = get_db_connection()
            conn.execute('DELETE FROM blocked_ips WHERE ip_address = ?', (ip,))
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"Error removing unblocked IP from database: {e}")

    # Handle Network Alerts
    elif event_type == "network_alert":
         severity = details.get('severity', 'info')
         message = details.get('message', 'Network Alert')
         source_ip = details.get('source_ip')
         if source_ip:
             message += f" [Source: {source_ip}]"

    # AI Analysis for Login Attempts
    elif event_type == "login_attempt_stats":
        failed_attempts = details.get('failed_attempts', 0)
        is_critical = details.get('is_critical', False)
        
        message = f"Detected {failed_attempts} Failed Login Attempts"
        
        if is_critical:
             if failed_attempts >= 5:
                 severity = "critical"
             else:
                 severity = "warning"
             message += " [High Velocity]"
        elif failed_attempts >= 5:
             severity = "critical"
             message += " [AI THREAT]"
        elif failed_attempts >= 3:
             severity = "warning"
        else:
             severity = "low"


    # Store in Database
    conn = get_db_connection()
    conn.execute('INSERT INTO events (agent, severity, message) VALUES (?, ?, ?)',
                 (agent_id, severity, message))
    conn.commit()
    conn.close()
    
    return jsonify({"status": "success", "severity": severity}), 201







if __name__ == '__main__':
    # Ensure DB exists
    if not os.path.exists(DB_PATH):
        print("Database not found. Please run database/setup_db.py")
    
    app.run(debug=True, host='0.0.0.0', port=5000)
