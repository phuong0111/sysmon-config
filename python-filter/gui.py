import os
import sys
import time
import threading
import json
import logging
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Deque
from collections import deque
import signal

from flask import Flask, render_template, jsonify, request, Response
from elasticsearch import Elasticsearch
from dotenv import load_dotenv

# Import the SecurityMonitor class and necessary functions
from server import SecurityMonitor
from main import create_es_client
from matching import (
    filter_bypassuac_attempt, 
    filter_malicious_shell_connect, 
    filter_lsass_access_attempt
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("security_monitor.log")
    ]
)
logger = logging.getLogger("SecurityMonitorWebGUI")

# Create Flask app
app = Flask(__name__)

# Global state
class MonitorState:
    def __init__(self):
        self.es_client = None
        self.security_monitor = None
        self.monitoring_active = False
        self.monitor_thread = None
        self.log_queue = deque(maxlen=1000)  # Store last 1000 log entries
        self.recent_alerts = deque(maxlen=50)  # Store last 50 alerts
        self.clients = {}  # Dictionary of client_id -> queue

state = MonitorState()

# Custom handler for logs to store in our queue
class QueueHandler(logging.Handler):
    def __init__(self, log_queue):
        logging.Handler.__init__(self)
        self.log_queue = log_queue
        
    def emit(self, record):
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "level": record.levelname.lower(),
            "message": self.format(record)
        }
        self.log_queue.append(log_entry)
        
        # Send to SSE clients
        for client_id, client_queue in list(state.clients.items()):
            try:
                client_queue.append(("log", {
                    "level": log_entry["level"],
                    "message": log_entry["message"]
                }))
            except Exception:
                state.clients.pop(client_id, None)

# Set up the queue handler
queue_handler = QueueHandler(state.log_queue)
queue_handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(message)s')
queue_handler.setFormatter(formatter)
logger.addHandler(queue_handler)
root_logger = logging.getLogger()
root_logger.addHandler(queue_handler)

# Custom alert handler class
class AlertHandler:
    def __init__(self, alert_type):
        self.alert_type = alert_type

    def __call__(self, alert):
        agent_id = alert.get('agent', {}).get('id', 'unknown')
        description = alert.get('rule', {}).get('description', 'No description')
        timestamp = alert.get('timestamp', datetime.now().isoformat())
        
        logger.warning(f"{self.alert_type}: Agent {agent_id} - {description}")
        
        # Add to recent alerts
        state.recent_alerts.appendleft({
            "type": self.alert_type,
            "agent_id": agent_id,
            "description": description,
            "timestamp": timestamp
        })
        
        # Send to clients
        for client_id, client_queue in list(state.clients.items()):
            try:
                client_queue.append(("alert", {
                    "type": self.alert_type,
                    "agent_id": agent_id,
                    "description": description,
                    "timestamp": timestamp
                }))
            except Exception:
                state.clients.pop(client_id, None)

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/connect', methods=['POST'])
def connect():
    try:
        if state.es_client:
            return jsonify({"success": True})
            
        state.es_client = create_es_client()
        
        # Test connection
        if state.es_client.ping():
            logger.info("Successfully connected to Elasticsearch")
            return jsonify({"success": True})
        else:
            return jsonify({"success": False, "error": "Failed to connect to Elasticsearch"})
    
    except Exception as e:
        logger.error(f"Error connecting to Elasticsearch: {str(e)}")
        return jsonify({"success": False, "error": str(e)})

@app.route('/api/start', methods=['POST'])
def start_monitoring():
    if state.monitoring_active:
        return jsonify({"success": True})
        
    try:
        # Get configuration from request
        config = request.json
        
        # Create SecurityMonitor instance
        state.security_monitor = SecurityMonitor(
            es_client=state.es_client,
            index=config.get("index", "wazuh-alerts-*"),
            interval=int(config.get("interval", 5)),
            agent_id=config.get("agent_id") if config.get("agent_id") else None
        )
        
        # Start monitoring thread
        state.monitoring_active = True
        state.monitor_thread = threading.Thread(target=monitoring_loop)
        state.monitor_thread.daemon = True
        state.monitor_thread.start()
        
        logger.info("Monitoring started")
        return jsonify({"success": True})
    
    except Exception as e:
        logger.error(f"Error starting monitoring: {str(e)}")
        return jsonify({"success": False, "error": str(e)})

@app.route('/api/stop', methods=['POST'])
def stop_monitoring():
    if not state.monitoring_active:
        return jsonify({"success": True})
    
    try:
        state.monitoring_active = False
        
        # Wait for thread to terminate (with timeout)
        if state.monitor_thread and state.monitor_thread.is_alive():
            state.monitor_thread.join(timeout=2.0)
        
        logger.info("Monitoring stopped")
        return jsonify({"success": True})
    
    except Exception as e:
        logger.error(f"Error stopping monitoring: {str(e)}")
        return jsonify({"success": False, "error": str(e)})

@app.route('/api/events')
def events():
    def generate():
        # Create a unique client ID and a new queue for this client
        client_id = str(uuid.uuid4())
        client_queue = deque(maxlen=100)
        state.clients[client_id] = client_queue
        
        # Send current stats
        if state.security_monitor:
            client_queue.append(("stats", state.security_monitor.alert_counters))
        
        try:
            while True:
                # Check if there's anything in the queue
                if client_queue:
                    event_type, data = client_queue.popleft()
                    yield f"event: {event_type}\ndata: {json.dumps(data)}\n\n"
                else:
                    # Send a heartbeat every 15 seconds
                    yield f"event: heartbeat\ndata: {{}}\n\n"
                    
                time.sleep(0.1)
        except GeneratorExit:
            # Clean up when the client disconnects
            state.clients.pop(client_id, None)
    
    return Response(generate(), mimetype='text/event-stream')

def monitoring_loop():
    """Main monitoring loop (runs in a separate thread)"""
    if not state.security_monitor:
        logger.error("SecurityMonitor not initialized")
        return
        
    # Register alert handlers to capture alerts for the web interface
    uac_handler = AlertHandler("UAC Bypass")
    shell_handler = AlertHandler("Malicious PowerShell")
    lsass_handler = AlertHandler("LSASS Access")
    
    # Override the process_alerts method to send stats to clients
    original_process_alerts = state.security_monitor.process_alerts
    
    def process_alerts_with_web_updates(alerts):
        # Call the original method first
        original_process_alerts(alerts)
        
        # Send updated stats to all clients
        for client_id, client_queue in list(state.clients.items()):
            try:
                client_queue.append(("stats", state.security_monitor.alert_counters))
            except Exception:
                state.clients.pop(client_id, None)
                
        # Handle specific alert types for web interface
        bypassuac_alerts = filter_bypassuac_attempt(alerts)
        for alert in bypassuac_alerts:
            uac_handler(alert)
            
        shell_alerts = filter_malicious_shell_connect(alerts)
        for alert in shell_alerts:
            shell_handler(alert)
            
        lsass_alerts = filter_lsass_access_attempt(alerts)
        for alert in lsass_alerts:
            lsass_handler(alert)
    
    # Replace the process_alerts method
    state.security_monitor.process_alerts = process_alerts_with_web_updates
    
    try:
        # Run the monitor with our own loop to control termination
        logger.info(f"Starting security monitor. Checking every {state.security_monitor.interval} seconds")
        logger.info(f"Monitoring index: {state.security_monitor.index}")
        
        if state.security_monitor.agent_id:
            logger.info(f"Filtering for agent ID: {state.security_monitor.agent_id}")
            
        last_stats_time = time.time()
        stats_interval = 60  # Print stats every minute
        
        while state.monitoring_active:
            state.security_monitor.check_new_alerts()
            
            # Print stats periodically
            current_time = time.time()
            if current_time - last_stats_time >= stats_interval:
                state.security_monitor.print_stats()
                last_stats_time = current_time
                
            # Sleep until next check
            time.sleep(state.security_monitor.interval)
            
    except Exception as e:
        logger.error(f"Error in monitoring loop: {str(e)}")
    finally:
        logger.info("Monitoring loop terminated")

def main():
    """Main entry point for the web GUI application"""
    try:
        # Register signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, lambda sig, frame: shutdown())
        signal.signal(signal.SIGTERM, lambda sig, frame: shutdown())
        
        # Load environment variables
        load_dotenv()
        
        # Get port from environment or use default
        port = int(os.environ.get('PORT', 5002))
        host = os.environ.get('HOST', '0.0.0.0')
        
        logger.info(f"Starting Security Monitor Web GUI on {host}:{port}")
        app.run(host=host, port=port, debug=False, threaded=True)
        
    except Exception as e:
        logger.error(f"Error starting application: {str(e)}")
        sys.exit(1)

def shutdown():
    """Gracefully shut down the application"""
    logger.info("Shutting down...")
    
    # Stop monitoring if active
    if state.monitoring_active:
        state.monitoring_active = False
        if state.monitor_thread and state.monitor_thread.is_alive():
            state.monitor_thread.join(timeout=2.0)
    
    # Other cleanup if needed
    sys.exit(0)

if __name__ == "__main__":
    main()