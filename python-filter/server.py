from datetime import datetime, timedelta
import time
import logging
import signal
import sys
from typing import List, Dict, Optional

from elasticsearch import Elasticsearch
from main import create_es_client, get_wazuh_alerts
from matching import (
    filter_bypassuac_attempt, 
    filter_malicious_shell_connect, 
    filter_lsass_access_attempt
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("SecurityMonitor")

# Global flag for graceful termination
running = True

def signal_handler(sig, frame):
    """Handle termination signals for graceful shutdown"""
    global running
    logger.info("Received termination signal. Shutting down...")
    running = False

class SecurityMonitor:
    """Real-time security monitoring service"""
    
    def __init__(self, 
                 es_client: Elasticsearch, 
                 index: str = "wazuh-alerts-*", 
                 interval: int = 3,
                 agent_id: Optional[str] = None):
        """
        Initialize the security monitor.
        
        Args:
            es_client: Elasticsearch client
            index: Elasticsearch index to query
            interval: How often to check for new alerts (in seconds)
            agent_id: Optional agent ID to filter results
        """
        self.es_client = es_client
        self.index = index
        self.interval = interval
        self.agent_id = agent_id
        self.last_check_time = datetime.now() - timedelta(seconds=interval)
        
        # Track alert counts for reporting
        self.alert_counters = {
            "total": 0,
            "bypassuac": 0,
            "malicious_shell": 0,
            "lsass_access": 0
        }
    
    def get_additional_filters(self) -> List[Dict]:
        """Generate additional filters based on configuration"""
        filters = []
        
        if self.agent_id:
            filters.append({"term": {"agent.id": self.agent_id}})
            
        return filters
    
    def process_alerts(self, alerts: List[Dict]) -> None:
        """
        Process alerts through all detection filters
        
        Args:
            alerts: List of alerts to process
        """
        if not alerts:
            return
            
        self.alert_counters["total"] += len(alerts)
        
        # Process through each filter
        bypassuac_alerts = filter_bypassuac_attempt(alerts)
        if bypassuac_alerts:
            self.alert_counters["bypassuac"] += len(bypassuac_alerts)
            logger.warning(f"Detected {len(bypassuac_alerts)} UAC bypass attempts!")
            for alert in bypassuac_alerts:
                logger.warning(f"UAC Bypass: Agent {alert.get('agent', {}).get('id', 'unknown')} - {alert.get('rule', {}).get('description', 'No description')}")
        
        shell_alerts = filter_malicious_shell_connect(alerts)
        if shell_alerts:
            self.alert_counters["malicious_shell"] += len(shell_alerts)
            logger.warning(f"Detected {len(shell_alerts)} malicious PowerShell activities!")
            for alert in shell_alerts:
                logger.warning(f"Malicious Shell: Agent {alert.get('agent', {}).get('id', 'unknown')} - {alert.get('rule', {}).get('description', 'No description')}")
        
        lsass_alerts = filter_lsass_access_attempt(alerts)
        if lsass_alerts:
            self.alert_counters["lsass_access"] += len(lsass_alerts)
            logger.warning(f"Detected {len(lsass_alerts)} LSASS memory access attempts!")
            for alert in lsass_alerts:
                logger.warning(f"LSASS Access: Agent {alert.get('agent', {}).get('id', 'unknown')} - {alert.get('rule', {}).get('description', 'No description')}")
    
    def check_new_alerts(self) -> None:
        """Check for new alerts since the last check time"""
        current_time = datetime.now()
        
        try:
            # Get alerts from the last interval
            start_time = self.last_check_time.isoformat()
            end_time = current_time.isoformat()
            
            # Calculate and display the time window being monitored
            time_diff = current_time - self.last_check_time
            seconds_diff = time_diff.total_seconds()
            
            logger.info(f"Monitoring time window: {self.last_check_time.strftime('%H:%M:%S.%f')[:-3]} to "
                       f"{current_time.strftime('%H:%M:%S.%f')[:-3]} ({seconds_diff:.2f} seconds)")
            
            additional_filters = self.get_additional_filters()
            
            alerts = get_wazuh_alerts(
                es_client=self.es_client,
                start_time=start_time,
                end_time=end_time,
                size=100,  # Adjust if needed
                index=self.index,
                additional_filters=additional_filters
            )
            
            if alerts:
                logger.info(f"Retrieved {len(alerts)} new alerts")
                self.process_alerts(alerts)
            
            # Update last check time
            self.last_check_time = current_time
            
        except Exception as e:
            logger.error(f"Error checking for new alerts: {str(e)}")
    
    def print_stats(self) -> None:
        """Print current detection statistics"""
        logger.info("=== Security Monitor Statistics ===")
        logger.info(f"Total alerts processed: {self.alert_counters['total']}")
        logger.info(f"UAC bypass attempts: {self.alert_counters['bypassuac']}")
        logger.info(f"Malicious PowerShell activities: {self.alert_counters['malicious_shell']}")
        logger.info(f"LSASS access attempts: {self.alert_counters['lsass_access']}")
        logger.info("=================================")
    
    def run(self) -> None:
        """Run the monitoring loop"""
        logger.info(f"Starting security monitor. Checking every {self.interval} seconds")
        logger.info(f"Monitoring index: {self.index}")
        if self.agent_id:
            logger.info(f"Filtering for agent ID: {self.agent_id}")
        
        stats_interval = 60  # Print stats every minute
        last_stats_time = time.time()
        
        try:
            while running:
                self.check_new_alerts()
                
                # Print stats periodically
                current_time = time.time()
                if current_time - last_stats_time >= stats_interval:
                    self.print_stats()
                    last_stats_time = current_time
                
                # Sleep until next check
                time.sleep(self.interval)
                
        except KeyboardInterrupt:
            logger.info("Monitoring stopped by user")
        except Exception as e:
            logger.error(f"Error in monitoring loop: {str(e)}")
        finally:
            # Print final stats
            self.print_stats()
            logger.info("Security monitor stopped")


def main():
    """Main entry point for the security monitor"""
    # Register signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        # Create Elasticsearch client
        es_client = create_es_client()
        
        # Create and run security monitor
        monitor = SecurityMonitor(
            es_client=es_client,
            index="wazuh-alerts-*",  # Adjust as needed
            interval=3,              # Check every 3 seconds
            agent_id=None            # Set to None to monitor all agents
        )
        
        # Start monitoring
        monitor.run()
        
    except Exception as e:
        logger.error(f"Error starting security monitor: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()