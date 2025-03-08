from datetime import datetime, timedelta
from typing import Dict, List, Optional
from dotenv import load_dotenv
import os
from elasticsearch import Elasticsearch
import logging

from matching import filter_bypassuac_attempt, filter_malicious_shell_connect, filter_lsass_access_attempt

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def create_es_client():
    """
    Create and return an Elasticsearch client using credentials from environment variables.

    Returns:
        Elasticsearch: Configured Elasticsearch client

    Raises:
        ConnectionError: If connection to Elasticsearch fails
        ValueError: If required environment variables are missing
    """
    try:
        # Load environment variables
        load_dotenv()

        # Get credentials from environment variables
        es_host = os.getenv("ES_HOST")
        es_port = os.getenv("ES_PORT")
        # es_user = os.getenv('ES_USER')
        # es_password = os.getenv('ES_PASSWORD')
        # es_use_ssl = os.getenv('ES_USE_SSL', 'true').lower() == 'true'

        # Validate required environment variables
        required_vars = ["ES_HOST", "ES_PORT"]
        missing_vars = [var for var in required_vars if not os.getenv(var)]

        if missing_vars:
            raise ValueError(
                f"Missing required environment variables: {', '.join(missing_vars)}"
            )

        # Create Elasticsearch client
        es_client = Elasticsearch(
            f"{'http'}://{es_host}:{es_port}",
            # basic_auth=(es_user, es_password),
            # verify_certs=es_use_ssl
        )

        # Test connection
        if es_client.ping():
            logger.info("Successfully connected to Elasticsearch")
            return es_client
        else:
            raise ConnectionError("Failed to connect to Elasticsearch")

    except Exception as e:
        logger.error(f"Error connecting to Elasticsearch: {str(e)}")
        raise


def get_wazuh_alerts(
    es_client: Elasticsearch,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    alert_level: Optional[int] = None,
    size: int = 100,
    scroll: str = "2m",
    additional_filters: Optional[List[Dict]] = None,
    index: str = "",
) -> List[Dict]:
    """
    Fetch Wazuh alerts from Elasticsearch with pagination support.

    Args:
        es_client: Elasticsearch client instance
        start_time: Start time in ISO format (default: 24 hours ago)
        end_time: End time in ISO format (default: now)
        alert_level: Minimum alert level to filter (optional)
        size: Number of results per page
        scroll: Scroll timeout
        additional_filters: List of additional Elasticsearch query filters

    Returns:
        List of Wazuh alerts
    """
    # Set default time range if not provided
    if not start_time:
        start_time = (datetime.now() - timedelta(days=1)).isoformat()
    if not end_time:
        end_time = datetime.now().isoformat()

    # Base query
    query = {
        "bool": {
            "must": [{"range": {"timestamp": {"gte": start_time, "lte": end_time}}}]
        }
    }

    # Add alert level filter if specified
    if alert_level is not None:
        query["bool"]["must"].append({"range": {"rule.level": {"gte": alert_level}}})

    # Add any additional filters
    if additional_filters:
        for filter_item in additional_filters:
            query["bool"]["must"].append(filter_item)

    # Initial search
    try:
        resp = es_client.search(
            index=index,
            query=query,
            size=size,
            scroll=scroll,
            sort=[{"timestamp": {"order": "desc"}}],
        )
    except Exception as e:
        logger.error(f"Error in initial search: {str(e)}")
        raise

    # Get initial batch of results
    all_hits = resp["hits"]["hits"]
    scroll_id = resp["_scroll_id"]

    # Continue scrolling until no more results
    while True:
        try:
            resp = es_client.scroll(scroll_id=scroll_id, scroll=scroll)
        except Exception as e:
            logger.error(f"Error during scroll: {str(e)}")
            break

        # Break if no more hits
        if not resp["hits"]["hits"]:
            break

        # Add this batch of results
        all_hits.extend(resp["hits"]["hits"])
        scroll_id = resp["_scroll_id"]

    # Clean up scroll
    try:
        es_client.clear_scroll(scroll_id=scroll_id)
    except Exception as e:
        logger.error(f"Error clearing scroll: {str(e)}")

    # Extract and format the results
    alerts = []
    for hit in all_hits:
        alert = hit["_source"]
        alerts.append(alert)

    return alerts


def main():
    """
    Example usage of the Wazuh alerts query function.
    """
    try:
        # Load environment variables and create ES client
        load_dotenv()
        es = Elasticsearch(
            f"{'http'}://{os.getenv('ES_HOST')}:{os.getenv('ES_PORT')}",
            # basic_auth=(os.getenv('ES_USER'), os.getenv('ES_PASSWORD')),
            # verify_certs=os.getenv('ES_USE_SSL', 'true').lower() == 'true'
        )

        start_time = (datetime.now() - timedelta(hours=3000)).isoformat()

        additional_filters = [{"term": {"agent.id": "005"}}]

        alerts = get_wazuh_alerts(
            es_client=es,
            start_time=start_time,
            # alert_level=10,
            size=100,
            index="wazuh-alerts-mimikatz",
            additional_filters=additional_filters,
        )

        filtered = filter_lsass_access_attempt(
            alerts
        )
        print(filtered)

        logger.info(f"Total alerts found: {len(alerts)}")

    except Exception as e:
        logger.error(f"Error in main: {str(e)}")


if __name__ == "__main__":
    main()