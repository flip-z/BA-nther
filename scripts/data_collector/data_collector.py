#!/usr/bin/env python3
"""
Panther GraphQL Security Log Collector
Fetches security logs from Panther's GraphQL API with pagination support
"""

import json
import os
import sys
import time
from typing import Dict, List, Any, Optional
import requests
from pathlib import Path
from dotenv import load_dotenv
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type, retry_if_not_exception_type

# Add shared utilities to path
sys.path.append(str(Path(__file__).parent.parent / "shared"))
from utils import setup_logging, load_config, save_json, load_json, ensure_directory

class NonRetryableError(Exception):
    """Exception for errors that should not be retried (auth, 100MB limit, etc)"""
    pass

class PantherDataCollector:
    def __init__(self, config_path: str):
        self.logger = setup_logging("PantherDataCollector")
        self.config = load_config(config_path)
        self.queries = self.config["queries"]
        
        # API configuration from environment
        self.api_config = {
            "base_url": os.getenv('PANTHER_API_URL', 'https://api.panther.com/public/graphql'),
            "headers": {
                "X-API-Key": os.getenv('PANTHER_API_TOKEN'),
                "Content-Type": "application/json"
            }
        }
        
        # Hard-coded data settings
        self.data_settings = {
            "output_directory": "../data",
            "max_pages": 10,
            "retry_attempts": 3,
            "retry_delay": 5,
            "limit": 20000  # ~20k events per query to stay under 100MB
        }
        
        # Validate required environment variables
        self._validate_environment()
        
        # Set up output directory first (needed for storage setup)
        storage_type = self.config.get("storage", "local")
        if storage_type == "local":
            self.output_dir = Path(__file__).parent.parent / "data"
        else:
            # For prod mode, we might use S3 or different storage
            self.output_dir = Path(__file__).parent.parent / "data"  # fallback
        ensure_directory(str(self.output_dir))
        
        # Set up storage (now that output_dir is available)
        self.storage = self._create_storage(storage_type)
        
        self.logger.info(f"Initialized collector with {len(self.queries)} queries")
        self.logger.info(f"API endpoint: {self.api_config['base_url']}")

    def _validate_environment(self):
        """Validate required environment variables"""
        required_vars = {
            'PANTHER_API_TOKEN': 'Panther API token',
            'PANTHER_API_URL': 'Panther API endpoint URL'
        }
        
        missing_vars = []
        for var, description in required_vars.items():
            value = os.getenv(var)
            if not value:
                missing_vars.append(f"{var} ({description})")
        
        if missing_vars:
            error_msg = f"Missing required environment variables: {', '.join(missing_vars)}"
            self.logger.error(error_msg)
            raise ValueError(error_msg)
        
        # Validate API URL format
        api_url = os.getenv('PANTHER_API_URL')
        if not api_url.startswith(('http://', 'https://')):
            error_msg = f"PANTHER_API_URL must be a valid URL starting with http:// or https://"
            self.logger.error(error_msg)
            raise ValueError(error_msg)
        
        if not api_url.endswith('/public/graphql'):
            self.logger.warning(f"PANTHER_API_URL should typically end with '/public/graphql', current: {api_url}")

    def _create_storage(self, storage_type: str):
        """Create storage backend based on configuration"""
        # Import here to avoid circular imports
        from storage import create_storage
        
        if storage_type == "local":
            # Use absolute path based on our data directory
            state_dir = self.output_dir / ".state"
            return create_storage(storage_type, str(state_dir))
        else:
            return create_storage(storage_type)

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=4, max=10)
    )
    def execute_graphql_query(self, query: str, variables: Dict[str, Any]) -> Dict[str, Any]:
        """Execute GraphQL query with retry logic"""
        payload = {
            "query": query,
            "variables": variables
        }
        
        try:
            response = requests.post(
                self.api_config["base_url"],
                json=payload,
                headers=self.api_config["headers"],
                timeout=60
            )
            response.raise_for_status()
            
            data = response.json()
            if "errors" in data:
                raise Exception(f"GraphQL errors: {data['errors']}")
                
            return data
            
        except requests.RequestException as e:
            self.logger.error(f"Request failed: {e}")
            raise
        except Exception as e:
            self.logger.error(f"Query execution failed: {e}")
            raise

    def execute_data_lake_query(self, sql_query: str, time_value: str) -> str:
        """Execute data lake query and return query ID"""
        # Replace {time} placeholder in SQL query (e.g., "30" becomes "30d" in p_occurs_since())
        processed_sql = sql_query.replace("{time}", str(time_value))
        
        # Create GraphQL mutation to execute the query
        mutation = """
        mutation ExecuteQuery($sql: String!) {
          executeDataLakeQuery(input: { sql: $sql }) {
            id
          }
        }
        """
        
        variables = {"sql": processed_sql}
        
        try:
            response_data = self.execute_graphql_query(mutation, variables)
            
            if "executeDataLakeQuery" not in response_data.get("data", {}):
                raise Exception("Failed to execute data lake query")
            
            query_id = response_data["data"]["executeDataLakeQuery"]["id"]
            self.logger.info(f"Started query with ID: {query_id}")
            
            return query_id
            
        except Exception as e:
            self.logger.error(f"Failed to execute query: {e}")
            raise

    def poll_query_results(self, query_id: str, cursor: Optional[str] = None) -> Dict[str, Any]:
        """Poll for query results using query ID"""
        query = """
        query GetResults($id: ID!, $cursor: String) {
          dataLakeQuery(id: $id) {
            status
            message
            results(input: { cursor: $cursor }) {
              edges {
                node
              }
              pageInfo {
                endCursor
                hasNextPage
              }
            }
          }
        }
        """
        
        variables = {"id": query_id, "cursor": cursor}
        
        try:
            response_data = self.execute_graphql_query(query, variables)
            
            if "dataLakeQuery" not in response_data.get("data", {}):
                raise Exception(f"Query {query_id} not found")
            
            return response_data["data"]["dataLakeQuery"]
            
        except Exception as e:
            self.logger.error(f"Failed to poll query {query_id}: {e}")
            raise

    def calculate_safe_chunk_size(self, sql_query: str, time_value: str) -> int:
        """Calculate safe chunk size by sampling first 1000 events"""
        # Add LIMIT 1000 to the query for sampling
        sample_query = f"{sql_query} LIMIT 1000"
        
        try:
            # Execute sample query
            query_id = self.execute_data_lake_query(sample_query, time_value)
            
            # Poll for completion
            max_poll_attempts = 60
            poll_attempt = 0
            
            while poll_attempt < max_poll_attempts:
                poll_result = self.poll_query_results(query_id)
                status = poll_result.get("status")
                
                if status == "running":
                    time.sleep(5)
                    poll_attempt += 1
                    continue
                elif status == "failed":
                    raise Exception(f"Sample query failed: {poll_result.get('message', 'Unknown error')}")
                elif status == "succeeded":
                    break
                else:
                    raise Exception(f"Unknown query status: {status}")
            
            if poll_attempt >= max_poll_attempts:
                raise Exception("Sample query timed out")
            
            # Get sample data
            poll_result = self.poll_query_results(query_id)
            results = poll_result.get("results", {})
            edges = results.get("edges", [])
            
            if not edges:
                self.logger.warning("No sample data found, using conservative chunk size")
                return 1000  # Conservative fallback
            
            # Calculate average event size
            sample_events = [edge["node"] for edge in edges]
            total_size = len(json.dumps(sample_events).encode('utf-8'))
            avg_event_size = total_size / len(sample_events)
            
            # Calculate safe chunk size (80MB limit with safety margin)
            safe_limit = int(80_000_000 / avg_event_size)
            
            self.logger.info(f"Sample: {len(sample_events)} events, avg size: {avg_event_size:.2f} bytes")
            self.logger.info(f"Calculated safe chunk size: {safe_limit:,} events")
            
            return max(safe_limit, 1000)  # Minimum 1000 events per chunk
            
        except Exception as e:
            self.logger.error(f"Failed to calculate chunk size: {e}")
            return 10000  # Conservative fallback

    def collect_logs_with_chunking(self, query_config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Collect logs using LIMIT/OFFSET chunking to avoid 100MB limit"""
        title = query_config["title"]
        window_days = query_config["time"]
        base_sql = query_config["query"]
        
        self.logger.info(f"Starting chunked collection for query: {title}")
        
        # Calculate safe chunk size
        chunk_size = self.calculate_safe_chunk_size(base_sql, window_days)
        self.logger.info(f"Using chunk size: {chunk_size:,} events")
        
        all_logs = []
        offset = 0
        chunk_number = 1
        start_time = time.time()
        
        while True:
            # Create chunked query with LIMIT/OFFSET
            chunked_sql = f"{base_sql} LIMIT {chunk_size} OFFSET {offset}"
            
            self.logger.info(f"Executing chunk {chunk_number} (offset: {offset:,})")
            
            try:
                # Execute chunked query
                query_id = self.execute_data_lake_query(chunked_sql, window_days)
                
                # Poll for completion
                max_poll_attempts = 60
                poll_attempt = 0
                
                while poll_attempt < max_poll_attempts:
                    poll_result = self.poll_query_results(query_id)
                    status = poll_result.get("status")
                    
                    if status == "running":
                        time.sleep(5)
                        poll_attempt += 1
                        continue
                    elif status == "failed":
                        error_msg = poll_result.get("message", "Unknown error")
                        if "result size exceeded" in error_msg.lower():
                            # Chunk size still too large, reduce it
                            chunk_size = max(chunk_size // 2, 500)
                            self.logger.warning(f"Chunk still too large, reducing to {chunk_size:,}")
                            break
                        else:
                            raise Exception(f"Chunk query failed: {error_msg}")
                    elif status == "succeeded":
                        break
                    else:
                        raise Exception(f"Unknown query status: {status}")
                
                if poll_attempt >= max_poll_attempts:
                    raise Exception("Chunk query timed out")
                
                if poll_result.get("status") != "succeeded":
                    continue  # Retry with smaller chunk size
                
                # Collect all pages for this chunk
                cursor = None
                chunk_logs = []
                
                while True:
                    poll_result = self.poll_query_results(query_id, cursor)
                    results = poll_result.get("results", {})
                    edges = results.get("edges", [])
                    page_info = results.get("pageInfo", {})
                    
                    if not edges:
                        break
                    
                    nodes = [edge["node"] for edge in edges]
                    chunk_logs.extend(nodes)
                    
                    if not page_info.get("hasNextPage", False):
                        break
                    
                    cursor = page_info.get("endCursor")
                    time.sleep(0.5)  # Rate limiting
                
                if not chunk_logs:
                    self.logger.info(f"No more data after {len(all_logs):,} total events")
                    break
                
                all_logs.extend(chunk_logs)
                
                # Calculate progress and throughput
                elapsed_time = time.time() - start_time
                estimation = self.estimate_total_events(all_logs, window_days)
                throughput = self.calculate_throughput_metrics(len(all_logs), elapsed_time, estimation["progress_pct"])
                
                # Format estimated total with k/M suffix
                est_total = estimation["estimated_total"]
                if est_total >= 1000000:
                    est_str = f"{est_total/1000000:.1f}M"
                elif est_total >= 1000:
                    est_str = f"{est_total/1000:.1f}k"
                else:
                    est_str = f"{est_total:,}"
                
                current_str = f"{estimation['current_count']/1000000:.1f}M" if estimation['current_count'] >= 1000000 else f"{estimation['current_count']/1000:.1f}k"
                
                self.logger.info(f"Chunk {chunk_number}: {len(chunk_logs):,} events, total: {len(all_logs):,}")
                self.logger.info(f"Progress: ~{estimation['progress_pct']:.0f}% ({current_str} of ~{est_str} estimated) | Rate: {throughput['rate']} | ETA: ~{throughput['eta']}")
                if len(all_logs) >= 1000:  # Only show time range if we have enough data
                    self.logger.info(f"Recent data: {estimation['time_range']}")
                
                # If we got fewer events than chunk size, we've reached the end
                if len(chunk_logs) < chunk_size:
                    self.logger.info(f"Last chunk completed! Final: {len(all_logs):,} events")
                    break
                
                # Move to next chunk
                offset += chunk_size
                chunk_number += 1
                
                # Rate limiting between chunks
                time.sleep(1)
                
            except Exception as e:
                self.logger.error(f"Failed to collect chunk {chunk_number}: {e}")
                raise
        
        self.logger.info(f"Completed chunked collection for {title}: {len(all_logs):,} total logs")
        return all_logs

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=30, max=120),
        retry=retry_if_not_exception_type(NonRetryableError),
        reraise=True
    )
    def collect_logs_for_query(self, query_config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Collect logs for a specific query with incremental updates and state management"""
        title = query_config["title"]
        window_days = query_config["time"]
        
        self.logger.info(f"Starting collection for query: {title}")
        
        # Load existing state
        state = self.storage.get_state(title)
        if state is None:
            self.logger.info(f"First run for {title}, creating initial state")
            from storage import create_initial_state
            state = create_initial_state(title, window_days)
            is_first_run = True
        else:
            self.logger.info(f"Found existing state for {title}, last run: {state.get('last_run', 'never')}")
            is_first_run = False
        
        try:
            # Step 1: Calculate optimized time window for incremental collection
            optimized_window_days = self.calculate_optimized_time_window(state, window_days)
            
            # Step 2: Execute the query to get query ID
            query_id = self.execute_data_lake_query(query_config["query"], optimized_window_days)
            
            # Step 3: Poll for query completion
            self.logger.info(f"Polling for query completion: {query_id}")
            
            max_poll_attempts = 60  # 5 minutes at 5-second intervals
            poll_attempt = 0
            chunked_used = False  # Track if we used chunked collection
            
            while poll_attempt < max_poll_attempts:
                poll_result = self.poll_query_results(query_id)
                status = poll_result.get("status")
                message = poll_result.get("message", "")
                
                if status == "running":
                    self.logger.info(f"Query {query_id} still running: {message}")
                    time.sleep(5)  # Wait 5 seconds before next poll
                    poll_attempt += 1
                    continue
                    
                elif status == "failed":
                    if "result size exceeded" in message.lower():
                        self.logger.warning(f"Query {query_id} exceeded 100MB limit, falling back to chunked collection")
                        # Use optimized query config for chunked collection
                        optimized_query_config = query_config.copy()
                        optimized_query_config["time"] = optimized_window_days
                        all_logs = self.collect_logs_with_chunking(optimized_query_config)
                        chunked_used = True
                        break  # Exit polling loop and continue to state management
                    elif "unauthorized" in message.lower() or "authentication" in message.lower():
                        # Don't retry auth errors
                        raise NonRetryableError(f"Authentication error for query {query_id}: {message}")
                    else:
                        error_msg = f"Query {query_id} failed: {message}"
                        self.logger.error(error_msg)
                        raise Exception(error_msg)
                    
                elif status == "succeeded":
                    self.logger.info(f"Query {query_id} completed successfully")
                    break
                    
                else:
                    error_msg = f"Unknown query status: {status}"
                    self.logger.error(error_msg)
                    raise Exception(error_msg)
            
            if poll_attempt >= max_poll_attempts:
                raise Exception(f"Query {query_id} timed out after {max_poll_attempts} polling attempts")
            
            # Step 4: Collect all result pages (skip if chunked collection was used)
            if not chunked_used:
                all_logs = []
                cursor = None
                page_count = 0
                max_pages = self.data_settings["max_pages"]
                start_time = time.time()
                
                while page_count < max_pages:
                    self.logger.info(f"Fetching results page {page_count + 1} for {title}")
                
                    try:
                        poll_result = self.poll_query_results(query_id, cursor)
                    except Exception as e:
                        if "result size exceeded" in str(e).lower():
                            self.logger.warning(f"Result size exceeded during pagination, falling back to chunked collection")
                            # Use optimized query config for chunked collection
                            optimized_query_config = query_config.copy()
                            optimized_query_config["time"] = optimized_window_days
                            all_logs = self.collect_logs_with_chunking(optimized_query_config)
                            break  # Exit pagination loop and continue to state management
                        elif "unauthorized" in str(e).lower() or "authentication" in str(e).lower():
                            raise NonRetryableError(f"Authentication error during result polling: {e}")
                        else:
                            raise
                
                    if poll_result.get("status") != "succeeded":
                        self.logger.error(f"Query status changed unexpectedly: {poll_result.get('status')}")
                        break
                    
                    results = poll_result.get("results", {})
                    edges = results.get("edges", [])
                    page_info = results.get("pageInfo", {})
                    
                    if not edges:
                        self.logger.info(f"No more data for {title}")
                        break
                    
                    # Extract nodes from edges
                    nodes = [edge["node"] for edge in edges]
                    all_logs.extend(nodes)
                    
                    # Calculate progress and throughput
                    elapsed_time = time.time() - start_time
                    estimation = self.estimate_total_events(all_logs, optimized_window_days)
                    throughput = self.calculate_throughput_metrics(len(all_logs), elapsed_time, estimation["progress_pct"])
                    
                    # Format estimated total with k/M suffix
                    est_total = estimation["estimated_total"]
                    if est_total >= 1000000:
                        est_str = f"{est_total/1000000:.1f}M"
                    elif est_total >= 1000:
                        est_str = f"{est_total/1000:.1f}k"
                    else:
                        est_str = f"{est_total:,}"
                    
                    current_str = f"{estimation['current_count']/1000000:.1f}M" if estimation['current_count'] >= 1000000 else f"{estimation['current_count']/1000:.1f}k"
                    
                    self.logger.info(f"Page {page_count + 1}: {len(nodes)} logs, total: {len(all_logs):,}")
                    self.logger.info(f"Progress: ~{estimation['progress_pct']:.0f}% ({current_str} of ~{est_str} estimated) | Rate: {throughput['rate']} | ETA: ~{throughput['eta']}")
                    if len(all_logs) >= 1000:  # Only show time range if we have enough data
                        self.logger.info(f"Recent data: {estimation['time_range']}")
                    
                    # Check for next page
                    if not page_info.get("hasNextPage", False):
                        self.logger.info(f"Reached last page for {title}! Final: {len(all_logs):,} events")
                        break
                    
                    cursor = page_info.get("endCursor")
                    page_count += 1
                    
                    # Rate limiting between pages
                    time.sleep(0.5)
            
            # Step 5: Process and merge data
            if is_first_run:
                # First run: just save the data
                self.logger.info(f"First run: saving {len(all_logs)} logs")
                final_logs = all_logs
            else:
                # Incremental run: merge with existing data
                self.logger.info(f"Incremental run: merging {len(all_logs)} new logs")
                final_logs = self._merge_and_dedupe_data(title, all_logs, window_days)
            
            # Step 6: Update state
            if all_logs:
                # Find latest timestamp from collected data
                latest_timestamp = self._find_latest_timestamp(all_logs)
                from storage import update_state_after_run
                updated_state = update_state_after_run(state, latest_timestamp, len(final_logs))
                self.storage.save_state(title, updated_state)
                self.logger.info(f"Updated state: {len(final_logs)} total records, latest: {latest_timestamp}")
            
        except Exception as e:
            self.logger.error(f"Failed to collect {title}: {e}")
            raise
        
        self.logger.info(f"Completed collection for {title}: {len(final_logs)} total logs")
        return final_logs

    def _merge_and_dedupe_data(self, title: str, new_logs: List[Dict[str, Any]], window_days: int) -> List[Dict[str, Any]]:
        """Merge new logs with existing data and remove duplicates"""
        from datetime import datetime, timedelta
        
        # Load existing data
        data_file = self.output_dir / f"{title}.json"
        existing_logs = []
        if data_file.exists():
            try:
                existing_logs = load_json(str(data_file))
                self.logger.info(f"Loaded {len(existing_logs)} existing logs")
            except Exception as e:
                self.logger.warning(f"Failed to load existing data: {e}")
        
        # Combine all logs
        all_logs = existing_logs + new_logs
        
        # Deduplicate based on common ID fields
        seen_ids = set()
        deduplicated_logs = []
        
        for log in all_logs:
            # Try common ID fields
            log_id = log.get('id') or log.get('alertId') or log.get('timestamp') or str(log)
            
            if log_id not in seen_ids:
                seen_ids.add(log_id)
                deduplicated_logs.append(log)
        
        self.logger.info(f"After deduplication: {len(deduplicated_logs)} logs (removed {len(all_logs) - len(deduplicated_logs)} duplicates)")
        
        # Remove expired logs outside time window
        cutoff_date = datetime.utcnow() - timedelta(days=window_days)
        valid_logs = []
        
        for log in deduplicated_logs:
            # Try to find timestamp field
            timestamp_str = log.get('timestamp') or log.get('createdAt') or log.get('p_event_time')
            
            if timestamp_str:
                try:
                    import pandas as pd
                    log_date = pd.to_datetime(timestamp_str).to_pydatetime()
                    if log_date >= cutoff_date:
                        valid_logs.append(log)
                except:
                    # If we can't parse the date, keep the log to be safe
                    valid_logs.append(log)
            else:
                # If no timestamp found, keep the log
                valid_logs.append(log)
        
        expired_count = len(deduplicated_logs) - len(valid_logs)
        if expired_count > 0:
            self.logger.info(f"Removed {expired_count} expired logs outside {window_days}-day window")
        
        return valid_logs

    def _find_latest_timestamp(self, logs: List[Dict[str, Any]]) -> str:
        """Find the latest timestamp from a list of logs"""
        from datetime import datetime
        import pandas as pd
        
        latest_date = None
        latest_timestamp = None
        
        for log in logs:
            # Try common timestamp fields
            timestamp_str = log.get('timestamp') or log.get('createdAt') or log.get('p_event_time')
            
            if timestamp_str:
                try:
                    log_date = pd.to_datetime(timestamp_str).to_pydatetime()
                    if latest_date is None or log_date > latest_date:
                        latest_date = log_date
                        latest_timestamp = timestamp_str
                except:
                    continue
        
        if latest_timestamp:
            return latest_timestamp
        else:
            # Fallback to current time if no timestamps found
            return datetime.utcnow().isoformat() + "Z"

    def estimate_total_events(self, logs: List[Dict[str, Any]], window_days: int) -> Dict[str, Any]:
        """Estimate total events and progress based on recent event density"""
        from datetime import datetime
        import pandas as pd
        
        if not logs:
            return {
                "estimated_total": 0,
                "progress_pct": 0,
                "current_count": 0,
                "time_range": "No data"
            }
        
        current_count = len(logs)
        
        # Use last 1000 events (or all if fewer) to estimate density
        sample_size = min(1000, len(logs))
        recent_logs = logs[-sample_size:]
        
        # Extract timestamps from recent logs
        timestamps = []
        for log in recent_logs:
            timestamp_str = log.get('timestamp') or log.get('createdAt') or log.get('p_event_time')
            if timestamp_str:
                try:
                    log_time = pd.to_datetime(timestamp_str).to_pydatetime()
                    timestamps.append(log_time)
                except:
                    continue
        
        if len(timestamps) < 2:
            # Not enough data for estimation
            return {
                "estimated_total": current_count * 2,  # Very rough guess
                "progress_pct": 50,  # Assume halfway
                "current_count": current_count,
                "time_range": "Insufficient timestamp data for estimation"
            }
        
        # Calculate event density from recent sample
        earliest = min(timestamps)
        latest = max(timestamps)
        time_span_days = max(0.1, (latest - earliest).total_seconds() / 86400)  # Minimum 0.1 days
        events_per_day = len(timestamps) / time_span_days
        
        # Estimate total events for the entire window
        estimated_total = max(current_count, int(events_per_day * window_days))
        progress_pct = min(100, (current_count / estimated_total) * 100)
        
        return {
            "estimated_total": estimated_total,
            "progress_pct": progress_pct,
            "current_count": current_count,
            "time_range": f"{earliest.strftime('%m/%d %H:%M')} to {latest.strftime('%m/%d %H:%M')}"
        }
    
    
    def calculate_throughput_metrics(self, total_events: int, elapsed_seconds: float, progress_pct: float) -> Dict[str, str]:
        """Calculate throughput metrics and ETA"""
        if elapsed_seconds <= 0:
            return {"rate": "calculating...", "eta": "calculating..."}
        
        events_per_second = total_events / elapsed_seconds
        events_per_minute = events_per_second * 60
        
        # Format rate
        if events_per_minute >= 1000000:
            rate = f"{events_per_minute/1000000:.1f}M events/min"
        elif events_per_minute >= 1000:
            rate = f"{events_per_minute/1000:.1f}k events/min"
        else:
            rate = f"{events_per_minute:.0f} events/min"
        
        # Calculate ETA based on progress
        if progress_pct > 0 and progress_pct < 100:
            total_estimated_time = (elapsed_seconds / progress_pct) * 100
            remaining_time = total_estimated_time - elapsed_seconds
            
            if remaining_time > 3600:  # More than 1 hour
                eta = f"{remaining_time/3600:.1f} hours"
            elif remaining_time > 60:  # More than 1 minute
                eta = f"{remaining_time/60:.0f} minutes"
            else:
                eta = f"{remaining_time:.0f} seconds"
        else:
            eta = "unknown"
        
        return {"rate": rate, "eta": eta}

    def calculate_optimized_time_window(self, state: Dict[str, Any], configured_window_days: int) -> int:
        """Calculate optimized time window based on state to minimize data overlap"""
        from datetime import datetime, timedelta
        import pandas as pd
        
        # First run or no state: use full configured window
        if not state or not state.get('last_data_timestamp'):
            self.logger.info(f"First run or no state: using full window of {configured_window_days} days")
            return configured_window_days
        
        try:
            # Parse the last data timestamp
            last_timestamp_str = state['last_data_timestamp']
            last_timestamp = pd.to_datetime(last_timestamp_str).to_pydatetime()
            current_time = datetime.utcnow()
            
            # Calculate days since last collection
            time_diff = current_time - last_timestamp
            days_since_last = time_diff.total_seconds() / (24 * 3600)
            
            # Add 1 day buffer for safety (timezone issues, processing delays, etc.)
            optimized_days = max(1, int(days_since_last) + 1)
            
            # Cap at configured window for edge cases (very old state, etc.)
            optimized_days = min(optimized_days, configured_window_days)
            
            self.logger.info(f"Last data timestamp: {last_timestamp_str}")
            self.logger.info(f"Days since last collection: {days_since_last:.2f}")
            self.logger.info(f"Optimized time window: {optimized_days} days (configured: {configured_window_days})")
            
            return optimized_days
            
        except Exception as e:
            self.logger.warning(f"Failed to calculate optimized window: {e}. Using full window.")
            return configured_window_days

    def collect_all_queries(self) -> Dict[str, int]:
        """Collect data for all configured queries"""
        results = {}
        
        for query_config in self.queries:
            title = query_config["title"]
            try:
                logs = self.collect_logs_for_query(query_config)
                
                # Save to file using title as filename
                output_file = self.output_dir / f"{title}.json"
                save_json(logs, str(output_file))
                
                results[title] = len(logs)
                self.logger.info(f"Saved {len(logs)} logs to {output_file}")
                
            except Exception as e:
                self.logger.error(f"Failed to collect {title}: {e}")
                results[title] = 0
        
        return results

def main():
    # Load environment variables
    load_dotenv()
    
    # Early validation will be done in PantherDataCollector.__init__
    
    # Set up paths
    config_path = Path(__file__).parent.parent / "config" / "config.json"
    
    if not config_path.exists():
        print(f"Error: Configuration file not found at {config_path}")
        sys.exit(1)
    
    # Initialize collector
    try:
        collector = PantherDataCollector(str(config_path))
        
        print("Starting Panther security log collection...")
        results = collector.collect_all_queries()
        
        print("\nCollection Summary:")
        print("-" * 50)
        total_logs = 0
        for title, log_count in results.items():
            print(f"{title}: {log_count:,} logs")
            total_logs += log_count
        
        print("-" * 50)
        print(f"Total logs collected: {total_logs:,}")
        
        if total_logs > 0:
            print(f"\nLogs saved to: {collector.output_dir}")
        
    except Exception as e:
        print(f"Collection failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()