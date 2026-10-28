"""
Streaming Data Simulator for KAVACH
Generates realistic security events for testing streaming pipeline
"""

import time
import random
import secrets
import json
import os
import argparse
import sqlite3
from datetime import datetime, timedelta
from typing import Generator, Dict, Any
from pathlib import Path
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class StreamingSimulator:
    """
    Simulate real-time streaming security events
    """
    
    def __init__(self, events_per_second=1, malicious_ratio=0.1):
        self.events_per_second = events_per_second
        self.malicious_ratio = malicious_ratio
        self.event_count = 0
        
        logger.info(f"StreamingSimulator initialized: {events_per_second} events/sec")
    
    def generate_event(self, base_time: datetime = None) -> Dict[str, Any]:
        """Generate a single security event"""
        if base_time is None:
            base_time = datetime.now()
        else:
            base_time += timedelta(seconds=1)
        
        # Determine if malicious
        is_malicious = random.random() < self.malicious_ratio
        
        # Generate user data
        user_id = f"user_{random.randint(1, 100)}"
        user_role = random.choice(['user', 'admin', 'service'])
        
        # Generate network data
        if is_malicious:
            bytes_transferred = random.randint(100000, 10000000)
            request_count = random.randint(50, 500)
            activity_types = ['sql_injection', 'unauthorized_access', 
                            'data_exfiltration', 'privilege_escalation']
            activity_type = random.choice(activity_types)
            location = random.choice(['UNKNOWN', 'ASIA', 'RUSSIA'])
        else:
            bytes_transferred = random.randint(100, 50000)
            request_count = random.randint(1, 50)
            activity_type = random.choice(['login', 'api_call', 'file_access', 
                                          'database_query', 'normal'])
            location = random.choice(['US', 'EU', 'ASIA'])
        
        # Generate IPs
        source_ip = f"192.168.{random.randint(1, 255)}.{random.randint(1, 255)}"
        destination_ip = f"10.0.0.{random.randint(1, 255)}"
        
        event = {
            'user_id': user_id,
            'timestamp': base_time.isoformat(),
            'user_role': user_role,
            'bytes_transferred': bytes_transferred,
            'request_count': request_count,
            'activity_type': activity_type,
            'source_ip': source_ip,
            'destination_ip': destination_ip,
            'location': location,
            'is_malicious': int(is_malicious),
            'session_id': secrets.token_hex(8),
            'request_duration_ms': random.randint(10, 5000)
        }
        
        return event
    
    def generate_stream(self, duration_seconds: int = 60) -> Generator[Dict[str, Any], None, None]:
        """
        Generate a stream of events for specified duration
        """
        start_time = datetime.now()
        end_time = start_time + timedelta(seconds=duration_seconds)
        
        logger.info(f"Starting event stream for {duration_seconds} seconds...")
        
        while datetime.now() < end_time:
            # Generate events at specified rate
            events_in_batch = random.randint(1, self.events_per_second * 2)
            
            for _ in range(events_in_batch):
                event = self.generate_event(datetime.now())
                event['stream_position'] = self.event_count
                self.event_count += 1
                
                yield event
            
            # Sleep to maintain rate
            time.sleep(1.0 / self.events_per_second)
        
        logger.info(f"Event stream complete. Generated {self.event_count} events")
    
    def generate_honeytoken_interaction(self) -> Dict[str, Any]:
        """Generate a honeytoken breach event"""
        honeytokens = [
            'credentials.txt',
            'backup_2024.zip',
            'admin_password.db',
            'secret_key.pem'
        ]
        
        event = {
            'user_id': f"user_{random.randint(1, 100)}",
            'timestamp': datetime.now().isoformat(),
            'activity_type': 'file_access',
            'file_name': random.choice(honeytokens),
            'source_ip': f"192.168.{random.randint(1, 255)}.{random.randint(1, 255)}",
            'is_honeytoken_access': True,
            'honeytoken_alert': {
                'type': 'HONEYTOKEN_BREACH',
                'severity': 'HIGH',
                'message': f'Attempted access to honeytoken: {event.get("file_name", "unknown")}'
            }
        }
        
        return event
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get stream statistics"""
        return {
            'total_events': self.event_count,
            'events_per_second': self.events_per_second,
            'malicious_ratio': self.malicious_ratio,
            'estimated_malicious': int(self.event_count * self.malicious_ratio)
        }


class BatchEventGenerator:
    """
    Generate batches of events for bulk processing
    """
    
    def __init__(self, simulator: StreamingSimulator):
        self.simulator = simulator
    
    def generate_batch(self, batch_size: int = 100) -> list:
        """Generate a batch of events"""
        batch = []
        base_time = datetime.now()
        
        for i in range(batch_size):
            event = self.simulator.generate_event(
                base_time + timedelta(seconds=i)
            )
            batch.append(event)
        
        return batch
    
    def generate_sliding_window(self, window_size: int = 1000, 
                                overlap: int = 100) -> Generator[list, None, None]:
        """Generate sliding windows of events"""
        window = []
        
        for event in self.simulator.generate_stream(duration_seconds=3600):
            window.append(event)
            
            if len(window) >= window_size:
                yield window
                # Slide window
                window = window[-overlap:]
        
        # Yield remaining events
        if len(window) > 0:
            yield window


def simulate_real_time_streaming(processor, duration=60):
    """
    Simulate real-time streaming with processing
    """
    simulator = StreamingSimulator(events_per_second=5)
    stream = simulator.generate_stream(duration_seconds=duration)
    
    processed = 0
    for event in stream:
        # Process event
        result = processor.process_single_event(event)
        
        if result.get('is_malicious') or result.get('is_anomaly'):
            logger.warning(f"⚠️ Alert: {result}")
        
        processed += 1
        if processed % 100 == 0:
            logger.info(f"Processed {processed} events")
    
    logger.info(f"Streaming simulation complete. Processed {processed} events")


def stream_threat_catalog(catalog_path="utils/threats_catalog.json", 
                         db_path="data/audit_trail.db",
                         use_kafka=False):
    """
    Stream threat catalog events either to Kafka or directly into SQLite.
    """
    # Load threat catalog
    if not os.path.isabs(catalog_path):
        project_root = Path(__file__).parent.parent.parent
        catalog_path = str(project_root / catalog_path)
    
    with open(catalog_path, 'r') as f:
        catalog = json.load(f)
    
    # Initialize schema
    from utils.db_schema import init_audit_trail_schema
    init_audit_trail_schema(db_path)
    
    if use_kafka:
        # Check if Kafka is enabled
        kafka_enabled = os.getenv('KAFKA_ENABLED', 'False').lower() in ('1', 'true', 'yes')
        if not kafka_enabled:
            logger.warning("Kafka not enabled, falling back to SQLite")
            use_kafka = False
    
    if use_kafka:
        # Stream to Kafka
        try:
            from core.streaming.kafka_stream import KafkaStream
            kafka = KafkaStream(
                bootstrap_servers=os.getenv('KAFKA_BOOTSTRAP_SERVERS', 'localhost:9092'),
                topic='kavach.events'
            )
            if kafka.connect():
                logger.info("Connected to Kafka, streaming events...")
                for threat in catalog:
                    event = {
                        'ts': datetime.now().isoformat(),
                        'user_id': f"user_{random.randint(1, 100)}",
                        'source_ip': f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}",
                        'activity_type': threat['suggested_activity_type'],
                        'target': threat['typical_target'],
                        'threat_type': threat['threat_type'],
                        'payload': threat['sample_payload'],
                        'severity': threat['severity'],
                        'label': threat.get('label', 'benign'),
                        'meta': threat.get('meta', {})
                    }
                    kafka.publish_event(event)
                    time.sleep(0.1)  # Small delay between events
                kafka.close()
                logger.info(f"Streamed {len(catalog)} events to Kafka")
            else:
                logger.error("Failed to connect to Kafka, falling back to SQLite")
                use_kafka = False
        except Exception as e:
            logger.error(f"Kafka error: {e}, falling back to SQLite")
            use_kafka = False
    
    if not use_kafka:
        # Write directly to SQLite
        if not os.path.isabs(db_path):
            project_root = Path(__file__).parent.parent.parent
            db_path = str(project_root / db_path)
        
        db_dir = os.path.dirname(db_path)
        if db_dir and not os.path.exists(db_dir):
            os.makedirs(db_dir, exist_ok=True)
        
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        inserted_count = 0
        for threat in catalog:
            event_time = datetime.now() - timedelta(
                hours=random.randint(0, 24),
                minutes=random.randint(0, 60)
            )
            
            user_id = f"user_{random.randint(1, 100)}"
            source_ip = f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
            
            cursor.execute('''
                INSERT INTO events 
                (ts, user_id, source_ip, activity_type, target, threat_type, payload, severity, label, meta)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                event_time.isoformat(),
                user_id,
                source_ip,
                threat['suggested_activity_type'],
                threat['typical_target'],
                threat['threat_type'],
                threat['sample_payload'],
                threat['severity'],
                threat.get('label', 'benign'),
                json.dumps(threat.get('meta', {}))
            ))
            inserted_count += 1
        
        conn.commit()
        conn.close()
        logger.info(f"Inserted {inserted_count} events into SQLite: {db_path}")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='KAVACH Streaming Simulator')
    parser.add_argument('--use-threat-catalog', action='store_true', 
                       help='Stream threat catalog events')
    parser.add_argument('--catalog-path', default='utils/threats_catalog.json',
                       help='Path to threat catalog JSON')
    parser.add_argument('--db-path', default='data/audit_trail.db',
                       help='SQLite database path')
    parser.add_argument('--events-per-second', type=int, default=2,
                       help='Events per second for normal simulation')
    parser.add_argument('--duration', type=int, default=10,
                       help='Duration in seconds for normal simulation')
    
    args = parser.parse_args()
    
    if args.use_threat_catalog:
        kafka_enabled = os.getenv('KAFKA_ENABLED', 'False').lower() in ('1', 'true', 'yes')
        stream_threat_catalog(args.catalog_path, args.db_path, use_kafka=kafka_enabled)
    else:
        # Demo: Generate streaming events
        simulator = StreamingSimulator(events_per_second=args.events_per_second)
        
        print("Generating security events...")
        for i, event in enumerate(simulator.generate_stream(duration_seconds=args.duration)):
            print(f"Event {i+1}: {event['activity_type']} from {event['source_ip']}")
            
            if i >= 20:  # Limit output
                break
        
        print(f"\nStatistics: {simulator.get_statistics()}")


