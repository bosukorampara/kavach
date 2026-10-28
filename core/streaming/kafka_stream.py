"""
Kafka streaming support for real-time event processing
"""

import logging
import json
from datetime import datetime
from typing import Callable, Dict, Any

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

try:
    from kafka import KafkaConsumer, KafkaProducer
    from kafka.errors import KafkaError
    HAS_KAFKA = True
except ImportError:
    HAS_KAFKA = False
    logger.warning("kafka-python not installed. Real Kafka streaming will be disabled.")


class KafkaStream:
    """
    Real-time streaming using Apache Kafka
    """
    
    def __init__(self, bootstrap_servers='localhost:9092', topic='security-events',
                 consumer_group='kavach-consumer'):
        self.bootstrap_servers = bootstrap_servers
        self.topic = topic
        self.consumer_group = consumer_group
        self.consumer = None
        self.producer = None
        self.is_connected = False
        
        logger.info("KafkaStream initialized")
    
    def connect(self):
        """Connect to Kafka cluster"""
        if not HAS_KAFKA:
            logger.error("kafka-python not available")
            return False
        
        try:
            self.producer = KafkaProducer(
                bootstrap_servers=self.bootstrap_servers,
                value_serializer=lambda v: json.dumps(v).encode('utf-8')
            )
            
            self.consumer = KafkaConsumer(
                self.topic,
                bootstrap_servers=self.bootstrap_servers,
                consumer_timeout_ms=1000,
                value_deserializer=lambda m: json.loads(m.decode('utf-8')),
                group_id=self.consumer_group,
                auto_offset_reset='latest',
                enable_auto_commit=True
            )
            
            self.is_connected = True
            logger.info(f"Connected to Kafka at {self.bootstrap_servers}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to connect to Kafka: {str(e)}")
            return False
    
    def produce(self, message: Dict[str, Any]):
        """Send message to Kafka topic"""
        if not self.is_connected:
            logger.error("Not connected to Kafka")
            return False
        
        try:
            # Add metadata
            enriched_message = {
                'payload': message,
                'timestamp': datetime.now().isoformat(),
                'source': 'kavach'
            }
            
            future = self.producer.send(self.topic, enriched_message)
            self.producer.flush()
            
            logger.debug(f"Message sent to topic {self.topic}")
            return True
            
        except KafkaError as e:
            logger.error(f"Failed to produce message: {str(e)}")
            return False
    
    def consume(self, callback: Callable = None, timeout_ms=1000):
        """Consume messages from Kafka topic"""
        if not self.is_connected:
            logger.error("Not connected to Kafka")
            return []
        
        messages = []
        
        try:
            for message in self.consumer:
                msg_value = message.value
                
                if callback:
                    callback(msg_value)
                else:
                    messages.append(msg_value)
                
                if timeout_ms:
                    break
                    
        except Exception as e:
            logger.error(f"Error consuming messages: {str(e)}")
        
        return messages
    
    def close(self):
        """Close Kafka connections"""
        try:
            if self.consumer:
                self.consumer.close()
            if self.producer:
                self.producer.close()
            self.is_connected = False
            logger.info("Kafka connections closed")
        except Exception as e:
            logger.error(f"Error closing connections: {str(e)}")


class SimulatedStream:
    """
    Simulated streaming for testing without Kafka
    """
    
    def __init__(self, delay=0.1):
        self.delay = delay
        self.events = []
        
        logger.info("SimulatedStream initialized")
    
    def produce(self, message: Dict[str, Any]):
        """Simulate producing a message"""
        import time
        
        enriched_message = {
            'payload': message,
            'timestamp': datetime.now().isoformat(),
            'source': 'kavach-simulated'
        }
        
        self.events.append(enriched_message)
        logger.debug(f"Simulated message produced: {len(self.events)} messages in queue")
        
        time.sleep(self.delay)
        return True
    
    def consume(self, callback: Callable = None, max_messages=None):
        """Simulate consuming messages"""
        consumed = []
        
        to_consume = self.events[:max_messages] if max_messages else self.events
        self.events = self.events[len(to_consume):]
        
        for message in to_consume:
            if callback:
                callback(message)
            consumed.append(message)
        
        return consumed
    
    def close(self):
        """Close simulated stream"""
        logger.info("Simulated stream closed")


class StreamProcessor:
    """
    Process streaming events with ML models
    """
    
    def __init__(self, stream, breach_detector=None, anomaly_detector=None, 
                 honeytoken_monitor=None, behavior_analyzer=None):
        self.stream = stream
        self.breach_detector = breach_detector
        self.anomaly_detector = anomaly_detector
        self.honeytoken_monitor = honeytoken_monitor
        self.behavior_analyzer = behavior_analyzer
        
        self.processed_count = 0
        self.alerts_generated = 0
        
        logger.info("StreamProcessor initialized")
    
    def process_single_event(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process a single streaming message and return the enriched event.
        """
        try:
            from core.threat_detection.pattern_detector import ThreatPatternDetector
            from datetime import datetime
            import sqlite3
            import json
            import os
            
            event = message.get('payload', message) if isinstance(message, dict) else message
            
            # Real-time threat pattern detection
            pattern_detector = ThreatPatternDetector()
            threat_result = pattern_detector.analyze_event(event)
            
            if threat_result:
                event['threat_detected'] = True
                event['threat_type'] = threat_result['threat_type']
                event['threat_severity'] = threat_result['severity']
                
                # Store alert in database
                try:
                    audit_db_path = os.getenv('AUDIT_DB_PATH', 'data/audit_trail.db')
                    if not os.path.isabs(audit_db_path):
                        from pathlib import Path
                        project_root = Path(__file__).parent.parent.parent
                        audit_db_path = str(project_root / audit_db_path)
                    
                    conn = sqlite3.connect(audit_db_path)
                    cursor = conn.cursor()
                    
                    # Store in alerts table
                    cursor.execute('''
                        INSERT INTO alerts 
                        (ts, user_id, source_ip, threat_type, severity, model_score, model_name, explanation)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        datetime.now().isoformat(),
                        event.get('user_id'),
                        event.get('source_ip'),
                        threat_result['threat_type'],
                        threat_result['severity'],
                        0.95,  # High confidence for pattern matches
                        'PatternDetector',
                        json.dumps(threat_result)
                    ))
                    
                    # Also store in events table for timeline visibility
                    cursor.execute('''
                        INSERT INTO events 
                        (ts, user_id, source_ip, activity_type, target, threat_type, payload, severity, label, meta)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        datetime.now().isoformat(),
                        event.get('user_id'),
                        event.get('source_ip'),
                        event.get('activity_type', 'api_call'),
                        threat_result.get('target', event.get('target', 'unknown')),
                        threat_result['threat_type'],
                        threat_result.get('payload', '')[:200],
                        threat_result['severity'],
                        'malicious',
                        json.dumps({'detected_by': 'PatternDetector', 'real_time': True})
                    ))
                    
                    conn.commit()
                    conn.close()
                    logger.warning("🚨 Real-time threat detected: %s - %s", threat_result['threat_type'], threat_result.get('payload', '')[:50])
                except Exception as e:
                    logger.error("Error storing threat alert: %s", e)
            
            if self.breach_detector:
                prediction = self.breach_detector.predict_streaming(event)
                event['prediction'] = prediction
            
            if self.anomaly_detector and 'bytes_transferred' in event:
                anomaly_data = [[event.get('bytes_transferred', 0), event.get('request_count', 0)]]
                anomaly_result = self.anomaly_detector.model.predict(anomaly_data)[0]
                event['is_anomaly'] = bool(anomaly_result == -1)
            
            if self.honeytoken_monitor:
                alert = self.honeytoken_monitor.check_event_for_honeytoken(event)
                if alert:
                    event['honeytoken_alert'] = alert
                    self.alerts_generated += 1
            
            if self.behavior_analyzer:
                ueba_result = self.behavior_analyzer.detect_anomaly(event)
                event['ueba_anomaly'] = ueba_result
            
            self.processed_count += 1
            logger.debug("Processed streaming event #%s", self.processed_count)
            return event
        
        except Exception as exc:
            logger.error("Error processing streaming message: %s", exc)
            return {'error': str(exc), 'payload': message}
    
    def process_stream(self, callback: Callable = None):
        """Process messages from stream"""
        def process_message(message):
            processed = self.process_single_event(message)
            if callback:
                callback(processed)
            return processed
        
        if hasattr(self.stream, 'consume'):
            messages = self.stream.consume(callback=process_message)
        else:
            messages = self.stream.consume(callback=process_message)
        
        return messages
    
    def get_statistics(self):
        """Get processing statistics"""
        return {
            'processed_count': self.processed_count,
            'alerts_generated': self.alerts_generated,
            'alert_rate': self.alerts_generated / max(self.processed_count, 1)
        }


