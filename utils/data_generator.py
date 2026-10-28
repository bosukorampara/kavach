"""
Generate sample data for training and testing
"""

import pandas as pd
import numpy as np
import secrets
import json
import sqlite3
import os
import argparse
from datetime import datetime, timedelta
from pathlib import Path
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def generate_sample_data(n_samples=10000, malicious_ratio=0.1, label_noise=0.03):
    """
    Generate sample data for training breach detection models.

    Notes:
    - Distributions for benign vs malicious traffic are overlapping but shifted,
      so perfect separation is unlikely.
    - A small amount of label noise is injected by default to produce more
      realistic, non-100% evaluation metrics.
    """
    np.random.seed(42)
    
    data = []
    
    for i in range(n_samples):
        # Determine if malicious
        is_malicious = np.random.random() < malicious_ratio
        
        # Generate timestamp
        timestamp = datetime.now() - timedelta(
            hours=np.random.randint(0, 720),
            minutes=np.random.randint(0, 60)
        )
        
        # Generate user data
        user_id = f"user_{np.random.randint(1, 100)}"
        user_role = np.random.choice(['user', 'admin', 'service'], p=[0.7, 0.2, 0.1])
        
        # Generate network data with overlapping distributions
        if is_malicious:
            # Malicious: higher typical volume / rate, but still overlapping with benign
            bytes_transferred = np.random.exponential(6000)
            request_count = np.random.poisson(20)
        else:
            # Benign: lower on average, but not trivial to separate
            bytes_transferred = np.random.exponential(2500)
            request_count = np.random.poisson(8)
        
        # Generate activity type
        activity_types = ['normal', 'api_call', 'file_access', 'database_query', 'login']
        if is_malicious:
            activity_type = np.random.choice(
                ['sql_injection', 'unauthorized_access', 'data_exfiltration', 'privilege_escalation']
            )
        else:
            activity_type = np.random.choice(activity_types)
        
        # Generate IPs
        source_ip = f"192.168.1.{np.random.randint(1, 255)}"
        destination_ip = f"10.0.0.{np.random.randint(1, 255)}"
        
        # Generate location
        locations = ['US', 'EU', 'ASIA', 'INVALID']
        location = np.random.choice(locations, p=[0.4, 0.3, 0.25, 0.05])
        
        # Additional features for context
        business_value_impact = np.random.uniform(0, 1)
        known_vulnerabilities = np.random.randint(0, 10)
        
        data.append({
            'user_id': user_id,
            'timestamp': timestamp.isoformat(),
            'user_role': user_role,
            'bytes_transferred': int(bytes_transferred),
            'request_count': int(request_count),
            'activity_type': activity_type,
            'source_ip': source_ip,
            'destination_ip': destination_ip,
            'location': location,
            'business_value_impact': business_value_impact,
            'known_vulnerabilities': known_vulnerabilities,
            'is_malicious': int(is_malicious)
        })
    
    df = pd.DataFrame(data)
    
    # Inject a small amount of label noise to avoid unrealistically perfect scores
    if label_noise and label_noise > 0:
        flip_mask = np.random.rand(len(df)) < float(label_noise)
        if flip_mask.any():
            original_malicious = df.loc[flip_mask, 'is_malicious'].copy()
            df.loc[flip_mask, 'is_malicious'] = 1 - df.loc[flip_mask, 'is_malicious']
            logger.info(
                f"Applied label noise: flipped {flip_mask.sum()} labels "
                f"(~{flip_mask.mean() * 100:.2f}% of samples)."
            )
            logger.debug(
                f"Label noise details - before: {original_malicious.value_counts().to_dict()} "
                f"after: {df.loc[flip_mask, 'is_malicious'].value_counts().to_dict()}"
            )
    
    logger.info(f"Generated {n_samples} samples with {df['is_malicious'].sum()} malicious events")
    
    return df


def generate_honeytoken_events(n_events=100):
    """Generate events to test honeytoken monitoring"""
    events = []
    
    for i in range(n_events):
        events.append({
            'token_value': f"fake_credential_{secrets.token_hex(4)}",
            'source': f"192.168.{secrets.randbelow(255)}.{secrets.randbelow(255)}",
            'timestamp': (datetime.now() - timedelta(minutes=i)).isoformat()
        })
    
    return events


def seed_threat_testcases(db_path="data/audit_trail.db", catalog_path="utils/threats_catalog.json", days=7):
    """
    Insert threat catalog rows into events table with synthetic timestamps
    across the last N days, random users/IPs, realistic frequencies.
    Generates 1000+ rows distributed over the specified days.
    """
    # Initialize schema first
    from utils.db_schema import init_audit_trail_schema
    init_audit_trail_schema(db_path)
    
    # Load threat catalog
    if not os.path.isabs(catalog_path):
        project_root = Path(__file__).parent.parent
        catalog_path = str(project_root / catalog_path)
    
    with open(catalog_path, 'r') as f:
        catalog = json.load(f)
    
    # Ensure db directory exists
    db_dir = os.path.dirname(db_path)
    if db_dir and not os.path.exists(db_dir):
        os.makedirs(db_dir, exist_ok=True)
    
    if not os.path.isabs(db_path):
        project_root = Path(__file__).parent.parent
        db_path = str(project_root / db_path)
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    inserted_count = 0
    np.random.seed(42)
    
    # Generate events for each threat type over last N days
    for threat in catalog:
        name = threat.get('name', 'Unknown')
        threat_type = threat.get('threat_type', 'Unknown')
        payload = threat.get('payload', threat.get('sample_payload', ''))
        target = threat.get('target', threat.get('typical_target', '/'))
        severity = threat.get('severity', 'MEDIUM')
        activity_type = threat.get('activity_type', threat.get('suggested_activity_type', 'api_call'))
        label = threat.get('label', 'benign')
        meta = threat.get('meta', {})
        
        # Get frequency from meta or default
        counts = meta.get('counts', 10)
        hour_of_day_list = meta.get('hour_of_day', [np.random.randint(0, 24)])
        if not isinstance(hour_of_day_list, list):
            hour_of_day_list = [hour_of_day_list]
        
        is_burst = meta.get('burst', False)
        burst_size = meta.get('size', counts)
        
        if is_burst:
            # For bursts, concentrate events in a short time window
            days_ago = np.random.randint(0, days)
            burst_day = datetime.now() - timedelta(days=days_ago)
            burst_hour = np.random.choice(hour_of_day_list) if hour_of_day_list else np.random.randint(0, 24)
            burst_start = burst_day.replace(hour=burst_hour, minute=0, second=0)
            
            # Generate burst events within a short window
            for i in range(burst_size):
                event_time = burst_start + timedelta(
                    minutes=np.random.randint(0, 60),
                    seconds=np.random.randint(0, 60)
                )
                
                user_id = f"user_{np.random.randint(1, 100)}"
                source_ip = f"{np.random.randint(1, 255)}.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}"
                
                cursor.execute('''
                    INSERT INTO events 
                    (ts, user_id, source_ip, activity_type, target, threat_type, payload, severity, label, meta)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    event_time.isoformat(),
                    user_id,
                    source_ip,
                    activity_type,
                    target,
                    threat_type,
                    payload,
                    severity,
                    label,
                    json.dumps(meta)
                ))
                inserted_count += 1
        else:
            # Distribute events across last N days
            for day_offset in range(days):
                days_ago = day_offset
                base_time = datetime.now() - timedelta(days=days_ago)
                
                # Distribute events across the day based on hour_of_day preferences
                events_per_day = max(1, counts // days)
                for i in range(events_per_day):
                    # Pick hour from preferred hours or random
                    if hour_of_day_list:
                        hour = np.random.choice(hour_of_day_list)
                    else:
                        hour = np.random.randint(0, 24)
                    
                    event_time = base_time.replace(hour=hour) + timedelta(
                        minutes=np.random.randint(0, 60),
                        seconds=np.random.randint(0, 60)
                    )
                    
                    user_id = f"user_{np.random.randint(1, 100)}"
                    source_ip = f"{np.random.randint(1, 255)}.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}"
                    
                    cursor.execute('''
                        INSERT INTO events 
                        (ts, user_id, source_ip, activity_type, target, threat_type, payload, severity, label, meta)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        event_time.isoformat(),
                        user_id,
                        source_ip,
                        activity_type,
                        target,
                        threat_type,
                        payload,
                        severity,
                        label,
                        json.dumps(meta)
                    ))
                    inserted_count += 1
    
    conn.commit()
    conn.close()
    
    logger.info(f"Seeded {inserted_count} threat testcase events into {db_path} over {days} days")
    return inserted_count


def simulate_bursts(db_path="data/audit_trail.db", burst_types=None):
    """
    Generate time-bursts for brute-force, port-scan, data-exfil, and dns-tunnel
    to stress UEBA.
    """
    if burst_types is None:
        burst_types = ['brute_force', 'port_scan', 'data_exfil', 'dns_tunnel']
    
    # Initialize schema
    from utils.db_schema import init_audit_trail_schema
    init_audit_trail_schema(db_path)
    
    # Ensure db directory exists
    db_dir = os.path.dirname(db_path)
    if db_dir and not os.path.exists(db_dir):
        os.makedirs(db_dir, exist_ok=True)
    
    if not os.path.isabs(db_path):
        project_root = Path(__file__).parent.parent
        db_path = str(project_root / db_path)
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    np.random.seed(42)
    inserted_count = 0
    
    # Brute force burst: 100 attempts in 5 minutes
    if 'brute_force' in burst_types:
        base_time = datetime.now() - timedelta(hours=2)
        user_id = f"user_{np.random.randint(1, 10)}"
        source_ip = f"192.168.1.{np.random.randint(100, 200)}"
        
        for i in range(100):
            event_time = base_time + timedelta(seconds=i * 3)  # 3 seconds apart
            cursor.execute('''
                INSERT INTO events 
                (ts, user_id, source_ip, activity_type, target, threat_type, payload, severity, label, meta)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                event_time.isoformat(),
                user_id,
                source_ip,
                'login',
                '/login',
                'Broken Auth',
                f'username=admin&password=attempt{i}',
                'MEDIUM',
                'malicious',
                json.dumps({'counts': 1, 'bytes': 256, 'hour_of_day': event_time.hour})
            ))
            inserted_count += 1
    
    # Port scan burst: 1000 connections in 10 minutes
    if 'port_scan' in burst_types:
        base_time = datetime.now() - timedelta(hours=1)
        source_ip = f"10.0.0.{np.random.randint(50, 100)}"
        
        for i in range(1000):
            event_time = base_time + timedelta(seconds=i * 0.6)  # 0.6 seconds apart
            port = np.random.randint(1, 65535)
            cursor.execute('''
                INSERT INTO events 
                (ts, user_id, source_ip, activity_type, target, threat_type, payload, severity, label, meta)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                event_time.isoformat(),
                None,
                source_ip,
                'api_call',
                f"192.168.1.1:{port}",
                'Port Scan',
                f"TCP SYN to port {port}",
                'MEDIUM',
                'malicious',
                json.dumps({'counts': 1, 'bytes': 0, 'hour_of_day': event_time.hour, 'port': port})
            ))
            inserted_count += 1
    
    # Data exfiltration burst: large transfers in short time
    if 'data_exfil' in burst_types:
        base_time = datetime.now() - timedelta(minutes=30)
        user_id = f"user_{np.random.randint(1, 10)}"
        source_ip = f"192.168.1.{np.random.randint(1, 50)}"
        
        for i in range(10):
            event_time = base_time + timedelta(minutes=i * 2)
            bytes_transferred = np.random.randint(10485760, 104857600)  # 10-100 MB
            cursor.execute('''
                INSERT INTO events 
                (ts, user_id, source_ip, activity_type, target, threat_type, payload, severity, label, meta)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                event_time.isoformat(),
                user_id,
                source_ip,
                'file_download',
                '/api/users/export',
                'Data Exfiltration',
                f"GET /api/users?limit=10000",
                'CRITICAL',
                'malicious',
                json.dumps({'counts': 1, 'bytes': bytes_transferred, 'hour_of_day': event_time.hour})
            ))
            inserted_count += 1
    
    # DNS tunneling burst: periodic low-volume queries
    if 'dns_tunnel' in burst_types:
        base_time = datetime.now() - timedelta(hours=6)
        source_ip = f"10.0.0.{np.random.randint(150, 200)}"
        
        for i in range(200):
            event_time = base_time + timedelta(minutes=i * 3)  # Every 3 minutes
            subdomain = secrets.token_hex(8)
            cursor.execute('''
                INSERT INTO events 
                (ts, user_id, source_ip, activity_type, target, threat_type, payload, severity, label, meta)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                event_time.isoformat(),
                None,
                source_ip,
                'dns_query',
                f"dns:{subdomain}.evil.com",
                'DNS Tunneling',
                f"{subdomain}.evil.com",
                'HIGH',
                'malicious',
                json.dumps({'counts': 1, 'bytes': 512, 'hour_of_day': event_time.hour, 'query_type': 'A'})
            ))
            inserted_count += 1
    
    conn.commit()
    conn.close()
    
    logger.info(f"Simulated {inserted_count} burst events into {db_path}")
    return inserted_count


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Generate sample data for KAVACH')
    parser.add_argument('--seed-threats', action='store_true', help='Seed threat testcases from catalog')
    parser.add_argument('--simulate-bursts', action='store_true', help='Simulate burst events (brute-force, port-scan, etc.)')
    parser.add_argument('--db-path', default='data/audit_trail.db', help='Path to audit trail database')
    parser.add_argument('--catalog-path', default='utils/threats_catalog.json', help='Path to threat catalog JSON')
    parser.add_argument('--days', type=int, default=7, help='Number of days to seed data for')
    
    args = parser.parse_args()
    
    if args.seed_threats:
        count = seed_threat_testcases(db_path=args.db_path, catalog_path=args.catalog_path, days=args.days)
        print(f"Seeded {count} threat testcase events")
    elif args.simulate_bursts:
        count = simulate_bursts(db_path=args.db_path)
        print(f"Generated {count} burst events")
    else:
        # Default: generate sample data
        print("Generating sample data...")
        generate_sample_data()
        print("Sample data generation complete")
    parser = argparse.ArgumentParser(description='KAVACH Data Generator')
    parser.add_argument('--seed-threats', action='store_true', help='Seed threat testcases')
    parser.add_argument('--simulate-bursts', action='store_true', help='Simulate attack bursts')
    parser.add_argument('--db-path', default='data/audit_trail.db', help='Database path')
    parser.add_argument('--catalog-path', default='utils/threats_catalog.json', help='Threat catalog path')
    parser.add_argument('--days', type=int, default=7, help='Number of days to seed data for')
    
    args = parser.parse_args()
    
    if args.seed_threats:
        count = seed_threat_testcases(args.db_path, args.catalog_path, days=args.days)
        print(f"Seeded {count} threat testcases")
    
    if args.simulate_bursts:
        count = simulate_bursts(args.db_path)
        print(f"Simulated {count} burst events")

