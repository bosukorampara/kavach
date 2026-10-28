"""
KAVACH Demo Script
Demonstrates all features of the threat detection system
"""

from datetime import datetime
from core.models.breach_detector import BreachDetector
from core.models.anomaly_detector import AnomalyDetector
from core.deception.honeytoken_monitor import HoneytokenMonitor
from chatbot.security_bot import SecurityBot
from ueba.behavior_analyzer import BehaviorAnalyzer
from utils.data_generator import generate_sample_data
import pandas as pd
import json

def print_section(title):
    """Print section header"""
    print("\n" + "=" * 60)
    print(title)
    print("=" * 60 + "\n")


def demo_breach_detection():
    """Demonstrate breach detection"""
    print_section("1. AI-POWERED BREACH DETECTION")
    
    print("Generating sample data...")
    data = generate_sample_data(n_samples=10000, malicious_ratio=0.1)
    
    print(f"Dataset size: {len(data)} samples")
    print(f"Malicious samples: {data['is_malicious'].sum()}")
    print(f"Benign samples: {(~data['is_malicious'].astype(bool)).sum()}")
    
    print("\nTraining Random Forest and Gradient Boosting models...")
    detector = BreachDetector(use_ensemble_consensus=True, consensus_threshold=0.5)
    detector.train(data, target_column='is_malicious')
    
    print("\nModel Performance:")
    print(json.dumps(detector.get_metrics_report(), indent=2))
    
    print("\nTesting real-time prediction...")
    test_event = {
        'user_id': 'user_123',
        'timestamp': '2024-01-01T12:00:00',
        'bytes_transferred': 150000,
        'request_count': 100,
        'activity_type': 'sql_injection',
        'source_ip': '192.168.1.100',
        'user_role': 'user',
        'location': 'US'
    }
    
    result = detector.predict_streaming(test_event)
    print(f"Prediction: Malicious={result['is_malicious']}, Confidence={result['confidence']:.2%}")
    print(f"Consensus: {result['consensus']}")
    
    return detector


def demo_honeytokens():
    """Demonstrate honeytoken monitoring"""
    print_section("2. DECEPTION LAYER - HONEYTOKEN MONITORING")
    
    monitor = HoneytokenMonitor()
    
    print("Planting honeytokens...")
    token1 = monitor.plant_honeytoken('credential', '/etc/shadow', severity='HIGH')
    token2 = monitor.plant_honeytoken('file', '/var/secrets/credentials.txt', severity='HIGH')
    token3 = monitor.plant_honeytoken('ip', '10.0.0.200', severity='MEDIUM')
    
    print(f"Planted honeytoken IDs: {token1[:8]}...")
    
    print("\nSimulating honeytoken interaction...")
    first_token = monitor.get_all_honeytokens()[0]
    alert = monitor.check_event_for_honeytoken({
        'honeytoken_value': first_token['value'],
        'user_id': 'attacker',
        'source_ip': '192.168.1.50'
    })
    
    if alert:
        print(f"\n⚠️ ALERT TRIGGERED:")
        print(f"   Type: {alert['type']}")
        print(f"   Severity: {alert['severity']}")
        print(f"   Message: {alert['message']}")
    
    stats = monitor.get_statistics()
    print(f"\nHoneytoken Statistics:")
    print(f"   Total tokens: {stats['total_tokens']}")
    print(f"   Active tokens: {stats['tokens_active']}")
    print(f"   Breach events: {stats['breach_events']}")
    
    return monitor


def demo_chatbot():
    """Demonstrate AI chatbot"""
    print_section("3. AI CHATBOT ASSISTANT")
    
    bot = SecurityBot()
    
    queries = [
        ("Explain HONEYTOKEN_BREACH alert", {'alert_type': 'HONEYTOKEN_BREACH'}),
        ("What should I do about a malicious activity alert?", {'alert_type': 'MALICIOUS_ACTIVITY'}),
        ("How confident is the model?", {
            'prediction': {
                'rf_confidence': 0.85,
                'gb_confidence': 0.92,
                'consensus': True
            }
        }),
        ("What is a honeytoken?", None)
    ]
    
    for query, context in queries:
        print(f"\nUser: {query}")
        response = bot.process_message(query, context=context)
        print(f"Bot: {response['response']}")
        if 'suggestions' in response and response['suggestions']:
            print("\nSuggested actions:")
            for action in response['suggestions']:
                print(f"  • {action}")
    
    return bot


def demo_ueba():
    """Demonstrate UEBA"""
    print_section("4. USER AND ENTITY BEHAVIOR ANALYTICS")
    
    # Generate behavioral data
    print("Generating behavioral profile data...")
    data = generate_sample_data(n_samples=5000, malicious_ratio=0.05)
    
    # Train UEBA
    analyzer = BehaviorAnalyzer(deviation_threshold=2.0)
    print("Building behavioral profiles...")
    analyzer.train(data)
    
    print(f"\nProfiles created: {len(analyzer.profiles)}")
    
    # Test anomaly detection
    print("\nTesting anomaly detection...")
    test_activity = {
        'user_id': 'user_123',
        'timestamp': '2024-01-01T03:00:00',  # Unusual time
        'bytes_transferred': 500000,  # Large transfer
        'request_count': 100,
        'activity_type': 'data_exfiltration',
        'location': 'UNKNOWN',  # New location
        'user_role': 'admin'
    }
    
    anomaly_result = analyzer.detect_anomaly(test_activity)
    
    print(f"Anomaly detected: {anomaly_result['is_anomaly']}")
    print(f"Risk score: {anomaly_result['risk_score']:.2f}")
    if anomaly_result['anomalies']:
        print(f"Detected anomalies: {', '.join(anomaly_result['anomalies'])}")
    
    # Show profile
    if 'user_123' in analyzer.profiles:
        profile = analyzer.profiles['user_123']
        print(f"\nBehavioral Profile for user_123:")
        print(f"   Baseline login time: {profile.baseline_login_time:.1f}")
        print(f"   Total sessions: {len(profile.login_times)}")
        print(f"   Activity types: {dict(profile.activity_types)}")
    
    return analyzer


def demo_integration():
    """Demonstrate integrated workflow"""
    print_section("5. INTEGRATED WORKFLOW")
    
    print("Simulating integrated threat detection workflow...")
    
    # Step 1: Detect threat
    data = generate_sample_data(n_samples=1000, malicious_ratio=0.1)
    detector = BreachDetector()
    detector.train(data, target_column='is_malicious')
    
    event = {
        'user_id': 'user_789',
        'timestamp': '2024-01-01T12:00:00',
        'bytes_transferred': 200000,
        'request_count': 150,
        'activity_type': 'unauthorized_access',
        'source_ip': '192.168.1.200',
        'user_role': 'user',
        'location': 'ASIA'
    }
    
    print("\nStep 1: Detecting threat...")
    result = detector.predict_streaming(event)
    print(f"   Threat detected: {result['is_malicious']}")
    print(f"   Confidence: {result['confidence']:.2%}")
    
    # Step 2: Check honeytokens
    print("\nStep 2: Checking honeytoken interactions...")
    monitor = HoneytokenMonitor()
    monitor.plant_honeytoken('credential', '/etc/passwd')
    alert = monitor.check_interaction(event['source_ip'], event['user_id'])
    
    if alert:
        print(f"   ⚠️ Honeytoken alert triggered!")
    
    # Step 3: UEBA analysis
    print("\nStep 3: UEBA analysis...")
    analyzer = BehaviorAnalyzer()
    analyzer.train(data)
    ueba_result = analyzer.detect_anomaly(event)
    print(f"   Anomaly detected: {ueba_result['is_anomaly']}")
    print(f"   Risk score: {ueba_result['risk_score']:.2f}")
    
    # Step 4: Chatbot recommendation
    print("\nStep 4: Getting chatbot recommendations...")
    bot = SecurityBot()
    response = bot.process_message(
        "What should I do?",
        context={'alert_type': 'MALICIOUS_ACTIVITY'}
    )
    print(f"   Recommendation: {response['response'][:200]}...")


def main():
    """Run complete demo"""
    print("\n" + "=" * 60)
    print("KAVACH - AI-Driven Threat and Anomaly Detection")
    print("Complete System Demonstration")
    print("=" * 60)
    
    try:
        # Run all demos
        demo_breach_detection()
        demo_honeytokens()
        demo_chatbot()
        demo_ueba()
        demo_integration()
        
        print_section("DEMO COMPLETE")
        print("✅ All features demonstrated successfully!")
        print("\nKAVACH system is ready for production use.")
        
    except Exception as e:
        print(f"\n❌ Error during demo: {str(e)}")
        import traceback
        traceback.print_exc()


if __name__ == '__main__':
    main()

