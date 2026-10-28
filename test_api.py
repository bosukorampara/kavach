"""
Quick test script to verify KAVACH API endpoints
Run this after starting the server with: python main.py
"""

import requests
import json
from datetime import datetime

BASE_URL = "http://127.0.0.1:5001"

def test_health():
    """Test health endpoint"""
    print("Testing /health endpoint...")
    response = requests.get(f"{BASE_URL}/health")
    print(f"Status: {response.status_code}")
    print(f"Response: {response.json()}\n")
    return response.status_code == 200

def test_predict():
    """Test prediction endpoint"""
    print("Testing /api/predict endpoint...")
    test_event = {
        'user_id': 'user_123',
        'timestamp': datetime.now().isoformat(),
        'bytes_transferred': 150000,
        'request_count': 100,
        'activity_type': 'sql_injection',
        'source_ip': '192.168.1.100',
        'user_role': 'user',
        'location': 'US',
        'business_value_impact': 0.8,
        'known_vulnerabilities': 2
    }
    response = requests.post(f"{BASE_URL}/api/predict", json=test_event)
    print(f"Status: {response.status_code}")
    result = response.json()
    print(f"Prediction: Malicious={result.get('prediction', {}).get('is_malicious')}")
    print(f"Confidence: {result.get('prediction', {}).get('confidence', 0):.2%}\n")
    return response.status_code == 200

def test_honeytoken():
    """Test honeytoken planting and checking"""
    print("Testing honeytoken functionality...")
    
    # Plant a honeytoken
    plant_data = {
        'token_type': 'credential',
        'location': '/etc/passwd',
        'severity': 'HIGH'
    }
    response = requests.post(f"{BASE_URL}/api/honeytokens/plant", json=plant_data)
    print(f"Plant honeytoken status: {response.status_code}")
    if response.status_code == 201:
        token_id = response.json().get('token_id')
        print(f"Planted token ID: {token_id[:16]}...\n")
    
    # Get all honeytokens
    response = requests.get(f"{BASE_URL}/api/honeytokens")
    print(f"Get honeytokens status: {response.status_code}")
    if response.status_code == 200:
        tokens = response.json().get('honeytokens', [])
        print(f"Total honeytokens: {len(tokens)}\n")
    
    return response.status_code == 200

def test_alerts():
    """Test alerts endpoint"""
    print("Testing /api/alerts endpoint...")
    response = requests.get(f"{BASE_URL}/api/alerts")
    print(f"Status: {response.status_code}")
    result = response.json()
    print(f"Total alerts: {result.get('count', 0)}\n")
    return response.status_code == 200

def test_metrics():
    """Test metrics endpoint"""
    print("Testing /api/metrics endpoint...")
    response = requests.get(f"{BASE_URL}/api/metrics")
    print(f"Status: {response.status_code}")
    if response.status_code == 200:
        metrics = response.json().get('metrics', {})
        print(f"Metrics available: {len(metrics) > 0}\n")
    return response.status_code == 200

def main():
    """Run all tests"""
    print("=" * 60)
    print("KAVACH API Test Suite")
    print("=" * 60)
    print(f"Testing against: {BASE_URL}\n")
    
    try:
        tests = [
            ("Health Check", test_health),
            ("Prediction", test_predict),
            ("Honeytokens", test_honeytoken),
            ("Alerts", test_alerts),
            ("Metrics", test_metrics)
        ]
        
        results = []
        for name, test_func in tests:
            try:
                result = test_func()
                results.append((name, result))
            except Exception as e:
                print(f"Error in {name}: {str(e)}\n")
                results.append((name, False))
        
        print("=" * 60)
        print("Test Results Summary")
        print("=" * 60)
        for name, result in results:
            status = "✅ PASS" if result else "❌ FAIL"
            print(f"{name}: {status}")
        
        all_passed = all(r[1] for r in results)
        print(f"\nOverall: {'✅ ALL TESTS PASSED' if all_passed else '❌ SOME TESTS FAILED'}")
        
    except requests.exceptions.ConnectionError:
        print("❌ ERROR: Could not connect to API server.")
        print("Make sure the server is running with: python main.py")
    except Exception as e:
        print(f"❌ ERROR: {str(e)}")

if __name__ == '__main__':
    main()

