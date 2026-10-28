"""
Smoke tests for threat seeding and dashboard endpoints
"""

import unittest
import os
import sys
import json
import requests
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from utils.data_generator import seed_threat_testcases
from utils.db_schema import init_audit_trail_schema


class TestSeedAndEndpoints(unittest.TestCase):
    """Test threat seeding and dashboard endpoints"""
    
    @classmethod
    def setUpClass(cls):
        """Set up test database"""
        cls.test_db_path = 'data/test_audit_trail.db'
        cls.api_base_url = os.getenv('API_BASE_URL', 'http://localhost:5001')
        
        # Initialize schema
        init_audit_trail_schema(cls.test_db_path)
    
    def test_seed_threat_testcases(self):
        """Test seeding threat testcases"""
        count = seed_threat_testcases(
            db_path=self.test_db_path,
            catalog_path='utils/threats_catalog.json'
        )
        self.assertGreater(count, 0, "Should seed at least one testcase")
        print(f"✓ Seeded {count} threat testcases")
    
    def test_threat_trends_endpoint(self):
        """Test GET /api/dashboard/threat-trends"""
        try:
            response = requests.get(
                f"{self.api_base_url}/api/dashboard/threat-trends?window=7d",
                timeout=5
            )
            self.assertEqual(response.status_code, 200, "Should return 200")
            data = response.json()
            self.assertIn('trends', data, "Should have 'trends' key")
            self.assertIsInstance(data['trends'], list, "Trends should be a list")
            print("✓ Threat trends endpoint works")
        except requests.exceptions.ConnectionError:
            self.skipTest("API server not running")
    
    def test_severity_dist_endpoint(self):
        """Test GET /api/dashboard/severity-dist"""
        try:
            response = requests.get(
                f"{self.api_base_url}/api/dashboard/severity-dist?window=7d",
                timeout=5
            )
            self.assertEqual(response.status_code, 200, "Should return 200")
            data = response.json()
            self.assertIn('distribution', data, "Should have 'distribution' key")
            self.assertIsInstance(data['distribution'], list, "Distribution should be a list")
            print("✓ Severity distribution endpoint works")
        except requests.exceptions.ConnectionError:
            self.skipTest("API server not running")
    
    def test_top_attack_types_endpoint(self):
        """Test GET /api/dashboard/top-attack-types"""
        try:
            response = requests.get(
                f"{self.api_base_url}/api/dashboard/top-attack-types?limit=10&window=7d",
                timeout=5
            )
            self.assertEqual(response.status_code, 200, "Should return 200")
            data = response.json()
            self.assertIn('top_attacks', data, "Should have 'top_attacks' key")
            self.assertIsInstance(data['top_attacks'], list, "Top attacks should be a list")
            print("✓ Top attack types endpoint works")
        except requests.exceptions.ConnectionError:
            self.skipTest("API server not running")
    
    def test_top_source_ips_endpoint(self):
        """Test GET /api/dashboard/top-source-ips"""
        try:
            response = requests.get(
                f"{self.api_base_url}/api/dashboard/top-source-ips?limit=20&window=7d",
                timeout=5
            )
            self.assertEqual(response.status_code, 200, "Should return 200")
            data = response.json()
            self.assertIn('top_ips', data, "Should have 'top_ips' key")
            self.assertIsInstance(data['top_ips'], list, "Top IPs should be a list")
            print("✓ Top source IPs endpoint works")
        except requests.exceptions.ConnectionError:
            self.skipTest("API server not running")
    
    def test_ueba_user_risk_endpoint(self):
        """Test GET /api/dashboard/ueba-user-risk"""
        try:
            response = requests.get(
                f"{self.api_base_url}/api/dashboard/ueba-user-risk?top=10&window=7d",
                timeout=5
            )
            self.assertEqual(response.status_code, 200, "Should return 200")
            data = response.json()
            self.assertIn('user_risks', data, "Should have 'user_risks' key")
            self.assertIsInstance(data['user_risks'], list, "User risks should be a list")
            print("✓ UEBA user risk endpoint works")
        except requests.exceptions.ConnectionError:
            self.skipTest("API server not running")
    
    def test_honeytoken_heatmap_endpoint(self):
        """Test GET /api/dashboard/honeytoken-heatmap"""
        try:
            response = requests.get(
                f"{self.api_base_url}/api/dashboard/honeytoken-heatmap?window=7d",
                timeout=5
            )
            self.assertEqual(response.status_code, 200, "Should return 200")
            data = response.json()
            self.assertIn('heatmap', data, "Should have 'heatmap' key")
            self.assertIsInstance(data['heatmap'], list, "Heatmap should be a list")
            print("✓ Honeytoken heatmap endpoint works")
        except requests.exceptions.ConnectionError:
            self.skipTest("API server not running")
    
    def test_feature_importance_endpoint(self):
        """Test GET /api/dashboard/feature-importance"""
        try:
            response = requests.get(
                f"{self.api_base_url}/api/dashboard/feature-importance?model=Ensemble",
                timeout=5
            )
            self.assertEqual(response.status_code, 200, "Should return 200")
            data = response.json()
            self.assertIn('features', data, "Should have 'features' key")
            self.assertIsInstance(data['features'], list, "Features should be a list")
            print("✓ Feature importance endpoint works")
        except requests.exceptions.ConnectionError:
            self.skipTest("API server not running")
    
    def test_model_metrics_endpoint(self):
        """Test GET /api/dashboard/model-metrics"""
        try:
            response = requests.get(
                f"{self.api_base_url}/api/dashboard/model-metrics?model=Ensemble",
                timeout=5
            )
            self.assertEqual(response.status_code, 200, "Should return 200")
            data = response.json()
            self.assertIn('metrics', data, "Should have 'metrics' key")
            metrics = data['metrics']
            self.assertIn('accuracy', metrics, "Should have 'accuracy' key")
            self.assertIn('f1', metrics, "Should have 'f1' key")
            self.assertIn('roc_auc', metrics, "Should have 'roc_auc' key")
            print("✓ Model metrics endpoint works")
        except requests.exceptions.ConnectionError:
            self.skipTest("API server not running")
    
    def test_seed_testcases_endpoint(self):
        """Test POST /api/testcases/seed"""
        try:
            response = requests.post(
                f"{self.api_base_url}/api/testcases/seed",
                timeout=10
            )
            self.assertEqual(response.status_code, 200, "Should return 200")
            data = response.json()
            self.assertIn('success', data, "Should have 'success' key")
            self.assertIn('count', data, "Should have 'count' key")
            print("✓ Seed testcases endpoint works")
        except requests.exceptions.ConnectionError:
            self.skipTest("API server not running")


if __name__ == '__main__':
    unittest.main()

