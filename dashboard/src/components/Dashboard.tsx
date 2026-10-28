import React, { useState, useEffect, useRef } from 'react';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  ArcElement,
  RadialLinearScale,
  Title,
  Tooltip,
  Legend,
  Filler
} from 'chart.js';
import { Line as LineChart, Bar as BarChart, Doughnut as DoughnutChart, Radar as RadarChart } from 'react-chartjs-2';
import { uniqStrings } from '../utils/uniq';
import { ThemeProvider, ThemeToggle } from '../theme/Theme';
import { ThreatTrendsCard, TopAttackTypesCard, SeverityDonutCard, TopSourceIPsCard, HoneytokenHourHeatmapCard } from './ChartComponents';
import './Dashboard.css';

// Register Chart.js components
ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  ArcElement,
  RadialLinearScale,
  Title,
  Tooltip,
  Legend,
  Filler
);

interface DashboardProps {
  onLogout: () => void;
}

interface Alert {
  id: string;
  type: string;
  severity: string;
  timestamp: string;
  message: string;
  source?: string;
}

interface ThreatTrend {
  timestamp: string;
  total_events: number;
  threats_detected: number;
  false_positives: number;
  honeytoken_breaches: number;
}

interface ActivityEvent {
  timestamp: string;
  user_id: string;
  action: string;
  threat_type?: string;
  severity?: string;
  risk_score: number;
  is_malicious?: boolean;
  is_anomaly?: boolean;
  source_ip?: string;
}

interface Honeytoken {
  id: string;
  type: string;
  value: string;
  location: string;
  planted_at: string;
  accessed: boolean;
  severity: string;
}

interface Metrics {
  models: {
    RandomForest?: any;
    GradientBoosting?: any;
  };
}

const Dashboard: React.FC<DashboardProps> = ({ onLogout }) => {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [trends, setTrends] = useState<ThreatTrend[]>([]);
  const [timeline, setTimeline] = useState<ActivityEvent[]>([]);
  const [honeytokens, setHoneytokens] = useState<Honeytoken[]>([]);
  const [honeytokenStats, setHoneytokenStats] = useState<any | null>(null);
  const [metrics, setMetrics] = useState<Metrics | null>(null);
  const [statistics, setStatistics] = useState<any>(null);
  const [showChatbot, setShowChatbot] = useState(false);
  const [chatInput, setChatInput] = useState('');
  const [chatResponses, setChatResponses] = useState<Array<{ user: string; bot: string; timestamp: string }>>([]);
  const [activeTab, setActiveTab] = useState('overview');
  const [loading, setLoading] = useState(true);
  const [user, setUser] = useState<any>(null);
  const chatEndRef = useRef<HTMLDivElement>(null);
  
  // New state for dashboard panels
  const [threatTrendsByType, setThreatTrendsByType] = useState<any[]>([]);
  const [topAttackTypes, setTopAttackTypes] = useState<any[]>([]);
  const [severityDist, setSeverityDist] = useState<any[]>([]);
  const [topSourceIPs, setTopSourceIPs] = useState<any[]>([]);
  const [uebaUserRisks, setUebaUserRisks] = useState<any[]>([]);
  const [honeytokenHeatmap, setHoneytokenHeatmap] = useState<any[]>([]);
  const [featureImportance, setFeatureImportance] = useState<any[]>([]);
  const [modelMetricsData, setModelMetricsData] = useState<any>(null);
  const [showPlantModal, setShowPlantModal] = useState(false);
  const [plantForm, setPlantForm] = useState({
    token_type: 'credential',
    location: '/etc/passwd',
    severity: 'HIGH',
    attack_type: ''
  });

  const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:5001';
  
  const attackTypes = [
    '', 'SQLi', 'XSS', 'CommandInjection', 'SSRF', 'DirTraversal', 
    'LDAPInjection', 'NoSQLInjection', 'XXE', 'JWTManipulation', 
    'BruteForce', 'CredentialStuffing', 'PortScan', 'C2Beacon'
  ];

  useEffect(() => {
    const userStr = localStorage.getItem('user');
    if (userStr) {
      setUser(JSON.parse(userStr));
    }
    fetchAllData();
    
    // Auto-refresh every 10 seconds for live updates
    const interval = setInterval(() => {
      fetchAllData();
    }, 10000);

    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    chatEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [chatResponses]);

  const fetchAllData = async () => {
    setLoading(true);
    await Promise.all([
      fetchAlerts(),
      fetchThreatTrends(),
      fetchActivityTimeline(),
      fetchHoneytokens(),
      fetchMetrics(),
      fetchStatistics(),
      fetchThreatTrendsByType(),
      fetchTopAttackTypes(),
      fetchSeverityDistribution(),
      fetchTopSourceIPs(),
      fetchUebaUserRisk(),
      fetchHoneytokenHeatmap(),
      fetchFeatureImportance(),
      fetchModelMetricsDashboard()
    ]);
    setLoading(false);
  };

  const fetchAlerts = async () => {
    try {
      const response = await fetch(`${API_BASE_URL}/api/alerts`);
      const data = await response.json();
      setAlerts(data.alerts || []);
    } catch (error) {
      console.error('Error fetching alerts:', error);
    }
  };

  const fetchThreatTrends = async () => {
    try {
      const response = await fetch(`${API_BASE_URL}/api/threat-trends?hours=24`);
      const data = await response.json();
      setTrends(data.trends || []);
      setStatistics(data.statistics);
    } catch (error) {
      console.error('Error fetching trends:', error);
    }
  };

  const fetchActivityTimeline = async () => {
    try {
      const response = await fetch(`${API_BASE_URL}/api/activity-timeline?limit=50`);
      const data = await response.json();
      setTimeline(data.timeline || []);
    } catch (error) {
      console.error('Error fetching timeline:', error);
    }
  };

  const fetchHoneytokens = async () => {
    try {
      const response = await fetch(`${API_BASE_URL}/api/honeytokens`);
      const data = await response.json();
      setHoneytokens(data.honeytokens || []);
      setHoneytokenStats(data.statistics || null);
    } catch (error) {
      console.error('Error fetching honeytokens:', error);
    }
  };

  const fetchMetrics = async () => {
    try {
      const response = await fetch(`${API_BASE_URL}/api/metrics`);
      const data = await response.json();
      if (data.metrics) {
        try {
          setMetrics(JSON.parse(data.metrics));
        } catch {
          setMetrics(data.metrics);
        }
      }
    } catch (error) {
      console.error('Error fetching metrics:', error);
    }
  };

  const fetchStatistics = async () => {
    try {
      const response = await fetch(`${API_BASE_URL}/api/threat-trends?hours=24`);
      const data = await response.json();
      setStatistics(data.statistics);
    } catch (error) {
      console.error('Error fetching statistics:', error);
    }
  };

  const fetchThreatTrendsByType = async () => {
    try {
      const response = await fetch(`${API_BASE_URL}/api/dashboard/threat-trends?window=7d`);
      const data = await response.json();
      // Handle both array and object responses
      setThreatTrendsByType(Array.isArray(data) ? data : (data.trends || []));
    } catch (error) {
      console.error('Error fetching threat trends by type:', error);
      setThreatTrendsByType([]);
    }
  };

  const fetchTopAttackTypes = async () => {
    try {
      const response = await fetch(`${API_BASE_URL}/api/dashboard/top-attack-types?limit=10&window=7d`);
      const data = await response.json();
      // Handle both array and object responses
      setTopAttackTypes(Array.isArray(data) ? data : (data.top_attacks || []));
    } catch (error) {
      console.error('Error fetching top attack types:', error);
      setTopAttackTypes([]);
    }
  };

  const fetchSeverityDistribution = async () => {
    try {
      const response = await fetch(`${API_BASE_URL}/api/dashboard/severity-dist?window=7d`);
      const data = await response.json();
      // Handle both array and object responses
      setSeverityDist(Array.isArray(data) ? data : (data.distribution || []));
    } catch (error) {
      console.error('Error fetching severity distribution:', error);
      setSeverityDist([]);
    }
  };

  const fetchTopSourceIPs = async () => {
    try {
      const response = await fetch(`${API_BASE_URL}/api/dashboard/top-source-ips?limit=20&window=7d`);
      const data = await response.json();
      // Handle both array and object responses
      setTopSourceIPs(Array.isArray(data) ? data : (data.top_ips || []));
    } catch (error) {
      console.error('Error fetching top source IPs:', error);
      setTopSourceIPs([]);
    }
  };

  const fetchUebaUserRisk = async () => {
    try {
      const response = await fetch(`${API_BASE_URL}/api/dashboard/ueba-user-risk?top=10&window=7d`);
      const data = await response.json();
      // Handle both array and object responses
      setUebaUserRisks(Array.isArray(data) ? data : (data.user_risks || []));
    } catch (error) {
      console.error('Error fetching UEBA user risk:', error);
      setUebaUserRisks([]);
    }
  };

  const fetchHoneytokenHeatmap = async () => {
    try {
      const response = await fetch(`${API_BASE_URL}/api/dashboard/honeytoken-heatmap?window=7d`);
      const data = await response.json();
      // Handle both array and object responses
      setHoneytokenHeatmap(Array.isArray(data) ? data : (data.heatmap || []));
    } catch (error) {
      console.error('Error fetching honeytoken heatmap:', error);
    }
  };

  const fetchFeatureImportance = async () => {
    try {
      const response = await fetch(`${API_BASE_URL}/api/dashboard/feature-importance?model=Ensemble`);
      const data = await response.json();
      setFeatureImportance(data.features || []);
    } catch (error) {
      console.error('Error fetching feature importance:', error);
    }
  };

  const fetchModelMetricsDashboard = async () => {
    try {
      const response = await fetch(`${API_BASE_URL}/api/dashboard/model-metrics?model=Ensemble`);
      const data = await response.json();
      setModelMetricsData(data.metrics || null);
    } catch (error) {
      console.error('Error fetching model metrics:', error);
    }
  };

  const handlePlantHoneytoken = async () => {
    try {
      const payload: any = {
        token_type: plantForm.token_type,
        location: plantForm.location,
        severity: plantForm.severity
      };
      
      if (plantForm.attack_type) {
        payload.attack_type = plantForm.attack_type;
      }
      
      const response = await fetch(`${API_BASE_URL}/api/honeytokens/plant`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      
      if (response.ok) {
        const data = await response.json();
        fetchHoneytokens();
        setShowPlantModal(false);
        setPlantForm({ token_type: 'credential', location: '/etc/passwd', severity: 'HIGH', attack_type: '' });
        alert(`Honeytoken planted successfully!${data.attack_type ? ` (Targeting ${data.attack_type} attacks)` : ''}`);
      } else {
        const error = await response.json();
        alert(`Error: ${error.error || 'Failed to plant honeytoken'}`);
      }
    } catch (error) {
      console.error('Error planting honeytoken:', error);
      alert('Error planting honeytoken. Please try again.');
    }
  };

  const sendChatMessage = async () => {
    if (!chatInput.trim()) return;

    const userMessage = chatInput;
    setChatInput('');

    try {
      const response = await fetch(`${API_BASE_URL}/api/chat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: userMessage })
      });
      const data = await response.json();
      
      setChatResponses([...chatResponses, {
        user: userMessage,
        bot: data.response,
        timestamp: new Date().toLocaleTimeString()
      }]);
    } catch (error) {
      console.error('Error sending chat message:', error);
      setChatResponses([...chatResponses, {
        user: userMessage,
        bot: 'Sorry, I encountered an error. Please try again.',
        timestamp: new Date().toLocaleTimeString()
      }]);
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'HIGH': return '#dc3545';
      case 'MEDIUM': return '#ffc107';
      case 'LOW': return '#17a2b8';
      default: return '#6c757d';
    }
  };

  // Chart configurations
  const threatTrendsChart = {
    labels: trends.map(t => new Date(t.timestamp).toLocaleTimeString()),
    datasets: [
      {
        label: 'Threats Detected',
        data: trends.map(t => t.threats_detected),
        borderColor: 'rgb(220, 53, 69)',
        backgroundColor: 'rgba(220, 53, 69, 0.1)',
        fill: true,
        tension: 0.4,
      },
      {
        label: 'Honeytoken Breaches',
        data: trends.map(t => t.honeytoken_breaches),
        borderColor: 'rgb(255, 193, 7)',
        backgroundColor: 'rgba(255, 193, 7, 0.1)',
        fill: true,
        tension: 0.4,
      },
      {
        label: 'Total Events',
        data: trends.map(t => t.total_events),
        borderColor: 'rgb(40, 167, 69)',
        backgroundColor: 'rgba(40, 167, 69, 0.1)',
        fill: true,
        tension: 0.4,
      }
    ]
  };

  const severityDistribution = {
    labels: ['HIGH', 'MEDIUM', 'LOW'],
    datasets: [{
      data: [
        alerts.filter(a => a.severity === 'HIGH').length,
        alerts.filter(a => a.severity === 'MEDIUM').length,
        alerts.filter(a => a.severity === 'LOW').length
      ],
      backgroundColor: [
        'rgba(220, 53, 69, 0.8)',
        'rgba(255, 193, 7, 0.8)',
        'rgba(40, 167, 69, 0.8)'
      ],
      borderColor: [
        'rgb(220, 53, 69)',
        'rgb(255, 193, 7)',
        'rgb(40, 167, 69)'
      ],
      borderWidth: 2
    }]
  };

  const modelPerformanceChart = metrics?.models ? {
    labels: ['Accuracy', 'Precision', 'Recall', 'F1-Score', 'ROC-AUC'],
    datasets: [
      {
        label: 'Random Forest',
        data: [
          metrics.models.RandomForest?.accuracy || 0,
          metrics.models.RandomForest?.precision || 0,
          metrics.models.RandomForest?.recall || 0,
          metrics.models.RandomForest?.f1_score || 0,
          metrics.models.RandomForest?.roc_auc || 0
        ],
        backgroundColor: 'rgba(102, 126, 234, 0.2)',
        borderColor: 'rgb(102, 126, 234)',
        borderWidth: 2
      },
      {
        label: 'Gradient Boosting',
        data: [
          metrics.models.GradientBoosting?.accuracy || 0,
          metrics.models.GradientBoosting?.precision || 0,
          metrics.models.GradientBoosting?.recall || 0,
          metrics.models.GradientBoosting?.f1_score || 0,
          metrics.models.GradientBoosting?.roc_auc || 0
        ],
        backgroundColor: 'rgba(118, 75, 162, 0.2)',
        borderColor: 'rgb(118, 75, 162)',
        borderWidth: 2
      }
    ]
  } : null;

  if (loading && trends.length === 0) {
    return (
      <div className="loading-container">
        <div className="spinner"></div>
        <p>Loading dashboard...</p>
      </div>
    );
  }

  return (
    <div className="dashboard-container">
      {/* Header */}
      <header className="dashboard-header">
        <div className="header-left">
          <h1>🛡️ KAVACH Dashboard</h1>
          <span className="status-badge pulse">Live</span>
        </div>
        <div className="header-right">
          <ThemeToggle />
          <span className="user-info">Welcome, {user?.username || 'User'}</span>
          <button className="logout-btn" onClick={onLogout}>Logout</button>
        </div>
      </header>

      {/* Navigation Tabs */}
      <nav className="dashboard-nav">
        <button
          className={`nav-tab ${activeTab === 'overview' ? 'active' : ''}`}
          onClick={() => setActiveTab('overview')}
        >
          📊 Overview
        </button>
        <button
          className={`nav-tab ${activeTab === 'threats' ? 'active' : ''}`}
          onClick={() => setActiveTab('threats')}
        >
          ⚠️ Threats
        </button>
        <button
          className={`nav-tab ${activeTab === 'honeytokens' ? 'active' : ''}`}
          onClick={() => setActiveTab('honeytokens')}
        >
          🍯 Honeytokens
        </button>
        <button
          className={`nav-tab ${activeTab === 'metrics' ? 'active' : ''}`}
          onClick={() => setActiveTab('metrics')}
        >
          📈 Metrics
        </button>
        <button
          className={`nav-tab ${activeTab === 'activity' ? 'active' : ''}`}
          onClick={() => setActiveTab('activity')}
        >
          📋 Activity
        </button>
        <button
          className="nav-tab chatbot-tab"
          onClick={() => setShowChatbot(true)}
        >
          💬 AI Assistant
        </button>
      </nav>

      {/* Main Content */}
      <main className="dashboard-main">
        {activeTab === 'overview' && (
          <div className="tab-content fade-in">
            {/* Stats Cards */}
            <div className="stats-grid">
              <div className="stat-card slide-in" style={{ animationDelay: '0.1s' }}>
                <div className="stat-icon">⚠️</div>
                <div className="stat-info">
                  <h3>{statistics?.threats_detected ?? 0}</h3>
                  <p>Detected Threats (24h)</p>
                </div>
              </div>
              <div className="stat-card slide-in" style={{ animationDelay: '0.2s' }}>
                <div className="stat-icon">🔴</div>
                <div className="stat-info">
                  <h3>{severityDist.find?.((d: any) => d.severity === 'HIGH')?.count ?? 0}</h3>
                  <p>High Severity Events</p>
                </div>
              </div>
              <div className="stat-card slide-in" style={{ animationDelay: '0.3s' }}>
                <div className="stat-icon">📊</div>
                <div className="stat-info">
                  <h3>{statistics?.total_events || 0}</h3>
                  <p>Total Events (24h)</p>
                </div>
              </div>
              <div className="stat-card slide-in" style={{ animationDelay: '0.4s' }}>
                <div className="stat-icon">🍯</div>
                <div className="stat-info">
                  <h3>{honeytokenStats?.breach_events ?? 0}</h3>
                  <p>Honeytoken Breach Events</p>
                </div>
              </div>
            </div>

            {/* Live Threat Analysis Chart */}
            <div className="chart-container fade-in">
              <h2>Live Threat Analysis (Last 24 Hours)</h2>
              {trends.length > 0 && (
                <LineChart
                  data={threatTrendsChart}
                  options={{
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                      legend: { position: 'top' },
                      title: { display: false }
                    },
                    scales: {
                      y: { beginAtZero: true }
                    },
                    animation: {
                      duration: 1000,
                      easing: 'easeInOutQuart'
                    }
                  }}
                />
              )}
            </div>

            {/* Quick Alerts */}
            <div className="quick-alerts fade-in">
              <h2>Recent High-Severity Alerts</h2>
              <div className="alerts-list">
                {alerts.filter(a => a.severity === 'HIGH').slice(0, 5).map(alert => (
                  <div key={alert.id} className="alert-item slide-in">
                    <div className="alert-severity" style={{ backgroundColor: getSeverityColor(alert.severity) }}></div>
                    <div className="alert-content">
                      <strong>{alert.type}</strong>
                      <p>{alert.message}</p>
                      <small>{new Date(alert.timestamp).toLocaleString()}</small>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {activeTab === 'threats' && (
          <div className="tab-content fade-in">
            <div className="section-header">
              <h2>Threat Detection & Alerts</h2>
              <button className="refresh-btn" onClick={fetchAllData}>🔄 Refresh</button>
            </div>

            <div className="charts-grid">
              <div className="chart-card">
                <h3>Threat Trends</h3>
                {trends.length > 0 && (
                  <LineChart
                    data={threatTrendsChart}
                    options={{
                      responsive: true,
                      maintainAspectRatio: false,
                      plugins: { legend: { position: 'top' } }
                    }}
                  />
                )}
              </div>
              <div className="chart-card">
                <h3>Severity Distribution</h3>
                <DoughnutChart
                  data={severityDist.length > 0 ? {
                    labels: severityDist.map(d => d.severity),
                    datasets: [{
                      data: severityDist.map(d => d.count),
                      backgroundColor: [
                        'rgba(220, 53, 69, 0.8)',
                        'rgba(255, 193, 7, 0.8)',
                        'rgba(40, 167, 69, 0.8)',
                        'rgba(23, 162, 184, 0.8)'
                      ]
                    }]
                  } : alerts.length > 0 ? severityDistribution : {
                    labels: ['HIGH', 'MEDIUM', 'LOW'],
                    datasets: [{
                      data: [0, 0, 0],
                      backgroundColor: [
                        'rgba(220, 53, 69, 0.8)',
                        'rgba(255, 193, 7, 0.8)',
                        'rgba(40, 167, 69, 0.8)'
                      ]
                    }]
                  }}
                  options={{
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: { legend: { position: 'bottom' } }
                  }}
                />
              </div>
            </div>

            {/* New Panel: Alerts over time by threat_type */}
            <div className="chart-container fade-in">
              <h2>Alerts Over Time by Threat Type</h2>
              {(() => {
                const threatTypes = threatTrendsByType.length > 0 
                  ? uniqStrings(threatTrendsByType.map(t => String(t.threat_type)))
                  : ['No Data'];
                const days = threatTrendsByType.length > 0
                  ? uniqStrings(threatTrendsByType.map(t => String(t.day))).sort()
                  : [new Date().toISOString().split('T')[0]];
                const datasets = threatTypes.map((type, idx) => ({
                  label: type,
                  data: days.map(day => {
                    if (threatTrendsByType.length === 0) return 0;
                    const entry = threatTrendsByType.find(t => t.day === day && t.threat_type === type);
                    return entry ? entry.count : 0;
                  }),
                  borderColor: `hsl(${idx * 60}, 70%, 50%)`,
                  backgroundColor: `hsla(${idx * 60}, 70%, 50%, 0.1)`,
                  fill: true,
                  tension: 0.4
                }));
                return (
                  <LineChart
                    data={{ labels: days, datasets }}
                    options={{
                      responsive: true,
                      maintainAspectRatio: false,
                      plugins: { legend: { position: 'top' } },
                      scales: { y: { beginAtZero: true } }
                    }}
                  />
                );
              })()}
            </div>

            {/* New Panel: Top Attack Types */}
            <div className="chart-container fade-in">
              <h2>Top Attack Types</h2>
              <BarChart
                data={{
                  labels: topAttackTypes.length > 0 
                    ? topAttackTypes.map(a => a.threat_type)
                    : ['No Data'],
                  datasets: [{
                    label: 'Count',
                    data: topAttackTypes.length > 0
                      ? topAttackTypes.map(a => a.count)
                      : [0],
                    backgroundColor: 'rgba(220, 53, 69, 0.8)',
                    borderColor: 'rgb(220, 53, 69)',
                    borderWidth: 1
                  }]
                }}
                options={{
                  indexAxis: 'y',
                  responsive: true,
                  maintainAspectRatio: false,
                  plugins: { legend: { display: false } },
                  scales: { x: { beginAtZero: true } }
                }}
              />
            </div>

            {/* New Panel: Top Source IPs */}
            <div className="chart-container fade-in">
              <h2>Top Source IPs by Event Count</h2>
              <BarChart
                data={{
                  labels: topSourceIPs.length > 0
                    ? topSourceIPs.slice(0, 15).map(ip => ip.source_ip)
                    : ['No Data'],
                  datasets: [{
                    label: 'Events',
                    data: topSourceIPs.length > 0
                      ? topSourceIPs.slice(0, 15).map(ip => ip.events)
                      : [0],
                    backgroundColor: 'rgba(255, 193, 7, 0.8)',
                    borderColor: 'rgb(255, 193, 7)',
                    borderWidth: 1
                  }]
                }}
                options={{
                  indexAxis: 'y',
                  responsive: true,
                  maintainAspectRatio: false,
                  plugins: { legend: { display: false } },
                  scales: { x: { beginAtZero: true } }
                }}
              />
            </div>

            {/* New Panel: UEBA User Risk */}
            <div className="chart-container fade-in">
              <h2>UEBA User Risk (Top Anomalies)</h2>
              <BarChart
                data={{
                  labels: uebaUserRisks.length > 0
                    ? uebaUserRisks.map(u => `${u.user_id} (${u.day})`)
                    : ['No Data'],
                  datasets: [{
                    label: 'Anomalies',
                    data: uebaUserRisks.length > 0
                      ? uebaUserRisks.map(u => u.anomalies)
                      : [0],
                    backgroundColor: 'rgba(118, 75, 162, 0.8)',
                    borderColor: 'rgb(118, 75, 162)',
                    borderWidth: 1
                  }]
                }}
                options={{
                  responsive: true,
                  maintainAspectRatio: false,
                  plugins: { legend: { display: false } },
                  scales: { y: { beginAtZero: true } }
                }}
              />
            </div>

            {/* New Panel: Honeytoken Heatmap (Grouped bars by hour) */}
            <div className="chart-container fade-in">
              <h2>Honeytoken Hits by Hour</h2>
              {(() => {
                const targets = honeytokenHeatmap.length > 0
                  ? uniqStrings(honeytokenHeatmap.map(h => String(h.target)))
                  : ['No Data'];
                const hours = Array.from({ length: 24 }, (_, i) => i);
                const datasets = targets.map((target, idx) => ({
                  label: target,
                  data: hours.map(hour => {
                    if (honeytokenHeatmap.length === 0) return 0;
                    const entry = honeytokenHeatmap.find(ht => ht.target === target && ht.hour === hour);
                    return entry ? entry.count : 0;
                  }),
                  backgroundColor: `hsla(${idx * 40}, 70%, 50%, 0.6)`,
                  borderColor: `hsl(${idx * 40}, 70%, 50%)`,
                  borderWidth: 1
                }));
                return (
                  <BarChart
                    data={{ labels: hours.map(h => `${h}:00`), datasets }}
                    options={{
                      responsive: true,
                      maintainAspectRatio: false,
                      plugins: { legend: { position: 'top' } },
                      scales: {
                        x: { stacked: false },
                        y: { beginAtZero: true, stacked: false }
                      }
                    }}
                  />
                );
              })()}
            </div>

            {/* New Chart Components with API Integration */}
            <div style={{ marginTop: '40px', padding: '20px 0', borderTop: '2px solid var(--border)' }}>
              <h2 style={{ marginBottom: '20px' }}>Threat Analysis Dashboard (API-Driven)</h2>
              <div style={{ display: 'grid', gap: '20px', gridTemplateColumns: 'repeat(auto-fit, minmax(400px, 1fr))' }}>
                <ThreatTrendsCard />
                <TopAttackTypesCard />
                <SeverityDonutCard />
                <TopSourceIPsCard />
                <HoneytokenHourHeatmapCard />
              </div>
            </div>

            <div className="alerts-table-container">
              <h3>All Alerts</h3>
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Timestamp</th>
                    <th>Type</th>
                    <th>Severity</th>
                    <th>Message</th>
                    <th>Source</th>
                  </tr>
                </thead>
                <tbody>
                  {alerts.map(alert => (
                    <tr key={alert.id} className="fade-in">
                      <td>{new Date(alert.timestamp).toLocaleString()}</td>
                      <td>{alert.type}</td>
                      <td>
                        <span className="severity-badge" style={{ backgroundColor: getSeverityColor(alert.severity) }}>
                          {alert.severity}
                        </span>
                      </td>
                      <td>{alert.message}</td>
                      <td>{alert.source || 'N/A'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {activeTab === 'honeytokens' && (
          <div className="tab-content fade-in">
            <div className="section-header">
              <h2>Honeytoken Management</h2>
              <button className="action-btn" onClick={() => setShowPlantModal(true)}>
                ➕ Plant Honeytoken
              </button>
            </div>

            {showPlantModal && (
              <div className="modal-overlay" onClick={() => setShowPlantModal(false)}>
                <div className="modal-content" onClick={(e) => e.stopPropagation()}>
                  <h3>Plant New Honeytoken</h3>
                  <div className="form-group">
                    <label>Token Type:</label>
                    <select 
                      value={plantForm.token_type} 
                      onChange={(e) => setPlantForm({...plantForm, token_type: e.target.value})}
                    >
                      <option value="credential">Credential</option>
                      <option value="file">File</option>
                      <option value="ip">IP Address</option>
                      <option value="url">URL</option>
                    </select>
                  </div>
                  <div className="form-group">
                    <label>Location:</label>
                    <input 
                      type="text" 
                      value={plantForm.location}
                      onChange={(e) => setPlantForm({...plantForm, location: e.target.value})}
                      placeholder="/etc/passwd"
                    />
                  </div>
                  <div className="form-group">
                    <label>Target Attack Type (Optional):</label>
                    <select 
                      value={plantForm.attack_type} 
                      onChange={(e) => setPlantForm({...plantForm, attack_type: e.target.value})}
                    >
                      <option value="">None (Generic)</option>
                      {attackTypes.filter(a => a).map(attack => (
                        <option key={attack} value={attack}>{attack}</option>
                      ))}
                    </select>
                    <small style={{color: 'var(--muted)', display: 'block', marginTop: '5px'}}>
                      Select an attack type to create a targeted honeytoken
                    </small>
                  </div>
                  <div className="form-group">
                    <label>Severity:</label>
                    <select 
                      value={plantForm.severity} 
                      onChange={(e) => setPlantForm({...plantForm, severity: e.target.value})}
                    >
                      <option value="LOW">LOW</option>
                      <option value="MEDIUM">MEDIUM</option>
                      <option value="HIGH">HIGH</option>
                      <option value="CRITICAL">CRITICAL</option>
                    </select>
                  </div>
                  <div className="modal-actions">
                    <button className="action-btn" onClick={handlePlantHoneytoken}>
                      Plant Honeytoken
                    </button>
                    <button className="logout-btn" onClick={() => setShowPlantModal(false)}>
                      Cancel
                    </button>
                  </div>
                </div>
              </div>
            )}

            <div className="honeytokens-grid">
              {honeytokens.map(token => {
                const metadata = (token as any).metadata || {};
                const attackType = metadata.attack_type || metadata.target_attack;
                return (
                  <div key={token.id} className="honeytoken-card slide-in">
                    <div className={`token-status ${token.accessed ? 'breached' : 'active'}`}>
                      {token.accessed ? '🔴 BREACHED' : '🟢 ACTIVE'}
                    </div>
                    <h4>{token.type.toUpperCase()}</h4>
                    {attackType && (
                      <div style={{background: 'rgba(102, 126, 234, 0.1)', padding: '5px 10px', borderRadius: '5px', marginBottom: '10px', fontSize: '0.9em'}}>
                        🎯 Targeting: <strong>{attackType}</strong>
                      </div>
                    )}
                    <p><strong>Location:</strong> {token.location}</p>
                    <p><strong>Planted:</strong> {new Date(token.planted_at).toLocaleString()}</p>
                    <p><strong>Severity:</strong> {token.severity}</p>
                    {token.accessed && (
                      <div className="breach-alert">⚠️ This honeytoken has been accessed!</div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {activeTab === 'metrics' && (
          <div className="tab-content fade-in">
            <h2>Model Performance Metrics</h2>
            {modelPerformanceChart && (
              <div className="chart-container">
                <RadarChart
                  data={modelPerformanceChart}
                  options={{
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: { legend: { position: 'top' } },
                    scales: {
                      r: { beginAtZero: true, max: 1 }
                    }
                  }}
                />
              </div>
            )}
            {metrics && (
              <div className="metrics-details">
                <div className="metric-card">
                  <h3>Random Forest</h3>
                  <ul>
                    <li>Accuracy: {(metrics.models.RandomForest?.accuracy * 100 || 0).toFixed(2)}%</li>
                    <li>Precision: {(metrics.models.RandomForest?.precision * 100 || 0).toFixed(2)}%</li>
                    <li>Recall: {(metrics.models.RandomForest?.recall * 100 || 0).toFixed(2)}%</li>
                    <li>F1-Score: {(metrics.models.RandomForest?.f1_score * 100 || 0).toFixed(2)}%</li>
                    <li>ROC-AUC: {(metrics.models.RandomForest?.roc_auc * 100 || 0).toFixed(2)}%</li>
                  </ul>
                </div>
                <div className="metric-card">
                  <h3>Gradient Boosting</h3>
                  <ul>
                    <li>Accuracy: {(metrics.models.GradientBoosting?.accuracy * 100 || 0).toFixed(2)}%</li>
                    <li>Precision: {(metrics.models.GradientBoosting?.precision * 100 || 0).toFixed(2)}%</li>
                    <li>Recall: {(metrics.models.GradientBoosting?.recall * 100 || 0).toFixed(2)}%</li>
                    <li>F1-Score: {(metrics.models.GradientBoosting?.f1_score * 100 || 0).toFixed(2)}%</li>
                    <li>ROC-AUC: {(metrics.models.GradientBoosting?.roc_auc * 100 || 0).toFixed(2)}%</li>
                  </ul>
                </div>
              </div>
            )}

            {/* New Panel: Feature Importance */}
            <div className="chart-container fade-in">
              <h2>Feature Importance (Top 20)</h2>
              {featureImportance.length > 0 ? (
                <BarChart
                  data={{
                    labels: featureImportance.map(f => f.feature),
                    datasets: [{
                      label: 'Importance',
                      data: featureImportance.map(f => f.importance),
                      backgroundColor: 'rgba(102, 126, 234, 0.8)',
                      borderColor: 'rgb(102, 126, 234)',
                      borderWidth: 1
                    }]
                  }}
                  options={{
                    indexAxis: 'y',
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: { legend: { display: false } },
                    scales: { x: { beginAtZero: true } }
                  }}
                />
              ) : (
                <p>No feature importance data available</p>
              )}
            </div>

            {/* New Panel: Model Metrics (AUC, F1, Confusion Matrix) */}
            <div className="charts-grid">
              <div className="chart-card">
                <h3>Model Performance (Ensemble)</h3>
                {modelMetricsData ? (
                  <div>
                    <div className="metric-cards-grid">
                      <div className="small-metric-card">
                        <h4>AUC</h4>
                        <p className="metric-value">{(modelMetricsData.roc_auc * 100 || 0).toFixed(2)}%</p>
                      </div>
                      <div className="small-metric-card">
                        <h4>F1 Score</h4>
                        <p className="metric-value">{(modelMetricsData.f1 * 100 || 0).toFixed(2)}%</p>
                      </div>
                      <div className="small-metric-card">
                        <h4>Accuracy</h4>
                        <p className="metric-value">{(modelMetricsData.accuracy * 100 || 0).toFixed(2)}%</p>
                      </div>
                      <div className="small-metric-card">
                        <h4>Precision</h4>
                        <p className="metric-value">{(modelMetricsData.precision * 100 || 0).toFixed(2)}%</p>
                      </div>
                    </div>
                    {modelMetricsData.cm && (
                      <div className="confusion-matrix">
                        <h4>Confusion Matrix</h4>
                        <table className="cm-table">
                          <tbody>
                            <tr>
                              <td className="cm-cell">{modelMetricsData.cm[0]?.[0] || 0}</td>
                              <td className="cm-cell">{modelMetricsData.cm[0]?.[1] || 0}</td>
                            </tr>
                            <tr>
                              <td className="cm-cell">{modelMetricsData.cm[1]?.[0] || 0}</td>
                              <td className="cm-cell">{modelMetricsData.cm[1]?.[1] || 0}</td>
                            </tr>
                          </tbody>
                        </table>
                        <div className="cm-labels">
                          <span>TN</span>
                          <span>FP</span>
                          <span>FN</span>
                          <span>TP</span>
                        </div>
                      </div>
                    )}
                  </div>
                ) : (
                  <p>No model metrics data available</p>
                )}
              </div>
            </div>
          </div>
        )}

        {activeTab === 'activity' && (
          <div className="tab-content fade-in">
            <h2>User Activity Timeline</h2>
            <div className="activity-timeline">
              {timeline.length > 0 ? (
                timeline.map((event, idx) => {
                  const severity = (event as any).severity || (event.risk_score > 0.7 ? 'HIGH' : event.risk_score > 0.4 ? 'MEDIUM' : 'LOW');
                  const threatType = (event as any).threat_type || event.action.split(' ')[0];
                  const getSeverityColor = (sev: string) => {
                    switch(sev) {
                      case 'CRITICAL': return '#dc3545';
                      case 'HIGH': return '#fd7e14';
                      case 'MEDIUM': return '#ffc107';
                      case 'LOW': return '#28a745';
                      default: return '#6c757d';
                    }
                  };
                  
                  return (
                    <div key={idx} className="timeline-item slide-in">
                      <div className="timeline-marker" style={{
                        backgroundColor: event.is_malicious ? '#dc3545' : event.is_anomaly ? '#ffc107' : '#28a745'
                      }}></div>
                      <div className="timeline-content">
                        <div className="timeline-header">
                          <strong>{event.user_id}</strong>
                          <div style={{ display: 'flex', gap: '8px', alignItems: 'center', flexWrap: 'wrap' }}>
                            {(event as any).threat_type && (
                              <span className="risk-badge" style={{
                                backgroundColor: getSeverityColor(severity),
                                fontSize: '0.75em',
                                padding: '3px 8px',
                                borderRadius: '4px',
                                color: 'white',
                                fontWeight: 600
                              }}>
                                {threatType}
                              </span>
                            )}
                            <span className="risk-badge" style={{
                              backgroundColor: event.risk_score > 0.7 ? '#dc3545' : event.risk_score > 0.4 ? '#ffc107' : '#28a745'
                            }}>
                              Risk: {(event.risk_score * 100).toFixed(1)}%
                            </span>
                          </div>
                        </div>
                        <p style={{ fontWeight: 500, marginBottom: '4px', color: 'var(--fg)' }}>{event.action}</p>
                        {(event as any).severity && (
                          <small style={{ color: getSeverityColor(severity), fontWeight: 600, marginRight: '10px' }}>
                            Severity: {severity}
                          </small>
                        )}
                        <br />
                        <small style={{ color: 'var(--muted)' }}>{new Date(event.timestamp).toLocaleString()}</small>
                        {event.source_ip && <small style={{ marginLeft: '10px', color: 'var(--muted)' }}>IP: {event.source_ip}</small>}
                      </div>
                    </div>
                  );
                })
              ) : (
                <div style={{ padding: '20px', textAlign: 'center', color: 'var(--muted)' }}>
                  <p>No activity data available. Events will appear here as they are detected.</p>
                </div>
              )}
            </div>
          </div>
        )}
      </main>

      {/* Enhanced Chatbot */}
      {showChatbot && (
        <div className="chatbot-overlay" onClick={() => setShowChatbot(false)}>
          <div className="chatbot-container" onClick={(e) => e.stopPropagation()}>
            <div className="chatbot-header">
              <h3>🤖 KAVACH AI Assistant</h3>
              <button className="close-btn" onClick={() => setShowChatbot(false)}>×</button>
            </div>
            <div className="chatbot-messages">
              {chatResponses.length === 0 && (
                <div className="welcome-message">
                  <p>👋 Hello! I'm your KAVACH security assistant.</p>
                  <p>I can help you with:</p>
                  <ul>
                    <li>Explaining security alerts</li>
                    <li>Suggesting incident responses</li>
                    <li>Analyzing threat metrics</li>
                    <li>Answering security questions</li>
                  </ul>
                  <p>How can I assist you today?</p>
                </div>
              )}
              {chatResponses.map((msg, idx) => (
                <div key={idx} className="chat-message fade-in">
                  <div className="user-message">
                    <strong>You:</strong> {msg.user}
                    <small>{msg.timestamp}</small>
                  </div>
                  <div className="bot-message">
                    <strong>Assistant:</strong> {msg.bot}
                  </div>
                </div>
              ))}
              <div ref={chatEndRef} />
            </div>
            <div className="chatbot-input">
              <input
                type="text"
                placeholder="Ask about alerts, threats, or security..."
                value={chatInput}
                onChange={(e) => setChatInput(e.target.value)}
                onKeyPress={(e) => e.key === 'Enter' && sendChatMessage()}
              />
              <button onClick={sendChatMessage}>Send</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default Dashboard;

