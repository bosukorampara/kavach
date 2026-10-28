/**
 * KAVACH Enhanced Dashboard Component
 * Displays threat trends, activity timeline, and alerts
 */

import React, { useState, useEffect } from 'react';
import { Line, Bar, Doughnut } from 'react-chartjs-2';
import {
  Card,
  CardBody,
  CardHeader,
  Col,
  Row,
  Table,
  Badge,
  Button,
  Modal,
  ModalHeader,
  ModalBody,
  ModalFooter
} from 'reactstrap';

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
  threats_detected: number;
  false_positives: number;
  honeytoken_breaches: number;
}

interface ActivityEvent {
  timestamp: string;
  user_id: string;
  action: string;
  risk_score: number;
}

const KavachDashboard: React.FC = () => {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [trends, setTrends] = useState<ThreatTrend[]>([]);
  const [timeline, setTimeline] = useState<ActivityEvent[]>([]);
  const [showChatbot, setShowChatbot] = useState(false);
  const [chatInput, setChatInput] = useState('');
  const [chatResponses, setChatResponses] = useState<Array<{user: string; bot: string}>>([]);

  useEffect(() => {
    fetchAlerts();
    fetchThreatTrends();
    fetchActivityTimeline();
    
    // Refresh every 30 seconds
    const interval = setInterval(() => {
      fetchAlerts();
      fetchThreatTrends();
      fetchActivityTimeline();
    }, 30000);

    return () => clearInterval(interval);
  }, []);

  // Default to 5001 (backend auto-switched to 5001 if 5000 is in use); can be overridden with REACT_APP_API_URL
  const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:5001';

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
      const response = await fetch(`${API_BASE_URL}/api/threat-trends`);
      const data = await response.json();
      setTrends(data.trends || []);
    } catch (error) {
      console.error('Error fetching trends:', error);
    }
  };

  const fetchActivityTimeline = async () => {
    try {
      const response = await fetch(`${API_BASE_URL}/api/activity-timeline`);
      const data = await response.json();
      setTimeline(data.timeline || []);
    } catch (error) {
      console.error('Error fetching timeline:', error);
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'HIGH':
        return 'danger';
      case 'MEDIUM':
        return 'warning';
      case 'LOW':
        return 'info';
      default:
        return 'secondary';
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
        bot: data.response
      }]);
    } catch (error) {
      console.error('Error sending chat message:', error);
    }
  };

  const threatTrendsChart = {
    labels: trends.map(t => new Date(t.timestamp).toLocaleTimeString()),
    datasets: [
      {
        label: 'Threats Detected',
        data: trends.map(t => t.threats_detected),
        borderColor: 'rgb(220, 53, 69)',
        backgroundColor: 'rgba(220, 53, 69, 0.2)',
      },
      {
        label: 'Honeytoken Breaches',
        data: trends.map(t => t.honeytoken_breaches),
        borderColor: 'rgb(255, 193, 7)',
        backgroundColor: 'rgba(255, 193, 7, 0.2)',
      }
    ]
  };

  // Build a 'Risk Over Time' chart derived from activity timeline (average risk per timestamp)
  const riskOverTimeData = React.useMemo(() => {
    if (!timeline || timeline.length === 0) return null;

    // Group by hour label
    const groups: Record<string, {sum: number; count: number}> = {};
    timeline.forEach(evt => {
      try {
        const d = new Date(evt.timestamp);
        const label = d.toISOString().slice(0,13) + ':00'; // hourly bucket
        const r = Number(evt.risk_score) || 0;
        if (!groups[label]) groups[label] = { sum: 0, count: 0 };
        groups[label].sum += r;
        groups[label].count += 1;
      } catch (e) {
        // ignore parse errors
      }
    });

    const labels = Object.keys(groups).sort();
    const values = labels.map(l => groups[l].count ? (groups[l].sum / groups[l].count) : 0);

    return {
      labels: labels.map(l => new Date(l).toLocaleString()),
      datasets: [
        {
          label: 'Average Risk Score',
          data: values.map(v => v * 100),
          borderColor: 'rgba(102, 126, 234, 1)',
          backgroundColor: 'rgba(102, 126, 234, 0.2)',
          fill: true,
          tension: 0.2
        }
      ]
    };
  }, [timeline]);

  const severityDistribution = {
    labels: ['HIGH', 'MEDIUM', 'LOW'],
    datasets: [{
      data: [
        alerts.filter(a => a.severity === 'HIGH').length,
        alerts.filter(a => a.severity === 'MEDIUM').length,
        alerts.filter(a => a.severity === 'LOW').length
      ],
      backgroundColor: [
        'rgba(220, 53, 69, 0.6)',
        'rgba(255, 193, 7, 0.6)',
        'rgba(40, 167, 69, 0.6)'
      ]
    }]
  };

  return (
    <div className="kavach-dashboard" style={{ fontFamily: "Inter, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial" }}>
      <Row>
        <Col md="12">
          <Card style={{ borderRadius: 12, overflow: 'hidden' }}>
            <div style={{
              padding: '18px 24px',
              background: 'linear-gradient(90deg, rgba(102,126,234,1) 0%, rgba(118,75,162,1) 100%)',
              color: 'white'
            }}>
              <h2 style={{ margin: 0, fontWeight: 700 }}>🛡️ KAVACH</h2>
              <div style={{ opacity: 0.92 }}>Threat Detection Dashboard</div>
            </div>
            <CardBody style={{ background: '#f7fafc' }}>
              <Row>
                <Col md="3">
                  <Card className="text-center">
                    <CardBody>
                      <h4 style={{ fontSize: 28, marginBottom: 6 }}>{alerts.length}</h4>
                      <p style={{ margin: 0, color: '#6b7280' }}>Active Alerts</p>
                    </CardBody>
                  </Card>
                </Col>
                <Col md="3">
                  <Card className="text-center">
                    <CardBody>
                      <h4 style={{ fontSize: 28, marginBottom: 6 }}>{alerts.filter(a => a.severity === 'HIGH').length}</h4>
                      <p style={{ margin: 0, color: '#6b7280' }}>High Severity</p>
                    </CardBody>
                  </Card>
                </Col>
                <Col md="3">
                  <Card className="text-center">
                    <CardBody>
                      <h4 style={{ fontSize: 28, marginBottom: 6 }}>{timeline.length}</h4>
                      <p style={{ margin: 0, color: '#6b7280' }}>Recent Events</p>
                    </CardBody>
                  </Card>
                </Col>
                <Col md="3">
                  <Card className="text-center">
                    <CardBody>
                      <Button color="primary" onClick={() => setShowChatbot(true)}>
                        <i className="fas fa-robot" /> Chat Assistant
                      </Button>
                    </CardBody>
                  </Card>
                </Col>
              </Row>
            </CardBody>
          </Card>
        </Col>
      </Row>

      <Row style={{ marginTop: 12 }}>
        <Col md="4">
          <Card>
            <CardHeader>Quick Test Suite</CardHeader>
            <CardBody>
              <p style={{ marginBottom: 8 }}>Test file: <code>test_api.py</code></p>
              <p style={{ marginBottom: 12, color: '#6b7280' }}>Run from project root after starting the backend:</p>
              <pre style={{ background: '#f3f4f6', padding: 8, borderRadius: 6 }}>python test_api.py</pre>
              <p style={{ marginTop: 8 }}>This script runs health, predict, honeytoken and metrics checks against the API.</p>
            </CardBody>
          </Card>
        </Col>
      </Row>

      <Row>
        <Col md="8">
          <Card>
            <CardHeader>Threat Trends & Risk Over Time</CardHeader>
            <CardBody>
              <div style={{ display: 'flex', gap: 12 }}>
                <div style={{ flex: 1 }}>
                  {trends.length > 0 && (
                    <Line data={threatTrendsChart} options={{ responsive: true }} />
                  )}
                </div>
                <div style={{ width: 280 }}>
                  {riskOverTimeData ? (
                    <Card style={{ padding: 12, borderRadius: 8 }}>
                      <h6 style={{ marginTop: 0 }}>Risk (avg) by Hour</h6>
                      <div style={{ height: 160 }}>
                        <Line data={riskOverTimeData} options={{ responsive: true, plugins: { legend: { display: false } }, scales: { y: { max: 100 } } }} />
                      </div>
                    </Card>
                  ) : (
                    <div style={{ color: '#6b7280' }}>No risk timeline available</div>
                  )}
                </div>
              </div>
            </CardBody>
          </Card>
        </Col>
        <Col md="4">
          <Card>
            <CardHeader>Alert Severity Distribution</CardHeader>
            <CardBody>
              {alerts.length > 0 && (
                <Doughnut data={severityDistribution} options={{ responsive: true }} />
              )}
            </CardBody>
          </Card>
        </Col>
      </Row>

      <Row>
        <Col md="12">
          <Card>
            <CardHeader>Recent Alerts</CardHeader>
            <CardBody>
              <Table striped hover>
                <thead>
                  <tr>
                    <th>Timestamp</th>
                    <th>Type</th>
                    <th>Severity</th>
                    <th>Message</th>
                  </tr>
                </thead>
                <tbody>
                  {alerts.slice(0, 10).map(alert => (
                    <tr key={alert.id}>
                      <td>{new Date(alert.timestamp).toLocaleString()}</td>
                      <td>{alert.type}</td>
                      <td>
                        <Badge color={getSeverityColor(alert.severity)}>
                          {alert.severity}
                        </Badge>
                      </td>
                      <td>{alert.message}</td>
                    </tr>
                  ))}
                </tbody>
              </Table>
            </CardBody>
          </Card>
        </Col>
      </Row>

      <Row>
        <Col md="12">
          <Card>
            <CardHeader>User Activity Timeline</CardHeader>
            <CardBody>
              <Table striped hover>
                <thead>
                  <tr>
                    <th>Timestamp</th>
                    <th>User</th>
                    <th>Action</th>
                    <th>Risk Score</th>
                  </tr>
                </thead>
                <tbody>
                  {timeline.slice(0, 20).map((event, idx) => (
                    <tr key={idx}>
                      <td>{new Date(event.timestamp).toLocaleString()}</td>
                      <td>{event.user_id}</td>
                      <td>{event.action}</td>
                      <td>
                        <Badge color={event.risk_score > 0.7 ? 'danger' : event.risk_score > 0.4 ? 'warning' : 'success'}>
                          {(event.risk_score * 100).toFixed(1)}%
                        </Badge>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </Table>
            </CardBody>
          </Card>
        </Col>
      </Row>

      {/* Chatbot Modal */}
      <Modal isOpen={showChatbot} toggle={() => setShowChatbot(false)}>
        <ModalHeader toggle={() => setShowChatbot(false)}>
          KAVACH AI Assistant
        </ModalHeader>
        <ModalBody>
          <div style={{ maxHeight: '400px', overflowY: 'auto', marginBottom: '20px' }}>
            {chatResponses.map((msg, idx) => (
              <div key={idx} style={{ marginBottom: '10px' }}>
                <strong>You:</strong> {msg.user}
                <br />
                <strong>Bot:</strong> {msg.bot}
              </div>
            ))}
          </div>
          <input
            type="text"
            className="form-control"
            placeholder="Ask a question about alerts, threats, or incidents..."
            value={chatInput}
            onChange={(e) => setChatInput(e.target.value)}
            onKeyPress={(e) => e.key === 'Enter' && sendChatMessage()}
          />
        </ModalBody>
        <ModalFooter>
          <Button color="primary" onClick={sendChatMessage}>Send</Button>
          <Button color="secondary" onClick={() => setShowChatbot(false)}>Close</Button>
        </ModalFooter>
      </Modal>
    </div>
  );
};

export default KavachDashboard;

