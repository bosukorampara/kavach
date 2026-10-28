"""
AI Chatbot for Security Operations
Provides alert explanation, incident response suggestions, and system queries
"""

import re
import logging
from typing import Dict, List, Optional
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class SecurityBot:
    """
    AI Chatbot for Security Operations
    Handles queries about alerts, suggests incident responses, explains risk scores
    """
    
    def __init__(self):
        self.intent_patterns = {
            'explain_alert': [
                r'explain.*alert',
                r'what.*alert.*mean',
                r'tell.*alert',
                r'describe.*alert'
            ],
            'suggest_response': [
                r'what.*do',
                r'how.*respond',
                r'suggest.*action',
                r'recommend.*response',
                r'incident.*response',
                r'playbook',
                r'runbook'
            ],
            'query_confidence': [
                r'confidence.*model',
                r'how.*confident',
                r'trust.*prediction',
                r'model.*score'
            ],
            'query_history': [
                r'history.*ip',
                r'activity.*user',
                r'past.*event',
                r'previous.*alert'
            ],
            'query_risk_score': [
                r'risk.*score',
                r'threat.*level',
                r'severity',
                r'how.*dangerous'
            ],
            'query_statistics': [
                r'statistic',
                r'summary',
                r'overall',
                r'total.*event',
                r'how.*many.*threat'
            ],
            'query_metrics': [
                r'metric',
                r'performance',
                r'accuracy',
                r'model.*score',
                r'how.*good.*model'
            ],
            'query_alerts_overview': [
                r'summary.*alert',
                r'alert.*overview',
                r'current.*alerts',
                r'how.*many.*alerts'
            ],
            'query_honeytokens': [
                r'honeytoken',
                r'honeypot',
                r'decoy.*credential',
                r'decoy.*file'
            ],
            'query_trends': [
                r'threat.*trend',
                r'trend.*last',
                r'activity.*trend',
                r'pattern.*last'
            ],
            'query_activity_timeline': [
                r'latest.*events',
                r'recent.*activity',
                r'what.*happening now',
                r'last.*incidents'
            ],
            'general': [
                r'hello',
                r'hi',
                r'help',
                r'capabilities'
            ]
        }
        
        self.alert_explanations = {
            'HONEYTOKEN_BREACH': {
                'description': 'A honeytoken (decoy credential, file, or IP) has been accessed',
                'severity': 'HIGH',
                'meaning': 'An attacker has interacted with a deliberately placed decoy resource. This is a strong indicator of unauthorized activity.',
                'recommended_actions': [
                    'Immediately isolate the affected system',
                    'Review logs for the source of access',
                    'Check for lateral movement attempts',
                    'Notify security team',
                    'Begin incident response procedures'
                ]
            },
            'MALICIOUS_ACTIVITY': {
                'description': 'ML model detected malicious patterns in network traffic',
                'severity': 'HIGH',
                'meaning': 'The Random Forest and Gradient Boosting models have identified anomalous behavior consistent with attack patterns.',
                'recommended_actions': [
                    'Review the specific event details',
                    'Check for data exfiltration',
                    'Verify authentication logs',
                    'Monitor the affected user/device',
                    'Consider quarantining if risk is confirmed'
                ]
            },
            'ANOMALY_DETECTED': {
                'description': 'Unusual behavior pattern detected',
                'severity': 'MEDIUM',
                'meaning': 'Behavior deviates significantly from the user/device baseline. Could indicate compromise or insider threat.',
                'recommended_actions': [
                    'Compare against user baseline profile',
                    'Check for legitimate reasons (business trip, project change)',
                    'Review recent access patterns',
                    'Enhance monitoring for this entity'
                ]
            }
        }
        
        logger.info("SecurityBot initialized")
    
    def process_message(self, message: str, context: Dict = None) -> Dict:
        """
        Process user message and generate response
        """
        # Ensure context is always a dict
        if context is None:
            context = {}
        
        message_lower = message.lower()
        
        # Detect intent
        intent = self._detect_intent(message_lower)
        
        # Get response based on intent
        if intent == 'explain_alert':
            response = self._explain_alert(context.get('alert_type', 'MALICIOUS_ACTIVITY'))
        elif intent == 'suggest_response':
            response = self._suggest_response(context.get('alert_type', 'MALICIOUS_ACTIVITY'))
        elif intent == 'query_confidence':
            response = self._explain_confidence(context.get('prediction', {}))
        elif intent == 'query_statistics':
            response = self._explain_statistics(context.get('statistics', {}))
        elif intent == 'query_metrics':
            response = self._explain_metrics(context.get('model_metrics', {}))
        elif intent == 'query_alerts_overview':
            response = self._summarize_alerts(context.get('alerts', []))
        elif intent == 'query_honeytokens':
            response = self._summarize_honeytokens(context.get('honeytoken_stats', {}))
        elif intent == 'query_trends':
            response = self._summarize_trends(context.get('threat_trends', []))
        elif intent == 'query_activity_timeline':
            response = self._summarize_activity_timeline(context.get('timeline', []))
        elif intent == 'query_history':
            response = self._query_history(message_lower, context)
        elif intent == 'query_risk_score' and context:
            response = self._explain_risk_score(context.get('risk_score', 0.5))
        elif intent == 'general':
            response = self._handle_general(message_lower)
        else:
            response = {
                'message': (
                    "I can help with: alert explanations, incident response suggestions, live alert and trend summaries, "
                    "model confidence queries, statistics, honeytoken status, and activity history. How can I assist?"
                ),
                'intent': 'general'
            }
        
        # Normalize response: allow handler methods to return either a string or a dict
        if isinstance(response, dict):
            message_text = response.get('message', '')
            suggestions = response.get('suggestions', [])
        else:
            # handlers may return plain strings
            message_text = str(response)
            suggestions = []

        return {
            'response': message_text,
            'intent': intent,
            'suggestions': suggestions,
            'timestamp': datetime.now().isoformat()
        }
    
    def _detect_intent(self, message: str) -> str:
        """Detect user intent from message"""
        for intent, patterns in self.intent_patterns.items():
            for pattern in patterns:
                if re.search(pattern, message):
                    return intent
        return 'general'
    
    def _explain_alert(self, alert_type: str) -> Dict:
        """Explain what an alert means"""
        if alert_type in self.alert_explanations:
            explanation = self.alert_explanations[alert_type]
            return {
                'message': f"Alert Type: {alert_type}\n\n"
                          f"Description: {explanation['description']}\n"
                          f"Severity: {explanation['severity']}\n\n"
                          f"What it means: {explanation['meaning']}",
                'suggestions': explanation['recommended_actions']
            }
        return {
            'message': f"Unknown alert type: {alert_type}",
            'suggestions': ['Check the alert details for more information']
        }
    
    def _suggest_response(self, alert_type: str) -> Dict:
        """Suggest incident response actions"""
        if alert_type in self.alert_explanations:
            explanation = self.alert_explanations[alert_type]
            actions = explanation['recommended_actions']
            
            return {
                'message': f"Recommended actions for {alert_type} alert:\n\n"
                          + "\n".join([f"{i+1}. {action}" for i, action in enumerate(actions)]),
                'suggestions': actions
            }
        
        return {
            'message': "General incident response steps:\n"
                       "1. Contain the threat\n"
                       "2. Investigate and analyze\n"
                       "3. Eradicate the threat\n"
                       "4. Recover and restore\n"
                       "5. Document lessons learned",
            'suggestions': ['Contain', 'Investigate', 'Eradicate', 'Recover', 'Document']
        }
    
    def _explain_confidence(self, prediction: Dict) -> str:
        """Explain model confidence"""
        rf_conf = prediction.get('rf_confidence', 0)
        gb_conf = prediction.get('gb_confidence', 0)
        consensus = prediction.get('consensus', False)
        
        avg_conf = (rf_conf + gb_conf) / 2
        
        if consensus:
            msg = f"Both Random Forest and Gradient Boosting models agree on this prediction.\n"
        else:
            msg = f"Models have different predictions.\n"
        
        msg += f"\nRandom Forest confidence: {rf_conf:.2%}\n"
        msg += f"Gradient Boosting confidence: {gb_conf:.2%}\n"
        msg += f"Average confidence: {avg_conf:.2%}"
        
        if avg_conf > 0.8:
            msg += "\n\n✅ High confidence - Strong indication of threat"
        elif avg_conf > 0.5:
            msg += "\n\n⚠️ Medium confidence - Monitor closely"
        else:
            msg += "\n\nℹ️ Low confidence - May be benign"
        
        return msg
    
    def _query_history(self, message: str, context: Dict) -> str:
        """Query activity history"""
        # Extract entity type (IP, user, etc.)
        if 'ip' in message:
            entity_type = 'IP'
        elif 'user' in message:
            entity_type = 'User'
        else:
            entity_type = 'Entity'
        
        return f"I can help you query {entity_type} history. Please provide the specific {entity_type} identifier for detailed activity logs."
    
    def _explain_risk_score(self, risk_score: float) -> str:
        """Explain risk score"""
        if risk_score >= 0.8:
            level = "CRITICAL"
            description = "Immediate action required. High probability of compromise."
        elif risk_score >= 0.6:
            level = "HIGH"
            description = "Significant risk detected. Investigate immediately."
        elif risk_score >= 0.4:
            level = "MEDIUM"
            description = "Potential threat. Monitor and review."
        elif risk_score >= 0.2:
            level = "LOW"
            description = "Minimal risk. May require verification."
        else:
            level = "NORMAL"
            description = "No significant risk detected."
        
        return f"Risk Score: {risk_score:.2f} ({level})\n\n{description}"
    
    def _explain_statistics(self, statistics: Dict) -> Dict:
        """Explain system statistics"""
        total = statistics.get('total_events', 0)
        threats = statistics.get('threats_detected', 0)
        anomalies = statistics.get('anomalies_detected', 0)
        honeytoken_breaches = statistics.get('honeytoken_breaches', 0)
        avg_risk = statistics.get('avg_risk_score', 0.0)
        period = statistics.get('period_hours', 24)
        
        threat_rate = (threats / total * 100) if total > 0 else 0
        
        message = f"System Statistics (Last {period} hours):\n\n"
        message += f"📊 Total Events: {total}\n"
        message += f"⚠️ Threats Detected: {threats} ({threat_rate:.1f}%)\n"
        message += f"🔍 Anomalies Detected: {anomalies}\n"
        message += f"🍯 Honeytoken Breaches: {honeytoken_breaches}\n"
        message += f"📈 Average Risk Score: {avg_risk:.2f}\n\n"
        
        if threat_rate > 10:
            message += "⚠️ High threat rate detected! Review security posture."
        elif threat_rate > 5:
            message += "⚠️ Moderate threat activity. Monitor closely."
        else:
            message += "✅ Low threat activity. System appears secure."
        
        return {'message': message}
    
    def _explain_metrics(self, metrics: Dict) -> Dict:
        """Explain model performance metrics"""
        message = "Model Performance Metrics:\n\n"
        
        if 'RandomForest' in metrics:
            rf = metrics['RandomForest']
            message += "🌲 Random Forest:\n"
            message += f"   Accuracy: {rf.get('accuracy', 0):.2%}\n"
            message += f"   Precision: {rf.get('precision', 0):.2%}\n"
            message += f"   Recall: {rf.get('recall', 0):.2%}\n"
            message += f"   F1-Score: {rf.get('f1_score', 0):.2%}\n"
            message += f"   ROC-AUC: {rf.get('roc_auc', 0):.2%}\n\n"
        
        if 'GradientBoosting' in metrics:
            gb = metrics['GradientBoosting']
            message += "📈 Gradient Boosting:\n"
            message += f"   Accuracy: {gb.get('accuracy', 0):.2%}\n"
            message += f"   Precision: {gb.get('precision', 0):.2%}\n"
            message += f"   Recall: {gb.get('recall', 0):.2%}\n"
            message += f"   F1-Score: {gb.get('f1_score', 0):.2%}\n"
            message += f"   ROC-AUC: {gb.get('roc_auc', 0):.2%}\n\n"
        
        message += "✅ Models are performing well with high accuracy and low false positive rates."
        
        return {'message': message}
    
    def _summarize_alerts(self, alerts: List[Dict]) -> Dict:
        """Summarize current alerts from live system data"""
        total = len(alerts)
        high = sum(1 for a in alerts if a.get('severity') == 'HIGH')
        medium = sum(1 for a in alerts if a.get('severity') == 'MEDIUM')
        low = sum(1 for a in alerts if a.get('severity') == 'LOW')
        
        message = "Current Alert Overview:\n\n"
        message += f"• Total alerts: {total}\n"
        message += f"• HIGH severity: {high}\n"
        message += f"• MEDIUM severity: {medium}\n"
        message += f"• LOW severity: {low}\n"
        
        if alerts:
            latest = alerts[-1]
            ts = latest.get('timestamp')
            ts_str = ts if isinstance(ts, str) else str(ts)
            message += "\nMost recent alert:\n"
            message += f"  • Type: {latest.get('type', 'UNKNOWN')}\n"
            message += f"  • Severity: {latest.get('severity', 'UNKNOWN')}\n"
            message += f"  • Time: {ts_str}\n"
            if latest.get('message'):
                message += f"  • Message: {latest.get('message')}\n"
        
        return {'message': message}
    
    def _summarize_honeytokens(self, stats: Dict) -> Dict:
        """Summarize honeytoken / deception-layer status"""
        total = stats.get('total_tokens', 0)
        accessed = stats.get('tokens_accessed', 0)
        active = stats.get('tokens_active', 0)
        breaches = stats.get('breach_events', 0)
        breach_rate = stats.get('breach_rate', 0.0)
        
        message = "Honeytoken / Deception Layer Status:\n\n"
        message += f"• Total honeytokens planted: {total}\n"
        message += f"• Active (unaccessed) tokens: {active}\n"
        message += f"• Tokens accessed at least once: {accessed}\n"
        message += f"• Honeytoken breach events: {breaches}\n"
        message += f"• Breach rate: {breach_rate:.2f}%\n\n"
        
        if breaches > 0:
            message += "⚠️ At least one decoy resource has been touched. Investigate the corresponding sources and sessions.\n"
        else:
            message += "✅ No honeytoken breaches observed so far.\n"
        
        return {'message': message}
    
    def _summarize_trends(self, trends: List[Dict]) -> Dict:
        """Summarize recent threat trends (last 24h or 7d)"""
        if not trends:
            return {'message': "No threat trend data is available yet."}
        
        # Use last N buckets to describe current situation
        sorted_trends = sorted(trends, key=lambda t: t.get('timestamp', ''))
        recent = sorted_trends[-3:]
        
        total_events = sum(t.get('total_events', 0) for t in recent)
        total_threats = sum(t.get('threats_detected', 0) for t in recent)
        total_honey = sum(t.get('honeytoken_breaches', 0) for t in recent)
        
        message = "Recent Threat Trends (most recent time buckets):\n\n"
        for t in recent:
            ts = t.get('timestamp')
            ts_str = ts if isinstance(ts, str) else str(ts)
            message += (
                f"• {ts_str}: events={t.get('total_events', 0)}, "
                f"threats={t.get('threats_detected', 0)}, "
                f"honeytoken breaches={t.get('honeytoken_breaches', 0)}\n"
            )
        
        message += "\nSummary (last few buckets):\n"
        message += f"• Total events: {total_events}\n"
        message += f"• Total threats: {total_threats}\n"
        message += f"• Honeytoken breaches: {total_honey}\n"
        
        return {'message': message}
    
    def _summarize_activity_timeline(self, timeline: List[Dict]) -> Dict:
        """Summarize most recent high-risk events from the activity timeline"""
        if not timeline:
            return {'message': "No recent activity found in the timeline."}
        
        # Take top N by risk_score
        sorted_events = sorted(
            timeline,
            key=lambda e: float(e.get('risk_score', 0.0)),
            reverse=True
        )
        top = sorted_events[:5]
        
        message = "Recent High-Risk Activity:\n\n"
        for evt in top:
            ts = evt.get('timestamp')
            ts_str = ts if isinstance(ts, str) else str(ts)
            risk = float(evt.get('risk_score', 0.0)) * 100.0
            user_id = evt.get('user_id', 'unknown')
            action = evt.get('action', 'unknown activity')
            src_ip = evt.get('source_ip', 'unknown')
            severity = evt.get('severity', 'UNKNOWN')
            
            message += (
                f"• [{ts_str}] user={user_id}, ip={src_ip}\n"
                f"   Action: {action} (severity={severity}, risk={risk:.1f}%)\n"
            )
        
        message += "\nThese are the top recent events by risk score from the activity timeline."
        return {'message': message}
    
    def _handle_general(self, message: str) -> Dict:
        """Handle general queries"""
        responses = {
            'hello': "Hello! I'm your security assistant. I can help explain alerts, suggest responses, and answer questions about threat detection.",
            'hi': "Hi there! How can I help you with security operations today?",
            'help': "I can assist with:\n"
                   "• Explaining security alerts\n"
                   "• Suggesting incident response actions\n"
                   "• Analyzing model confidence scores\n"
                   "• Querying activity history\n"
                   "• Interpreting risk scores\n"
                   "• System statistics\n"
                   "• Model performance metrics",
            'capabilities': "My capabilities include:\n"
                           "1. Alert explanation - Understand what alerts mean\n"
                           "2. Incident response - Get recommended actions\n"
                           "3. Model confidence - Check prediction reliability\n"
                           "4. Activity history - Query past events\n"
                           "5. Risk assessment - Interpret risk scores\n"
                           "6. System statistics - Get overall system status\n"
                           "7. Model metrics - Check ML model performance"
        }
        
        for key, response in responses.items():
            if key in message:
                return {'message': response}
        
        return {
            'message': "I'm here to help with security operations. Ask me about alerts, incident response, statistics, or system queries."
        }

