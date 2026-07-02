"""
Threat Intelligence Service
Central orchestration of threat analysis
"""

from typing import Dict, Optional
from datetime import datetime
from backend.intelligence.threat_reporter import ThreatReporter
from backend.storage.nids_store import nids_db


class ThreatIntelligenceService:
    """Orchestrates threat intelligence analysis"""
    
    def __init__(self):
        self.reporter = ThreatReporter()
        self.generated_reports: Dict[str, Dict] = {}
    
    def analyze_alert(self, alert: Dict) -> Dict:
        """
        Generate threat analysis for alert
        
        Input: Alert from Fusion Engine
        Output: Complete threat analysis report
        """
        
        # Generate comprehensive report
        report = self.reporter.generate_report(alert)
        
        # Store report
        self.generated_reports[alert.get("incident_id")] = report
        
        # Enrich alert with threat intelligence
        enriched_alert = self._enrich_alert(alert, report)
        
        # Store enriched alert
        self._store_threat_report(enriched_alert, report)
        
        return report
    
    def _enrich_alert(self, alert: Dict, report: Dict) -> Dict:
        """Add threat intelligence to alert"""
        
        alert["threat_intelligence"] = report
        alert["enriched_at"] = datetime.utcnow().isoformat()
        
        return alert
    
    def _store_threat_report(self, alert: Dict, report: Dict):
        """Store threat report in database"""
        
        try:
            # Store as part of alert
            import json
            alert_data = alert.copy()
            alert_data["threat_report_json"] = json.dumps(report)
            
            nids_db.insert_alert(alert_data)
        except Exception as e:
            print(f"[Threat Intel] Error storing report: {e}")
    
    def get_report(self, incident_id: str) -> Optional[Dict]:
        """Retrieve threat report by incident ID"""
        return self.generated_reports.get(incident_id)
    
    def export_report(self, incident_id: str, format: str = "json") -> Optional[str]:
        """Export threat report in specified format"""
        
        report = self.get_report(incident_id)
        if not report:
            return None
        
        if format == "json":
            import json
            return json.dumps(report, indent=2)
        
        elif format == "text":
            return self._format_as_text(report)
        
        elif format == "html":
            return self._format_as_html(report)
        
        return None
    
    def _format_as_text(self, report: Dict) -> str:
        """Format report as plaintext"""
        
        text = "=" * 80 + "\n"
        text += "THREAT INTELLIGENCE REPORT\n"
        text += f"Report ID: {report.get('report_id')}\n"
        text += f"Generated: {report.get('timestamp')}\n"
        text += "=" * 80 + "\n\n"
        
        # Attack section
        attack = report.get("attack", {})
        text += "ATTACK INFORMATION\n"
        text += "-" * 80 + "\n"
        text += f"Type: {attack.get('type')}\n"
        text += f"Severity: {attack.get('severity')}\n"
        text += f"Description: {attack.get('description')}\n"
        text += f"Decision: {attack.get('decision')}\n\n"
        
        # MITRE information
        mitre = attack.get("mitre", {})
        if mitre:
            text += "MITRE ATT&CK MAPPING\n"
            text += "-" * 80 + "\n"
            text += f"Techniques: {', '.join(mitre.get('techniques', []))}\n"
            text += f"Tactics: {', '.join(mitre.get('tactics', []))}\n\n"
        
        # Evidence section
        evidence = report.get("evidence", {})
        if evidence.get("network_detection"):
            text += "NETWORK EVIDENCE\n"
            text += "-" * 80 + "\n"
            for key, value in evidence["network_detection"].items():
                text += f"  {key}: {value}\n"
            text += "\n"
        
        # Risk section
        risk = report.get("risk", {})
        if risk.get("overall_risk"):
            text += "RISK ASSESSMENT\n"
            text += "-" * 80 + "\n"
            overall = risk["overall_risk"]
            text += f"Risk Level: {overall.get('level')}\n"
            text += f"Priority: {overall.get('priority')}\n\n"
        
        # Response section
        response = report.get("response", {})
        if response.get("immediate_actions"):
            text += "RECOMMENDED RESPONSE\n"
            text += "-" * 80 + "\n"
            text += "IMMEDIATE ACTIONS:\n"
            for action in response["immediate_actions"]:
                text += f"  - {action}\n"
            text += "\n"
        
        return text
    
    def _format_as_html(self, report: Dict) -> str:
        """Format report as HTML"""
        
        html = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Threat Intelligence Report</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                h1 { color: #333; }
                h2 { color: #666; border-bottom: 2px solid #007bff; padding-bottom: 5px; }
                .critical { color: #d9534f; font-weight: bold; }
                .high { color: #f0ad4e; font-weight: bold; }
                table { border-collapse: collapse; width: 100%; margin: 10px 0; }
                th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                th { background-color: #f5f5f5; }
            </style>
        </head>
        <body>
        """
        
        html += f"<h1>Threat Intelligence Report</h1>\n"
        html += f"<p><strong>Report ID:</strong> {report.get('report_id')}</p>\n"
        html += f"<p><strong>Generated:</strong> {report.get('timestamp')}</p>\n"
        
        # Attack info
        attack = report.get("attack", {})
        html += f"<h2>Attack Information</h2>\n"
        html += f"<p><strong>Type:</strong> {attack.get('type')}</p>\n"
        html += f"<p><strong>Severity:</strong> <span class='{attack.get('severity', '').lower()}'>{attack.get('severity')}</span></p>\n"
        html += f"<p><strong>Description:</strong> {attack.get('description')}</p>\n"
        
        html += """
        </body>
        </html>
        """
        
        return html
    
    def search_iocs(self, ioc_value: str) -> Optional[Dict]:
        """Search for related incidents by IOC"""
        
        # This would search database for incidents with matching IOCs
        # Placeholder implementation
        return None
    
    def get_threat_history(self, source_ip: str = None, 
                         username: str = None) -> list:
        """Get historical threats for given indicators"""
        
        # This would query database for related incidents
        # Placeholder implementation
        return []


# Global instance
threat_intel_service = ThreatIntelligenceService()