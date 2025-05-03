from datetime import datetime
from extensions import db

class PhishingURL(db.Model):
    """Model for storing detected phishing URLs"""
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(2048), nullable=False, index=True, unique=True)
    is_phishing = db.Column(db.Boolean, nullable=False)
    ml_confidence = db.Column(db.Float)
    virustotal_positives = db.Column(db.Integer, nullable=True)
    virustotal_total = db.Column(db.Integer, nullable=True)
    screenshot_path = db.Column(db.String(500), nullable=True)
    features = db.Column(db.JSON, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f'<PhishingURL {self.url}, is_phishing={self.is_phishing}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'url': self.url,
            'is_phishing': self.is_phishing,
            'ml_confidence': self.ml_confidence,
            'virustotal_positives': self.virustotal_positives,
            'virustotal_total': self.virustotal_total,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }
