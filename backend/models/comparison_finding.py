from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Float, DateTime, ForeignKey, Text, JSON
from sqlalchemy.orm import relationship
from backend.database import Base

def utc_now():
    return datetime.now(timezone.utc)

class ComparisonFinding(Base):
    __tablename__ = "comparison_findings"

    id = Column(Integer, primary_key=True, index=True)
    analysis_id = Column(Integer, ForeignKey("analyses.id", ondelete="CASCADE"), nullable=False, index=True)

    finding_type = Column(String(100), nullable=False, index=True)  # COMBO_THREAT, DECEPTIVE_CONTRADICTION, UNDISCLOSED_DANGEROUS_PERMISSION, SDK_WARNING
    severity = Column(String(50), nullable=False, index=True)  # CRITICAL, HIGH, MEDIUM, LOW
    title = Column(String(255), nullable=False)
    explanation = Column(Text, nullable=False)
    remediation = Column(Text, nullable=True)
    risk_penalty = Column(Float, default=0.0)
    matched_data = Column(JSON, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)

    analysis = relationship("Analysis", back_populates="comparison_findings")

    def __repr__(self):
        return f"<ComparisonFinding id={self.id} type='{self.finding_type}' sev='{self.severity}'>"

