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

    finding_type = Column(String(100), nullable=False, index=True)  # COMBO_THREAT, DECEPTIVE_CONTRADICTION, UNDISCLOSED_DANGEROUS_PERMISSION, SDK_WARNING, PURPOSE_COMPARISON
    severity = Column(String(50), nullable=False, index=True)  # CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN
    title = Column(String(255), nullable=False)
    explanation = Column(Text, nullable=False)
    remediation = Column(Text, nullable=True)
    risk_penalty = Column(Float, default=0.0)
    matched_data = Column(JSON, nullable=True)
    
    # Explainable Risk and Purpose Comparison Fields
    permission = Column(String(255), nullable=True, index=True)
    finding_category = Column(String(50), nullable=True, index=True)  # POTENTIALLY_EXPECTED, REQUIRES_REVIEW, PURPOSE_MISMATCH, UNKNOWN_PERMISSION, INSUFFICIENT_INFORMATION
    review_question = Column(Text, nullable=True)
    purpose_comparison = Column(Text, nullable=True)
    evidence_source = Column(String(100), default="AndroidManifest.xml", nullable=True)
    source_reference = Column(String(255), nullable=True)
    confidence = Column(String(50), default="RULE_BASED", nullable=True)

    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)

    analysis = relationship("Analysis", back_populates="comparison_findings")

    def __repr__(self):
        return f"<ComparisonFinding id={self.id} type='{self.finding_type}' sev='{self.severity}'>"

