from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Float, DateTime, ForeignKey, JSON
from sqlalchemy.orm import relationship
from backend.database import Base

def utc_now():
    return datetime.now(timezone.utc)

class AnalysisRecord(Base):
    __tablename__ = "analysis_records"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    
    app_name = Column(String(255), nullable=False)
    package_name = Column(String(255), nullable=False, index=True)
    version_code = Column(String(50), nullable=True)
    version_name = Column(String(50), nullable=True)
    min_sdk = Column(String(50), nullable=True)
    target_sdk = Column(String(50), nullable=True)

    total_permissions = Column(Integer, default=0, nullable=False)
    dangerous_count = Column(Integer, default=0, nullable=False)
    normal_count = Column(Integer, default=0, nullable=False)
    special_count = Column(Integer, default=0, nullable=False)

    risk_score = Column(Float, default=0.0, nullable=False)  # 0.0 to 100.0
    risk_level = Column(String(50), default="LOW", nullable=False)  # LOW, MEDIUM, HIGH, CRITICAL
    exported_components_count = Column(Integer, default=0, nullable=False)

    # Detailed structured analysis results
    manifest_data = Column(JSON, nullable=True)
    policy_data = Column(JSON, nullable=True)
    discrepancy_data = Column(JSON, nullable=True)

    pdf_report_path = Column(String(512), nullable=True)
    created_at = Column(DateTime, default=utc_now, nullable=False, index=True)

    user = relationship("User", back_populates="analyses")

    def __repr__(self):
        return f"<AnalysisRecord id={self.id} package='{self.package_name}' risk_level='{self.risk_level}'>"
