from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Float, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship
from backend.database import Base

def utc_now():
    return datetime.now(timezone.utc)

class Analysis(Base):
    __tablename__ = "analyses"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)

    app_name = Column(String(255), nullable=False, index=True)
    package_name = Column(String(255), nullable=False, index=True)
    version_code = Column(String(50), nullable=True)
    version_name = Column(String(50), nullable=True)
    min_sdk = Column(String(50), nullable=True)
    target_sdk = Column(String(50), nullable=True)

    total_permissions = Column(Integer, default=0, nullable=False)
    dangerous_count = Column(Integer, default=0, nullable=False)
    normal_count = Column(Integer, default=0, nullable=False)
    special_count = Column(Integer, default=0, nullable=False)

    risk_score = Column(Float, default=0.0, nullable=False, index=True)
    risk_level = Column(String(50), default="LOW", nullable=False, index=True)  # LOW, MEDIUM, HIGH, CRITICAL
    exported_components_count = Column(Integer, default=0, nullable=False)

    raw_manifest = Column(Text, nullable=True)
    raw_policy = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False, index=True)

    # Relationships to normalized tables
    user = relationship("User", back_populates="analyses")
    permissions = relationship("Permission", back_populates="analysis", cascade="all, delete-orphan")
    policy_excerpts = relationship("PolicyExcerpt", back_populates="analysis", cascade="all, delete-orphan")
    comparison_findings = relationship("ComparisonFinding", back_populates="analysis", cascade="all, delete-orphan")
    reports = relationship("Report", back_populates="analysis", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Analysis id={self.id} package='{self.package_name}' risk_level='{self.risk_level}'>"
