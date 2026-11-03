from sqlalchemy import Column, Integer, String, Float, ForeignKey, Text, Boolean, JSON
from sqlalchemy.orm import relationship
from backend.database import Base

class Permission(Base):
    __tablename__ = "permissions"

    id = Column(Integer, primary_key=True, index=True)
    analysis_id = Column(Integer, ForeignKey("analyses.id", ondelete="CASCADE"), nullable=False, index=True)
    
    name = Column(String(255), nullable=False, index=True)
    short_name = Column(String(100), nullable=False)
    permission_group = Column(String(100), nullable=True)
    protection_level = Column(String(50), default="normal", nullable=False)
    description = Column(Text, nullable=True)
    privacy_risk = Column(Text, nullable=True)
    abuse_scenarios = Column(JSON, nullable=True)
    severity_score = Column(Float, default=1.0, nullable=False)
    remediation = Column(Text, nullable=True)
    policy_disclosed = Column(Boolean, default=False, nullable=False)
    discrepancy_status = Column(String(100), default="NORMAL", nullable=False)

    analysis = relationship("Analysis", back_populates="permissions")

    def __repr__(self):
        return f"<Permission id={self.id} name='{self.name}' level='{self.protection_level}'>"
