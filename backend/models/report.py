from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, JSON
from sqlalchemy.orm import relationship
from backend.database import Base

def utc_now():
    return datetime.now(timezone.utc)

class Report(Base):
    __tablename__ = "reports"

    id = Column(Integer, primary_key=True, index=True)
    analysis_id = Column(Integer, ForeignKey("analyses.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)

    report_format = Column(String(20), default="PDF", nullable=False)
    file_path = Column(String(512), nullable=False)
    file_size = Column(Integer, default=0)
    summary_json = Column(JSON, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False, index=True)

    analysis = relationship("Analysis", back_populates="reports")
    user = relationship("User", back_populates="reports")

    def __repr__(self):
        return f"<Report id={self.id} analysis_id={self.analysis_id} format='{self.report_format}'>"

