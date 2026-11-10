from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship
from backend.database import Base

def utc_now():
    return datetime.now(timezone.utc)

class PolicyExcerpt(Base):
    __tablename__ = "policy_excerpts"

    id = Column(Integer, primary_key=True, index=True)
    analysis_id = Column(Integer, ForeignKey("analyses.id", ondelete="CASCADE"), nullable=False, index=True)

    domain = Column(String(100), nullable=False, index=True)  # Camera, Microphone, Location, etc.
    excerpt_type = Column(String(50), nullable=False)  # "disclosure", "negation", "ambiguous"
    text_snippet = Column(Text, nullable=False)
    sentiment_or_stance = Column(String(50), default="neutral")  # affirmative_collection, assertive_denial, vague_unclear
    paragraph_ref = Column(String(50), nullable=True)  # e.g. "Paragraph 3"
    start_offset = Column(Integer, nullable=True)
    end_offset = Column(Integer, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)

    analysis = relationship("Analysis", back_populates="policy_excerpts")

    def __repr__(self):
        return f"<PolicyExcerpt id={self.id} domain='{self.domain}' type='{self.excerpt_type}'>"

