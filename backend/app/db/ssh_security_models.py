"""
SSH Security models for enhanced SSH connection security.
Contains SSHSecurityPolicy and SSHSecurityLog models.
"""

import json
from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship

from .base import Base


class SSHSecurityPolicy(Base):
    """SSH security policy configuration."""

    __tablename__ = "ssh_security_policies"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    name = Column(String(255), unique=True, nullable=False)
    description = Column(Text)

    # Connection settings
    max_auth_tries = Column(Integer, default=3)
    connection_timeout = Column(Integer, default=10)
    idle_timeout = Column(Integer, default=600)

    # Security settings
    require_host_key_verification = Column(Boolean, default=True)
    minimum_key_size = Column(Integer, default=2048)
    allowed_auth_methods = Column(String(255), default="publickey,password")
    allowed_ciphers = Column(String(255), default="aes256-ctr,aes192-ctr,aes128-ctr")
    allowed_macs = Column(String(255), default="hmac-sha2-512,hmac-sha2-256")
    allowed_kex = Column(String(255), default="diffie-hellman-group-exchange-sha256")

    # Audit settings
    log_commands = Column(Boolean, default=True)
    log_file_transfers = Column(Boolean, default=True)

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    created_by = Column(Integer, ForeignKey("user.id"), nullable=False)

    # Relationships
    systems = relationship("System", back_populates="ssh_security_policy")
    creator = relationship("User")


class SSHSecurityLog(Base):
    """SSH security event log."""

    __tablename__ = "ssh_security_logs"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    system_id = Column(Integer, ForeignKey("systems.id"), nullable=False)
    event_type = Column(
        String(50), nullable=False
    )  # auth_attempt, connection, command_execution, etc.
    event_details = Column(Text)  # JSON-encoded details
    source_ip = Column(String(50))
    username = Column(String(255))
    success = Column(Boolean, default=False)
    timestamp = Column(DateTime, default=datetime.utcnow)

    # Relationships
    system = relationship("System", back_populates="security_logs")

    def set_event_details(self, details_dict):
        """Set event details as JSON string."""
        self.event_details = json.dumps(details_dict)

    def get_event_details(self):
        """Get event details as dictionary."""
        if self.event_details:
            try:
                return json.loads(self.event_details)
            except json.JSONDecodeError:
                return {}
        return {}


class SSHHostKey(Base):
    """SSH host key storage for host verification."""

    __tablename__ = "ssh_host_keys"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    system_id = Column(Integer, ForeignKey("systems.id"), nullable=False)
    hostname = Column(String(255), nullable=False)
    key_type = Column(String(50), nullable=False)  # ssh-rsa, ssh-ed25519, etc.
    public_key = Column(Text, nullable=False)
    fingerprint = Column(String(255), nullable=False)
    verified = Column(Boolean, default=False)
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    system = relationship("System", back_populates="host_keys")
