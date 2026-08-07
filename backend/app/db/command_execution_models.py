"""
Database models for command execution system.
Contains models for tracking command execution results, resource usage, and execution history.
"""

import json
from datetime import datetime
from typing import Any, Dict, Optional

from sqlalchemy import (
    BigInteger,
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import INET
from sqlalchemy.orm import relationship

from .base import Base


class CommandExecutionResult(Base):
    """Model for storing command execution results."""

    __tablename__ = "command_execution_results"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    system_id = Column(Integer, ForeignKey("systems.id"), nullable=False)
    user_id = Column(Integer, ForeignKey("user.id"), nullable=False)
    session_id = Column(String(255), nullable=True)
    command = Column(Text, nullable=False)
    normalized_command = Column(Text, nullable=True)
    command_hash = Column(String(64), nullable=False, index=True)  # SHA256 hash

    # Execution details
    execution_status = Column(
        String(50), nullable=False
    )  # success, failed, timeout, killed
    exit_code = Column(Integer, nullable=True)
    stdout = Column(Text, nullable=True)
    stderr = Column(Text, nullable=True)

    # Timing information
    started_at = Column(DateTime, nullable=False)
    completed_at = Column(DateTime, nullable=True)
    execution_time_ms = Column(Integer, nullable=True)
    timeout_seconds = Column(Integer, nullable=False, default=30)

    # Resource usage
    max_memory_usage_bytes = Column(BigInteger, nullable=True)
    cpu_time_ms = Column(Integer, nullable=True)
    disk_io_bytes = Column(BigInteger, nullable=True)
    network_io_bytes = Column(BigInteger, nullable=True)

    # Security and audit
    validation_status = Column(
        String(50), nullable=False
    )  # validated, bypassed, failed
    risk_level = Column(String(50), nullable=False)  # low, medium, high, critical
    requires_sudo = Column(Boolean, default=False, nullable=False)
    actual_user = Column(
        String(100), nullable=True
    )  # User who actually ran the command

    # Context information
    ip_address = Column(INET, nullable=True)
    user_agent = Column(String(500), nullable=True)
    execution_context = Column(
        Text, nullable=True
    )  # JSON string with additional context

    # Error handling
    error_type = Column(String(100), nullable=True)
    error_message = Column(Text, nullable=True)
    retry_count = Column(Integer, default=0, nullable=False)

    # PRA-153: which transport ran this command (ssh | agent).
    # NULL on rows created before PRA-153 shipped.
    transport = Column(String(8), nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    system = relationship("System")
    user = relationship("User")
    resource_limits = relationship(
        "CommandResourceLimit",
        back_populates="execution_result",
        cascade="all, delete-orphan",
    )

    def set_execution_context(self, context: Dict[str, Any]) -> None:
        """Set execution context as JSON string."""
        self.execution_context = json.dumps(context) if context else None

    def get_execution_context(self) -> Optional[Dict[str, Any]]:
        """Get execution context as dictionary."""
        if self.execution_context:
            try:
                return json.loads(self.execution_context)
            except json.JSONDecodeError:
                return None
        return None


class CommandResourceLimit(Base):
    """Model for tracking resource limits applied to command execution."""

    __tablename__ = "command_resource_limits"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    execution_result_id = Column(
        Integer, ForeignKey("command_execution_results.id"), nullable=False
    )

    # Resource limits
    max_memory_bytes = Column(BigInteger, nullable=True)
    max_cpu_time_ms = Column(Integer, nullable=True)
    max_disk_io_bytes = Column(BigInteger, nullable=True)
    max_network_io_bytes = Column(BigInteger, nullable=True)
    max_open_files = Column(Integer, nullable=True)
    max_processes = Column(Integer, nullable=True)

    # Enforcement status
    memory_limit_exceeded = Column(Boolean, default=False, nullable=False)
    cpu_limit_exceeded = Column(Boolean, default=False, nullable=False)
    disk_io_limit_exceeded = Column(Boolean, default=False, nullable=False)
    network_io_limit_exceeded = Column(Boolean, default=False, nullable=False)

    # Limit source
    limit_source = Column(
        String(100), nullable=False
    )  # system_default, user_defined, policy
    policy_name = Column(String(255), nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    execution_result = relationship(
        "CommandExecutionResult", back_populates="resource_limits"
    )


class CommandExecutionPolicy(Base):
    """Model for defining command execution policies."""

    __tablename__ = "command_execution_policies"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    name = Column(String(255), nullable=False, unique=True, index=True)
    description = Column(Text, nullable=True)

    # Timeout settings
    default_timeout_seconds = Column(Integer, default=30, nullable=False)
    max_timeout_seconds = Column(Integer, default=300, nullable=False)

    # Resource limits
    max_memory_bytes = Column(BigInteger, nullable=True)
    max_cpu_time_ms = Column(Integer, nullable=True)
    max_disk_io_bytes = Column(BigInteger, nullable=True)
    max_network_io_bytes = Column(BigInteger, nullable=True)
    max_open_files = Column(Integer, nullable=True)
    max_processes = Column(Integer, nullable=True)

    # Security settings
    allow_sudo = Column(Boolean, default=False, nullable=False)
    allow_network_access = Column(Boolean, default=True, nullable=False)
    allow_file_system_write = Column(Boolean, default=True, nullable=False)
    require_validation = Column(Boolean, default=True, nullable=False)

    # Retry settings
    max_retry_attempts = Column(Integer, default=0, nullable=False)
    retry_delay_seconds = Column(Integer, default=5, nullable=False)

    # Logging and monitoring
    log_stdout = Column(Boolean, default=True, nullable=False)
    log_stderr = Column(Boolean, default=True, nullable=False)
    monitor_resources = Column(Boolean, default=True, nullable=False)

    # Policy scope
    applies_to_all_systems = Column(Boolean, default=False, nullable=False)
    applies_to_all_users = Column(Boolean, default=False, nullable=False)

    is_active = Column(Boolean, default=True, nullable=False)
    priority = Column(
        Integer, default=100, nullable=False
    )  # Lower number = higher priority

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    created_by = Column(Integer, ForeignKey("user.id"), nullable=False)

    # Relationships
    system_policies = relationship(
        "CommandExecutionSystemPolicy",
        back_populates="policy",
        cascade="all, delete-orphan",
    )
    user_policies = relationship(
        "CommandExecutionUserPolicy",
        back_populates="policy",
        cascade="all, delete-orphan",
    )


class CommandExecutionSystemPolicy(Base):
    """Model for linking execution policies to specific systems."""

    __tablename__ = "command_execution_system_policies"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    policy_id = Column(
        Integer, ForeignKey("command_execution_policies.id"), nullable=False
    )
    system_id = Column(Integer, ForeignKey("systems.id"), nullable=False)

    # Override settings
    timeout_override = Column(Integer, nullable=True)
    memory_limit_override = Column(BigInteger, nullable=True)

    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    policy = relationship("CommandExecutionPolicy", back_populates="system_policies")
    system = relationship("System")


class CommandExecutionUserPolicy(Base):
    """Model for linking execution policies to specific users."""

    __tablename__ = "command_execution_user_policies"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    policy_id = Column(
        Integer, ForeignKey("command_execution_policies.id"), nullable=False
    )
    user_id = Column(Integer, ForeignKey("user.id"), nullable=False)

    # Override settings
    timeout_override = Column(Integer, nullable=True)
    memory_limit_override = Column(BigInteger, nullable=True)

    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    policy = relationship("CommandExecutionPolicy", back_populates="user_policies")
    user = relationship("User")


class CommandExecutionQueue(Base):
    """Model for queuing command executions."""

    __tablename__ = "command_execution_queue"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    system_id = Column(Integer, ForeignKey("systems.id"), nullable=False)
    user_id = Column(Integer, ForeignKey("user.id"), nullable=False)
    command = Column(Text, nullable=False)

    # Queue management
    priority = Column(
        Integer, default=100, nullable=False
    )  # Lower number = higher priority
    status = Column(
        String(50), nullable=False, default="queued"
    )  # queued, running, completed, failed
    scheduled_at = Column(DateTime, nullable=True)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)

    # Execution settings
    timeout_seconds = Column(Integer, default=30, nullable=False)
    retry_count = Column(Integer, default=0, nullable=False)
    max_retries = Column(Integer, default=0, nullable=False)

    # Results
    execution_result_id = Column(
        Integer, ForeignKey("command_execution_results.id"), nullable=True
    )
    error_message = Column(Text, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    system = relationship("System")
    user = relationship("User")
    execution_result = relationship("CommandExecutionResult")


class CommandExecutionMetrics(Base):
    """Model for storing execution metrics and statistics."""

    __tablename__ = "command_execution_metrics"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    system_id = Column(Integer, ForeignKey("systems.id"), nullable=False)
    user_id = Column(Integer, ForeignKey("user.id"), nullable=True)

    # Time period
    metric_date = Column(DateTime, nullable=False, index=True)
    metric_hour = Column(Integer, nullable=False)  # 0-23

    # Execution counts
    total_executions = Column(Integer, default=0, nullable=False)
    successful_executions = Column(Integer, default=0, nullable=False)
    failed_executions = Column(Integer, default=0, nullable=False)
    timeout_executions = Column(Integer, default=0, nullable=False)

    # Performance metrics
    avg_execution_time_ms = Column(Integer, nullable=True)
    max_execution_time_ms = Column(Integer, nullable=True)
    min_execution_time_ms = Column(Integer, nullable=True)

    # Resource usage
    avg_memory_usage_bytes = Column(BigInteger, nullable=True)
    max_memory_usage_bytes = Column(BigInteger, nullable=True)
    total_cpu_time_ms = Column(BigInteger, nullable=True)

    # Security metrics
    validation_failures = Column(Integer, default=0, nullable=False)
    high_risk_executions = Column(Integer, default=0, nullable=False)
    sudo_executions = Column(Integer, default=0, nullable=False)

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    system = relationship("System")
    user = relationship("User")
