"""
Distribution detection models for the application.
Contains models for OS families, package managers, detection rules, and system capabilities.
"""

from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship

from .base import Base


class OSFamily(Base):  # pylint: disable=too-few-public-methods
    """OSFamily model for operating system families."""

    __tablename__ = "os_families"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    name = Column(String(100), nullable=False, unique=True, index=True)
    display_name = Column(String(100), nullable=False)
    description = Column(Text, nullable=True)
    base_family = Column(String(100), nullable=True)
    init_system = Column(String(50), nullable=True)
    shell_default = Column(String(50), nullable=True)
    filesystem_hierarchy = Column(String(50), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    distros = relationship("Distro", back_populates="os_family")


class PackageManager(Base):  # pylint: disable=too-few-public-methods
    """PackageManager model for package management systems."""

    __tablename__ = "package_managers"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    name = Column(String(100), nullable=False, unique=True, index=True)
    display_name = Column(String(100), nullable=False)
    install_command = Column(String(200), nullable=False)
    update_command = Column(String(200), nullable=False)
    remove_command = Column(String(200), nullable=False)
    search_command = Column(String(200), nullable=False)
    list_command = Column(String(200), nullable=False)
    info_command = Column(String(200), nullable=False)
    upgrade_command = Column(String(200), nullable=True)
    clean_command = Column(String(200), nullable=True)
    requires_sudo = Column(Boolean, nullable=False, default=True)
    supports_repositories = Column(Boolean, nullable=False, default=True)
    config_file_path = Column(String(500), nullable=True)
    cache_directory = Column(String(500), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    distros = relationship("Distro", back_populates="package_manager")


class DistributionFeature(Base):  # pylint: disable=too-few-public-methods
    """DistributionFeature model for distribution-specific features."""

    __tablename__ = "distribution_features"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    name = Column(String(100), nullable=False, unique=True, index=True)
    display_name = Column(String(100), nullable=False)
    description = Column(Text, nullable=True)
    feature_type = Column(String(50), nullable=False)
    detection_method = Column(String(100), nullable=False)
    detection_command = Column(String(500), nullable=True)
    detection_file = Column(String(500), nullable=True)
    detection_pattern = Column(String(500), nullable=True)
    is_regex = Column(Boolean, nullable=False, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    distro_features = relationship(
        "DistroFeature", back_populates="feature", cascade="all, delete-orphan"
    )


class DetectionRule(Base):  # pylint: disable=too-few-public-methods
    """DetectionRule model for OS/distribution detection rules."""

    __tablename__ = "detection_rules"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    name = Column(String(100), nullable=False, unique=True, index=True)
    description = Column(Text, nullable=True)
    rule_type = Column(String(50), nullable=False, index=True)
    priority = Column(Integer, nullable=False, default=100, index=True)
    detection_method = Column(String(100), nullable=False)
    file_path = Column(String(500), nullable=True)
    command = Column(String(500), nullable=True)
    pattern = Column(String(1000), nullable=False)
    is_regex = Column(Boolean, nullable=False, default=False)
    expected_value = Column(String(200), nullable=True)
    fallback_rule_id = Column(Integer, ForeignKey("detection_rules.id"), nullable=True)
    is_active = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    fallback_rule = relationship("DetectionRule", remote_side=[id])
    distro_rules = relationship(
        "DistroDetectionRule", back_populates="rule", cascade="all, delete-orphan"
    )


class DistroDetectionRule(Base):  # pylint: disable=too-few-public-methods
    """DistroDetectionRule model for mapping distributions to detection rules."""

    __tablename__ = "distro_detection_rules"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    distro_id = Column(Integer, ForeignKey("distros.id"), nullable=False)
    detection_rule_id = Column(
        Integer, ForeignKey("detection_rules.id"), nullable=False
    )
    version_pattern = Column(String(100), nullable=True)
    is_primary = Column(Boolean, nullable=False, default=False)
    confidence_score = Column(Integer, nullable=False, default=100)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    distro = relationship("Distro")
    rule = relationship("DetectionRule", back_populates="distro_rules")


class DistroFeature(Base):  # pylint: disable=too-few-public-methods
    """DistroFeature model for mapping distributions to features."""

    __tablename__ = "distro_features"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    distro_id = Column(Integer, ForeignKey("distros.id"), nullable=False)
    feature_id = Column(Integer, ForeignKey("distribution_features.id"), nullable=False)
    version_introduced = Column(String(50), nullable=True)
    version_deprecated = Column(String(50), nullable=True)
    is_default = Column(Boolean, nullable=False, default=False)
    configuration_notes = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    distro = relationship("Distro")
    feature = relationship("DistributionFeature", back_populates="distro_features")


class SystemDetectionResult(Base):  # pylint: disable=too-few-public-methods
    """SystemDetectionResult model for storing detection results."""

    __tablename__ = "system_detection_results"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    system_id = Column(Integer, ForeignKey("systems.id"), nullable=False, index=True)
    detection_timestamp = Column(DateTime, nullable=False)
    detected_os_family = Column(String(100), nullable=True)
    detected_distro = Column(String(100), nullable=True)
    detected_version = Column(String(50), nullable=True)
    detected_codename = Column(String(100), nullable=True)
    detected_architecture = Column(String(50), nullable=True)
    detected_kernel = Column(String(100), nullable=True)
    detected_package_manager = Column(String(100), nullable=True)
    confidence_score = Column(Integer, nullable=False)
    detection_method = Column(String(100), nullable=False)
    raw_detection_data = Column(Text, nullable=True)
    features_detected = Column(Text, nullable=True)
    capabilities_detected = Column(Text, nullable=True)
    is_current = Column(Boolean, nullable=False, default=True, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    system = relationship("System")


class CapabilityDefinition(Base):  # pylint: disable=too-few-public-methods
    """CapabilityDefinition model for system capability definitions."""

    __tablename__ = "capability_definitions"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    name = Column(String(100), nullable=False, unique=True, index=True)
    display_name = Column(String(100), nullable=False)
    description = Column(Text, nullable=True)
    capability_type = Column(String(50), nullable=False)
    category = Column(String(100), nullable=False)
    detection_method = Column(String(100), nullable=False)
    detection_command = Column(String(500), nullable=True)
    detection_file = Column(String(500), nullable=True)
    detection_pattern = Column(String(500), nullable=True)
    is_regex = Column(Boolean, nullable=False, default=False)
    default_value = Column(String(200), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    system_capabilities = relationship(
        "SystemCapability", back_populates="capability", cascade="all, delete-orphan"
    )


class SystemCapability(Base):  # pylint: disable=too-few-public-methods
    """SystemCapability model for detected system capabilities."""

    __tablename__ = "system_capabilities"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    system_id = Column(Integer, ForeignKey("systems.id"), nullable=False, index=True)
    capability_id = Column(
        Integer, ForeignKey("capability_definitions.id"), nullable=False, index=True
    )
    detected_value = Column(String(500), nullable=True)
    is_available = Column(Boolean, nullable=False, default=False)
    version_info = Column(String(100), nullable=True)
    configuration_path = Column(String(500), nullable=True)
    last_detected = Column(DateTime, nullable=False)
    detection_method_used = Column(String(100), nullable=False)
    notes = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    system = relationship("System")
    capability = relationship(
        "CapabilityDefinition", back_populates="system_capabilities"
    )
