"""
Distribution detection service for identifying target system distributions.
Provides OS detection, version detection, package manager identification,
feature detection, and capability mapping.
"""

import json
import re
from datetime import datetime
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from ..db.distribution_models import (
    CapabilityDefinition,
    DetectionRule,
    DistributionFeature,
    DistroDetectionRule,
    DistroFeature,
    SystemCapability,
    SystemDetectionResult,
)
from ..db.models import Distro, System


class DistributionDetectionService:
    """Service for detecting and identifying Linux distributions and their capabilities."""

    def __init__(self, db: Session):
        self.db = db

    def detect_system_distribution(
        self, system_id: int, force_redetection: bool = False
    ) -> Dict[str, Any]:
        """
        Detect the distribution and capabilities of a target system.

        Args:
            system_id: ID of the target system
            force_redetection: Whether to force a new detection even if recent results exist

        Returns:
            Dict containing detection results with confidence scores and detected features
        """
        system = self.db.query(System).filter(System.id == system_id).first()
        if not system:
            return {"error": "System not found", "system_id": system_id}

        # Check for existing recent detection results
        if not force_redetection:
            existing_result = self._get_latest_detection_result(system_id)
            if existing_result and self._is_detection_recent(existing_result):
                return self._format_detection_result(existing_result)

        # Perform new detection
        detection_result = self._perform_detection(system)

        # Store detection results
        stored_result = self._store_detection_result(system_id, detection_result)

        return self._format_detection_result(stored_result)

    def _perform_detection(self, system: System) -> Dict[str, Any]:
        """Perform the actual distribution detection logic."""
        detection_data = {
            "os_family": None,
            "distro_name": None,
            "distro_version": None,
            "codename": None,
            "architecture": None,
            "kernel_version": None,
            "package_manager": None,
            "confidence_score": 0,
            "detection_method": "multi_rule",
            "raw_data": {},
            "features": [],
            "capabilities": {},
        }

        # Get all active detection rules ordered by priority
        detection_rules = (
            self.db.query(DetectionRule)
            .filter(DetectionRule.is_active.is_(True))
            .order_by(DetectionRule.priority.asc())
            .all()
        )

        # Apply detection rules
        for rule in detection_rules:
            rule_result = self._apply_detection_rule(rule, system)
            if rule_result["matched"]:
                detection_data = self._merge_detection_results(
                    detection_data, rule_result
                )

        # Identify distribution based on detection results
        distro_match = self._identify_distribution(detection_data)
        if distro_match:
            detection_data.update(distro_match)

        # Detect package manager
        package_manager = self._detect_package_manager(detection_data)
        if package_manager:
            detection_data["package_manager"] = package_manager

        # Detect features and capabilities
        features = self._detect_features(detection_data)
        capabilities = self._detect_capabilities(system, detection_data)

        detection_data["features"] = features
        detection_data["capabilities"] = capabilities

        return detection_data

    def _apply_detection_rule(
        self, rule: DetectionRule, system: System
    ) -> Dict[str, Any]:
        """Apply a single detection rule to a system."""
        result = {
            "matched": False,
            "rule_id": rule.id,
            "rule_name": rule.name,
            "confidence": 0,
            "extracted_data": {},
        }

        try:
            if rule.detection_method == "file_content":
                result = self._detect_from_file(rule, system)
            elif rule.detection_method == "command_output":
                result = self._detect_from_command(rule, system)
            elif rule.detection_method == "file_existence":
                result = self._detect_file_existence(rule, system)
            elif rule.detection_method == "kernel_info":
                result = self._detect_kernel_info(rule, system)
            elif rule.detection_method == "environment_var":
                result = self._detect_environment_var(rule, system)

        except Exception as e:
            result["error"] = str(e)

        return result

    def _detect_from_file(self, rule: DetectionRule, system: System) -> Dict[str, Any]:
        """Detect information from file content."""
        # This would typically involve SSH connection to read file content
        # For now, return a mock implementation
        result = {
            "matched": False,
            "rule_id": rule.id,
            "rule_name": rule.name,
            "confidence": 0,
            "extracted_data": {},
            "method": "file_content",
            "file_path": rule.file_path,
        }

        # Mock detection logic - in real implementation, this would:
        # 1. Connect to the system via SSH
        # 2. Read the specified file
        # 3. Apply the pattern matching
        # 4. Extract relevant information

        if rule.file_path == "/etc/os-release":
            # Mock os-release detection
            mock_content = (
                'NAME="Ubuntu"\nVERSION="20.04.3 LTS (Focal Fossa)"\nID=ubuntu'
            )
            if self._match_pattern(mock_content, rule.pattern, rule.is_regex):
                result["matched"] = True
                result["confidence"] = 95
                result["extracted_data"] = {
                    "distro_name": "Ubuntu",
                    "version": "20.04.3",
                    "codename": "Focal Fossa",
                }

        return result

    def _detect_from_command(
        self, rule: DetectionRule, system: System
    ) -> Dict[str, Any]:
        """Detect information from command output."""
        result = {
            "matched": False,
            "rule_id": rule.id,
            "rule_name": rule.name,
            "confidence": 0,
            "extracted_data": {},
            "method": "command_output",
            "command": rule.command,
        }

        # Mock command execution - in real implementation, this would:
        # 1. Connect to the system via SSH
        # 2. Execute the specified command
        # 3. Apply pattern matching to the output
        # 4. Extract relevant information

        if rule.command == "uname -a":
            mock_output = "Linux ubuntu-server 5.4.0-74-generic #83-Ubuntu SMP Sat May 8 02:35:39 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux"
            if self._match_pattern(mock_output, rule.pattern, rule.is_regex):
                result["matched"] = True
                result["confidence"] = 90
                result["extracted_data"] = {
                    "kernel_version": "5.4.0-74-generic",
                    "architecture": "x86_64",
                }

        return result

    def _detect_file_existence(
        self, rule: DetectionRule, system: System
    ) -> Dict[str, Any]:
        """Detect information based on file existence."""
        result = {
            "matched": False,
            "rule_id": rule.id,
            "rule_name": rule.name,
            "confidence": 0,
            "extracted_data": {},
            "method": "file_existence",
            "file_path": rule.file_path,
        }

        # Mock file existence check
        common_files = [
            "/etc/debian_version",
            "/etc/redhat-release",
            "/etc/arch-release",
            "/usr/bin/apt",
            "/usr/bin/yum",
            "/usr/bin/pacman",
        ]

        if rule.file_path in common_files:
            result["matched"] = True
            result["confidence"] = 70
            if "apt" in rule.file_path:
                result["extracted_data"]["package_manager"] = "apt"
            elif "yum" in rule.file_path:
                result["extracted_data"]["package_manager"] = "yum"

        return result

    def _detect_kernel_info(
        self, rule: DetectionRule, system: System
    ) -> Dict[str, Any]:
        """Detect kernel information."""
        result = {
            "matched": False,
            "rule_id": rule.id,
            "rule_name": rule.name,
            "confidence": 0,
            "extracted_data": {},
            "method": "kernel_info",
        }

        # Mock kernel detection
        mock_kernel = "5.4.0-74-generic"
        if self._match_pattern(mock_kernel, rule.pattern, rule.is_regex):
            result["matched"] = True
            result["confidence"] = 85
            result["extracted_data"]["kernel_version"] = mock_kernel

        return result

    def _detect_environment_var(
        self, rule: DetectionRule, system: System
    ) -> Dict[str, Any]:
        """Detect information from environment variables."""
        result = {
            "matched": False,
            "rule_id": rule.id,
            "rule_name": rule.name,
            "confidence": 0,
            "extracted_data": {},
            "method": "environment_var",
        }

        # Mock environment variable detection
        return result

    def _match_pattern(self, content: str, pattern: str, is_regex: bool) -> bool:
        """Match content against a pattern."""
        if is_regex:
            try:
                return bool(re.search(pattern, content, re.IGNORECASE | re.MULTILINE))
            except re.error:
                return False
        else:
            return pattern.lower() in content.lower()

    def _merge_detection_results(
        self, base_data: Dict[str, Any], rule_result: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Merge detection results from multiple rules."""
        if not rule_result["matched"]:
            return base_data

        extracted = rule_result.get("extracted_data", {})

        # Update base data with higher confidence results
        for key, value in extracted.items():
            if key not in base_data or base_data[key] is None:
                base_data[key] = value
            elif rule_result["confidence"] > base_data.get("confidence_score", 0):
                base_data[key] = value

        # Update confidence score
        base_data["confidence_score"] = max(
            base_data["confidence_score"], rule_result["confidence"]
        )

        # Store raw detection data
        base_data["raw_data"][rule_result["rule_name"]] = rule_result

        return base_data

    def _identify_distribution(
        self, detection_data: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Identify the specific distribution based on detection results."""
        distro_name = detection_data.get("distro_name")
        if not distro_name:
            return None

        # Query for matching distributions
        distros = (
            self.db.query(Distro).filter(Distro.name.ilike(f"%{distro_name}%")).all()
        )

        if not distros:
            return None

        # Find best match based on version and other criteria
        best_match = None
        best_score = 0

        for distro in distros:
            score = self._calculate_distro_match_score(distro, detection_data)
            if score > best_score:
                best_score = score
                best_match = distro

        if best_match:
            return {
                "distro_id": best_match.id,
                "distro_name": best_match.name,
                "distro_version": best_match.version,
                "confidence_score": min(detection_data["confidence_score"] + 10, 100),
            }

        return None

    def _calculate_distro_match_score(
        self, distro: Distro, detection_data: Dict[str, Any]
    ) -> int:
        """Calculate how well a distribution matches the detection data."""
        score = 0

        # Name match
        if distro.name.lower() == detection_data.get("distro_name", "").lower():
            score += 50

        # Version match
        detected_version = detection_data.get("distro_version", "")
        if detected_version and distro.version in detected_version:
            score += 30

        return score

    def _detect_package_manager(self, detection_data: Dict[str, Any]) -> Optional[str]:
        """Detect the package manager based on detection results."""
        # Check if package manager was already detected
        if detection_data.get("package_manager"):
            return detection_data["package_manager"]

        # Infer from distribution
        distro_name = detection_data.get("distro_name", "").lower()
        if "ubuntu" in distro_name or "debian" in distro_name:
            return "apt"
        if "centos" in distro_name or "rhel" in distro_name or "fedora" in distro_name:
            return "yum"
        if "arch" in distro_name:
            return "pacman"
        if "opensuse" in distro_name or "suse" in distro_name:
            return "zypper"

        return None

    def _detect_features(self, detection_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect distribution-specific features."""
        features = []

        # Get features for the detected distribution
        distro_id = detection_data.get("distro_id")
        if distro_id:
            distro_features = (
                self.db.query(DistroFeature)
                .join(DistributionFeature)
                .filter(DistroFeature.distro_id == distro_id)
                .all()
            )

            for df in distro_features:
                features.append(
                    {
                        "name": df.feature.name,
                        "display_name": df.feature.display_name,
                        "type": df.feature.feature_type,
                        "is_default": df.is_default,
                        "version_introduced": df.version_introduced,
                        "version_deprecated": df.version_deprecated,
                    }
                )

        return features

    def _detect_capabilities(
        self, system: System, detection_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Detect system capabilities."""
        capabilities = {}

        # Get all capability definitions
        capability_defs = self.db.query(CapabilityDefinition).all()

        for cap_def in capability_defs:
            capability_result = self._detect_single_capability(
                cap_def, system, detection_data
            )
            if capability_result:
                capabilities[cap_def.name] = capability_result

        return capabilities

    def _detect_single_capability(
        self,
        cap_def: CapabilityDefinition,
        system: System,
        detection_data: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        """Detect a single system capability."""
        # Mock capability detection
        capability = {
            "name": cap_def.name,
            "display_name": cap_def.display_name,
            "type": cap_def.capability_type,
            "category": cap_def.category,
            "is_available": False,
            "detected_value": None,
            "version_info": None,
            "detection_method": cap_def.detection_method,
        }

        # Mock some common capabilities
        if cap_def.name == "systemd":
            capability["is_available"] = True
            capability["detected_value"] = "systemd 245"
            capability["version_info"] = "245"
        elif cap_def.name == "docker":
            capability["is_available"] = True
            capability["detected_value"] = "Docker version 20.10.7"
            capability["version_info"] = "20.10.7"

        return capability

    def _store_detection_result(
        self, system_id: int, detection_data: Dict[str, Any]
    ) -> SystemDetectionResult:
        """Store detection results in the database."""
        # Mark previous results as not current
        self.db.query(SystemDetectionResult).filter(
            SystemDetectionResult.system_id == system_id,
            SystemDetectionResult.is_current.is_(True),
        ).update({"is_current": False})

        # Create new detection result
        result = SystemDetectionResult(
            system_id=system_id,
            detection_timestamp=datetime.utcnow(),
            detected_os_family=detection_data.get("os_family"),
            detected_distro=detection_data.get("distro_name"),
            detected_version=detection_data.get("distro_version"),
            detected_codename=detection_data.get("codename"),
            detected_architecture=detection_data.get("architecture"),
            detected_kernel=detection_data.get("kernel_version"),
            detected_package_manager=detection_data.get("package_manager"),
            confidence_score=detection_data.get("confidence_score", 0),
            detection_method=detection_data.get("detection_method", "unknown"),
            raw_detection_data=json.dumps(detection_data.get("raw_data", {})),
            features_detected=json.dumps(detection_data.get("features", [])),
            capabilities_detected=json.dumps(detection_data.get("capabilities", {})),
            is_current=True,
        )

        self.db.add(result)
        self.db.commit()
        self.db.refresh(result)

        # Store individual capabilities
        self._store_system_capabilities(
            system_id, detection_data.get("capabilities", {})
        )

        return result

    def _store_system_capabilities(self, system_id: int, capabilities: Dict[str, Any]):
        """Store detected capabilities for a system."""
        for cap_name, cap_data in capabilities.items():
            # Find capability definition
            cap_def = (
                self.db.query(CapabilityDefinition)
                .filter(CapabilityDefinition.name == cap_name)
                .first()
            )

            if not cap_def:
                continue

            # Check if capability already exists for this system
            existing_cap = (
                self.db.query(SystemCapability)
                .filter(
                    SystemCapability.system_id == system_id,
                    SystemCapability.capability_id == cap_def.id,
                )
                .first()
            )

            if existing_cap:
                # Update existing capability
                existing_cap.detected_value = cap_data.get("detected_value")
                existing_cap.is_available = cap_data.get("is_available", False)
                existing_cap.version_info = cap_data.get("version_info")
                existing_cap.last_detected = datetime.utcnow()
                existing_cap.detection_method_used = cap_data.get(
                    "detection_method", "unknown"
                )
            else:
                # Create new capability record
                new_cap = SystemCapability(
                    system_id=system_id,
                    capability_id=cap_def.id,
                    detected_value=cap_data.get("detected_value"),
                    is_available=cap_data.get("is_available", False),
                    version_info=cap_data.get("version_info"),
                    last_detected=datetime.utcnow(),
                    detection_method_used=cap_data.get("detection_method", "unknown"),
                )
                self.db.add(new_cap)

        self.db.commit()

    def _get_latest_detection_result(
        self, system_id: int
    ) -> Optional[SystemDetectionResult]:
        """Get the latest detection result for a system."""
        return (
            self.db.query(SystemDetectionResult)
            .filter(
                SystemDetectionResult.system_id == system_id,
                SystemDetectionResult.is_current.is_(True),
            )
            .first()
        )

    def _is_detection_recent(
        self, result: SystemDetectionResult, hours: int = 24
    ) -> bool:
        """Check if a detection result is recent enough to avoid re-detection."""
        if not result.detection_timestamp:
            return False

        time_diff = datetime.utcnow() - result.detection_timestamp
        return time_diff.total_seconds() < (hours * 3600)

    def _format_detection_result(self, result: SystemDetectionResult) -> Dict[str, Any]:
        """Format detection result for API response."""
        return {
            "system_id": result.system_id,
            "detection_timestamp": (
                result.detection_timestamp.isoformat()
                if result.detection_timestamp
                else None
            ),
            "os_family": result.detected_os_family,
            "distro": result.detected_distro,
            "version": result.detected_version,
            "codename": result.detected_codename,
            "architecture": result.detected_architecture,
            "kernel": result.detected_kernel,
            "package_manager": result.detected_package_manager,
            "confidence_score": result.confidence_score,
            "detection_method": result.detection_method,
            "features": (
                json.loads(result.features_detected) if result.features_detected else []
            ),
            "capabilities": (
                json.loads(result.capabilities_detected)
                if result.capabilities_detected
                else {}
            ),
            "is_current": result.is_current,
        }

    def get_supported_distributions(self) -> List[Dict[str, Any]]:
        """Get list of supported distributions with their detection rules."""
        distros = self.db.query(Distro).all()
        result = []

        for distro in distros:
            distro_data = {
                "id": distro.id,
                "name": distro.name,
                "version": distro.version,
                "release_date": (
                    distro.release_date.isoformat() if distro.release_date else None
                ),
                "end_of_life_date": (
                    distro.end_of_life_date.isoformat()
                    if distro.end_of_life_date
                    else None
                ),
                "detection_rules": [],
                "features": [],
            }

            # Get detection rules for this distribution
            distro_rules = (
                self.db.query(DistroDetectionRule)
                .join(DetectionRule)
                .filter(DistroDetectionRule.distro_id == distro.id)
                .all()
            )

            for dr in distro_rules:
                distro_data["detection_rules"].append(
                    {
                        "rule_name": dr.rule.name,
                        "rule_type": dr.rule.rule_type,
                        "is_primary": dr.is_primary,
                        "confidence_score": dr.confidence_score,
                    }
                )

            # Get features for this distribution
            distro_features = (
                self.db.query(DistroFeature)
                .join(DistributionFeature)
                .filter(DistroFeature.distro_id == distro.id)
                .all()
            )

            for df in distro_features:
                distro_data["features"].append(
                    {
                        "name": df.feature.name,
                        "display_name": df.feature.display_name,
                        "type": df.feature.feature_type,
                        "is_default": df.is_default,
                    }
                )

            result.append(distro_data)

        return result

    def get_system_capabilities(self, system_id: int) -> List[Dict[str, Any]]:
        """Get detected capabilities for a system."""
        capabilities = (
            self.db.query(SystemCapability)
            .join(CapabilityDefinition)
            .filter(SystemCapability.system_id == system_id)
            .all()
        )

        result = []
        for cap in capabilities:
            result.append(
                {
                    "name": cap.capability.name,
                    "display_name": cap.capability.display_name,
                    "category": cap.capability.category,
                    "type": cap.capability.capability_type,
                    "is_available": cap.is_available,
                    "detected_value": cap.detected_value,
                    "version_info": cap.version_info,
                    "configuration_path": cap.configuration_path,
                    "last_detected": (
                        cap.last_detected.isoformat() if cap.last_detected else None
                    ),
                    "detection_method": cap.detection_method_used,
                    "notes": cap.notes,
                }
            )

        return result
