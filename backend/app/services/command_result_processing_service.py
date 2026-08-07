"""
Command result processing service for parsing, analyzing, and formatting command execution results.
Provides output parsing, error identification, result formatting, status reporting, and history tracking.
"""

import logging
import re
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set

from sqlalchemy import and_, desc
from sqlalchemy.orm import Session

from ..db.command_execution_models import (
    CommandExecutionMetrics,
    CommandExecutionResult,
)

logger = logging.getLogger(__name__)


class CommandResultProcessor:
    """Service for processing and analyzing command execution results."""

    def __init__(self, db: Session):
        self.db = db
        self._error_patterns = self._load_error_patterns()
        self._output_parsers = self._load_output_parsers()

    def process_execution_result(
        self, execution_result: CommandExecutionResult
    ) -> Dict[str, Any]:
        """
        Process a command execution result with comprehensive analysis.

        Args:
            execution_result: The execution result to process

        Returns:
            Dict containing processed result with analysis
        """
        try:
            # Parse output
            parsed_output = self._parse_command_output(
                execution_result.command,
                execution_result.stdout,
                execution_result.stderr,
                execution_result.exit_code,
            )

            # Identify errors
            error_analysis = self._identify_errors(
                execution_result.stderr,
                execution_result.exit_code,
                execution_result.command,
            )

            # Format result
            formatted_result = self._format_execution_result(
                execution_result, parsed_output, error_analysis
            )

            # Update status
            status_info = self._determine_status(
                execution_result, error_analysis, parsed_output
            )

            # Track metrics
            self._update_execution_metrics(execution_result, status_info)

            return {
                "execution_id": execution_result.id,
                "processed_at": datetime.utcnow().isoformat(),
                "parsed_output": parsed_output,
                "error_analysis": error_analysis,
                "formatted_result": formatted_result,
                "status_info": status_info,
                "processing_status": "success",
            }

        except Exception as e:
            logger.error(
                "Error processing execution result %s: %s", execution_result.id, str(e)
            )
            return {
                "execution_id": execution_result.id,
                "processed_at": datetime.utcnow().isoformat(),
                "processing_status": "error",
                "error_message": str(e),
            }

    def _parse_command_output(
        self,
        command: str,
        stdout: Optional[str],
        stderr: Optional[str],
        exit_code: Optional[int],
    ) -> Dict[str, Any]:
        """Parse command output based on command type and content."""
        parsed = {
            "command_type": self._identify_command_type(command),
            "stdout_lines": (stdout or "").split("\n") if stdout else [],
            "stderr_lines": (stderr or "").split("\n") if stderr else [],
            "exit_code": exit_code,
            "output_summary": {},
            "structured_data": {},
        }

        # Apply command-specific parsers
        command_type = parsed["command_type"]
        if command_type in self._output_parsers:
            parser = self._output_parsers[command_type]
            try:
                structured_data = parser(stdout, stderr, exit_code)
                parsed["structured_data"] = structured_data
            except Exception as e:
                logger.warning("Failed to parse %s output: %s", command_type, str(e))

        # Generate output summary
        parsed["output_summary"] = self._generate_output_summary(
            stdout, stderr, exit_code
        )

        return parsed

    def _identify_command_type(self, command: str) -> str:
        """Identify the type of command for specialized parsing."""
        command_lower = command.lower().strip()

        # Define command type mappings
        command_mappings = {
            "process_info": ["ps", "top", "htop"],
            "disk_info": ["df", "du", "lsblk"],
            "memory_info": ["free", "vmstat"],
            "network_info": ["netstat", "ss", "lsof"],
            "service_management": ["systemctl", "service"],
            "log_analysis": ["journalctl", "dmesg"],
            "package_management": ["apt", "yum", "dnf", "zypper", "pip", "npm", "yarn"],
            "file_listing": ["ls", "find", "locate"],
            "file_content": ["cat", "head", "tail", "grep"],
            "file_operation": ["cp", "mv", "rm", "mkdir"],
            "network_operation": ["ping", "curl", "wget"],
            "identity_info": ["whoami", "id", "pwd"],
        }

        # Check each command type
        for cmd_type, commands in command_mappings.items():
            if any(cmd in command_lower for cmd in commands):
                return cmd_type

        # Special case for echo
        if command_lower.startswith("echo"):
            return "echo"

        return "generic"

    def _identify_errors(
        self, stderr: Optional[str], exit_code: Optional[int], command: str
    ) -> Dict[str, Any]:
        """Identify and categorize errors from command execution."""
        error_analysis = {
            "has_errors": False,
            "error_type": None,
            "error_severity": "none",
            "error_messages": [],
            "suggested_fixes": [],
            "error_categories": [],
        }

        # Check exit code
        if exit_code is not None and exit_code != 0:
            error_analysis["has_errors"] = True
            error_analysis["error_type"] = "non_zero_exit"
            error_analysis["error_severity"] = self._determine_error_severity(exit_code)

        # Analyze stderr content
        if stderr:
            stderr_analysis = self._analyze_stderr_content(stderr)
            if stderr_analysis["has_errors"]:
                error_analysis["has_errors"] = True
                error_analysis["error_messages"].extend(
                    stderr_analysis["error_messages"]
                )
                error_analysis["error_categories"].extend(
                    stderr_analysis["error_categories"]
                )
                error_analysis["suggested_fixes"].extend(
                    stderr_analysis["suggested_fixes"]
                )

                # Update severity if stderr indicates higher severity
                if stderr_analysis["severity"] == "critical":
                    error_analysis["error_severity"] = "critical"
                elif (
                    stderr_analysis["severity"] == "high"
                    and error_analysis["error_severity"] != "critical"
                ):
                    error_analysis["error_severity"] = "high"

        # Command-specific error analysis
        command_errors = self._analyze_command_specific_errors(command, stderr)
        if command_errors:
            error_analysis["error_categories"].extend(command_errors)

        return error_analysis

    def _analyze_stderr_content(self, stderr: str) -> Dict[str, Any]:
        """Analyze stderr content for error patterns."""
        analysis = {
            "has_errors": False,
            "error_messages": [],
            "error_categories": [],
            "suggested_fixes": [],
            "severity": "low",
        }

        for pattern_name, pattern_info in self._error_patterns.items():
            if re.search(pattern_info["pattern"], stderr, re.IGNORECASE):
                analysis["has_errors"] = True
                analysis["error_messages"].append(pattern_info["message"])
                analysis["error_categories"].append(pattern_name)
                analysis["suggested_fixes"].extend(pattern_info.get("fixes", []))

                # Update severity
                pattern_severity = pattern_info.get("severity", "low")
                if pattern_severity == "critical":
                    analysis["severity"] = "critical"
                elif pattern_severity == "high" and analysis["severity"] != "critical":
                    analysis["severity"] = "high"
                elif pattern_severity == "medium" and analysis["severity"] == "low":
                    analysis["severity"] = "medium"

        return analysis

    def _determine_error_severity(self, exit_code: int) -> str:
        """Determine error severity based on exit code."""
        if exit_code == 1:
            return "low"
        if exit_code in [2, 126, 127]:
            return "medium"
        if exit_code in [128, 130, 137, 143]:
            return "high"
        if exit_code >= 128:
            return "critical"
        return "medium"

    def _analyze_command_specific_errors(
        self, command: str, stderr: Optional[str]
    ) -> List[str]:
        """Analyze command-specific error patterns."""
        if not stderr:
            return []

        command_lower = command.lower()
        stderr_lower = stderr.lower()
        categories = []

        # Define command-specific error mappings
        error_mappings = {
            "package_management": {
                "commands": ["apt", "yum", "dnf"],
                "errors": {
                    "permission denied": "package_permission_error",
                    "not found": "package_not_found",
                    "dependency": "package_dependency_error",
                },
            },
            "network_operations": {
                "commands": ["curl", "wget", "ping"],
                "errors": {
                    "connection refused": "network_connection_refused",
                    "timeout": "network_timeout",
                    "not found": "network_host_not_found",
                },
            },
            "filesystem_operations": {
                "commands": ["cp", "mv", "rm", "mkdir"],
                "errors": {
                    "permission denied": "filesystem_permission_error",
                    "no space left": "filesystem_no_space",
                    "not found": "filesystem_not_found",
                },
            },
        }

        # Check each command category
        for category_info in error_mappings.values():
            if any(cmd in command_lower for cmd in category_info["commands"]):
                for error_pattern, error_category in category_info["errors"].items():
                    if error_pattern in stderr_lower:
                        categories.append(error_category)

        return categories

    def _format_execution_result(
        self,
        execution_result: CommandExecutionResult,
        parsed_output: Dict[str, Any],
        error_analysis: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Format execution result for presentation."""
        return {
            "execution_summary": {
                "command": execution_result.command,
                "status": execution_result.execution_status,
                "exit_code": execution_result.exit_code,
                "duration_ms": execution_result.execution_time_ms,
                "started_at": (
                    execution_result.started_at.isoformat()
                    if execution_result.started_at
                    else None
                ),
                "completed_at": (
                    execution_result.completed_at.isoformat()
                    if execution_result.completed_at
                    else None
                ),
            },
            "output_info": {
                "stdout_lines": len(parsed_output["stdout_lines"]),
                "stderr_lines": len(parsed_output["stderr_lines"]),
                "has_output": bool(execution_result.stdout),
                "has_errors": error_analysis["has_errors"],
                "command_type": parsed_output["command_type"],
            },
            "resource_usage": {
                "memory_bytes": execution_result.max_memory_usage_bytes,
                "cpu_time_ms": execution_result.cpu_time_ms,
                "disk_io_bytes": execution_result.disk_io_bytes,
                "network_io_bytes": execution_result.network_io_bytes,
            },
            "security_info": {
                "risk_level": execution_result.risk_level,
                "validation_status": execution_result.validation_status,
                "requires_sudo": execution_result.requires_sudo,
                "actual_user": execution_result.actual_user,
            },
            "formatted_output": self._format_output_for_display(
                parsed_output, error_analysis
            ),
        }

    def _format_output_for_display(
        self, parsed_output: Dict[str, Any], error_analysis: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Format output for user-friendly display."""
        formatted = {
            "stdout": "\n".join(parsed_output["stdout_lines"]),
            "stderr": "\n".join(parsed_output["stderr_lines"]),
            "summary": parsed_output["output_summary"],
        }

        # Add structured data if available
        if parsed_output["structured_data"]:
            formatted["structured_data"] = parsed_output["structured_data"]

        # Add error information
        if error_analysis["has_errors"]:
            formatted["error_info"] = {
                "error_type": error_analysis["error_type"],
                "severity": error_analysis["error_severity"],
                "messages": error_analysis["error_messages"],
                "categories": error_analysis["error_categories"],
                "suggested_fixes": error_analysis["suggested_fixes"],
            }

        return formatted

    def _determine_status(
        self,
        execution_result: CommandExecutionResult,
        error_analysis: Dict[str, Any],
        parsed_output: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Determine overall execution status and health."""
        status_info = {
            "overall_status": execution_result.execution_status,
            "health_score": 100,  # Start with perfect score
            "status_details": [],
            "recommendations": [],
        }

        # Reduce health score based on issues
        if error_analysis["has_errors"]:
            severity = error_analysis["error_severity"]
            if severity == "critical":
                status_info["health_score"] -= 50
            elif severity == "high":
                status_info["health_score"] -= 30
            elif severity == "medium":
                status_info["health_score"] -= 20
            else:
                status_info["health_score"] -= 10

            status_info["status_details"].append(
                f"Errors detected with {severity} severity"
            )

        # Check performance issues
        if (
            execution_result.execution_time_ms
            and execution_result.execution_time_ms > 30000
        ):
            status_info["health_score"] -= 15
            status_info["status_details"].append("Long execution time detected")
            status_info["recommendations"].append(
                "Consider optimizing command or increasing timeout"
            )

        # Check resource usage
        if (
            execution_result.max_memory_usage_bytes
            and execution_result.max_memory_usage_bytes > 1024 * 1024 * 1024
        ):  # 1GB
            status_info["health_score"] -= 10
            status_info["status_details"].append("High memory usage detected")

        # Add recommendations based on error analysis
        if error_analysis["suggested_fixes"]:
            status_info["recommendations"].extend(error_analysis["suggested_fixes"])

        # Ensure health score doesn't go below 0
        status_info["health_score"] = max(0, status_info["health_score"])

        return status_info

    def _generate_output_summary(
        self, stdout: Optional[str], stderr: Optional[str], exit_code: Optional[int]
    ) -> Dict[str, Any]:
        """Generate a summary of command output."""
        summary = {
            "total_lines": 0,
            "stdout_lines": 0,
            "stderr_lines": 0,
            "exit_code": exit_code,
            "has_warnings": False,
            "has_errors": False,
            "key_information": [],
        }

        if stdout:
            stdout_lines = stdout.split("\n")
            summary["stdout_lines"] = len(stdout_lines)
            summary["total_lines"] += len(stdout_lines)

            # Extract key information from stdout
            summary["key_information"].extend(
                self._extract_key_information(stdout, "stdout")
            )

        if stderr:
            stderr_lines = stderr.split("\n")
            summary["stderr_lines"] = len(stderr_lines)
            summary["total_lines"] += len(stderr_lines)
            summary["has_errors"] = True

            # Check for warnings in stderr
            if any(
                warning in stderr.lower()
                for warning in ["warning", "warn", "deprecated"]
            ):
                summary["has_warnings"] = True

        return summary

    def _extract_key_information(self, output: str, stream_type: str) -> List[str]:
        """Extract key information from command output."""
        key_info = []

        # Look for common patterns that indicate important information
        lines = output.split("\n")
        for line in lines:
            line = line.strip()
            if not line:
                continue

            # Look for status indicators
            if any(
                indicator in line.lower()
                for indicator in ["status:", "state:", "result:", "total:", "count:"]
            ):
                key_info.append(f"{stream_type}: {line}")

            # Look for error/success indicators
            elif any(
                indicator in line.lower()
                for indicator in ["success", "completed", "finished", "done"]
            ):
                key_info.append(f"{stream_type}: {line}")

            # Look for numerical summaries
            elif re.search(r"\d+\s+(files?|items?|records?|bytes?)", line.lower()):
                key_info.append(f"{stream_type}: {line}")

        return key_info[:5]  # Limit to 5 key pieces of information

    def _update_execution_metrics(
        self, execution_result: CommandExecutionResult, status_info: Dict[str, Any]
    ) -> None:
        """Update execution metrics for reporting and analysis."""
        try:
            # Get or create metrics record for current hour
            now = datetime.utcnow()
            metric_date = now.replace(minute=0, second=0, microsecond=0)

            metrics = (
                self.db.query(CommandExecutionMetrics)
                .filter(
                    and_(
                        CommandExecutionMetrics.system_id == execution_result.system_id,
                        CommandExecutionMetrics.user_id == execution_result.user_id,
                        CommandExecutionMetrics.metric_date == metric_date,
                        CommandExecutionMetrics.metric_hour == now.hour,
                    )
                )
                .first()
            )

            if not metrics:
                metrics = CommandExecutionMetrics(
                    system_id=execution_result.system_id,
                    user_id=execution_result.user_id,
                    metric_date=metric_date,
                    metric_hour=now.hour,
                    total_executions=0,
                    successful_executions=0,
                    failed_executions=0,
                    timeout_executions=0,
                    validation_failures=0,
                    high_risk_executions=0,
                    sudo_executions=0,
                )
                self.db.add(metrics)
                self.db.flush()

            # Update counters
            metrics.total_executions += 1

            if execution_result.execution_status == "success":
                metrics.successful_executions += 1
            elif execution_result.execution_status == "failed":
                metrics.failed_executions += 1
            elif execution_result.execution_status == "timeout":
                metrics.timeout_executions += 1

            # Update performance metrics
            if execution_result.execution_time_ms:
                if metrics.avg_execution_time_ms is None:
                    metrics.avg_execution_time_ms = execution_result.execution_time_ms
                else:
                    # Calculate running average
                    total_time = (
                        metrics.avg_execution_time_ms * (metrics.total_executions - 1)
                        + execution_result.execution_time_ms
                    )
                    metrics.avg_execution_time_ms = (
                        total_time // metrics.total_executions
                    )

                metrics.max_execution_time_ms = max(
                    metrics.max_execution_time_ms or 0,
                    execution_result.execution_time_ms,
                )
                metrics.min_execution_time_ms = min(
                    metrics.min_execution_time_ms or float("inf"),
                    execution_result.execution_time_ms,
                )

            # Update resource metrics
            if execution_result.max_memory_usage_bytes:
                metrics.max_memory_usage_bytes = max(
                    metrics.max_memory_usage_bytes or 0,
                    execution_result.max_memory_usage_bytes,
                )

            # Update security metrics
            if execution_result.validation_status == "failed":
                metrics.validation_failures += 1

            if execution_result.risk_level in ["high", "critical"]:
                metrics.high_risk_executions += 1

            if execution_result.requires_sudo:
                metrics.sudo_executions += 1

            self.db.commit()

        except Exception as e:
            logger.error("Failed to update execution metrics: %s", str(e))
            self.db.rollback()

    def get_execution_history_with_analysis(
        self,
        system_id: Optional[int] = None,
        user_id: Optional[int] = None,
        limit: int = 50,
        offset: int = 0,
        include_analysis: bool = True,
        scope_system_ids: Optional[Set[int]] = None,
    ) -> Dict[str, Any]:
        """Get execution history with optional result analysis.

        PRA-281: ``scope_system_ids`` restricts results to the caller's fleet
        scope. ``None`` = tenant-wide (unchanged); an explicit set is an
        allow-list; an empty set returns no rows.
        """
        if scope_system_ids is not None and not scope_system_ids:
            return {
                "total_count": 0,
                "limit": limit,
                "offset": offset,
                "executions": [],
            }
        query = self.db.query(CommandExecutionResult)

        if system_id:
            query = query.filter(CommandExecutionResult.system_id == system_id)
        if user_id:
            query = query.filter(CommandExecutionResult.user_id == user_id)
        if scope_system_ids is not None:
            query = query.filter(CommandExecutionResult.system_id.in_(scope_system_ids))

        total_count = query.count()
        results = (
            query.order_by(desc(CommandExecutionResult.started_at))
            .offset(offset)
            .limit(limit)
            .all()
        )

        history_data = {
            "total_count": total_count,
            "limit": limit,
            "offset": offset,
            "executions": [],
        }

        for result in results:
            execution_data = {
                "id": result.id,
                "command": result.command,
                "status": result.execution_status,
                "exit_code": result.exit_code,
                "started_at": (
                    result.started_at.isoformat() if result.started_at else None
                ),
                "completed_at": (
                    result.completed_at.isoformat() if result.completed_at else None
                ),
                "execution_time_ms": result.execution_time_ms,
                "risk_level": result.risk_level,
                "validation_status": result.validation_status,
            }

            if include_analysis:
                # Process the result for analysis
                processed = self.process_execution_result(result)
                execution_data["analysis"] = processed

            history_data["executions"].append(execution_data)

        return history_data

    def get_execution_metrics_report(
        self,
        system_id: Optional[int] = None,
        user_id: Optional[int] = None,
        days: int = 7,
        scope_system_ids: Optional[Set[int]] = None,
    ) -> Dict[str, Any]:
        """Generate execution metrics report for specified period.

        PRA-281: ``scope_system_ids`` restricts the aggregated metrics rows to
        the caller's fleet scope (``None`` = tenant-wide; empty set → no rows →
        zeroed report).
        """
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=days)

        query = self.db.query(CommandExecutionMetrics).filter(
            CommandExecutionMetrics.metric_date >= start_date
        )

        if system_id:
            query = query.filter(CommandExecutionMetrics.system_id == system_id)
        if user_id:
            query = query.filter(CommandExecutionMetrics.user_id == user_id)

        if scope_system_ids is not None and not scope_system_ids:
            metrics = []
        elif scope_system_ids is not None:
            metrics = query.filter(
                CommandExecutionMetrics.system_id.in_(scope_system_ids)
            ).all()
        else:
            metrics = query.all()

        # Aggregate metrics
        report = {
            "period": {
                "start_date": start_date.isoformat(),
                "end_date": end_date.isoformat(),
                "days": days,
            },
            "summary": {
                "total_executions": sum(m.total_executions for m in metrics),
                "successful_executions": sum(m.successful_executions for m in metrics),
                "failed_executions": sum(m.failed_executions for m in metrics),
                "timeout_executions": sum(m.timeout_executions for m in metrics),
                "validation_failures": sum(m.validation_failures for m in metrics),
                "high_risk_executions": sum(m.high_risk_executions for m in metrics),
                "sudo_executions": sum(m.sudo_executions for m in metrics),
            },
            "performance": {
                "avg_execution_time_ms": (
                    sum(
                        m.avg_execution_time_ms
                        for m in metrics
                        if m.avg_execution_time_ms
                    )
                    / len([m for m in metrics if m.avg_execution_time_ms])
                    if metrics
                    else 0
                ),
                "max_execution_time_ms": max(
                    (
                        m.max_execution_time_ms
                        for m in metrics
                        if m.max_execution_time_ms
                    ),
                    default=0,
                ),
                "max_memory_usage_bytes": max(
                    (
                        m.max_memory_usage_bytes
                        for m in metrics
                        if m.max_memory_usage_bytes
                    ),
                    default=0,
                ),
            },
            "daily_breakdown": [],
        }

        # Calculate success rate
        total_executions = report["summary"]["total_executions"]
        if total_executions > 0:
            report["summary"]["success_rate"] = (
                report["summary"]["successful_executions"] / total_executions * 100
            )
        else:
            report["summary"]["success_rate"] = 0

        # Group metrics by date for daily breakdown
        daily_metrics = {}
        for metric in metrics:
            date_key = metric.metric_date.date().isoformat()
            if date_key not in daily_metrics:
                daily_metrics[date_key] = {
                    "date": date_key,
                    "total_executions": 0,
                    "successful_executions": 0,
                    "failed_executions": 0,
                    "timeout_executions": 0,
                }

            daily_metrics[date_key]["total_executions"] += metric.total_executions
            daily_metrics[date_key][
                "successful_executions"
            ] += metric.successful_executions
            daily_metrics[date_key]["failed_executions"] += metric.failed_executions
            daily_metrics[date_key]["timeout_executions"] += metric.timeout_executions

        report["daily_breakdown"] = list(daily_metrics.values())

        return report

    def _load_error_patterns(self) -> Dict[str, Dict[str, Any]]:
        """Load error patterns for stderr analysis."""
        return {
            "permission_denied": {
                "pattern": r"permission denied|access denied|operation not permitted",
                "message": "Permission denied - insufficient privileges",
                "severity": "medium",
                "fixes": [
                    "Check file/directory permissions",
                    "Run with appropriate user privileges",
                    "Use sudo if necessary",
                ],
            },
            "file_not_found": {
                "pattern": r"no such file or directory|file not found|cannot find",
                "message": "File or directory not found",
                "severity": "medium",
                "fixes": [
                    "Verify file path is correct",
                    "Check if file exists",
                    "Ensure proper working directory",
                ],
            },
            "network_error": {
                "pattern": r"connection refused|network unreachable|timeout|dns resolution failed",
                "message": "Network connectivity issue",
                "severity": "high",
                "fixes": [
                    "Check network connectivity",
                    "Verify target host is reachable",
                    "Check firewall settings",
                ],
            },
            "disk_space": {
                "pattern": r"no space left|disk full|quota exceeded",
                "message": "Insufficient disk space",
                "severity": "critical",
                "fixes": [
                    "Free up disk space",
                    "Check disk usage with df -h",
                    "Clean temporary files",
                ],
            },
            "memory_error": {
                "pattern": r"out of memory|cannot allocate memory|memory exhausted",
                "message": "Memory allocation failure",
                "severity": "critical",
                "fixes": [
                    "Check available memory",
                    "Reduce memory usage",
                    "Consider increasing system memory",
                ],
            },
            "syntax_error": {
                "pattern": r"syntax error|invalid syntax|parse error",
                "message": "Command syntax error",
                "severity": "low",
                "fixes": [
                    "Check command syntax",
                    "Verify command parameters",
                    "Consult command documentation",
                ],
            },
        }

    def _load_output_parsers(self) -> Dict[str, Any]:
        """Load command-specific output parsers."""
        return {
            "process_info": self._parse_process_info,
            "disk_info": self._parse_disk_info,
            "memory_info": self._parse_memory_info,
            "network_info": self._parse_network_info,
            "package_management": self._parse_package_management,
            "service_management": self._parse_service_management,
        }

    def _parse_process_info(
        self, stdout: Optional[str], stderr: Optional[str], exit_code: Optional[int]
    ) -> Dict[str, Any]:
        """Parse process information output (ps, top, etc.)."""
        if not stdout:
            return {}

        lines = stdout.strip().split("\n")
        if len(lines) < 2:
            return {}

        return {
            "process_count": len(lines) - 1,  # Exclude header
            "header": lines[0] if lines else "",
            "sample_processes": lines[1:6],  # First 5 processes
        }

    def _parse_disk_info(
        self, stdout: Optional[str], stderr: Optional[str], exit_code: Optional[int]
    ) -> Dict[str, Any]:
        """Parse disk information output (df, du, etc.)."""
        if not stdout:
            return {}

        # Simple parsing for df output
        lines = stdout.strip().split("\n")
        filesystems = []

        for line in lines[1:]:  # Skip header
            parts = line.split()
            if len(parts) >= 6:
                filesystems.append(
                    {
                        "filesystem": parts[0],
                        "size": parts[1],
                        "used": parts[2],
                        "available": parts[3],
                        "use_percent": parts[4],
                        "mount_point": parts[5],
                    }
                )

        return {"filesystems": filesystems}

    def _parse_memory_info(
        self, stdout: Optional[str], stderr: Optional[str], exit_code: Optional[int]
    ) -> Dict[str, Any]:
        """Parse memory information output (free, etc.)."""
        if not stdout:
            return {}

        lines = stdout.strip().split("\n")
        memory_info = {}

        for line in lines:
            if "Mem:" in line:
                parts = line.split()
                if len(parts) >= 7:
                    memory_info["total"] = parts[1]
                    memory_info["used"] = parts[2]
                    memory_info["free"] = parts[3]
                    memory_info["shared"] = parts[4]
                    memory_info["buff_cache"] = parts[5]
                    memory_info["available"] = parts[6]

        return memory_info

    def _parse_network_info(
        self, stdout: Optional[str], stderr: Optional[str], exit_code: Optional[int]
    ) -> Dict[str, Any]:
        """Parse network information output (netstat, ss, etc.)."""
        if not stdout:
            return {}

        lines = stdout.strip().split("\n")
        connections = []

        for line in lines[1:]:  # Skip header
            if line.strip():
                connections.append(line.strip())

        return {
            "connection_count": len(connections),
            "sample_connections": connections[:10],  # First 10 connections
        }

    def _parse_package_management(
        self, stdout: Optional[str], stderr: Optional[str], exit_code: Optional[int]
    ) -> Dict[str, Any]:
        """Parse package management output (apt, yum, etc.)."""
        if not stdout:
            return {}

        lines = stdout.strip().split("\n")
        packages = []

        for line in lines:
            if line.strip() and not line.startswith("#"):
                packages.append(line.strip())

        return {
            "package_count": len(packages),
            "packages": packages[:20],  # First 20 packages
        }

    def _parse_service_management(
        self, stdout: Optional[str], stderr: Optional[str], exit_code: Optional[int]
    ) -> Dict[str, Any]:
        """Parse service management output (systemctl, etc.)."""
        if not stdout:
            return {}

        lines = stdout.strip().split("\n")
        services = []

        for line in lines:
            if "active" in line.lower() or "inactive" in line.lower():
                services.append(line.strip())

        return {
            "service_count": len(services),
            "services": services[:15],  # First 15 services
        }
