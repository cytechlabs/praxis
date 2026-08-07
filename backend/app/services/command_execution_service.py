"""
Command execution service for secure command execution on remote systems.
Provides command validation, execution, output capture, error handling,
timeout management, and resource limits.

PRA-153 #3d: command execution now goes through the transport
factory so System.transport_preference (auto / ssh / agent) routes
the request to the right transport. The CommandExecutionResult row
records which transport actually ran the command. Existing
nonzero-exit → execution_status="failed" semantics preserved.
"""

import asyncio
import concurrent.futures
import hashlib
import logging
import threading
import time
from datetime import datetime
from typing import Any, Awaitable, Dict, List, Optional, Set

from sqlalchemy.orm import Session

from ..core.entitlements import COMMANDS_APPROVALS, assert_entitled
from ..db.command_execution_models import (
    CommandExecutionPolicy,
    CommandExecutionResult,
    CommandExecutionSystemPolicy,
    CommandExecutionUserPolicy,
    CommandResourceLimit,
)
from ..db.models import CommandApproval, CommandWhitelist, System, User
from .broker_client import BrokerClient
from .command_validation_service import CommandValidationService
from .ssh_service import SSHService
from .transport import (
    TransportError,
    TransportUnavailable,
    TransportUnsupported,
    get_transport,
)

logger = logging.getLogger(__name__)


class CommandExecutionError(Exception):
    """Exception raised for command execution errors."""


class ResourceLimitExceeded(Exception):
    """Exception raised when resource limits are exceeded."""


class CommandExecutionService:
    """Service for secure command execution on remote systems."""

    def __init__(
        self,
        db: Session,
        *,
        broker_client: Optional[BrokerClient] = None,
        ssh_service: Optional[SSHService] = None,
    ):
        self.db = db
        self.ssh_service = ssh_service or SSHService(db)
        # IMPORTANT: do NOT default-create a BrokerClient here.
        # BrokerClient holds an httpx.AsyncClient bound to the event
        # loop it was created in. _run_async_from_sync uses
        # asyncio.run / fresh-thread loops that close after each call,
        # so a persistent BrokerClient leaks an AsyncClient tied to a
        # dead loop and breaks subsequent executions.
        # Tests inject a stub broker_client (no real httpx); production
        # sync paths build a fresh one per coroutine inside
        # _execute_command_with_monitoring.
        self.broker_client = broker_client
        self.validation_service = CommandValidationService(db)
        self._active_executions = {}  # execution_id -> execution_info
        self._execution_lock = threading.RLock()

    def execute_command(  # pylint: disable=too-many-locals
        self,
        system_id: int,
        user_id: int,
        command: str,
        timeout_seconds: Optional[int] = None,
        session_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        bypass_validation: bool = False,
        execution_context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Execute a command on the specified system with comprehensive monitoring.

        Args:
            system_id: ID of the target system
            user_id: ID of the user executing the command
            command: Command to execute
            timeout_seconds: Execution timeout (overrides policy defaults)
            session_id: Session identifier for tracking
            ip_address: Source IP address
            user_agent: User agent string
            bypass_validation: Whether to bypass command validation
            execution_context: Additional context information

        Returns:
            Dict containing execution results and metadata
        """
        start_time = datetime.utcnow()
        command_hash = hashlib.sha256(command.encode()).hexdigest()

        # Get system and user
        system = self.db.query(System).filter(System.id == system_id).first()
        if not system:
            raise CommandExecutionError(f"System with ID {system_id} not found")

        user = self.db.query(User).filter(User.id == user_id).first()
        if not user:
            raise CommandExecutionError(f"User with ID {user_id} not found")

        # Get execution policy
        policy = self._get_execution_policy(system_id, user_id)

        # Validate command if required
        validation_result = None
        if not bypass_validation and policy.require_validation:
            validation_result = self.validation_service.validate_command(
                command, system_id, user_id
            )
            if validation_result["status"] == "denied":
                return self._create_execution_result(
                    system_id=system_id,
                    user_id=user_id,
                    command=command,
                    command_hash=command_hash,
                    session_id=session_id,
                    ip_address=ip_address,
                    user_agent=user_agent,
                    execution_context=execution_context,
                    started_at=start_time,
                    execution_status="failed",
                    validation_status="failed",
                    error_type="validation_error",
                    error_message=validation_result["reason"],
                    risk_level=validation_result.get("risk_level") or "unknown",
                    requires_sudo=validation_result.get("requires_sudo"),
                    timeout_seconds=timeout_seconds or policy.default_timeout_seconds,
                )

        # PRA-80: Check if matched whitelist entry requires approval
        if validation_result and not bypass_validation:
            matched_command_id = validation_result.get("command_id")
            if matched_command_id:
                wl_entry = (
                    self.db.query(CommandWhitelist)
                    .filter(CommandWhitelist.id == matched_command_id)
                    .first()
                )
                if wl_entry and wl_entry.requires_approval:
                    # PRA-132: the command approval queue / multi-approval flow is
                    # a paid feature. A free-edition whitelist entry that requires
                    # approval must reject with the 402 entitlement contract
                    # BEFORE any CommandApproval row is created — otherwise a free
                    # user would strand a pending approval they cannot act on
                    # through the (gated) approval queue.
                    assert_entitled(COMMANDS_APPROVALS)

                    # PRA-129: compute expires_at (default 24h) and carry
                    # required_approvals from the whitelist entry.
                    from datetime import timedelta as _td

                    approval_timeout = wl_entry.timeout_seconds or 86400
                    approval = CommandApproval(
                        command=command,
                        system_id=system_id,
                        whitelist_entry_id=matched_command_id,
                        requested_by=user_id,
                        timeout_seconds=timeout_seconds
                        or policy.default_timeout_seconds,
                        required_approvals=wl_entry.required_approvals or 1,
                        expires_at=datetime.utcnow() + _td(seconds=approval_timeout),
                        session_id=session_id,
                    )
                    self.db.add(approval)
                    self.db.commit()
                    self.db.refresh(approval)

                    # Notify admins
                    try:
                        from .notification_service import create_notification

                        requesting_user = (
                            self.db.query(User).filter(User.id == user_id).first()
                        )
                        username = (
                            requesting_user.username
                            if requesting_user
                            else f"User {user_id}"
                        )
                        create_notification(
                            self.db,
                            type="approval_requested",
                            title="Command approval requested",
                            message=(f"{username} requests approval to run: {command}"),
                            severity="warning",
                        )
                    except Exception:  # pylint: disable=broad-except
                        pass

                    return self._create_execution_result(
                        system_id=system_id,
                        user_id=user_id,
                        command=command,
                        command_hash=command_hash,
                        session_id=session_id,
                        ip_address=ip_address,
                        user_agent=user_agent,
                        execution_context=execution_context,
                        started_at=start_time,
                        execution_status="pending_approval",
                        validation_status="validated",
                        error_message=(
                            f"Command requires admin approval (request #{approval.id})"
                        ),
                        risk_level=validation_result.get("risk_level") or "unknown",
                        requires_sudo=validation_result.get("requires_sudo"),
                        timeout_seconds=timeout_seconds
                        or policy.default_timeout_seconds,
                    )

        # Determine timeout
        effective_timeout = self._get_effective_timeout(
            timeout_seconds, policy, system_id, user_id
        )

        # Create execution result record
        execution_result = CommandExecutionResult(
            system_id=system_id,
            user_id=user_id,
            session_id=session_id,
            command=command,
            normalized_command=self._normalize_command(command),
            command_hash=command_hash,
            execution_status="running",
            validation_status="validated" if validation_result else "bypassed",
            # PRA-306: persist the validated risk classification. Bypassed executions
            # have no validation and stay ``unknown`` (auditable as bypassed).
            risk_level=(
                (validation_result.get("risk_level") or "unknown")
                if validation_result
                else "unknown"
            ),
            requires_sudo=(
                validation_result.get("requires_sudo")
                if validation_result
                and validation_result.get("requires_sudo") is not None
                else "sudo" in command.lower()
            ),
            ip_address=ip_address,
            user_agent=user_agent,
            started_at=start_time,
            timeout_seconds=effective_timeout,
            retry_count=0,
        )

        if execution_context:
            execution_result.set_execution_context(execution_context)

        self.db.add(execution_result)
        self.db.commit()
        self.db.refresh(execution_result)

        # Create resource limits
        resource_limits = self._create_resource_limits(execution_result.id, policy)

        try:
            # Execute the command
            result = self._execute_command_with_monitoring(
                system, command, effective_timeout, resource_limits, execution_result.id
            )

            # Update execution result
            execution_result.execution_status = result["status"]
            execution_result.exit_code = result.get("exit_code")
            execution_result.stdout = result.get("stdout")
            execution_result.stderr = result.get("stderr")
            execution_result.completed_at = datetime.utcnow()
            execution_result.execution_time_ms = result.get("execution_time_ms")
            execution_result.max_memory_usage_bytes = result.get("max_memory_usage")
            execution_result.cpu_time_ms = result.get("cpu_time_ms")
            execution_result.actual_user = result.get("actual_user")
            # PRA-153: durable transport attribution on the ledger.
            execution_result.transport = result.get("transport")

            if result.get("error_message"):
                execution_result.error_message = result["error_message"]
                execution_result.error_type = result.get(
                    "error_type", "execution_error"
                )

            self.db.commit()

            # Auto-process result so metrics and analysis are populated
            try:
                from .command_result_processing_service import CommandResultProcessor

                CommandResultProcessor(self.db).process_execution_result(
                    execution_result
                )
            except Exception as proc_err:  # pylint: disable=broad-except
                logger.warning(
                    "Auto-processing failed for execution %s: %s",
                    execution_result.id,
                    proc_err,
                )

            return self._format_execution_result(execution_result)

        except Exception as e:
            # Update execution result with error
            execution_result.execution_status = "failed"
            execution_result.completed_at = datetime.utcnow()
            execution_result.error_message = str(e)
            execution_result.error_type = type(e).__name__

            if start_time:
                execution_time = (datetime.utcnow() - start_time).total_seconds() * 1000
                execution_result.execution_time_ms = int(execution_time)

            self.db.commit()

            logger.error(
                "Command execution failed for system %s: %s", system.hostname, str(e)
            )
            raise CommandExecutionError(f"Command execution failed: {str(e)}") from e

    def _execute_command_with_monitoring(
        self,
        system: System,
        command: str,
        timeout_seconds: int,
        resource_limits: CommandResourceLimit,
        execution_id: int,
    ) -> Dict[str, Any]:
        """Execute command via the transport factory.

        PRA-153 #3d: routes through ``get_transport`` so
        ``System.transport_preference`` (auto/ssh/agent) decides
        whether the command goes over SSH or the agent path. The
        returned dict includes a ``"transport"`` key so the caller
        can populate ``CommandExecutionResult.transport``.

        Existing user-facing semantics preserved:
            - exit_code == 0          → execution_status="success"
            - exit_code != 0          → execution_status="failed"
            - TransportUnavailable    → "failed", error_type=
                                        "transport_unavailable",
                                        transport="agent" (operator intent)
            - TransportUnsupported    → "failed", error_type=
                                        "transport_unsupported"
            - other transport errors  → "failed", error_type=
                                        "transport_error"
        """
        start_time = time.time()

        # Register active execution
        with self._execution_lock:
            self._active_executions[execution_id] = {
                "system": system,
                "command": command,
                "start_time": start_time,
                "timeout": timeout_seconds,
                "resource_limits": resource_limits,
                "process": None,
            }

        # Wrap the command in `sh -c` so the transport's argv-based
        # exec semantics still honour shell features (pipes, redirects,
        # variable expansion). Both SSHTransport and AgentTransport
        # take list[str].
        argv = ["sh", "-c", command]

        # selected_transport_name is captured by the inner coroutine
        # so the EXCEPT handlers below can attribute a run_command
        # failure to the transport that was actually attempted, not
        # to system.transport_preference (which would write "auto"
        # for an op that actually went over ssh or agent).
        selected: Dict[str, Optional[str]] = {"name": None}

        async def _run():
            broker_client = self.broker_client
            owns_broker = False
            if broker_client is None:
                # Build + own a fresh BrokerClient inside this
                # coroutine so its httpx.AsyncClient is bound to the
                # current event loop and torn down before the loop
                # closes. Reusing a persistent client across the
                # asyncio.run / fresh-thread bridge would tie us to
                # a dead loop on the second call.
                broker_client = BrokerClient()
                owns_broker = True
            try:
                transport = await get_transport(
                    system,
                    broker_client,
                    ssh_service=self.ssh_service,
                )
                selected["name"] = transport.name
                cmd_result = await transport.run_command(
                    argv,
                    timeout_seconds=float(timeout_seconds) if timeout_seconds else None,
                )
                return transport.name, cmd_result
            finally:
                if owns_broker:
                    await broker_client.__aexit__(None, None, None)

        try:
            transport_name, cmd_result = _run_async_from_sync(_run())
            exit_code = cmd_result.exit_code
            status = "success" if exit_code == 0 else "failed"
            return {
                "status": status,
                "exit_code": exit_code,
                "stdout": cmd_result.stdout.decode("utf-8", errors="replace"),
                "stderr": cmd_result.stderr.decode("utf-8", errors="replace"),
                "execution_time_ms": int((time.time() - start_time) * 1000),
                "transport": transport_name,
            }
        except TransportUnavailable as e:
            # Operator asked for force-agent but tunnel is down.
            # Audit attribution = "agent" because that's what was
            # requested, not "ssh" (which we never tried).
            return {
                "status": "failed",
                "error_type": "transport_unavailable",
                "error_message": str(e),
                "execution_time_ms": int((time.time() - start_time) * 1000),
                "transport": "agent",
            }
        except TransportUnsupported as e:
            # Force-agent + an op the agent doesn't support — the
            # selection happened, so we know it was "agent".
            return {
                "status": "failed",
                "error_type": "transport_unsupported",
                "error_message": str(e),
                "execution_time_ms": int((time.time() - start_time) * 1000),
                "transport": selected["name"] or "agent",
            }
        except TransportError as e:
            return {
                "status": "failed",
                "error_type": "transport_error",
                "error_message": str(e),
                "execution_time_ms": int((time.time() - start_time) * 1000),
                # Prefer the selected transport name (post-factory
                # failures during run_command know what they were
                # talking to). Only fall back to operator intent
                # when the factory itself raised before selecting.
                "transport": selected["name"]
                or (system.transport_preference or "auto"),
            }
        except Exception as e:  # pylint: disable=broad-except
            return {
                "status": "failed",
                "error_message": str(e),
                "error_type": type(e).__name__,
                "execution_time_ms": int((time.time() - start_time) * 1000),
                "transport": selected["name"],
            }
        finally:
            # Unregister active execution
            with self._execution_lock:
                if execution_id in self._active_executions:
                    del self._active_executions[execution_id]

    def _monitor_execution(  # pylint: disable=too-many-branches
        self,
        stdout,
        stderr,
        timeout_seconds: int,
        resource_limits: CommandResourceLimit,
        execution_id: int,
    ) -> Dict[str, Any]:
        """Monitor command execution with resource tracking."""
        result = {
            "stdout": "",
            "stderr": "",
            "max_memory_usage": 0,
            "cpu_time_ms": 0,
            "status": "running",
        }

        start_time = time.time()
        stdout_data = []
        stderr_data = []

        # Read output with timeout
        try:
            # Set up non-blocking reads
            stdout.channel.settimeout(1.0)
            stderr.channel.settimeout(1.0)

            while True:
                current_time = time.time()
                if current_time - start_time > timeout_seconds:
                    result["status"] = "timeout"
                    result["error_message"] = "Command execution timed out"
                    break

                # Check if command is still running
                if stdout.channel.exit_status_ready():
                    # Read remaining output
                    try:
                        remaining_stdout = stdout.read().decode(
                            "utf-8", errors="replace"
                        )
                        if remaining_stdout:
                            stdout_data.append(remaining_stdout)
                    except Exception:
                        pass

                    try:
                        remaining_stderr = stderr.read().decode(
                            "utf-8", errors="replace"
                        )
                        if remaining_stderr:
                            stderr_data.append(remaining_stderr)
                    except Exception:
                        pass
                    break

                # Read available output
                try:
                    data = stdout.read(4096).decode("utf-8", errors="replace")
                    if data:
                        stdout_data.append(data)
                except Exception:
                    pass

                try:
                    data = stderr.read(4096).decode("utf-8", errors="replace")
                    if data:
                        stderr_data.append(data)
                except Exception:
                    pass

                # Check resource limits (simplified for SSH execution)
                if resource_limits and resource_limits.max_memory_bytes:
                    # Note: Resource monitoring for SSH commands is limited
                    # This would require additional tools on the remote system
                    pass

                time.sleep(0.1)  # Small delay to prevent busy waiting

        except Exception as e:
            result["status"] = "failed"
            result["error_message"] = f"Monitoring error: {str(e)}"

        # Combine output
        result["stdout"] = "".join(stdout_data)
        result["stderr"] = "".join(stderr_data)

        return result

    def _get_execution_policy(
        self, system_id: int, user_id: int
    ) -> CommandExecutionPolicy:
        """Get the effective execution policy for a system and user."""
        # Check for user-specific policy
        user_policy = (
            self.db.query(CommandExecutionUserPolicy)
            .join(CommandExecutionPolicy)
            .filter(
                CommandExecutionUserPolicy.user_id == user_id,
                CommandExecutionUserPolicy.is_active.is_(True),
                CommandExecutionPolicy.is_active.is_(True),
            )
            .order_by(CommandExecutionPolicy.priority.asc())
            .first()
        )

        if user_policy:
            return user_policy.policy

        # Check for system-specific policy
        system_policy = (
            self.db.query(CommandExecutionSystemPolicy)
            .join(CommandExecutionPolicy)
            .filter(
                CommandExecutionSystemPolicy.system_id == system_id,
                CommandExecutionSystemPolicy.is_active.is_(True),
                CommandExecutionPolicy.is_active.is_(True),
            )
            .order_by(CommandExecutionPolicy.priority.asc())
            .first()
        )

        if system_policy:
            return system_policy.policy

        # Check for global policies
        global_policy = (
            self.db.query(CommandExecutionPolicy)
            .filter(
                CommandExecutionPolicy.applies_to_all_systems.is_(True),
                CommandExecutionPolicy.applies_to_all_users.is_(True),
                CommandExecutionPolicy.is_active.is_(True),
            )
            .order_by(CommandExecutionPolicy.priority.asc())
            .first()
        )

        if global_policy:
            return global_policy

        # Return default policy
        return self._get_default_policy()

    def _get_default_policy(self) -> CommandExecutionPolicy:
        """Get or create a default execution policy."""
        default_policy = (
            self.db.query(CommandExecutionPolicy)
            .filter(CommandExecutionPolicy.name == "default")
            .first()
        )

        if not default_policy:
            # Create default policy
            default_policy = CommandExecutionPolicy(
                name="default",
                description="Default command execution policy",
                default_timeout_seconds=30,
                max_timeout_seconds=300,
                require_validation=True,
                log_stdout=True,
                log_stderr=True,
                monitor_resources=True,
                applies_to_all_systems=True,
                applies_to_all_users=True,
                created_by=1,  # System user
            )
            self.db.add(default_policy)
            self.db.commit()
            self.db.refresh(default_policy)

        return default_policy

    def _get_effective_timeout(
        self,
        requested_timeout: Optional[int],
        policy: CommandExecutionPolicy,
        system_id: int,
        user_id: int,
    ) -> int:
        """Get the effective timeout considering policy limits and overrides."""
        # Start with policy default
        timeout = policy.default_timeout_seconds

        # Apply user override if exists
        user_policy = (
            self.db.query(CommandExecutionUserPolicy)
            .filter(
                CommandExecutionUserPolicy.user_id == user_id,
                CommandExecutionUserPolicy.policy_id == policy.id,
                CommandExecutionUserPolicy.is_active.is_(True),
            )
            .first()
        )

        if user_policy and user_policy.timeout_override:
            timeout = user_policy.timeout_override

        # Apply system override if exists
        system_policy = (
            self.db.query(CommandExecutionSystemPolicy)
            .filter(
                CommandExecutionSystemPolicy.system_id == system_id,
                CommandExecutionSystemPolicy.policy_id == policy.id,
                CommandExecutionSystemPolicy.is_active.is_(True),
            )
            .first()
        )

        if system_policy and system_policy.timeout_override:
            timeout = system_policy.timeout_override

        # Apply requested timeout if provided and within limits
        if requested_timeout:
            timeout = min(requested_timeout, policy.max_timeout_seconds)

        return timeout

    def _create_resource_limits(
        self, execution_result_id: int, policy: CommandExecutionPolicy
    ) -> CommandResourceLimit:
        """Create resource limits for command execution."""
        resource_limits = CommandResourceLimit(
            execution_result_id=execution_result_id,
            max_memory_bytes=policy.max_memory_bytes,
            max_cpu_time_ms=policy.max_cpu_time_ms,
            max_disk_io_bytes=policy.max_disk_io_bytes,
            max_network_io_bytes=policy.max_network_io_bytes,
            max_open_files=policy.max_open_files,
            max_processes=policy.max_processes,
            limit_source="policy",
            policy_name=policy.name,
        )

        self.db.add(resource_limits)
        self.db.commit()
        self.db.refresh(resource_limits)

        return resource_limits

    def _normalize_command(self, command: str) -> str:
        """Normalize command for consistent storage and comparison."""
        # Remove extra whitespace
        normalized = " ".join(command.split())

        # Convert to lowercase for comparison (but preserve original case in storage)
        return normalized

    def _create_execution_result(  # pylint: disable=too-many-locals
        self,
        system_id: int,
        user_id: int,
        command: str,
        command_hash: str,
        session_id: Optional[str],
        ip_address: Optional[str],
        user_agent: Optional[str],
        execution_context: Optional[Dict[str, Any]],
        started_at: datetime,
        execution_status: str,
        validation_status: str,
        error_type: Optional[str] = None,
        error_message: Optional[str] = None,
        risk_level: str = "unknown",
        timeout_seconds: int = 30,
        requires_sudo: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """Create an execution result record for failed validations or errors."""
        execution_result = CommandExecutionResult(
            system_id=system_id,
            user_id=user_id,
            session_id=session_id,
            command=command,
            normalized_command=self._normalize_command(command),
            command_hash=command_hash,
            execution_status=execution_status,
            validation_status=validation_status,
            risk_level=risk_level,
            # PRA-306: prefer the whitelist's requires_sudo classification; fall back
            # to a string heuristic only when no classification is available.
            requires_sudo=(
                requires_sudo
                if requires_sudo is not None
                else "sudo" in command.lower()
            ),
            ip_address=ip_address,
            user_agent=user_agent,
            started_at=started_at,
            completed_at=datetime.utcnow(),
            timeout_seconds=timeout_seconds,
            error_type=error_type,
            error_message=error_message,
        )

        if execution_context:
            execution_result.set_execution_context(execution_context)

        self.db.add(execution_result)
        self.db.commit()
        self.db.refresh(execution_result)

        return self._format_execution_result(execution_result)

    def _format_execution_result(
        self, execution_result: CommandExecutionResult
    ) -> Dict[str, Any]:
        """Format execution result for API response."""
        username = None
        if execution_result.user_id:
            user = (
                self.db.query(User).filter(User.id == execution_result.user_id).first()
            )
            if user:
                username = user.username
        system_hostname = None
        if execution_result.system_id:
            system = (
                self.db.query(System)
                .filter(System.id == execution_result.system_id)
                .first()
            )
            if system:
                system_hostname = system.hostname
        return {
            "id": execution_result.id,
            "system_id": execution_result.system_id,
            "system_hostname": system_hostname,
            "user_id": execution_result.user_id,
            "username": username,
            "session_id": execution_result.session_id,
            "command": execution_result.command,
            "normalized_command": execution_result.normalized_command,
            "command_hash": execution_result.command_hash,
            "execution_status": execution_result.execution_status,
            "exit_code": execution_result.exit_code,
            "stdout": execution_result.stdout,
            "stderr": execution_result.stderr,
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
            "execution_time_ms": execution_result.execution_time_ms,
            "timeout_seconds": execution_result.timeout_seconds,
            "max_memory_usage_bytes": execution_result.max_memory_usage_bytes,
            "cpu_time_ms": execution_result.cpu_time_ms,
            "validation_status": execution_result.validation_status,
            "risk_level": execution_result.risk_level,
            "requires_sudo": execution_result.requires_sudo,
            "actual_user": execution_result.actual_user,
            # PRA-153: surface the transport that ran (or attempted)
            # this command so API/UI/history consumers can display +
            # filter without re-querying the model.
            "transport": execution_result.transport,
            "error_type": execution_result.error_type,
            "error_message": execution_result.error_message,
            "retry_count": execution_result.retry_count,
            "execution_context": execution_result.get_execution_context(),
        }

    def get_execution_history(
        self,
        system_id: Optional[int] = None,
        user_id: Optional[int] = None,
        limit: int = 100,
        offset: int = 0,
        system_ids: Optional[Set[int]] = None,
    ) -> List[Dict[str, Any]]:
        """Get command execution history with optional filtering.

        ``system_ids`` (PRA-281) is the caller's fleet scope: ``None`` = tenant-wide
        (admin), a set = allow-list, an empty set = nothing. It constrains the
        aggregate so a scoped caller never sees executions on systems outside
        their grants.
        """
        query = self.db.query(CommandExecutionResult)

        if system_id:
            query = query.filter(CommandExecutionResult.system_id == system_id)

        if user_id:
            query = query.filter(CommandExecutionResult.user_id == user_id)

        if system_ids is not None:
            if system_ids:
                query = query.filter(CommandExecutionResult.system_id.in_(system_ids))
            else:
                from sqlalchemy import false

                query = query.filter(false())

        results = (
            query.order_by(CommandExecutionResult.started_at.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )

        return [self._format_execution_result(result) for result in results]

    def get_active_executions(
        self, system_ids: Optional[Set[int]] = None
    ) -> List[Dict[str, Any]]:
        """Get currently active command executions.

        ``system_ids`` (PRA-281) constrains the list to the caller's fleet scope
        (``None`` = tenant-wide admin), so a scoped caller never sees active
        executions on systems outside their grants.
        """
        with self._execution_lock:
            active = []
            for execution_id, info in self._active_executions.items():
                sid = info["system"].id
                if system_ids is not None and sid not in system_ids:
                    continue
                active.append(
                    {
                        "execution_id": execution_id,
                        "system_id": sid,
                        "system_hostname": info["system"].hostname,
                        "command": info["command"],
                        "start_time": info["start_time"],
                        "timeout": info["timeout"],
                        "elapsed_time": time.time() - info["start_time"],
                    }
                )
            return active

    def kill_execution(
        self, execution_id: int, allowed_system_ids: Optional[Set[int]] = None
    ) -> bool:
        """Kill an active command execution.

        ``allowed_system_ids`` (PRA-281) is the caller's fleet scope. When it is a
        set and the execution's system is not in it, the kill is refused as if the
        execution did not exist (the route maps a ``False`` return to a
        non-disclosing 404), so a scoped caller cannot terminate work on systems
        outside their grants.
        """
        with self._execution_lock:
            if execution_id in self._active_executions:
                info = self._active_executions[execution_id]
                if (
                    allowed_system_ids is not None
                    and info["system"].id not in allowed_system_ids
                ):
                    return False
                if info.get("process"):
                    try:
                        info["process"].terminate()
                        return True
                    except Exception as e:
                        logger.error(
                            "Error killing execution %s: %s", execution_id, str(e)
                        )
                        return False
        return False

    def test_command_execution(self, system_id: int, user_id: int) -> Dict[str, Any]:
        """Test command execution capability on a system."""
        test_command = "echo 'Command execution test successful'"

        try:
            result = self.execute_command(
                system_id=system_id,
                user_id=user_id,
                command=test_command,
                timeout_seconds=10,
                execution_context={"test": True, "purpose": "connectivity_test"},
            )

            return {
                "system_id": system_id,
                "test_status": (
                    "success" if result["execution_status"] == "success" else "failed"
                ),
                "execution_time_ms": result.get("execution_time_ms", 0),
                "stdout": result.get("stdout", ""),
                "stderr": result.get("stderr", ""),
                "tested_at": datetime.utcnow().isoformat(),
            }

        except Exception as e:
            return {
                "system_id": system_id,
                "test_status": "error",
                "error_message": str(e),
                "tested_at": datetime.utcnow().isoformat(),
            }


def _run_async_from_sync(coro: Awaitable) -> Any:
    """Run an awaitable from sync code, even if a parent event loop
    is already running (e.g. FastAPI ``async def`` route → sync
    service method → wants to call async transport).

    ``asyncio.run`` raises if a loop is already running in this
    thread. The fallback runs the coroutine in a fresh worker thread
    that owns its own event loop. Synchronous from the caller's POV.
    """
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        # No running loop in this thread — straight asyncio.run is fine.
        return asyncio.run(coro)
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(asyncio.run, coro).result()
