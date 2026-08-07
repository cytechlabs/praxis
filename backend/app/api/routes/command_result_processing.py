"""
Command result processing API routes.
Provides endpoints for processing, analyzing, and retrieving command execution results.
"""

from datetime import datetime
from typing import Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ...core.auth import get_current_user, require_system_access
from ...core.entitlements import COMMANDS_METRICS, require_entitlement
from ...db.command_execution_models import CommandExecutionResult
from ...db.models import User
from ...db.session import get_db
from ...services.access_authorization_service import scoped_system_ids
from ...services.command_result_processing_service import CommandResultProcessor

router = APIRouter()


def _scope_for_filter(db: Session, current_user: User, system_id: Optional[int]):
    """PRA-281: resolve the caller's fleet scope and reject an explicit
    ``system_id`` filter that is out of scope with a non-disclosing 404 (before
    any aggregation). Returns the scope set (``None`` = tenant-wide admin) so
    callers can thread it into the processor.
    """
    scope = scoped_system_ids(db, current_user)
    if system_id is not None and scope is not None and system_id not in scope:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"System {system_id} not found",
        )
    return scope


class ResultProcessingRequest(BaseModel):
    """Request model for processing a specific execution result."""

    execution_id: int = Field(..., description="ID of the execution result to process")


class ResultProcessingResponse(BaseModel):
    """Response model for result processing."""

    execution_id: int
    processed_at: str
    parsed_output: Dict
    error_analysis: Dict
    formatted_result: Dict
    status_info: Dict
    processing_status: str
    error_message: Optional[str] = None


class ExecutionHistoryResponse(BaseModel):
    """Response model for execution history with analysis."""

    total_count: int
    limit: int
    offset: int
    executions: List[Dict]


class MetricsReportResponse(BaseModel):
    """Response model for execution metrics report."""

    period: Dict
    summary: Dict
    performance: Dict
    daily_breakdown: List[Dict]


@router.post("/process/{execution_id}", response_model=ResultProcessingResponse)
async def process_execution_result(
    execution_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Process a specific command execution result.

    This endpoint analyzes the execution result, parses output, identifies errors,
    formats the result, and updates metrics.
    """
    try:
        # Get the execution result
        execution_result = (
            db.query(CommandExecutionResult)
            .filter(CommandExecutionResult.id == execution_id)
            .first()
        )

        if not execution_result:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Execution result {execution_id} not found",
            )

        # PRA-281: fleet-scope gate BEFORE the ownership check. A result on a
        # system outside the caller's scope — including the caller's OWN result
        # on a system that has since left scope — is a non-disclosing 404
        # (indistinguishable from missing), matching earlier command-execution
        # slices. In-scope-but-not-owned still yields the 403 below.
        scope = scoped_system_ids(db, current_user)
        if scope is not None and execution_result.system_id not in scope:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Execution result {execution_id} not found",
            )

        # Check permissions - users can only process their own results unless admin
        if not current_user.is_admin and execution_result.user_id != current_user.id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You don't have permission to process this execution result",
            )

        # Process the result
        processor = CommandResultProcessor(db)
        processed_result = processor.process_execution_result(execution_result)

        return ResultProcessingResponse(**processed_result)

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to process execution result: {str(e)}",
        ) from e


@router.get("/history", response_model=ExecutionHistoryResponse)
async def get_execution_history_with_analysis(
    system_id: Optional[int] = Query(None, description="Filter by system ID"),
    limit: int = Query(50, ge=1, le=200, description="Number of results to return"),
    offset: int = Query(0, ge=0, description="Number of results to skip"),
    include_analysis: bool = Query(
        True, description="Whether to include result analysis"
    ),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Get command execution history with optional result analysis.

    Returns a paginated list of execution results with comprehensive analysis
    including output parsing, error identification, and status reporting.
    """
    # PRA-281 scope check runs OUTSIDE the try so its non-disclosing 404 is not
    # swallowed by the broad 500 handler below.
    scope = _scope_for_filter(db, current_user, system_id)
    try:
        processor = CommandResultProcessor(db)

        # Regular users can only see their own executions
        user_id = None if current_user.is_admin else current_user.id

        history_data = processor.get_execution_history_with_analysis(
            system_id=system_id,
            user_id=user_id,
            limit=limit,
            offset=offset,
            include_analysis=include_analysis,
            scope_system_ids=scope,
        )

        return ExecutionHistoryResponse(**history_data)

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve execution history: {str(e)}",
        ) from e


@router.get(
    "/metrics/report",
    response_model=MetricsReportResponse,
    dependencies=[Depends(require_entitlement(COMMANDS_METRICS))],
)
async def get_execution_metrics_report(
    system_id: Optional[int] = Query(None, description="Filter by system ID"),
    days: int = Query(7, ge=1, le=90, description="Number of days to include"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Generate execution metrics report for specified period.

    Returns aggregated metrics including success rates, performance statistics,
    error analysis, and daily breakdowns.
    """
    scope = _scope_for_filter(db, current_user, system_id)
    try:
        processor = CommandResultProcessor(db)

        # Regular users can only see their own metrics
        user_id = None if current_user.is_admin else current_user.id

        report = processor.get_execution_metrics_report(
            system_id=system_id,
            user_id=user_id,
            days=days,
            scope_system_ids=scope,
        )

        return MetricsReportResponse(**report)

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to generate metrics report: {str(e)}",
        ) from e


@router.get("/analysis/{execution_id}")
async def get_execution_analysis(
    execution_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Get detailed analysis for a specific execution result.

    Returns comprehensive analysis including output parsing, error identification,
    result formatting, and status reporting for a single execution.
    """
    try:
        # Get the execution result
        execution_result = (
            db.query(CommandExecutionResult)
            .filter(CommandExecutionResult.id == execution_id)
            .first()
        )

        if not execution_result:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Execution result {execution_id} not found",
            )

        # PRA-281: fleet-scope gate BEFORE the ownership check (see /process).
        scope = scoped_system_ids(db, current_user)
        if scope is not None and execution_result.system_id not in scope:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Execution result {execution_id} not found",
            )

        # Check permissions
        if not current_user.is_admin and execution_result.user_id != current_user.id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You don't have permission to view this execution result",
            )

        # Process and return analysis
        processor = CommandResultProcessor(db)
        analysis = processor.process_execution_result(execution_result)

        return analysis

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to analyze execution result: {str(e)}",
        ) from e


@router.get(
    "/summary/system/{system_id}",
    dependencies=[Depends(require_system_access())],
)
async def get_system_execution_summary(
    system_id: int,
    days: int = Query(7, ge=1, le=90, description="Number of days to include"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Get execution summary for a specific system.

    Returns aggregated execution statistics, error patterns, and performance
    metrics for commands executed on the specified system.
    """
    try:
        processor = CommandResultProcessor(db)

        # Regular users can only see their own executions
        user_id = None if current_user.is_admin else current_user.id

        # Get metrics report for the system
        report = processor.get_execution_metrics_report(
            system_id=system_id,
            user_id=user_id,
            days=days,
        )

        # Get recent execution history for additional context
        history = processor.get_execution_history_with_analysis(
            system_id=system_id,
            user_id=user_id,
            limit=10,
            offset=0,
            include_analysis=False,
        )

        return {
            "system_id": system_id,
            "period_days": days,
            "metrics": report,
            "recent_executions": history["executions"],
            "generated_at": datetime.utcnow().isoformat(),
        }

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to generate system summary: {str(e)}",
        ) from e


@router.get(
    "/errors/patterns",
    dependencies=[Depends(require_entitlement(COMMANDS_METRICS))],
)
async def get_error_patterns(
    system_id: Optional[int] = Query(None, description="Filter by system ID"),
    days: int = Query(7, ge=1, le=90, description="Number of days to analyze"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Get common error patterns from recent executions.

    Analyzes recent command executions to identify common error patterns,
    their frequency, and suggested fixes.
    """
    scope = _scope_for_filter(db, current_user, system_id)
    try:
        processor = CommandResultProcessor(db)

        # Regular users can only see their own executions
        user_id = None if current_user.is_admin else current_user.id

        # Get recent failed executions
        history = processor.get_execution_history_with_analysis(
            system_id=system_id,
            user_id=user_id,
            limit=200,  # Analyze more executions for patterns
            offset=0,
            include_analysis=True,
            scope_system_ids=scope,
        )

        # Analyze error patterns
        error_patterns = {}
        total_errors = 0

        for execution in history["executions"]:
            if (
                execution.get("analysis", {})
                .get("error_analysis", {})
                .get("has_errors")
            ):
                total_errors += 1
                error_analysis = execution["analysis"]["error_analysis"]

                for category in error_analysis.get("error_categories", []):
                    if category not in error_patterns:
                        error_patterns[category] = {
                            "count": 0,
                            "percentage": 0,
                            "recent_examples": [],
                            "suggested_fixes": set(),
                        }

                    error_patterns[category]["count"] += 1
                    error_patterns[category]["recent_examples"].append(
                        {
                            "execution_id": execution["id"],
                            "command": execution["command"],
                            "error_messages": error_analysis.get("error_messages", []),
                        }
                    )

                    # Collect suggested fixes
                    for fix in error_analysis.get("suggested_fixes", []):
                        error_patterns[category]["suggested_fixes"].add(fix)

        # Calculate percentages and convert sets to lists
        for pattern in error_patterns.values():
            pattern["percentage"] = (
                (pattern["count"] / total_errors * 100) if total_errors > 0 else 0
            )
            pattern["suggested_fixes"] = list(pattern["suggested_fixes"])
            pattern["recent_examples"] = pattern["recent_examples"][
                :5
            ]  # Limit examples

        return {
            "analysis_period_days": days,
            "total_executions_analyzed": len(history["executions"]),
            "total_errors": total_errors,
            "error_rate": (
                (total_errors / len(history["executions"]) * 100)
                if history["executions"]
                else 0
            ),
            "error_patterns": error_patterns,
            "generated_at": datetime.utcnow().isoformat(),
        }

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to analyze error patterns: {str(e)}",
        ) from e


@router.get(
    "/performance/trends",
    dependencies=[Depends(require_entitlement(COMMANDS_METRICS))],
)
async def get_performance_trends(
    system_id: Optional[int] = Query(None, description="Filter by system ID"),
    days: int = Query(30, ge=7, le=90, description="Number of days to analyze"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Get performance trends for command executions.

    Analyzes execution performance over time including execution times,
    resource usage, and success rates.
    """
    scope = _scope_for_filter(db, current_user, system_id)
    try:
        processor = CommandResultProcessor(db)

        # Regular users can only see their own metrics
        user_id = None if current_user.is_admin else current_user.id

        # Get metrics report
        report = processor.get_execution_metrics_report(
            system_id=system_id,
            user_id=user_id,
            days=days,
            scope_system_ids=scope,
        )

        # Calculate trends from daily breakdown
        daily_data = report["daily_breakdown"]
        trends = {
            "execution_count_trend": [],
            "success_rate_trend": [],
            "avg_execution_time_trend": [],
        }

        for day_data in daily_data:
            trends["execution_count_trend"].append(
                {
                    "date": day_data["date"],
                    "value": day_data["total_executions"],
                }
            )

            success_rate = (
                (day_data["successful_executions"] / day_data["total_executions"] * 100)
                if day_data["total_executions"] > 0
                else 0
            )
            trends["success_rate_trend"].append(
                {
                    "date": day_data["date"],
                    "value": success_rate,
                }
            )

        return {
            "analysis_period_days": days,
            "system_id": system_id,
            "summary": report["summary"],
            "performance": report["performance"],
            "trends": trends,
            "generated_at": datetime.utcnow().isoformat(),
        }

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to analyze performance trends: {str(e)}",
        ) from e
