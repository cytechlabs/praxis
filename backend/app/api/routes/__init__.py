"""
API routes module.
"""

from .access_requests import router as access_requests_router
from .access_reviews import router as access_reviews_router
from .activation_tokens import router as activation_tokens_router
from .activity_feed import router as activity_feed_router
from .agent import router as agent_router
from .agent_bootstrap import router as agent_bootstrap_router
from .agent_enroll import router as agent_enroll_router
from .airgap import router as airgap_router
from .alerts import router as alerts_router
from .analytics import router as analytics_router
from .app_settings import router as app_settings_router
from .audit import router as audit_router
from .audits import router as audits_router
from .auth import router as auth_router
from .baselines import router as baselines_router
from .bulk import router as bulk_router
from .command_approvals import router as command_approvals_router
from .command_execution import router as command_execution_router
from .command_result_processing import router as command_result_processing_router
from .command_whitelist import router as command_whitelist_router
from .compliance import checks_router as compliance_checks_router
from .compliance import executions_router as compliance_remediation_executions_router
from .compliance import exports_router as compliance_exports_router
from .compliance import fleet_router as compliance_fleet_router
from .compliance import plans_router as compliance_remediation_plans_router
from .compliance import policies_router as compliance_policies_router
from .compliance import remediation_fleet_router as compliance_remediation_fleet_router
from .compliance import remediation_router as compliance_remediation_router
from .compliance import starter_pack_router as compliance_starter_pack_router
from .compliance import systems_router as compliance_systems_router
from .connection_settings import router as connection_settings_router
from .content_channels import router as content_channels_router
from .content_profile_apply import router as content_profile_apply_router
from .content_profiles import router as content_profiles_router
from .content_profiles import systems_router as content_profile_systems_router
from .credentials import router as credentials_router
from .diagnostics import router as diagnostics_router
from .edition import router as edition_router
from .export import router as export_router
from .facts import router as facts_router
from .file_transfer import router as file_transfer_router
from .fleet_access import router as fleet_access_router
from .fleet_operations import router as fleet_operations_router
from .groups import router as groups_router
from .health import router as health_router
from .jobs import router as jobs_router
from .lifecycle import fleet_router as lifecycle_fleet_router
from .lifecycle import router as lifecycle_router
from .maintenance_windows import router as maintenance_windows_router
from .mirror_serve import router as mirror_serve_router
from .mirror_serve_credentials import router as mirror_serve_credentials_router
from .mirror_upstream_keys import router as mirror_upstream_keys_router
from .mirrors import router as mirrors_router
from .notification_preferences import router as notification_preferences_router
from .notifications import router as notifications_router
from .package_reports import router as package_reports_router
from .packages import router as packages_router
from .patch_advisories import router as patch_advisories_router
from .patch_executions import router as patch_executions_router
from .patch_policies import router as patch_policies_router
from .patch_rings import router as patch_rings_router
from .patch_update_plans import router as patch_update_plans_router
from .recordings import router as recordings_router
from .reports import router as reports_router
from .repos import router as repos_router
from .session_approvals import router as session_approvals_router
from .session_locks import router as session_locks_router
from .sessions import router as sessions_router
from .smart_groups import router as smart_groups_router
from .ssh import router as ssh_router
from .ssh_identity import router as ssh_identity_router
from .ssh_security import router as ssh_security_router
from .system_compare import router as system_compare_router
from .system_patch_advisories import router as system_patch_advisories_router
from .system_patch_policy import router as system_patch_policy_router
from .system_patch_ring import router as system_patch_ring_router
from .system_status import router as system_status_router
from .systems import router as systems_router
from .tags import router as tags_router
from .totp import router as totp_router
from .users import router as users_router
from .vault import router as vault_router
from .views import router as views_router

__all__ = [
    "app_settings_router",
    "activity_feed_router",
    "airgap_router",
    "alerts_router",
    "analytics_router",
    "audits_router",
    "auth_router",
    "baselines_router",
    "bulk_router",
    "command_approvals_router",
    "command_execution_router",
    "diagnostics_router",
    "connection_settings_router",
    "command_result_processing_router",
    "command_whitelist_router",
    "compliance_checks_router",
    "compliance_exports_router",
    "edition_router",
    "compliance_fleet_router",
    "compliance_policies_router",
    "compliance_remediation_executions_router",
    "compliance_remediation_fleet_router",
    "compliance_remediation_plans_router",
    "compliance_remediation_router",
    "compliance_starter_pack_router",
    "compliance_systems_router",
    "content_channels_router",
    "content_profile_apply_router",
    "content_profiles_router",
    "content_profile_systems_router",
    "credentials_router",
    "export_router",
    "facts_router",
    "lifecycle_router",
    "lifecycle_fleet_router",
    "access_requests_router",
    "access_reviews_router",
    "audit_router",
    "fleet_access_router",
    "fleet_operations_router",
    "groups_router",
    "health_router",
    "jobs_router",
    "maintenance_windows_router",
    "mirror_serve_router",
    "mirror_serve_credentials_router",
    "mirror_upstream_keys_router",
    "mirrors_router",
    "notification_preferences_router",
    "notifications_router",
    "package_reports_router",
    "packages_router",
    "patch_advisories_router",
    "patch_executions_router",
    "patch_policies_router",
    "patch_rings_router",
    "patch_update_plans_router",
    "reports_router",
    "repos_router",
    "file_transfer_router",
    "recordings_router",
    "session_approvals_router",
    "session_locks_router",
    "sessions_router",
    "ssh_router",
    "smart_groups_router",
    "activation_tokens_router",
    "agent_bootstrap_router",
    "agent_enroll_router",
    "agent_router",
    "ssh_identity_router",
    "ssh_security_router",
    "system_compare_router",
    "system_patch_advisories_router",
    "system_patch_policy_router",
    "system_patch_ring_router",
    "system_status_router",
    "systems_router",
    "tags_router",
    "totp_router",
    "users_router",
    "vault_router",
    "views_router",
]
