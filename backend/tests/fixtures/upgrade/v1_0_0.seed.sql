-- Operator data for the v1.0.0 upgrade fixture.
--
-- The 1.0.1 migrations backfill history that a released 1.0.0 database already
-- holds. A fixture carrying only the schema proves the chain applies; it cannot
-- prove the backfills read that history correctly. These rows are the smallest
-- shape that exercises all three:
--
--   audit attribution   a plan event and an execution event that name no host,
--                       alongside an event that already names one and an event
--                       about no host at all. The backfill has to reach the
--                       first two, leave the third alone, and touch neither the
--                       fourth nor any host the plan does not target.
--   command policy      surviving baseline rows, with one shipped entry absent
--                       because an administrator removed it. The upgrade has to
--                       read this installation as already initialized and leave
--                       the removal standing.
--   bootstrap admin     existing accounts, including the configured one. The
--                       upgrade has to record the installation as initialized
--                       without provisioning anything.
--
-- Every value is synthetic: reserved example hostnames, RFC 5737 documentation
-- addresses, and placeholder password fields that are not hashes and cannot
-- authenticate. Identifiers and timestamps are fixed so the dump is
-- reproducible.
--
-- Applied by scripts/test-upgrade-smoke.sh --regenerate, after alembic reaches
-- the target revision and before pg_dump.

BEGIN;

-- ------------------------------------------------------------------ reference

INSERT INTO groups (id, name, description, created_at, updated_at) VALUES
    (1, 'All Systems', 'Default group containing all systems',
     '2026-01-15 12:00:00', '2026-01-15 12:00:00');

INSERT INTO distros (id, name, version, release_date, end_of_life_date,
                     created_at, updated_at) VALUES
    (1, 'Ubuntu', '24.04', '2024-04-25', '2034-04-25',
     '2026-01-15 12:00:00', '2026-01-15 12:00:00');

INSERT INTO credentials (id, name, auth_method, sudo_method,
                         created_at, updated_at) VALUES
    (1, 'fixture-key', 'ssh_key', 'none',
     '2026-01-15 12:00:00', '2026-01-15 12:00:00');

-- ---------------------------------------------------------------- accounts
-- praxisadmin is the account a stock 1.0.0 install bootstraps, so the 1.0.1
-- boot has an installation to adopt rather than one to provision. The password
-- columns hold a fixed placeholder, not a hash; no login is possible with it.

INSERT INTO role (id, name, description, created_at, updated_at) VALUES
    (1, 'admin', 'Full access to everything',
     '2026-01-15 12:00:00', '2026-01-15 12:00:00'),
    (2, 'maintainer', 'Manage systems, credentials, packages, jobs, SSH, vault',
     '2026-01-15 12:00:00', '2026-01-15 12:00:00'),
    (3, 'auditor', 'Read-only access to all data',
     '2026-01-15 12:00:00', '2026-01-15 12:00:00');

INSERT INTO "user" (id, username, email, hashed_password, is_active,
                    created_at, updated_at) VALUES
    (1, 'praxisadmin', 'praxisadmin@example.test', 'placeholder-not-a-hash',
     true, '2026-01-15 12:00:00', '2026-01-15 12:00:00'),
    (2, 'fixture-operator', 'operator@example.test', 'placeholder-not-a-hash',
     true, '2026-01-15 12:00:00', '2026-01-15 12:00:00');

INSERT INTO user_role (user_id, role_id) VALUES (1, 1), (2, 2);

-- ------------------------------------------------------------------- hosts
-- Three hosts. The plan below targets the first two; the third exists so the
-- attribution backfill can be shown not to reach it.

INSERT INTO systems (id, hostname, ip_address, distro_id, os_version, status,
                     group_id, credentials_id, created_at, updated_at) VALUES
    (1, 'host-one.example.test',   '192.0.2.11', 1, '24.04', 'active', 1, 1,
     '2026-01-15 12:00:00', '2026-01-15 12:00:00'),
    (2, 'host-two.example.test',   '192.0.2.12', 1, '24.04', 'active', 1, 1,
     '2026-01-15 12:00:00', '2026-01-15 12:00:00'),
    (3, 'host-three.example.test', '192.0.2.13', 1, '24.04', 'active', 1, 1,
     '2026-01-15 12:00:00', '2026-01-15 12:00:00');

-- ---------------------------------------------------------- command policy
-- Two shipped whitelist entries and one shipped validation rule survive, which
-- is what marks this installation as one that already applied the baseline.
-- "APT Search" is a shipped entry deliberately left out: an administrator
-- deleted it before the upgrade, and it must not come back.

INSERT INTO command_whitelist (id, name, description, command_pattern, is_regex,
                               is_active, risk_level, category, requires_sudo,
                               timeout_seconds, created_by, requires_approval,
                               required_approvals, created_at, updated_at) VALUES
    (1, 'APT Update', 'Update package lists', 'apt-get update', false, true,
     'low', 'package_management', true, 300, 1, false, 1,
     '2026-01-15 12:00:00', '2026-01-15 12:00:00'),
    (2, 'APT Upgrade', 'Upgrade installed packages', 'apt-get upgrade', false,
     true, 'medium', 'package_management', true, 600, 1, false, 1,
     '2026-01-15 12:00:00', '2026-01-15 12:00:00');

INSERT INTO command_validation_rules (id, name, description, validation_type,
                                      pattern, is_regex, is_active, severity,
                                      created_by, created_at, updated_at) VALUES
    (1, 'Dangerous File Operations', 'Block recursive removal of /',
     'blacklist', 'rm\s+-rf\s+/', true, true, 'critical', 1,
     '2026-01-15 12:00:00', '2026-01-15 12:00:00');

-- ------------------------------------------------------------ patch history

INSERT INTO patch_update_plans (id, name, description, state, created_by,
                                created_at, updated_at) VALUES
    (1, 'Fixture baseline plan', 'Targets host-one and host-two', 'approved', 1,
     '2026-01-15 12:00:00', '2026-01-15 12:00:00');

INSERT INTO patch_update_plan_hosts (id, plan_id, system_id,
                                     system_hostname_snapshot,
                                     policy_resolution_kind,
                                     ring_resolution_status, wave_index,
                                     content_profile_state, state,
                                     created_at, updated_at) VALUES
    (1, 1, 1, 'host-one.example.test', 'direct_host', 'resolved', 0,
     'resolved', 'planned', '2026-01-15 12:00:00', '2026-01-15 12:00:00'),
    (2, 1, 2, 'host-two.example.test', 'direct_host', 'resolved', 0,
     'resolved', 'planned', '2026-01-15 12:00:00', '2026-01-15 12:00:00');

INSERT INTO patch_update_executions (id, plan_id, state, started_by, started_at,
                                     max_parallel_per_wave,
                                     plan_state_snapshot,
                                     created_at, updated_at) VALUES
    (1, 1, 'succeeded', 1, '2026-01-15 12:00:00', 5, 'approved',
     '2026-01-15 12:00:00', '2026-01-15 12:00:00');

INSERT INTO patch_update_execution_hosts (id, execution_id, plan_host_id,
                                          system_id_snapshot,
                                          system_hostname_snapshot, wave_index,
                                          state, created_at, updated_at) VALUES
    (1, 1, 1, 1, 'host-one.example.test', 0, 'succeeded',
     '2026-01-15 12:00:00', '2026-01-15 12:00:00'),
    (2, 1, 2, 2, 'host-two.example.test', 0, 'succeeded',
     '2026-01-15 12:00:00', '2026-01-15 12:00:00');

-- ------------------------------------------------------------ audit history
-- Events 1 and 2 are the shape 1.0.0 wrote for a change spanning several hosts:
-- they name the plan or the execution and no host at all. Event 3 already names
-- its own host. Event 4 is about no host. After the upgrade, 1 and 2 must link
-- to hosts 1 and 2 only, and 3 and 4 must gain no links.

INSERT INTO audit_events (id, schema_version, event_uuid, "timestamp", action,
                          outcome, target_kind, target_id, target_system_id,
                          context_json, created_at, updated_at) VALUES
    (1, 1, '00000000-0000-4000-8000-000000000001', '2026-01-15 12:00:00',
     'patch_update_plan.created', 'success', 'patch_update_plan', '1', NULL,
     '{}', '2026-01-15 12:00:00', '2026-01-15 12:00:00'),
    (2, 1, '00000000-0000-4000-8000-000000000002', '2026-01-15 12:00:00',
     'patch_update_execution.completed', 'success', 'patch_update_execution',
     '1', NULL, '{}', '2026-01-15 12:00:00', '2026-01-15 12:00:00'),
    (3, 1, '00000000-0000-4000-8000-000000000003', '2026-01-15 12:00:00',
     'host_facts.collected', 'success', 'system', '3', 3,
     '{}', '2026-01-15 12:00:00', '2026-01-15 12:00:00'),
    (4, 1, '00000000-0000-4000-8000-000000000004', '2026-01-15 12:00:00',
     'audit_sink.created', 'success', 'audit_sink', '1', NULL,
     '{}', '2026-01-15 12:00:00', '2026-01-15 12:00:00');

-- --------------------------------------------------------------- sequences
-- Explicit ids do not advance a serial's sequence. Without this every table
-- seeded above hands out a colliding id on the first insert after restore.

SELECT setval('groups_id_seq',                        (SELECT max(id) FROM groups));
SELECT setval('distros_id_seq',                       (SELECT max(id) FROM distros));
SELECT setval('credentials_id_seq',                   (SELECT max(id) FROM credentials));
SELECT setval('role_id_seq',                          (SELECT max(id) FROM role));
SELECT setval('user_id_seq',                          (SELECT max(id) FROM "user"));
SELECT setval('systems_id_seq',                       (SELECT max(id) FROM systems));
SELECT setval('command_whitelist_id_seq',             (SELECT max(id) FROM command_whitelist));
SELECT setval('command_validation_rules_id_seq',      (SELECT max(id) FROM command_validation_rules));
SELECT setval('patch_update_plans_id_seq',            (SELECT max(id) FROM patch_update_plans));
SELECT setval('patch_update_plan_hosts_id_seq',       (SELECT max(id) FROM patch_update_plan_hosts));
SELECT setval('patch_update_executions_id_seq',       (SELECT max(id) FROM patch_update_executions));
SELECT setval('patch_update_execution_hosts_id_seq',  (SELECT max(id) FROM patch_update_execution_hosts));
SELECT setval('audit_events_id_seq',                  (SELECT max(id) FROM audit_events));

COMMIT;
