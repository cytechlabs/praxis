# System Management Schema Extensions

This document outlines the database schema extensions implemented to support enhanced system management functionality.

## New Tables

### system_metadata

Stores detailed technical and operational information about managed systems.

| Column | Type | Description |
|--------|------|-------------|
| id | Integer | Primary key |
| system_id | Integer | Foreign key to systems table |
| cpu_arch | String(50) | CPU architecture |
| cpu_cores | Integer | Number of CPU cores |
| memory_total | BigInteger | Total memory in bytes |
| disk_total | BigInteger | Total disk space in bytes |
| environment_type | String(50) | e.g., production, staging |
| maintenance_window | String(100) | Scheduled maintenance period |
| owner_contact | String(255) | System owner contact information |
| location | String(255) | Physical or virtual location |
| ssh_port | Integer | SSH port (default: 22) |
| last_connection | DateTime | Last successful connection timestamp |
| connection_status | String(50) | Current connection status |

### jobs

Manages scheduled system operations.

| Column | Type | Description |
|--------|------|-------------|
| id | Integer | Primary key |
| system_id | Integer | Foreign key to systems table |
| job_type | String(50) | Type of job (e.g., update, audit) |
| schedule | String(100) | Cron expression for scheduling |
| status | String(50) | Current job status |
| last_run | DateTime | Last execution timestamp |
| next_run | DateTime | Next scheduled execution |
| created_by | Integer | Foreign key to user who created the job |

### job_history

Tracks the execution history of scheduled jobs.

| Column | Type | Description |
|--------|------|-------------|
| id | Integer | Primary key |
| job_id | Integer | Foreign key to jobs table |
| start_time | DateTime | Job start timestamp |
| end_time | DateTime | Job completion timestamp |
| status | String(50) | Execution status |
| result | Text | Job execution result |
| error_message | Text | Error details if failed |

### system_audits

Records system changes for audit purposes.

| Column | Type | Description |
|--------|------|-------------|
| id | Integer | Primary key |
| system_id | Integer | Foreign key to systems table |
| audit_type | String(50) | Type of audit record |
| changed_by | Integer | Foreign key to user who made the change |
| changed_at | DateTime | When the change occurred |
| old_value | Text | Previous value |
| new_value | Text | New value |
| operation | String(50) | Type of operation performed |

### package_history

Tracks package installation and update history.

| Column | Type | Description |
|--------|------|-------------|
| id | Integer | Primary key |
| package_id | Integer | Foreign key to packages table |
| system_id | Integer | Foreign key to systems table |
| operation | String(50) | Operation type (install, update, remove) |
| old_version | String(50) | Previous package version |
| new_version | String(50) | New package version |
| performed_at | DateTime | When the operation was performed |
| performed_by | Integer | Foreign key to user who performed the operation |
| job_history_id | Integer | Foreign key to job_history if part of a scheduled job |

## Extensions to Existing Tables

### systems

Added columns to the systems table:

| Column | Type | Description |
|--------|------|-------------|
| registered_at | DateTime | When the system was registered |
| registered_by | Integer | Foreign key to user who registered the system |
| update_policy | String(50) | System update policy configuration |
| last_successful_update | DateTime | Last successful system update |

### packages

Added columns to the packages table:

| Column | Type | Description |
|--------|------|-------------|
| installation_date | DateTime | When the package was installed |
| package_type | String(50) | Type of package |
| is_security_critical | Boolean | Whether package is security-critical |

## Relationships

- Each system has one system_metadata record (1:1)
- Systems can have multiple jobs (1:N)
- Jobs have multiple history records (1:N)
- Systems have multiple audit records (1:N)
- Packages have multiple history records (1:N)
- Package operations can be linked to job executions (N:1)

## Indexes

The following indexes are maintained for performance:

- Primary key indexes on all tables
- Foreign key indexes where appropriate
- Additional indexes on frequently queried columns:
  - system_id in system_metadata (unique)
  - hostname in systems
  - name in packages
  - job_id in job_history

## Usage Examples

### System Registration

When a new system is registered:
1. Create record in systems table
2. Create corresponding system_metadata record
3. Record registration in system_audits

### Package Updates

When packages are updated:
1. Update package version in packages table
2. Create package_history record
3. If part of a scheduled job, link to job_history

### System Auditing

System changes are tracked by:
1. Recording changes in system_audits table
2. Including user who made the change
3. Storing both old and new values for change tracking

### Job Scheduling

To schedule system operations:
1. Create job record with schedule
2. Track executions in job_history
3. Link related operations (e.g., package updates) to job execution
