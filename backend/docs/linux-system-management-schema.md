# Linux System Management Database Schema

This document outlines the database schema implementation for managing Linux systems, including system information, grouping, credentials, package management, and distribution tracking.

## Overview

The schema consists of six main tables:
- `systems`: Stores information about managed Linux systems
- `groups`: Organizes systems into logical groups
- `credentials`: Manages access credentials for systems
- `packages`: Tracks installed packages on systems
- `package_updates`: Records available updates for packages
- `distros`: Maintains information about supported Linux distributions

## Table Schemas

### Systems Table
```sql
Table: systems
- id (Primary Key, Auto Increment)
- hostname (VARCHAR(255), Unique, Indexed)
- ip_address (INET)
- os_distribution (VARCHAR(50), Indexed)
- os_version (VARCHAR(50), Indexed)
- last_audited (TIMESTAMP, Nullable)
- status (VARCHAR(50))
- group_id (Foreign Key to groups.id)
- credentials_id (Foreign Key to credentials.id)
- created_at (TIMESTAMP)
- updated_at (TIMESTAMP)
```

### Groups Table
```sql
Table: groups
- id (Primary Key, Auto Increment)
- name (VARCHAR(255), Unique, Indexed)
- description (TEXT)
- created_at (TIMESTAMP)
- updated_at (TIMESTAMP)
```

### Credentials Table
```sql
Table: credentials
- id (Primary Key, Auto Increment)
- name (VARCHAR(255), Unique)
- type (VARCHAR(50)) # SSH key, username/password
- username (VARCHAR(255), Nullable)
- password (TEXT, Nullable) # Encrypted/hashed
- ssh_key (TEXT, Nullable)
- vault_kv_path (VARCHAR(255)) # Path in HashiCorp Vault
- created_at (TIMESTAMP)
- updated_at (TIMESTAMP)
```

### Packages Table
```sql
Table: packages
- id (Primary Key, Auto Increment)
- system_id (Foreign Key to systems.id)
- name (VARCHAR(255), Indexed)
- installed_version (VARCHAR(50))
- last_audited (TIMESTAMP, Nullable)
- created_at (TIMESTAMP)
- updated_at (TIMESTAMP)
```

### Package Updates Table
```sql
Table: package_updates
- id (Primary Key, Auto Increment)
- package_id (Foreign Key to packages.id)
- system_id (Foreign Key to systems.id)
- available_version (VARCHAR(50))
- update_type (VARCHAR(50)) # security, normal
- discovered_on (TIMESTAMP)
- created_at (TIMESTAMP)
- updated_at (TIMESTAMP)
```

### Distros Table
```sql
Table: distros
- id (Primary Key, Auto Increment)
- name (VARCHAR(255), Indexed)
- version (VARCHAR(50))
- release_date (DATE)
- end_of_life_date (DATE)
- created_at (TIMESTAMP)
- updated_at (TIMESTAMP)
```

## Relationships

### One-to-Many Relationships
- `groups.id -> systems.group_id`: A group can contain multiple systems
- `systems.id -> packages.system_id`: A system can have multiple installed packages
- `packages.id -> package_updates.package_id`: A package can have multiple updates
- `credentials.id -> systems.credentials_id`: A credential set can be used by multiple systems

## Indexes

The following indexes are created for performance:

### Systems Table
- `ix_systems_id`: Primary key index
- `ix_systems_hostname`: For quick hostname lookups
- `ix_systems_os_distribution`: For filtering by OS distribution
- `ix_systems_os_version`: For filtering by OS version

### Groups Table
- `ix_groups_id`: Primary key index
- `ix_groups_name`: For quick group name lookups

### Credentials Table
- `ix_credentials_id`: Primary key index

### Packages Table
- `ix_packages_id`: Primary key index
- `ix_packages_name`: For quick package name lookups

### Package Updates Table
- `ix_package_updates_id`: Primary key index

### Distros Table
- `ix_distros_id`: Primary key index
- `ix_distros_name`: For quick distribution name lookups

## Implementation Details

The schema was implemented using SQLAlchemy models and Alembic migrations:

1. Models are defined in `backend/app/db/models.py`
2. Migration file: `backend/alembic/versions/20241129_1527_6414485e3d7e_add_linux_system_management_tables.py`

## Verifying the Implementation

You can verify the table structure using psql in the backend container:

```bash
# List all tables
docker compose exec backend psql $DATABASE_URL -c "\dt"

# View detailed table structure
docker compose exec backend psql $DATABASE_URL -c "\d+ systems"
docker compose exec backend psql $DATABASE_URL -c "\d+ groups"
docker compose exec backend psql $DATABASE_URL -c "\d+ credentials"
docker compose exec backend psql $DATABASE_URL -c "\d+ packages"
docker compose exec backend psql $DATABASE_URL -c "\d+ package_updates"
docker compose exec backend psql $DATABASE_URL -c "\d+ distros"
```

## Security Considerations

1. Credentials Management:
   - Passwords are stored encrypted/hashed
   - SSH keys are stored securely
   - Integration with HashiCorp Vault for sensitive data

2. Data Integrity:
   - Foreign key constraints ensure referential integrity
   - Unique constraints prevent duplicate entries
   - Timestamps track creation and updates

## Future Considerations

1. Performance:
   - Additional indexes may be added based on query patterns
   - Partitioning for large tables (e.g., package_updates)

2. Scalability:
   - The schema supports multiple systems and packages
   - Consider archiving old package updates
