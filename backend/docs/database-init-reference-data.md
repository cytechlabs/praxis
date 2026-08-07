# Database Initialization for Reference Data

## Overview
This document describes the implementation of automatic database initialization for reference data in the Praxis application. Reference data includes information that is essential for the application to function and should always be present in a consistent state, such as supported Linux distributions.

## Implementation Approach

### PostgreSQL Initialization Scripts
We utilize Docker's PostgreSQL initialization feature, which automatically executes SQL scripts located in the `/docker-entrypoint-initdb.d/` directory when the container is first created. This approach ensures that reference data is consistently available in every new instance of the database.

### Directory Structure
```
backend/
├── app/
│   └── db/
│       └── init/
│           └── init.sql    # Database initialization script
```

### Docker Configuration
The `docker-compose.yml` includes a volume mount that makes the initialization scripts available to the PostgreSQL container:

```yaml
services:
  db:
    volumes:
      - ./backend/app/db/init:/docker-entrypoint-initdb.d
```

## Reference Data

### Linux Distributions
The initialization script creates and populates the `distros` table with supported Linux distributions. This includes:

- Ubuntu LTS versions (18.04, 20.04, 22.04)
- RHEL versions (8, 9)

Each entry contains:
- Distribution name
- Version
- Release date
- End of life date
- Automatic timestamps (created_at, updated_at)

## Implementation Details

### Table Schema
```sql
CREATE TABLE IF NOT EXISTS distros (
    id INTEGER PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    version VARCHAR(50) NOT NULL,
    release_date DATE NOT NULL,
    end_of_life_date DATE NOT NULL,
    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS ix_distros_name ON distros(name);
```

### Data Population
The initialization script includes INSERT statements for each supported distribution. For example:

```sql
INSERT INTO distros (id, name, version, release_date, end_of_life_date) VALUES
(1, 'Ubuntu', '18.04', '2018-04-26', '2028-04-26');
```

## Usage

### Initial Setup
The initialization occurs automatically when creating a fresh database container:
```bash
# Remove existing containers and volumes, then create fresh containers.
docker compose -f docker-compose.yml -f docker-compose.prod.yml --profile bundled --profile proxy down -v
docker compose -f docker-compose.yml -f docker-compose.prod.yml --profile bundled --profile proxy up -d --build
```

### Modifying Reference Data
To modify the reference data:
1. Update the INSERT statements in `backend/app/db/init/init.sql`
2. Recreate the database container to apply changes

### Verification
You can verify the data initialization by connecting to the database and querying the distros table:
```sql
SELECT * FROM distros;
```

## Benefits
- **Consistency**: Ensures reference data is always present and consistent
- **Version Control**: Reference data is tracked in version control with the application code
- **Automation**: No manual intervention required for new deployments
- **Reliability**: Uses native PostgreSQL initialization features
