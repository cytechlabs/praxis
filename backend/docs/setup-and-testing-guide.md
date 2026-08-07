# Command Validation System - Setup and Testing Guide

## Database Setup

The command validation system requires a PostgreSQL database. You have several options:

### Option 1: Using Docker Compose (Recommended)

1. **Start the database using Docker Compose:**
```bash
# From the project root
docker compose --profile bundled up -d db
```

2. **Wait for the database to be ready, then run migrations:**
```bash
cd backend
alembic upgrade head
```

### Option 2: Local PostgreSQL Installation

1. **Install PostgreSQL locally:**
```bash
# Ubuntu/Debian
sudo apt-get install postgresql postgresql-contrib

# macOS with Homebrew
brew install postgresql
```

2. **Create database and user:**
```bash
sudo -u postgres psql
CREATE DATABASE praxis;
CREATE USER praxis_user WITH PASSWORD 'your_password';
GRANT ALL PRIVILEGES ON DATABASE praxis TO praxis_user;
\q
```

3. **Update environment variables:**
```bash
# Create .env file in backend directory
cd backend
cp .env.example .env

# Edit .env file with your database credentials
DATABASE_URL=postgresql://praxis_user:your_password@localhost:5432/praxis
```

4. **Run migrations:**
```bash
cd backend
alembic upgrade head
```

### Option 3: Testing Without Database

If you want to test the validation logic without a database connection, you can run the standalone demo scripts:

```bash
cd backend
python scripts/demo_validation_logic.py
```

## Running Tests

### Unit Tests (No Database Required)

The core validation logic can be tested without a database:

```bash
cd backend
python -m pytest tests/services/test_command_validation_service.py::test_normalize_command -v
python -m pytest tests/services/test_command_validation_service.py::test_pattern_matching -v
```

### Integration Tests (Database Required)

For full integration tests, ensure the database is running:

```bash
cd backend
python scripts/test_command_validation.py
```

### Demo Script

Run the interactive demonstration:

```bash
cd backend
python scripts/demo_validation_logic.py
```

## Verification Steps

### 1. Check Migration Status

```bash
cd backend
alembic current
alembic history
```

### 2. Verify Database Tables

Connect to your database and check that the tables were created:

```sql
-- Connect to PostgreSQL
psql -h localhost -U praxis_user -d praxis

-- List tables
\dt

-- Check command validation tables
SELECT table_name FROM information_schema.tables
WHERE table_schema = 'public'
AND table_name LIKE '%command%';
```

Expected tables:
- command_whitelist
- command_distro_mapping
- command_validation_rules
- command_validation_logs
- command_templates
- command_template_distros

### 3. Test Core Functionality

```bash
cd backend
python -c "
from app.services.command_validation_service import CommandValidationService
print('Command validation service imported successfully')

# Test basic validation logic
service = CommandValidationService(None)  # No DB for basic tests
normalized = service.normalize_command('  apt-get   update  ')
print(f'Normalized command: {normalized}')
"
```

## Troubleshooting

### Database Connection Issues

1. **"could not translate host name 'db'"**
   - The Docker database isn't running
   - Run: `docker compose --profile bundled up -d db`

2. **"connection refused"**
   - PostgreSQL isn't running locally
   - Start PostgreSQL service or use Docker

3. **"authentication failed"**
   - Check your database credentials in .env file
   - Ensure user has proper permissions

### Migration Issues

1. **"target database is not up to date"**
   - Run: `alembic upgrade head`

2. **"can't locate revision"**
   - Check alembic version table: `SELECT * FROM alembic_version;`
   - Reset if needed: `alembic stamp head`

### Import Issues

1. **"ModuleNotFoundError"**
   - Ensure you're in the backend directory
   - Check Python path: `export PYTHONPATH=$PYTHONPATH:$(pwd)`

## Development Workflow

### Making Changes

1. **Modify models:**
   - Edit files in `app/db/`
   - Generate migration: `alembic revision --autogenerate -m "description"`
   - Review and edit the generated migration
   - Apply: `alembic upgrade head`

2. **Test changes:**
   - Run unit tests: `python -m pytest tests/`
   - Run integration tests: `python scripts/test_command_validation.py`
   - Manual testing: `python scripts/demo_validation_logic.py`

### Code Quality

```bash
# Linting
cd backend
python -m pylint app/services/command_validation_service.py
python -m pylint app/services/distribution_detection_service.py

# Type checking (if mypy is installed)
python -m mypy app/services/
```

## Production Deployment

### Environment Variables

```bash
# Required
DATABASE_URL=postgresql://user:password@host:port/database
SECRET_KEY=your-secret-key

# Optional
COMMAND_VALIDATION_ENABLED=true
VALIDATION_LOG_LEVEL=INFO
MAX_COMMAND_LENGTH=1000
DEFAULT_TIMEOUT_SECONDS=30
```

### Database Initialization

```bash
# Run migrations
alembic upgrade head

# Populate initial data
python scripts/populate_command_whitelist.py
```

### Health Checks

```bash
# Check database connection
python -c "
from app.db.session import SessionLocal
from sqlalchemy import text
db = SessionLocal()
result = db.execute(text('SELECT 1')).scalar()
print(f'Database connection: {'OK' if result == 1 else 'FAILED'}')
db.close()
"
```

## Next Steps

Once the database is set up and migrations are applied:

1. **Populate initial data:**
   ```bash
   python scripts/populate_command_whitelist.py
   ```

2. **Test the full system:**
   ```bash
   python scripts/test_command_validation.py
   ```

3. **Explore the API (when implemented):**
   - Command validation endpoints
   - Distribution detection endpoints
   - Whitelist management endpoints

The command validation and whitelist system is now ready for integration with the main application!
