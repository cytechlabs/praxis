# FastAPI Project Setup

## Overview

This document provides a reference guide for setting up the FastAPI project.

## Directory Structure

- `backend/app/api`: Contains the main FastAPI application and routers.
- `backend/app/core`: Contains core configurations and settings.
- `backend/docs`: Contains project documentation.

## Running the Application

To run the FastAPI application, start the production-parity stack:

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml --profile bundled --profile proxy up -d --build
```

The backend publishes no direct host port; it is reached through Caddy at
`https://localhost/api/backend/...` (PRA-299). Inside the container it listens on
`http://localhost:8000`.

## Configuration

Configuration settings are managed using Pydantic's `BaseSettings` in `backend/app/core/config.py`.

## Dependencies

Dependencies are listed in `backend/requirements.txt`. Ensure you have all necessary packages installed.

## Docker Integration

The `start.prod.sh` script in `backend/scripts` is the production image entrypoint
(PRA-299 retired the dev-only `start.sh`). It loads `.env` safely, waits for the
database, runs migrations + seeds, resolves the Vault token, and starts the
application under Uvicorn:

```bash
exec uvicorn app.api.main:app --host 0.0.0.0 --port 8000
```

## Future Features

This setup prepares the project for future features and enhancements.
