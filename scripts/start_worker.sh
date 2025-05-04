#!/usr/bin/env bash
# Start RQ worker for scan tasks
# Requires REDIS_URL environment variable or default to redis://localhost:6379/0
REDIS_URL=${REDIS_URL:-redis://localhost:6379/0}
echo "Starting RQ worker on queue 'scans' with Redis '${REDIS_URL}'"
exec rq worker scans --url "$REDIS_URL"