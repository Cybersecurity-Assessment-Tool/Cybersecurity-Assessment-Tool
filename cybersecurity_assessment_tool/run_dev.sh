#!/bin/bash

# Run Django development server and Django Q cluster simultaneously.
# Usage: ./run_dev.sh [port]  (default port: 8000)

PORT=${1:-8000}
MANAGE="python manage.py"
DIR="$(cd "$(dirname "$0")" && pwd)"

# Trap SIGINT/SIGTERM to kill both child processes on exit.
cleanup() {
    echo ""
    echo "Shutting down server and qcluster..."
    kill "$SERVER_PID" "$QCLUSTER_PID" 2>/dev/null
    wait "$SERVER_PID" "$QCLUSTER_PID" 2>/dev/null
    echo "Done."
    exit 0
}
trap cleanup SIGINT SIGTERM

cd "$DIR" || { echo "Could not find project directory: $DIR"; exit 1; }

echo "Starting Django development server on port $PORT..."
$MANAGE runserver "$PORT" &
SERVER_PID=$!

echo "Starting Django Q cluster..."
$MANAGE qcluster &
QCLUSTER_PID=$!

echo "Server PID: $SERVER_PID | QCluster PID: $QCLUSTER_PID"
echo "Press Ctrl+C to stop both."

# Wait for either process to exit.
wait -n 2>/dev/null || wait
cleanup
