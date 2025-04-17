#!/bin/bash -e

# Exit on any error
set -euo pipefail

# Configuration
readonly APP_NAME=${APP_NAME:-"enclave-app"}
readonly EIF_PATH="/$APP_NAME.eif"
readonly LOG_LEVEL=${LOG_LEVEL:-"INFO"}  # Default to INFO level

# Enclave configuration with reasonable defaults
readonly ENCLAVE_CPU_COUNT=${ENCLAVE_CPU_COUNT:-1}
readonly ENCLAVE_MEMORY_SIZE=${ENCLAVE_MEMORY_SIZE:-1000}
readonly ENCLAVE_CID=${ENCLAVE_CID:-16}

# Logging function
log() {
    local level=$1
    shift
    
    # Define log level priorities
    local -A log_levels=(
        ["DEBUG"]=0
        ["INFO"]=1
        ["WARN"]=2
        ["ERROR"]=3
        ["NONE"]=4
    )
    
    # Get the numeric priority of the current log level and configured log level
    local current_priority=${log_levels[$level]}
    local configured_priority=${log_levels[$LOG_LEVEL]}
    
    # Only log if the current level is at or above the configured level
    if [ "$current_priority" -ge "$configured_priority" ]; then
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $*"
    fi
}

# Error handling function
handle_error() {
    local exit_code=$1
    local error_message=$2
    log "ERROR" "$error_message"
    exit $exit_code
}

# Cleanup function
cleanup() {
    log "INFO" "Starting cleanup process"
    if nitro-cli describe-enclaves | grep -q "$APP_NAME"; then
        log "INFO" "Terminating enclave: $APP_NAME"
        if ! nitro-cli terminate-enclave --enclave-name "$APP_NAME"; then
            log "WARN" "Failed to terminate enclave gracefully"
        fi
    fi
    log "INFO" "Cleanup complete"
    exit 0
}

# Health check function
healthcheck() {
    local retries=3
    local delay=5
    
    for ((i=1; i<=retries; i++)); do
        if nitro-cli describe-enclaves | jq -e "[ .[] | select( .EnclaveName == \"$APP_NAME\" and .State == \"RUNNING\") ] | length == 1" > /dev/null; then
            log "DEBUG" "Health check passed"
            return 0
        fi
        if [ $i -lt $retries ]; then
            log "WARN" "Health check attempt $i failed, retrying in $delay seconds..."
            sleep $delay
        fi
    done
    
    log "ERROR" "Health check failed after $retries attempts"
    return 1
}

# Get EIF measurements function
get_measurements() {
    if [ ! -f "$EIF_PATH" ]; then
        handle_error 1 "EIF file not found at $EIF_PATH"
    fi

    log "INFO" "Getting measurements for EIF: $EIF_PATH"
    nitro-cli describe-eif --eif-path "$EIF_PATH" | jq '.Measurements'
}

# Start enclave function
start() {
    log "INFO" "Starting enclave process"
    
    # Set up signal handlers
    trap cleanup SIGTERM SIGINT SIGQUIT
    
    # Validate EIF file exists
    if [ ! -f "$EIF_PATH" ]; then
        handle_error 1 "EIF file not found at $EIF_PATH"
    fi
    
    # Start enclave based on mode
    if [[ -z "${ENCLAVE_DEBUG_MODE:-}" ]]; then
        log "INFO" "Starting production enclave"
        if ! nitro-cli run-enclave \
            --cpu-count "$ENCLAVE_CPU_COUNT" \
            --memory "$ENCLAVE_MEMORY_SIZE" \
            --eif-path "$EIF_PATH" \
            --enclave-cid "$ENCLAVE_CID"; then
            handle_error 1 "Failed to start enclave"
        fi
        log "INFO" "Enclave started successfully"
    else
        log "INFO" "Starting development enclave with console attachment"
        if ! nitro-cli run-enclave \
            --cpu-count "$ENCLAVE_CPU_COUNT" \
            --memory "$ENCLAVE_MEMORY_SIZE" \
            --eif-path "$EIF_PATH" \
            --enclave-cid "$ENCLAVE_CID" \
            --attach-console; then
            handle_error 1 "Failed to start enclave in debug mode"
        fi
        log "INFO" "Enclave started in debug mode"
    fi
    
    # Initial health check
    if ! healthcheck; then
        handle_error 1 "Initial health check failed"
    fi
    
    # Main loop
    while true; do
        if ! healthcheck; then
            handle_error 1 "Health check failed during runtime"
        fi
        sleep 30
    done
}

# Main execution
case "${1:-}" in
    start)
        start
        ;;
    healthcheck)
        healthcheck
        ;;
    measurements)
        get_measurements
        ;;
    *)
        log "ERROR" "Invalid command: $1"
        echo "Usage: $0 {start|healthcheck|measurements}"
        exit 1
        ;;
esac 