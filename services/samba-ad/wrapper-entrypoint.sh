#!/usr/bin/env bash
set -Eeuo pipefail

ORIGINAL_ENTRYPOINT="/usr/local/bin/entrypoint.sh"
PROVISION_SCRIPT="/opt/scripts/provision.sh"
PROVISION_USER_SCRIPT="/opt/scripts/provision-user.sh"
PROVISION_USER_AD_NAME="kaktus"
PROVISION_USER_AS_NAME="admin"

log() {
  echo "[$(date +'%Y-%m-%d %H:%M:%S')] $*"
}

forward_signal() {
  local sig="$1"
  if [[ -n "${child_pid:-}" ]] && kill -0 "$child_pid" 2>/dev/null; then
    log "Forwarding signal ${sig} to entrypoint process ${child_pid}"
    kill "-${sig}" "$child_pid" 2>/dev/null || true
  fi
}

trap 'forward_signal TERM' TERM
trap 'forward_signal INT' INT
trap 'forward_signal HUP' HUP
trap 'forward_signal QUIT' QUIT

wait_for_samba() {
  local retries="${SAMBA_WAIT_RETRIES:-120}"
  local sleep_seconds="${SAMBA_WAIT_INTERVAL:-2}"

  log "Waiting for Samba to become ready..."

  for ((i=1; i<=retries; i++)); do
    if ! kill -0 "$child_pid" 2>/dev/null; then
      log "Entrypoint process exited before Samba became ready"
      return 1
    fi

    # Prefer a real health check if samba-tool is available
    if command -v samba-tool >/dev/null 2>&1; then
      if samba-tool domain info 127.0.0.1 >/dev/null 2>&1; then
        log "Samba is ready"
        return 0
      fi
    fi

    # Fallback: check common Samba AD DC ports
    if command -v nc >/dev/null 2>&1; then
      if nc -z 127.0.0.1 389 >/dev/null 2>&1 && nc -z 127.0.0.1 445 >/dev/null 2>&1; then
        log "Samba ports are accepting connections"
        return 0
      fi
    fi

    log "Samba not ready yet (${i}/${retries})"
    sleep "$sleep_seconds"
  done

  log "Timed out waiting for Samba readiness"
  return 1
}

run_provisioning_once() {
  if [[ ! -x "$PROVISION_SCRIPT" ]]; then
    log "Provision script not found or not executable: $PROVISION_SCRIPT"
    return 1
  fi

  if [[ ! -x "$PROVISION_USER_SCRIPT" ]]; then
    log "Provision-user script not found or not executable: $PROVISION_USER_SCRIPT"
    return 1
  fi

  log "Running $PROVISION_SCRIPT"
  "$PROVISION_SCRIPT"

  log "Running $PROVISION_USER_SCRIPT $PROVISION_USER_AD_NAME $PROVISION_USER_AS_NAME"
  "$PROVISION_USER_SCRIPT" $PROVISION_USER_AD_NAME $PROVISION_USER_AS_NAME

  log "Provisioning finished"
}

main() {
  log "Starting original entrypoint: $ORIGINAL_ENTRYPOINT $*"
  "$ORIGINAL_ENTRYPOINT" "$@" &
  child_pid=$!

  wait_for_samba
  run_provisioning_once

  log "Waiting for original entrypoint process ${child_pid}"
  wait "$child_pid"
}

main "$@"