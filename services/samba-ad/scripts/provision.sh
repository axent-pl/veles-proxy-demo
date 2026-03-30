#!/usr/bin/env bash

export LDB_MODULES_PATH=/usr/lib/samba/ldb

set -o errexit
set -o nounset
set -o pipefail

log() {
  echo "[$(date +'%Y-%m-%d %H:%M:%S')] $*"
}

SAMBA_TOOL="${SAMBA_TOOL:-samba-tool}"


ensure_ad_service() {
  local username="${1:?username is required}"
  local password="${2:?password is required}"

  if "$SAMBA_TOOL" user show "$username" >/dev/null 2>&1; then
    log "Service '$username' already exists."
    return 0
  fi

  log "Service '$username' does not exist. Creating..."
  "$SAMBA_TOOL" user create "$username" "$password"
  "$SAMBA_TOOL" user setexpiry "$username" --noexpiry
  "$SAMBA_TOOL" spn add "HTTP/$username" "$username"
  "$SAMBA_TOOL" spn add "HTTP/$username.example.local" "$username"
}


ensure_ad_user() {
  local username="${1:?username is required}"
  local password="${2:?password is required}"
  local employeenumber="${3:?employeenumber is required}"

  if "$SAMBA_TOOL" user show "$username" >/dev/null 2>&1; then
    log "User '$username' already exists."
    return 0
  fi

  log "User '$username' does not exist. Creating..."
  "$SAMBA_TOOL" user create "$username" "$password"

  # Create temporary LDIF file
  cat > /tmp/set-employeeNumber.ldif <<LDIF
dn: CN=$username,CN=Users,DC=example,DC=local
changetype: modify
replace: employeeNumber
employeeNumber: $employeenumber
-
LDIF
  
  # Apply the modification
  ldbmodify -H /var/lib/samba/private/sam.ldb /tmp/set-employeeNumber.ldif

  if "$SAMBA_TOOL" user show "$username" >/dev/null 2>&1; then
    log "User '$username' created successfully."
  else
    log "ERROR: failed to create user '$username'."
    return 1
  fi
}


ensure_ad_group() {
  local groupname="${1:?groupname is required}"

  if "$SAMBA_TOOL" group show "$groupname" >/dev/null 2>&1; then
    log "Group '$groupname' already exists."
    return 0
  fi

  log "Group '$groupname' does not exist. Creating..."
  "$SAMBA_TOOL" group add "$groupname"

  if "$SAMBA_TOOL" group show "$groupname" >/dev/null 2>&1; then
    log "Group '$groupname' created successfully."
  else
    log "ERROR: failed to create group '$groupname'."
    return 1
  fi
}


ensure_user_in_group() {
  local username="${1:?username is required}"
  local groupname="${2:?groupname is required}"

  if ! "$SAMBA_TOOL" user show "$username" >/dev/null 2>&1; then
    log "ERROR: user '$username' does not exist."
    return 1
  fi

  if ! "$SAMBA_TOOL" group show "$groupname" >/dev/null 2>&1; then
    log "ERROR: group '$groupname' does not exist."
    return 1
  fi

  # Check membership using 'group listmembers'
  if "$SAMBA_TOOL" group listmembers "$groupname" 2>/dev/null | grep -Fxq "$username"; then
    log "User '$username' is already a member of group '$groupname'."
    return 0
  fi

  log "User '$username' is not in group '$groupname'. Adding..."
  "$SAMBA_TOOL" group addmembers "$groupname" "$username"

  if "$SAMBA_TOOL" group listmembers "$groupname" 2>/dev/null | grep -Fxq "$username"; then
    log "User '$username' added to group '$groupname' successfully."
  else
    log "ERROR: failed to add user '$username' to group '$groupname'."
    return 1
  fi
}


ensure_ad_delegation() {
  local account="${1:?account is required}"
  shift

  if [ "$#" -eq 0 ]; then
    log "ERROR: at least one service principal is required."
    return 1
  fi

  if ! "$SAMBA_TOOL" user show "$account" >/dev/null 2>&1 \
     && ! "$SAMBA_TOOL" group show "$account" >/dev/null 2>&1; then
    log "ERROR: account '$account' does not exist."
    return 1
  fi

  local delegation_output
  delegation_output="$("$SAMBA_TOOL" delegation show "$account" 2>/dev/null || true)"

  # Ensure "Trust this user/computer for delegation to any authentication protocol"
  # is enabled via "delegation for-any-protocol ... on".
  #
  # We use a loose grep because exact formatting may vary a bit by version.
  if printf '%s\n' "$delegation_output" \
      | grep -Eiq 'any[ -]?protocol.*(on|true|yes)|trusted_to_authenticate_for_delegation.*(on|true|yes)'; then
    log "Delegation for-any-protocol already enabled for '$account'."
  else
    log "Enabling delegation for-any-protocol for '$account'..."
    "$SAMBA_TOOL" delegation for-any-protocol "$account" on
    delegation_output="$("$SAMBA_TOOL" delegation show "$account" 2>/dev/null || true)"
  fi

  local principal
  for principal in "$@"; do
    if printf '%s\n' "$delegation_output" | grep -Fqx "$principal" \
       || printf '%s\n' "$delegation_output" | grep -Fq " $principal" \
       || printf '%s\n' "$delegation_output" | grep -Fq ": $principal"; then
      log "Delegation target '$principal' already present for '$account'."
      continue
    fi

    log "Adding delegation target '$principal' to '$account'..."
    "$SAMBA_TOOL" delegation add-service "$account" "$principal"
    delegation_output="$("$SAMBA_TOOL" delegation show "$account" 2>/dev/null || true)"
  done

  log "Delegation ensured for '$account'."
}

ensure_ad_keytab() {
  local account="${1:?account is required}"
  shift

  if [ -f "/keytabs/$account.keytab" ]; then
    log "Keytabs for '$account' already exists"
    return 0
  fi

  local principal
  local step=0
  local ktutil_input=""
  for principal in "$@"; do
    log "Exporting keytab for '$account' SPN '$principal'..."
    samba-tool domain exportkeytab /keytabs/$account.$step.keytab --principal=$principal
    ktutil_input="${ktutil_input}rkt /keytabs/$account.$step.keytab
"
    step=$((step + 1))
  done

  printf '%swkt /keytabs/%s.keytab\nquit\n' "$ktutil_input" "$account" | ktutil

  log "Keytabs ensured for '$account'."
}

# user account
ensure_ad_user "testuser" "Passw0rd!" "demo"

# user groups
ensure_ad_group "testgroup"
ensure_ad_group "testgroup2"

# user in groups
ensure_user_in_group "testuser" "testgroup"
ensure_user_in_group "testuser" "testgroup2"

# kerberos application account
ensure_ad_service "app_svc" "Passw0rd!"

# proxy service account
ensure_ad_service "proxy_svc" "Passw0rd!"

# delegation
ensure_ad_delegation "proxy_svc" "HTTP/app_svc" "HTTP/app_svc.${DOMAIN}"

# keytab generation
ensure_ad_keytab "app_svc" "app_svc@${REALM}" "HTTP/app_svc@${REALM}" "HTTP/app_svc.${DOMAIN}@${REALM}"
ensure_ad_keytab "proxy_svc" "proxy_svc@${REALM}" "HTTP/proxy_svc@${REALM}" "HTTP/proxy_svc.${DOMAIN}@${REALM}"

touch /var/run/provisioning.done