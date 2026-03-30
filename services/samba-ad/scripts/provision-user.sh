#!/usr/bin/env bash

export LDB_MODULES_PATH=/usr/lib/samba/ldb

set -o errexit
set -o nounset
set -o pipefail

if [ $# -ne 2 ]; then
    echo "Usage: $0 <username> <employeeNumber>"
    exit 1
fi

log() {
  echo "[$(date +'%Y-%m-%d %H:%M:%S')] $*"
}

SAMBA_TOOL="${SAMBA_TOOL:-samba-tool}"
USERNAME="$1"
EMPLOYEENUMBER="$2"

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

ensure_ad_user "$USERNAME" "Passw0rd!" $EMPLOYEENUMBER
ensure_user_in_group "$USERNAME" "testgroup"
