#!/usr/bin/env bash

# Detect CalicoVPP source layout through the Makefile target "make
# repo-layout". This was exposed release/v3.33.0 onwards. Earlier
# releases do not have that target - use pre-restructure constants.
detect_calicovpp_layout() {
  [ -n "${CALICOVPP_DIR:-}" ] || return 1
  [ -d "$CALICOVPP_DIR" ] || return 1

  local layout
  if layout=$(make --no-print-directory -s -C "$CALICOVPP_DIR" repo-layout 2>/dev/null); then
    local key value
    VPP_MANAGER_REL_PATH=
    VPP_BUILD_REL_PATH=
    CALICOVPP_AGENT_IMAGE=

    while IFS='=' read -r key value; do
      case "$key" in
        VPP_MANAGER_REL_PATH) VPP_MANAGER_REL_PATH=$value ;;
        VPP_BUILD_REL_PATH) VPP_BUILD_REL_PATH=$value ;;
        CALICOVPP_AGENT_IMAGE) CALICOVPP_AGENT_IMAGE=$value ;;
      esac
    done <<< "$layout"

    if [ -n "$VPP_MANAGER_REL_PATH" ] && [ -n "$VPP_BUILD_REL_PATH" ] && [ -n "$CALICOVPP_AGENT_IMAGE" ]; then
      CALICOVPP_MAKE_DIR="$CALICOVPP_DIR/$VPP_MANAGER_REL_PATH"
      export CALICOVPP_MAKE_DIR VPP_MANAGER_REL_PATH VPP_BUILD_REL_PATH CALICOVPP_AGENT_IMAGE
      return 0
    fi
  fi

  VPP_MANAGER_REL_PATH="vpp-manager"
  VPP_BUILD_REL_PATH="vpp-manager/vpp_build"
  CALICOVPP_AGENT_IMAGE="calicovpp/agent"

  CALICOVPP_MAKE_DIR="$CALICOVPP_DIR/$VPP_MANAGER_REL_PATH"
  export CALICOVPP_MAKE_DIR VPP_MANAGER_REL_PATH VPP_BUILD_REL_PATH CALICOVPP_AGENT_IMAGE
  return 0
}

calicovpp_default_vpp_build_dir() {
  if detect_calicovpp_layout; then
    printf '%s/%s\n' "$CALICOVPP_DIR" "$VPP_BUILD_REL_PATH"
    return 0
  fi

  printf '%s/vpp-manager/vpp_build\n' "$CALICOVPP_DIR"
}
