#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Cisco Systems, Inc.

function validate_ip() {
  local ip=$1
  if [[ ! $ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "Error: Invalid IP address: $ip"
    return 1
  fi
  return 0
}

function detect_numa_node() {
  local pci_dev=$1
  local pci_path="/sys/bus/pci/devices/${pci_dev}"

  if [[ -f "${pci_path}/numa_node" ]]; then
    local numa_node
    numa_node=$(cat "${pci_path}/numa_node" 2>/dev/null || echo "0")
    # Handle case where numa_node is -1 (NUMA not available)
    if [[ "$numa_node" -lt 0 ]]; then
      numa_node=0
    fi
    echo "$numa_node"
  else
    echo "0"
  fi
}

function get_cpus_on_numa() {
  local numa_node=$1
  local cpulist=""

  # Try to read from sysfs
  if [[ -f "/sys/devices/system/node/node${numa_node}/cpulist" ]]; then
    cpulist=$(cat "/sys/devices/system/node/node${numa_node}/cpulist" 2>/dev/null || echo "")
  fi

  # If no cpulist found, try using lscpu
  if [[ -z "$cpulist" ]] && command -v lscpu &>/dev/null; then
    cpulist=$(lscpu -p=CPU,NODE | grep ",${numa_node}$" | cut -d',' -f1 | tr '\n' ',' | sed 's/,$//')
  fi

  # If still no cpulist, fall back to default
  if [[ -z "$cpulist" ]]; then
    echo "1-3"
    return
  fi

  echo "$cpulist"
}

function adjust_cpus_for_numa() {
  local pci_dev=$1
  local workers=$2

  # Detect NUMA node
  local numa_node
  numa_node=$(detect_numa_node "$pci_dev")

  echo "Detected NUMA node: $numa_node for device $pci_dev"

  # If device is on NUMA 0, use default configuration
  if [[ "$numa_node" -eq 0 ]]; then
    echo "Device is on NUMA 0, using default CPU configuration"
    return
  fi

  # Get CPUs on the detected NUMA node
  local cpulist
  cpulist=$(get_cpus_on_numa "$numa_node")

  echo "CPUs on NUMA $numa_node: $cpulist"

  # Parse cpulist to get individual CPUs
  # Handle ranges like "16-31" or lists like "16,17,18" or mixed "16-19,24-27"
  local -a cpu_array
  IFS=',' read -ra cpu_ranges <<< "$cpulist"
  for range in "${cpu_ranges[@]}"; do
    if [[ "$range" =~ ^([0-9]+)-([0-9]+)$ ]]; then
      # It's a range
      local start="${BASH_REMATCH[1]}"
      local end="${BASH_REMATCH[2]}"
      for ((cpu=start; cpu<=end; cpu++)); do
        cpu_array+=("$cpu")
      done
    else
      # Single CPU
      cpu_array+=("$range")
    fi
  done

  # Ensure we have enough CPUs (skipping first core, so need workers + 2)
  if [[ ${#cpu_array[@]} -lt $((workers + 2)) ]]; then
    echo "Warning: Not enough CPUs on NUMA $numa_node (have ${#cpu_array[@]}, need $((workers + 2)))"
    echo "Using available CPUs anyway"
  fi

  # Skip the first CPU on NUMA node, set MAIN_CORE to second CPU
  MAIN_CORE="${cpu_array[1]}"

  # Set worker cores starting from third CPU
  if [[ $workers -gt 1 ]]; then
    local worker_start="${cpu_array[2]}"
    local worker_end="${cpu_array[$((workers + 1))]}"
    if [[ -n "$worker_end" ]]; then
      CFG_CORELIST_WKS="corelist-workers ${worker_start}-${worker_end}"
    else
      # Not enough CPUs, just use what we have
      CFG_CORELIST_WKS="corelist-workers ${worker_start}"
    fi
  else
    CFG_CORELIST_WKS="corelist-workers ${cpu_array[2]}"
  fi

  echo "Skipping first core (${cpu_array[0]}) on NUMA $numa_node"
  echo "Updated MAIN_CORE to: $MAIN_CORE"
  echo "Updated CFG_CORELIST_WKS to: $CFG_CORELIST_WKS"
}

