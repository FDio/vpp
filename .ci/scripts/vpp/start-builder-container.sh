#!/bin/bash

# Exit immediately if a command exits with a non-zero status
set -e

# Function to ensure Docker is installed
ensure_docker_installed() {
  if command -v docker &> /dev/null; then
    echo "Docker is already installed."
    return
  fi

  echo "Docker is not installed. Installing Docker..."

  sudo apt-get update
  sudo apt-get install -y \
    ca-certificates \
    curl \
    gnupg \
    lsb-release

  sudo mkdir -p /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg

  echo \
    "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
    $(lsb_release -cs) stable" | \
    sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

  sudo apt-get update
  sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

  echo "Docker installation completed."
}

# Function to get Ubuntu version (22.04, 24.04, etc.)
get_ubuntu_version() {
  if [ -f /etc/os-release ]; then
    source /etc/os-release
    if [ "$ID" == "ubuntu" ]; then
      echo "$VERSION_ID"  # This will output 22.04, 24.04, etc.
    else
      echo "Error: This script requires Ubuntu. Current OS: $ID" >&2
      exit 1
    fi
  else
    echo "Error: Cannot determine OS version. /etc/os-release file not found." >&2
    exit 1
  fi
}

# Function to start the Docker container
start_container() {
  local version=$1
  local image="fdiotools/builder-ubuntu${version}:prod-x86_64"
  echo "Starting Docker container from image: $image"
  docker pull $image
  sudo docker run --privileged --shm-size=1024M -m24g $image
}

# Display usage information
usage() {
  echo "Usage: $0 [ubuntu_version]"
  echo "  ubuntu_version: Optional. The Ubuntu version to use (e.g., 22.04, 24.04)."
  echo "                  If not provided, will auto-detect from the host."
}

# Main execution
main() {
  # Process command line arguments
  if [ "$1" == "-h" ] || [ "$1" == "--help" ]; then
    usage
    exit 0
  fi

  ensure_docker_installed

  # Use provided Ubuntu version or auto-detect
  ubuntu_version=""
  if [ -n "$1" ]; then
    # OS version provided as argument
    ubuntu_version="$1"
    echo "Using provided Ubuntu version: $ubuntu_version"
  else
    # Auto-detect the OS version
    ubuntu_version=$(get_ubuntu_version)
    echo "Detected Ubuntu version: $ubuntu_version"
  fi

  # Remove dots from version (e.g., 22.04 -> 2204) required
  # for fdiotools docker image naming convention
  ubuntu_version_no_dots=$(echo $ubuntu_version | tr -d '.')
  echo "Using fdiotools/builder-ubuntu$ubuntu_version_no_dots:prod-x86_64"

  # Start the container
  start_container $ubuntu_version_no_dots
}

main "$@"
