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
  sudo apt-get install -y
    ca-certificates
    curl
    gnupg
    lsb-release

  sudo mkdir -p /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg

  echo
    "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu
    $(lsb_release -cs) stable" |
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

# Function to get architecture (x86_64, aarch64)
get_architecture() {
  local arch=$(uname -m)
  if [ "$arch" == "aarch64" ] || [ "$arch" == "arm64" ]; then
    echo "aarch64"
  else
    echo "x86_64"  # Default to x86_64 for all other architectures
  fi
}

# Function to start the Docker container
start_container() {
  local os=$1
  local arch=$2
  local image="fdiotools/builder-${os}:prod-${arch}"

  # Set memory and shared memory size based on architecture
  local shm_size="1024M"
  if [ "$arch" == "aarch64" ]; then
    shm_size="2048M"
  fi

  echo "Starting Docker container from image: $image"
  docker pull $image

  # Run the container with architecture-specific settings
  echo "Using shared memory size: $shm_size"
  sudo docker run --privileged --shm-size=${shm_size} -m24g $image /bin/bash -c "echo 'Container started successfully'; ls -la; uname -a"
}

# Display usage information
usage() {
  echo "Usage: $0 [os_version] [architecture]"
  echo "  os_version: Optional. The OS version to use (e.g., ubuntu2204, ubuntu2404, debian12)."
  echo "              If not provided, will auto-detect Ubuntu version from the host."
  echo "  architecture: Optional. The architecture to use (x86_64 or aarch64)."
  echo "                If not provided, will auto-detect from the host."
}

# Main execution
main() {
  # Process command line arguments
  if [ "$1" == "-h" ] || [ "$1" == "--help" ]; then
    usage
    exit 0
  fi

  ensure_docker_installed

  # Use provided OS version or auto-detec
  os_version=""
  if [ -n "$1" ]; then
    # OS version provided as argument - can be ubuntu2204, ubuntu2404, debian12, etc.
    os_version="$1"
    echo "Using provided OS version: $os_version"
  else
    # Auto-detect Ubuntu version and format i
    detected_ubuntu_version=$(get_ubuntu_version)
    ubuntu_version_no_dots=$(echo $detected_ubuntu_version | tr -d '.')
    os_version="ubuntu$ubuntu_version_no_dots"
    echo "Detected OS version: $os_version"
  fi

  # Use provided architecture or auto-detec
  architecture=""
  if [ -n "$2" ]; then
    # Architecture provided as argumen
    architecture="$2"
    echo "Using provided architecture: $architecture"
  else
    # Auto-detect the architecture
    architecture=$(get_architecture)
    echo "Detected architecture: $architecture"
  fi

  echo "Using fdiotools/builder-${os_version}:prod-${architecture}"

  # Start the container
  start_container $os_version $architecture
}

main "$@"
