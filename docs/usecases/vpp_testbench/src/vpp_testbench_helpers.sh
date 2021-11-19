#!/bin/bash
################################################################################
# @brief:       Helper functions for the VPP testbench project.
#               NOTE: functions prefixed with "host_only" are functions
#               intended to be executed on the host OS, **outside** of the
#               Docker containers. These are typically functions for bring-up
#               (i.e. creating the Docker networks, launching/terminating the
#               Docker containers, etc.). If a function is not prefixed with
#               "host_only", assume that the function/value/etc. is intended
#               for use within the Docker containers. We could maybe re-factor
#               this in the future so "host_only" functions live in a separate
#               file.
# @author:      Matthew Giassa <mgiassa@cisco.com>
# @copyright:   (C) Cisco 2021.
################################################################################

# Meant to be sourced, not executed directly.
if [ "${BASH_SOURCE[0]}" -ef "$0" ]; then
    echo "This script is intended to be sourced, not run. Aborting."
    false
    exit
fi

#------------------------------------------------------------------------------#
# For tests using the Linux kernel network stack.
#------------------------------------------------------------------------------#
# Health check probe port for all containers.
export DOCKER_HEALTH_PROBE_PORT="8123"
# Docker bridge network settings.
export CLIENT_BRIDGE_IP_DOCKER="169.254.0.1"
export SERVER_BRIDGE_IP_DOCKER="169.254.0.2"
export BRIDGE_NET_DOCKER="169.254.0.0/24"
export BRIDGE_GW_DOCKER="169.254.0.254"
# Overlay IP addresses.
export CLIENT_VXLAN_IP_LINUX="169.254.10.1"
export SERVER_VXLAN_IP_LINUX="169.254.10.2"
export MASK_VXLAN_LINUX="24"
export VXLAN_ID_LINUX="42"
# IANA (rather than Linux legacy port value).
export VXLAN_PORT="4789"

# Docker network we use to bridge containers.
export DOCKER_NET="vpp-testbench-net"
# Docker container names for client and server (runtime aliases).
export DOCKER_CLIENT_HOST="vpp-testbench-client"
export DOCKER_SERVER_HOST="vpp-testbench-server"
# Some related variables have to be computed at the last second, so they
# are not all defined up-front.
export CLIENT_VPP_NETNS_DST="/var/run/netns/${DOCKER_CLIENT_HOST}"
export SERVER_VPP_NETNS_DST="/var/run/netns/${DOCKER_SERVER_HOST}"

# VPP options.
# These can be arbitrarily named.
export CLIENT_VPP_HOST_IF="vpp1"
export SERVER_VPP_HOST_IF="vpp2"
# Putting VPP interfaces on separate subnet from Linux-stack i/f.
export CLIENT_VPP_MEMIF_IP="169.254.11.1"
export SERVER_VPP_MEMIF_IP="169.254.11.2"
export VPP_MEMIF_NM="24"
export CLIENT_VPP_TAP_IP_MEMIF="169.254.12.1"
export SERVER_VPP_TAP_IP_MEMIF="169.254.12.2"
export VPP_TAP_NM="24"
# Bridge domain ID (for VPP tap + VXLAN interfaces). Arbitrary.
export VPP_BRIDGE_DOMAIN_TAP="1000"

# VPP socket path. Make it one level "deeper" than the "/run/vpp" that is used
# by default, so our containers don't accidentally connect to an instance of
# VPP running on the host OS (i.e. "/run/vpp/vpp.sock"), and hang the system.
export VPP_SOCK_PATH="/run/vpp/containers"

#------------------------------------------------------------------------------#
# @brief:       Converts an integer value representation of a VXLAN ID to a
#               VXLAN IPv4 multicast address (string represenation). This
#               effectively sets the first octet to "239" and the remaining 3x
#               octets to the IP-address equivalent of a 24-bit value.
#               Assumes that it's never supplied an input greater than what a
#               24-bit unsigned integer can hold.
function vxlan_id_to_mc_ip()
{
    if [ $# -ne 1 ]; then
        echo "Sanity failure."
        false
        exit
    fi

    local id="${1}"
    local a b c d ret
    a="239"
    b="$(((id>>16) & 0xff))"
    c="$(((id>>8)  & 0xff))"
    d="$(((id)     & 0xff))"
    ret="${a}.${b}.${c}.${d}"

    echo "${ret}"
    true
}
# Multicast address for VXLAN. Treat the lower three octets as the 24-bit
# representation of the VXLAN ID for ease-of-use (use-case specific, not
# necessarily an established rule/protocol).
MC_VXLAN_ADDR_LINUX="$(vxlan_id_to_mc_ip ${VXLAN_ID_LINUX})"
export MC_VXLAN_ADDR_LINUX

#------------------------------------------------------------------------------#
# @brief:       Get'er function (so makefile can re-use common values from this
#               script, and propagate them down to the Docker build operations
#               and logic within the Dockerfile; "DRY").
function host_only_get_docker_health_probe_port()
{
    echo "${DOCKER_HEALTH_PROBE_PORT}"
}

#------------------------------------------------------------------------------#
# @brief:       Creates the Docker bridge network used to connect the
#               client and server testbench containers.
function host_only_create_docker_networks()
{
    # Create network (bridge for VXLAN). Don't touch 172.16/12 subnet, as
    # Docker uses it by default for its own overlay functionality.
    docker network create \
        --driver bridge \
        --subnet=${BRIDGE_NET_DOCKER} \
        --gateway=${BRIDGE_GW_DOCKER} \
        "${DOCKER_NET}"
}

#------------------------------------------------------------------------------#
# @brief:       Destroys the Docker bridge network for connecting the
#               containers.
function host_only_destroy_docker_networks()
{
    docker network rm "${DOCKER_NET}" || true
}

#------------------------------------------------------------------------------#
# @brief:       Bringup/dependency helper for VPP.
function host_only_create_vpp_deps()
{
    # Create area for VPP sockets and mount points, if it doesn't already
    # exist. Our containers need access to this path so they can see each
    # others' respective sockets so we can bind them together via memif.
    sudo mkdir -p "${VPP_SOCK_PATH}"
}

#------------------------------------------------------------------------------#
# @brief:       Launches the testbench client container.
function host_only_run_testbench_client_container()
{
    # Sanity check.
    if [ $# -ne 1 ]; then
        echo "Sanity failure."
        false
        exit
    fi

    # Launch container. Mount the local PWD into the container too (so we can
    # backup results).
    local image_name="${1}"
    docker run -d --rm \
        --cap-add=NET_ADMIN \
        --cap-add=SYS_NICE \
        --cap-add=SYS_PTRACE \
        --device=/dev/net/tun:/dev/net/tun \
        --device=/dev/vfio/vfio:/dev/vfio/vfio \
        --device=/dev/vhost-net:/dev/vhost-net \
        --name "${DOCKER_CLIENT_HOST}" \
        --volume="$(pwd):/work:rw" \
        --volume="${VPP_SOCK_PATH}:/run/vpp:rw" \
        --network name="${DOCKER_NET},ip=${CLIENT_BRIDGE_IP_DOCKER}" \
        --workdir=/work \
        "${image_name}"
}

#------------------------------------------------------------------------------#
# @brief:       Launches the testbench server container.
function host_only_run_testbench_server_container()
{
    # Sanity check.
    if [ $# -ne 1 ]; then
        echo "Sanity failure."
        false
        exit
    fi

    # Launch container. Mount the local PWD into the container too (so we can
    # backup results).
    local image_name="${1}"
    docker run -d --rm \
        --cap-add=NET_ADMIN \
        --cap-add=SYS_NICE \
        --cap-add=SYS_PTRACE \
        --device=/dev/net/tun:/dev/net/tun \
        --device=/dev/vfio/vfio:/dev/vfio/vfio \
        --device=/dev/vhost-net:/dev/vhost-net \
        --name "${DOCKER_SERVER_HOST}" \
        --volume="${VPP_SOCK_PATH}:/run/vpp:rw" \
        --network name="${DOCKER_NET},ip=${SERVER_BRIDGE_IP_DOCKER}" \
        "${image_name}"
}

#------------------------------------------------------------------------------#
# @brief:       Terminates the testbench client container.
function host_only_kill_testbench_client_container()
{
    docker kill "${DOCKER_CLIENT_HOST}" || true
    docker rm   "${DOCKER_CLIENT_HOST}" || true
}

#------------------------------------------------------------------------------#
# @brief:       Terminates the testbench server container.
function host_only_kill_testbench_server_container()
{
    docker kill "${DOCKER_SERVER_HOST}" || true
    docker rm   "${DOCKER_SERVER_HOST}" || true
}

#------------------------------------------------------------------------------#
# @brief:       Launches an interactive shell in the client container.
function host_only_shell_client_container()
{
    docker exec -it "${DOCKER_CLIENT_HOST}" bash --init-file /entrypoint.sh
}

#------------------------------------------------------------------------------#
# @brief:       Launches an interactive shell in the server container.
function host_only_shell_server_container()
{
    docker exec -it "${DOCKER_SERVER_HOST}" bash --init-file /entrypoint.sh
}

#------------------------------------------------------------------------------#
# @brief:       Determines the network namespace or "netns" associated with a
#               running Docker container, and then creates a network interface
#               in the default/host netns, and moves it into the netns
#               associated with the container.
function host_only_move_host_interfaces_into_container()
{
    # NOTE: this is only necessary if we want to create Linux network
    # interfaces while working in the default namespace, and then move them
    # into container network namespaces.
    # In earlier versions of this code, we did such an operation, but now we
    # just create the interfaces inside the containers themselves (requires
    # CAP_NET_ADMIN, or privileged containers, which we avoid). This is left
    # here as it's occasionally useful for debug purposes (or might become a
    # mini-lab itself).

    # Make sure netns path exists.
    sudo mkdir -p /var/run/netns

    # Mount container network namespaces so that they are accessible via "ip
    # netns". Ignore "START_OF_SCRIPT": just used to make
    # linter-compliant text indentation look nicer.
    DOCKER_CLIENT_PID=$(docker inspect -f '{{.State.Pid}}' ${DOCKER_CLIENT_HOST})
    DOCKER_SERVER_PID=$(docker inspect -f '{{.State.Pid}}' ${DOCKER_SERVER_HOST})
    CLIENT_VPP_NETNS_SRC=/proc/${DOCKER_CLIENT_PID}/ns/net
    SERVER_VPP_NETNS_SRC=/proc/${DOCKER_SERVER_PID}/ns/net
    sudo ln -sfT "${CLIENT_VPP_NETNS_SRC}" "${CLIENT_VPP_NETNS_DST}"
    sudo ln -sfT "${SERVER_VPP_NETNS_SRC}" "${SERVER_VPP_NETNS_DST}"

    # Move these interfaces into the namespaces of the containers and assign an
    # IPv4 address to them.
    sudo ip link set dev "${CLIENT_VPP_HOST_IF}" netns "${DOCKER_CLIENT_NETNS}"
    sudo ip link set dev "${SERVER_VPP_HOST_IF}" netns "${DOCKER_SERVER_NETNS}"
    docker exec ${DOCKER_CLIENT_HOST} ip a
    docker exec ${DOCKER_SERVER_HOST} ip a

    # Bring up the links and assign IP addresses. This must be done
    # **after** moving the interfaces to a new netns, as we might have a
    # hypothetical use case where we assign the same IP to multiple
    # interfaces, which would be a problem. This collision issue isn't a
    # problem though if the interfaces are in separate network namespaces
    # though.
}

