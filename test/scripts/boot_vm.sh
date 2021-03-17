#!/usr/bin/env bash
# set -o xtrace

# Spawns a Vagrant VM for VPP physical interface testing & runs make test inside it
############################# USAGE ###################################################
# ******************* boot_vm.sh [$VM_VNICS] [$VM_RAM] [$VM_VCPUS] ********************
#######################################################################################
# Optional Arguments: 
# $1: Desired number of virtio interfaces (Default: 2) 
# $2: RAM in MB (Default: 2048)
# $3: Number of vCPUs (Default: 4)

NUM_INTERFACES=${1:-2}
RAM=${2:-2048}
VCPUS=${3:-4}
VAGRANT_VERSION="${VAGRANT_VERSION:-2.2.14}"
# Set VagrantBox and VirtualBox versions:
# If unset, vagrant box release == host ubuntu release
# VAGRANT_BOX="generic/ubuntu2004"
# If unset, virtualbox=6.1 installed by default for ubuntu2004
# and virtualbox=5.2 for other ubuntu releases
# VIRTUALBOX_VERSION="6.1"

VM_TEST_DIR="/tmp/vpp-vm-tests"
VAGRANT="/usr/bin/vagrant"
HUGEPAGES=${HUGEPAGES:-256}

function check_os_version {
    OS_RELEASE=$(lsb_release -r -s)
    OS_VENDOR=$(lsb_release -i -s)
    if [[ "$OS_VENDOR" != "Ubuntu" ]]; then
       echo "VM tests are only supported on Ubuntu"
       exit 1
    fi
}

# Install vagrant on the host
function get_vagrant {
    if [[ ! -x "${VAGRANT}" ]]; then
        VAGRANT_DEB="vagrant_${VAGRANT_VERSION}_x86_64.deb"
        if [[ ! -f ${VAGRANT_DEB} ]]; then
            echo "Getting vagrant..${VAGRANT_DEB}"
            curl -O https://releases.hashicorp.com/vagrant/${VAGRANT_VERSION}/${VAGRANT_DEB}
        fi
        sudo dpkg -i ${VAGRANT_DEB}
        touch vagrant-installed
    fi
}

# Get the vagrant box version
function get_vagrant_box_version {
    check_os_version
    BOX_RELEASE=$(echo $OS_RELEASE | sed -e 's/\.//g')
    BOX_OS=$(echo $OS_VENDOR | awk '{print tolower($0)}')
    VAGRANT_BOX=${VAGRANT_BOX:-"generic/${BOX_OS}${BOX_RELEASE}"}
}

# Return true if the vagrant box exists
function exists_vagrant_box {
    get_vagrant_box_version
    BOX_EXISTS=$(${VAGRANT} box list | grep ${VAGRANT_BOX})
    [ -n "${BOX_EXISTS}" ]
}

# Add the vagrant box if it doesn't exist
function get_vagrant_box {
    if ! exists_vagrant_box; then
      echo "Adding vagrant box.. ${VAGRANT_BOX}"
      ${VAGRANT} box add ${VAGRANT_BOX} --provider virtualbox
    fi
}

function add_virtual_box_repo {
   sudo apt install -y linux-headers-$(uname -r) build-essential dkms
   sudo apt install -y software-properties-common
   # Add apt repo
   REPO_EXISTS=$(egrep '^deb.*virtualbox' /etc/apt/*.list)
   if [[ -z "$REPO_EXISTS" ]]; then 
     wget –q https://www.virtualbox.org/download/oracle_vbox_2016.asc -O- | sudo apt-key add -
     wget -q https://www.virtualbox.org/download/oracle_vbox.asc -O- | sudo apt-key add –
     sudo add-apt-repository -y "deb [arch=amd64] http://download.virtualbox.org/virtualbox/debian $(lsb_release -cs) contrib"
   fi
}

# True if the VirtualBox version is installed
# $1 = virtualbox-${VIRTUALBOX_VERSION}
function exists_virtualbox {
    VIRTUALBOX=$1
    INSTALLED=$(sudo dpkg --list | grep ${VIRTUALBOX} | awk '{print $1}')
    [ "${INSTALLED}" = "ii" ]
}

function get_virtual_box_version {
    get_vagrant_box_version
    if [[ "$VAGRANT_BOX" = "generic/ubuntu2004" ]]; then
        VIRTUALBOX_VERSION=${VIRTUALBOX_VERSION:-"6.1"}
    else
        VIRTUALBOX_VERSION=${VIRTUALBOX_VERSION:-"5.2"}
    fi
    VIRTUALBOX="virtualbox-${VIRTUALBOX_VERSION}"
}

function get_virtual_box {
    get_virtual_box_version
    if [[ ! -f /usr/lib/virtualbox/VirtualBox ]]; then
         add_virtual_box_repo
         if ! exists_virtualbox $VIRTUALBOX; then
            echo "Installing VirtualBox ..${VIRTUALBOX}"
            sudo apt update && sudo apt install -y ${VIRTUALBOX}
            touch virtualbox-installed
        else
           echo "VirtualBox ..${VIRTUALBOX} is already installed"
        fi
    fi
}

function make_vagrantfile {
   ip=10
   nets=( "config.vm.network \"private_network\", ip: \"192.168.${ip}.${ip}\", auto_config: false" )
   for num in $(seq 2 ${NUM_INTERFACES});do
     ip=$(( $ip + $num ))
     nets+=(  
    "  config.vm.network \"private_network\", ip: \"192.168.${ip}.${ip}\", auto_config: false"
         )
   done
   get_vagrant_box_version
   # Get the host nameserver address
   NAMESERVER=$(grep -m 1 "^nameserver" /etc/resolv.conf)
   IFS=$'\n'
   read -r -a VAGRANTFILE -d '' << EOF
Vagrant.configure("2") do |config|
  config.vm.box = "$VAGRANT_BOX"
  config.vm.provider "virtualbox" do |v|
    v.name = "vpp_vm"
    v.customize ["modifyvm", :id, "--natdnsproxy1", "on"]
    v.default_nic_type = "virtio"
    v.memory = ${RAM}
    v.cpus = ${VCPUS}
  end
  ${nets[*]}
  config.vm.synced_folder "${WS_ROOT}", "${WS_ROOT}"
  config.vm.synced_folder "/opt/vpp/external", "/opt/vpp/external"

  config.vm.provision "dns", type: "shell",
    inline: "echo ${NAMESERVER} | sudo tee /etc/resolv.conf > /dev/null", run: "always"
  config.vm.provision "build", type: "shell", 
    inline: "sudo apt-get update && sudo apt-get install -y build-essential"
  config.vm.provision "install", type: "shell", 
    inline: "cd ${WS_ROOT} && make UNATTENDED=yes install-dep"
  config.vm.provision "hugepages", type: "shell", 
    inline: "sudo sysctl -w vm.nr_hugepages=${HUGEPAGES}", run: "always"
end
EOF

echo "${VAGRANTFILE[*]}"  > Vagrantfile
}

# Return True if the Virtual machine is running
function is_running {
    RUNNING=$(${VAGRANT} status | grep running)
    [ -n "${RUNNING}" ]
}

function provision_vm {
    ${VAGRANT} up --provision
    if is_running; then
       echo "VM is provisioned"
    else
       echo "Error provisioning VM"
       exit 1
    fi
}

# Run make test inside the VM using vagrant ssh
function run_in_vm {
    EXCLUDED_PATTERNS=("MAKEFLAGS" "VM_TESTS" "VM_VNICS" "VM_RAM" "VM_VCPUS")
    SSH_VARS=()
    IFS=" "
    # Get the make test environment on the host 
    for env_var in $(set | grep "^MAKEFLAGS="); do
       # Extract valid key-value pairs from the host environment for running tests inside the VM
       key=$(echo "${env_var}" | awk -F= '{if ( index($0, "=") != 0 ) print $1}')
       if [[ -n "${key}" ]] && [[ ! " ${EXCLUDED_PATTERNS[*]} " =~ " ${key} " ]]; then
          SSH_VARS+=( "${env_var}" )
       fi 
    done
    echo "@@@@ Running make test inside the VM @@@@"
    echo "Running ssh command .. vagrant ssh -- -t cd ${WS_ROOT} && make test -o ${SSH_VARS[*]//\'/}"
    # Remove any trailing quotes in SSH_VARS
    vagrant ssh -- -t "cd ${WS_ROOT} && make test" -o ${SSH_VARS[*]//\'/}
}

# Wipe all data & binaries installed for running VM based tests
# $1=true to uninstall binaries
function wipe_vm_tests {
    local UNINSTALL_BINARIES=${1:-false}
    CWD=$(pwd)
    if [[ -x "${VAGRANT}" ]] && [[ -d "${VM_TEST_DIR}" ]]; then
       echo "Wiping VM test data"
       cd ${VM_TEST_DIR}
       ${VAGRANT} halt -f 2>/dev/null
       ${VAGRANT} destroy -f 2>/dev/null
    fi
    if ${UNINSTALL_BINARIES} && [[ -d "${VM_TEST_DIR}" ]]; then
        get_virtual_box_version
        echo "Installed VirtualBox Version=${VIRTUALBOX}"
        if [[ -f "${VM_TEST_DIR}/virtualbox-installed" ]] && exists_virtualbox "${VIRTUALBOX}"; then
            echo "Uninstalling VirtualBox.."
            # Takes about 10s for the vbox vm to stop
            sleep 10
            sudo apt remove -y --purge ${VIRTUALBOX}
        fi
        if [[ -f "${VM_TEST_DIR}/vagrant-installed" ]] && [[ -x "${VAGRANT}" ]]; then
            echo "Uninstalling Vagrant.."
            exists_vagrant_box && get_vagrant_box_version && ${VAGRANT} box remove ${VAGRANT_BOX} --provider virtualbox
            sudo dpkg --purge vagrant
        fi
    fi
    cd ${CWD}
    rm -rf ${VM_TEST_DIR}
}

function run_tests {
    CWD=$(pwd)
    mkdir -p ${VM_TEST_DIR}
    cd ${VM_TEST_DIR}
    check_os_version
    get_vagrant
    get_vagrant_box
    make_vagrantfile
    get_virtual_box
    # Provision the VM, if not already running
    if ! is_running ; then
        provision_vm
    else
        echo "VM is running..nothing to provision"
        echo "Run 'make test-wipe' to reset the VM"
    fi
    run_in_vm
    cd ${CWD}
}

# Run tests or wipe test data
if [[ "$*" =~ "wipe-vm" ]]; then
   wipe_vm_tests true
elif [[ -z "${WS_ROOT}" ]]; then
   echo "WS_ROOT is unset..exiting VM tests"
   exit 1
else
   run_tests
fi
