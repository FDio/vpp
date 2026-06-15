#!/usr/bin/env bash
set -e

COMMAND=$1
CALICOVPP_DIR=${CALICOVPP_DIR:-"$HOME/vpp-dataplane"}
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
VPP_BUILD_DIR=${VPP_BUILD_DIR:-"${SCRIPT_DIR%/extras*}"}
COMMIT_HASH=$(git -C "$VPP_BUILD_DIR" rev-parse HEAD)
BASE=${BASE:-"$COMMIT_HASH"}
# set to false to skip resetting vpp-dataplane directory, useful for testing changes
RESTORE_CV=${RESTORE_CV:-"true"}
# TAG "kt-master" (kube-test master) is only used when setting up a master cluster.
# "kt-master" is then written to .vars, from where kube-test parses it
TAG=${TAG:-"kt-master"}
echo "CALICOVPP_DIR=$CALICOVPP_DIR"
echo "VPP_BUILD_DIR=$VPP_BUILD_DIR"

reg_name='kind-registry'
reg_port='5000'
[ "$BASE" = "default" ] && BASE=""
VPP_BASE_REF=$BASE

# [KinD only] sets VPP's mtu. Only works if kind network is configured to use MTU=9000
export CALICO_NETWORK_CONFIG=${CALICO_NETWORK_CONFIG:-"mtu: 9000"}
# used for Calico images
export TIGERA_VERSION="${TIGERA_VERSION:-"v3.32.0"}"
export KIND_CALICO_VERSION=$TIGERA_VERSION
export TIGERA_OPERATOR_VERSION=$KIND_CALICO_VERSION
export DOCKER_BUILD_PROXY=$HTTP_PROXY
export TAG=$TAG
export VPP_DIR=$VPP_BUILD_DIR

source "$SCRIPT_DIR/common.sh"

kind_config=$(cat kubernetes/kind-config.yaml)
kind_config=$(cat <<EOF
$kind_config
- role: control-plane
  extraMounts:
    - hostPath: $HOME
      containerPath: $HOME
- role: worker
  extraMounts:
    - hostPath: $HOME
      containerPath: $HOME
- role: worker
  extraMounts:
    - hostPath: $HOME
      containerPath: $HOME
EOF
)

if [ "$(docker network inspect kind -f '{{ index .Options "com.docker.network.driver.mtu" }}')" -ne "9000" ]; then
  echo "Deleting kind network"
  docker network rm kind || true
  echo "Creating custom kind network"
  docker network create kind --driver bridge --opt com.docker.network.driver.mtu=9000 --opt com.docker.network.bridge.enable_ip_masquerade=true --ipv6
fi

# create registry
if [ "$(docker inspect -f '{{.State.Running}}' "${reg_name}" 2>/dev/null || true)" != 'true' ]; then
  docker run \
    -d --restart=always -p "127.0.0.1:${reg_port}:5000" --name "${reg_name}" \
    registry:2
fi

connect_registry() {
  if [ "$(docker inspect -f='{{json .NetworkSettings.Networks.kind}}' "${reg_name}")" = 'null' ]; then
    docker network connect "kind" "${reg_name}"
  fi
}

write_kube_vars_file() {
  cat > kubernetes/.vars <<EOF
CALICOVPP_VERSION=$CALICOVPP_VERSION
EOF
}

# Fetch the KinD manifest from CalicoVPP (layout-aware via kustomize), write
# the vars file, and produce the final kubernetes/kind-calicovpp-config.yaml.
apply_kind_manifest_from_calicovpp() {
  make -C "$CALICOVPP_DIR" kube-test-template FLAVOR=kind \
    > kubernetes/kind-calicovpp-config-template.yaml
  write_kube_vars_file
  envsubst < kubernetes/kind-calicovpp-config-template.yaml > kubernetes/kind-calicovpp-config.yaml
}

help() {
  echo "Usage:"
  echo -e "  make master-cluster | rebuild-master-cluster | release-cluster\n"

  echo "'master-cluster' pulls CalicoVPP and builds VPP from this directory, then brings up a KinD cluster. You can
    override the version with: BASE=[(remote or local branch) | (commit hash)], e.g. BASE=origin/master.
    To test changes made in the vpp-dataplane repo, use RESTORE_CV=false"
  echo "'rebuild-master-cluster' stops CalicoVPP pods, rebuilds VPP and restarts CalicoVPP pods. Cluster keeps running."
  echo "'release-cluster' starts up a KinD cluster and uses latest CalicoVPP release (e.g. v3.32.0),
    or you can override versions by using env variables 'CALICOVPP_VERSION' and 'TIGERA_VERSION':
    CALICOVPP_VERSION: v[x].[y].[z] (default="v3.32.0")
    TIGERA_VERSION:    master | v[x].[y].[z] (default="v3.32.0")"

  echo -e "\nTo shut down the cluster, use 'kind delete cluster'"
}

done_message() {
  green "  Done. Please wait for the cluster to come fully online before running tests.
  Use 'watch kubectl get pods -A' to monitor cluster status.
  To delete the cluster, use 'kind delete cluster'"
}

push_calico_to_registry() {
  for component in pod2daemon-flexvol cni node typha apiserver csi kube-controllers node-driver-registrar; do
    docker pull docker.io/calico/$component:$TIGERA_VERSION
    docker image tag docker.io/calico/$component:$TIGERA_VERSION localhost:5000/calico/$component:$TIGERA_VERSION
	  docker push localhost:5000/calico/$component:$TIGERA_VERSION
  done
}

build_calicovpp() {
  clone_calicovpp_if_missing
  if [ "$RESTORE_CV" = "true" ]; then
    echo "Repo found, resetting"
    git -C "$CALICOVPP_DIR" fetch --tags --force
    git -C "$CALICOVPP_DIR" reset --hard origin/master
  fi

  make -C "$CALICOVPP_DIR" vpp VPP_DIR="$VPP_BUILD_DIR" BASE="$BASE" && \
  make -C "$CALICOVPP_DIR" dev TAG="$TAG" && \
  make -C "$CALICOVPP_DIR" image-kind TAG="$TAG"
}

start_cni() {
  kubectl create --save-config -f kubernetes/kind-calicovpp-config.yaml || true
}

setup_master() {
  save_stash
  export CALICOVPP_VERSION=${CALICOVPP_VERSION:-"kt-master"}

  echo -e "$kind_config" | kind create cluster --config=-
  kubectl apply -f kubernetes/registry.yaml
  connect_registry
  push_calico_to_registry
  kubectl create -f https://raw.githubusercontent.com/projectcalico/calico/$TIGERA_VERSION/manifests/tigera-operator.yaml
  while [[ "$(kubectl api-resources --api-group=operator.tigera.io | grep Installation)" == "" ]]; do echo "waiting for Installation kubectl resource"; sleep 2; done

  build_and_verify_vpp

  # Fetch kube-test KinD manifest from CalicoVPP. CalicoVPP owns all
  # repo-layout details (image name, VPP build path); kube-test just envsubst's
  # the runtime placeholders (CALICOVPP_VERSION, HOME, etc.).
  apply_kind_manifest_from_calicovpp

  start_cni
  restore_repo
  done_message
}

rebuild_master() {
  save_stash
  build_and_verify_vpp
  export CALICOVPP_VERSION=${CALICOVPP_VERSION:-"kt-master"}

  apply_kind_manifest_from_calicovpp

  start_cni || true
  restore_repo
  kubectl rollout restart -n calico-vpp-dataplane ds/calico-vpp-node
  done_message
}

setup_release() {
  export CALICOVPP_VERSION="${CALICOVPP_VERSION:-"v3.32.0"}"
  echo "CALICOVPP_VERSION=$CALICOVPP_VERSION"
  echo "TIGERA_VERSION=$TIGERA_VERSION"
  echo -e "$kind_config" | kind create cluster --config=-
  kubectl apply -f kubernetes/registry.yaml
  connect_registry

  # Checkout CalicoVPP at the requested release tag.
  # Each release branch knows its own image names and paths.
  clone_calicovpp_if_missing
  git -C "$CALICOVPP_DIR" fetch --tags
  git -C "$CALICOVPP_DIR" checkout "release/${CALICOVPP_VERSION}" 2>/dev/null || \
    git -C "$CALICOVPP_DIR" checkout "${CALICOVPP_VERSION}"

  # CalicoVPP knows which images belong to this release; push them to local registry
  make -C "$CALICOVPP_DIR" kube-test-push-images CALICOVPP_VERSION=$CALICOVPP_VERSION
  push_calico_to_registry

  # Fetch kube-test template from CalicoVPP (image name and paths baked in for this release)
  apply_kind_manifest_from_calicovpp

  kubectl create -f https://raw.githubusercontent.com/projectcalico/calico/$TIGERA_VERSION/manifests/tigera-operator.yaml

  while [[ "$(kubectl api-resources --api-group=operator.tigera.io | grep Installation)" == "" ]]; do echo "waiting for Installation kubectl resource"; sleep 2; done

  kubectl create --save-config -f kubernetes/kind-calicovpp-config.yaml
  done_message
}

case "$COMMAND" in
  master-cluster)
    setup_master
    ;;
  rebuild-master-cluster)
    rebuild_master
    ;;
  release-cluster)
    setup_release
    ;;
*)
    help
    ;;
esac

red "If ImagePullBackOff: add \"NO_PROXY=kind-registry\" and \"no_proxy=kind-registry\" to /etc/environment"
