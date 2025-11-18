#!/usr/bin/env bash
set -e

COMMAND=$1
CALICOVPP_DIR=${CALICOVPP_DIR:-"$HOME/vpp-dataplane"}
VPP_DIR=$(pwd)
VPP_DIR=${VPP_DIR%test-c*}
reg_name='kind-registry'
reg_port='5000'
BASE=${BASE:-"origin/master"}
TAG=${TAG:-"kt-master"}
echo "CALICOVPP_DIR=$CALICOVPP_DIR"

export CALICO_NETWORK_CONFIG=${CALICO_NETWORK_CONFIG:-"mtu: 9000"}
export TIGERA_VERSION="${TIGERA_VERSION:-master}"
export DOCKER_BUILD_PROXY=$HTTP_PROXY

envsubst < kubernetes/kind-calicovpp-config-template.yaml > kubernetes/kind-calicovpp-config.yaml
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

help() {
  echo "Usage:"
  echo -e "  make master-cluster | rebuild-master-cluster | release-cluster\n"

  echo "'master-cluster' pulls CalicoVPP and builds VPP from this directory, then brings up a KinD cluster. You can
    override the version with: BASE=[(remote or local branch) | (commit hash)], e.g. BASE=origin/master"
  echo "'rebuild-master-cluster' stops CalicoVPP pods, rebuilds VPP and restarts CalicoVPP pods. Cluster keeps running."
  echo "'release-cluster' starts up a KinD cluster and uses latest CalicoVPP release (e.g. v3.29),
    or you can override versions by using env variables 'CALICOVPP_VERSION' and 'TIGERA_VERSION':
    CALICOVPP_VERSION: latest | v[x].[y].[z] (default=latest)
    TIGERA_VERSION:    master | v[x].[y].[z] (default="release-v3.31")"

  echo -e "\nTo shut down the cluster, use 'kind delete cluster'"
}

push_calico_to_registry() {
  for component in pod2daemon-flexvol cni node typha apiserver csi kube-controllers node-driver-registrar; do
    docker pull docker.io/calico/$component:$TIGERA_VERSION
    docker image tag docker.io/calico/$component:$TIGERA_VERSION localhost:5000/calico/$component:$TIGERA_VERSION
	  docker push localhost:5000/calico/$component:$TIGERA_VERSION
  done
}

push_release_to_registry() {
  for component in vpp agent multinet-monitor; do
    docker pull docker.io/calicovpp/$component:$CALICOVPP_VERSION
    docker image tag docker.io/calicovpp/$component:$CALICOVPP_VERSION localhost:5000/calicovpp/$component:$CALICOVPP_VERSION
	  docker push localhost:5000/calicovpp/$component:$CALICOVPP_VERSION
  done
}

push_tag_to_registry() {
  for component in vpp agent multinet-monitor; do
    docker image tag docker.io/calicovpp/$component:$TAG localhost:5000/calicovpp/$component:$TAG
	  docker push localhost:5000/calicovpp/$component:$TAG
  done
}

build_calicovpp() {
  if [ ! -d "$CALICOVPP_DIR" ]; then
      git clone https://github.com/projectcalico/vpp-dataplane.git $CALICOVPP_DIR
  else
      echo "Repo found, resetting"
      cd $CALICOVPP_DIR
      git reset --hard origin/master
      git fetch --tags --force
      git pull
      cd vpp-manager
      rm vpp*.tar || true
      make clean-vpp
      if [[ -d "$CALICOVPP_DIR/vpp-manager/vpp_build" ]]; then
        cd $CALICOVPP_DIR/vpp-manager/vpp_build
        make wipe || true
        make wipe-release || true
        git reset --hard origin/master
        git fetch --tags --force
        git pull
      fi
      
      cd $VPP_DIR/test-c/kube-test
  fi
  make -C $CALICOVPP_DIR/vpp-manager vpp BASE=$BASE
  make -C $CALICOVPP_DIR dev TAG=$TAG
  make -C $CALICOVPP_DIR image-kind TAG=$TAG
}

start_cni() {
  kubectl create --save-config -f kubernetes/kind-calicovpp-config.yaml
}

setup_master() {
  export CALICOVPP_VERSION=${CALICOVPP_VERSION:-"kt-master"}
  echo "CALICOVPP_VERSION=$CALICOVPP_VERSION" > kubernetes/.vars
  envsubst < kubernetes/kind-calicovpp-config-template.yaml > kubernetes/kind-calicovpp-config.yaml

  echo -e "$kind_config" | kind create cluster --config=-
  kubectl apply -f kubernetes/registry.yaml
  connect_registry
  push_calico_to_registry
  kubectl create -f https://raw.githubusercontent.com/projectcalico/calico/$TIGERA_VERSION/manifests/tigera-operator.yaml
  while [[ "$(kubectl api-resources --api-group=operator.tigera.io | grep Installation)" == "" ]]; do echo "waiting for Installation kubectl resource"; sleep 2; done

  build_calicovpp
  push_tag_to_registry
  start_cni
}

rebuild_master() {
  echo "Shutting down pods may take some time, timeout is set to 1m."
  timeout 1m kubectl delete -f kubernetes/kind-calicovpp-config.yaml || true
  build_calicovpp
  push_tag_to_registry
  start_cni
}

setup_release() {
  export CALICOVPP_VERSION="${CALICOVPP_VERSION:-"latest"}"
  echo "CALICOVPP_VERSION=$CALICOVPP_VERSION" > kubernetes/.vars
  envsubst < kubernetes/kind-calicovpp-config-template.yaml > kubernetes/kind-calicovpp-config.yaml
  echo "CALICOVPP_VERSION=$CALICOVPP_VERSION"
  echo "TIGERA_VERSION=$TIGERA_VERSION"
  echo -e "$kind_config" | kind create cluster --config=-
  kubectl apply -f kubernetes/registry.yaml
  connect_registry
  push_release_to_registry
  push_calico_to_registry
  kubectl create -f https://raw.githubusercontent.com/projectcalico/calico/$TIGERA_VERSION/manifests/tigera-operator.yaml

  while [[ "$(kubectl api-resources --api-group=operator.tigera.io | grep Installation)" == "" ]]; do echo "waiting for Installation kubectl resource"; sleep 2; done

  kubectl create --save-config -f kubernetes/kind-calicovpp-config.yaml

  echo "Done. Please wait for the cluster to come fully online before running tests."
  echo "Use 'watch kubectl get pods -A' to monitor cluster status."
  echo "To delete the cluster, use 'kind delete cluster'"
}

red () { printf "\e[0;31m$1\e[0m\n" >&2 ; }

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
