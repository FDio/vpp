#!/usr/bin/env bash
set -e

COMMAND=$1
CALICOVPP_DIR="$HOME/vpp-dataplane"
VPP_DIR=$(pwd)
VPP_DIR=${VPP_DIR%extras*}
COMMIT_HASH=$(git rev-parse HEAD)

export DOCKER_BUILD_PROXY=$HTTP_PROXY
# ---------------- images ----------------
export CALICO_AGENT_IMAGE=localhost:5000/calicovpp/agent:latest
export CALICO_VPP_IMAGE=localhost:5000/calicovpp/vpp:latest
export MULTINET_MONITOR_IMAGE=localhost:5000/calicovpp/multinet-monitor:latest
export IMAGE_PULL_POLICY=Always

# ---------------- interfaces ----------------
export CALICOVPP_INTERFACES='{
    "uplinkInterfaces": [
      {
        "interfaceName": "eth0",
        "vppDriver": "af_packet"
      }
    ]
  }'
export CALICOVPP_DISABLE_HUGEPAGES=true
export CALICOVPP_CONFIG_TEMPLATE="
    unix {
        nodaemon
        full-coredump
        log /var/run/vpp/vpp.log
        cli-listen /var/run/vpp/cli.sock
        pidfile /run/vpp/vpp.pid
    }
    buffers {
        buffers-per-numa 131072
    }
    socksvr { socket-name /var/run/vpp/vpp-api.sock }
    plugins {
        plugin default { enable }
        plugin calico_plugin.so { enable }
        plugin dpdk_plugin.so { disable }
    }"
export CALICOVPP_ENABLE_VCL=true

help() {
  echo "Usage:"
  echo -e "  make master-cluster | rebuild-master-cluster | release-cluster\n"

  echo "'master-cluster' pulls CalicoVPP and builds VPP from this directory, then brings up a KinD cluster."
  echo "'rebuild-master-cluster' stops CalicoVPP pods, rebuilds VPP and restarts CalicoVPP pods. Cluster keeps running."
  echo "'release-cluster' starts up a KinD cluster and uses latest CalicoVPP release (e.g. v3.29),
    or you can override versions by using env variables 'CALICOVPP_VERSION' and 'TIGERA_VERSION':
    CALICOVPP_VERSION: latest | v[x].[y].[z] (default=latest)
    TIGERA_VERSION:    master | v[x].[y].[z] (default=v3.28.3)"

  echo -e "\nTo shut down the cluster, use 'kind delete cluster'"
}

cherry_pick() {
  STASHED_CHANGES=0
  echo "checkpoint: $COMMIT_HASH"
  # chery-vpp hard resets the repo to a commit - we want to keep our changes
  if ! git diff-index --quiet HEAD --; then
	    echo "Saving stash"
      git stash save "HST: temp stash"
      STASHED_CHANGES=1
	fi
  make -C $CALICOVPP_DIR cherry-vpp FORCE=y BASE=origin/master VPP_DIR=$VPP_DIR

  # pop the stash to build VPP with CalicoVPP's patches + our changes
  if [ $STASHED_CHANGES -eq 1 ]; then
	    git stash pop
	fi
}

build_load_start_cni() {
  make -C $VPP_DIR/extras/hs-test build-vpp-release
  make -C $CALICOVPP_DIR dev-kind
  make -C $CALICOVPP_DIR load-kind
  $CALICOVPP_DIR/yaml/overlays/dev/kustomize.sh up
}

restore_repo() {
  # stash changes, reset local repo to the original state and unstash changes (removes CalicoVPP's patches)
  if ! git diff-index --quiet HEAD --; then
	    echo "Saving stash"
      git stash save "HST: temp stash"
      git reset --hard $COMMIT_HASH
      git stash pop
	else
    git reset --hard $COMMIT_HASH
  fi
}

setup_master() {
  if [ ! -d "$CALICOVPP_DIR" ]; then
      git clone https://github.com/projectcalico/vpp-dataplane.git $CALICOVPP_DIR
  else
      cd $CALICOVPP_DIR
      git pull
      cd $VPP_DIR
  fi

  make -C $CALICOVPP_DIR kind-new-cluster N_KIND_WORKERS=2
  kubectl create -f https://raw.githubusercontent.com/projectcalico/calico/v3.28.3/manifests/tigera-operator.yaml

  cherry_pick
  build_load_start_cni
  restore_repo
}

rebuild_master() {
  echo "Shutting down pods may take some time, timeout is set to 1m."
  timeout 1m $CALICOVPP_DIR/yaml/overlays/dev/kustomize.sh dn || true
  cherry_pick
  build_load_start_cni
  restore_repo
}

setup_release() {
  export CALICOVPP_VERSION="${CALICOVPP_VERSION:-latest}"
  export TIGERA_VERSION="${TIGERA_VERSION:-v3.28.3}"
  echo "CALICOVPP_VERSION=$CALICOVPP_VERSION"
  echo "TIGERA_VERSION=$TIGERA_VERSION"
  envsubst < kubernetes/calico-config-template.yaml > kubernetes/calico-config.yaml

  kind create cluster --config kubernetes/kind-config.yaml
  kubectl create -f https://raw.githubusercontent.com/projectcalico/calico/$TIGERA_VERSION/manifests/tigera-operator.yaml

  echo "Waiting for tigera-operator pod to start up."
  kubectl -n tigera-operator wait --for=condition=Ready pod --all --timeout=1m

  kubectl create -f https://raw.githubusercontent.com/projectcalico/vpp-dataplane/master/yaml/calico/installation-default.yaml
  kubectl create -f kubernetes/calico-config.yaml

  echo "Done. Please wait for the cluster to come fully online before running tests."
  echo "Use 'watch kubectl get pods -A' to monitor cluster status."
  echo "To delete the cluster, use 'kind delete cluster'"
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
