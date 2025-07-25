#!/usr/bin/env bash
set -e

COMMAND=$1
CALICOVPP_DIR="$HOME/vpp-dataplane"
VPP_DIR=$(pwd)
VPP_DIR=${VPP_DIR%extras*}
STASH_SAVED=0

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
  echo "  make master-cluster | rebuild-master-cluster | release-cluster"
  echo "or"
  echo "  ./kubernetes/setupCluster.sh [master-cluster | rebuild-master-cluster | release-cluster]"
  echo ""
  echo "'master-cluster' pulls CalicoVPP and builds VPP from this directory, then brings up a KinD cluster."
  echo "'rebuild-master-cluster' stops CalicoVPP pods, rebuilds VPP and restarts CalicoVPP pods. Cluster keeps running."
  echo "'release-cluster' starts up a KinD cluster and uses latest CalicoVPP release (e.g. v3.29)"
  echo ""
  echo "To shut down the cluster, use 'kind delete cluster'"
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
  make -C $CALICOVPP_DIR cherry-vpp FORCE=y BASE=origin/master VPP_DIR=$VPP_DIR
  make build-vpp-release
  make -C $CALICOVPP_DIR dev-kind
  make -C $CALICOVPP_DIR load-kind
  $CALICOVPP_DIR/yaml/overlays/dev/kustomize.sh up
  if ! git diff-index --quiet HEAD --; then
	    echo "Saving stash"
      git stash save "HST: temp stash"
      git reset --hard origin/master
      git stash pop
	fi
}

rebuild_master() {
  echo "Shutting down pods may take some time, timeout is set to 1m."
  timeout 1m $CALICOVPP_DIR/yaml/overlays/dev/kustomize.sh dn || true
  make build-vpp-release
  make -C $CALICOVPP_DIR dev-kind
  make -C $CALICOVPP_DIR load-kind
  $CALICOVPP_DIR/yaml/overlays/dev/kustomize.sh up
}

setup_release() {
  kind create cluster --config kubernetes/kind-config.yaml
  kubectl create -f https://raw.githubusercontent.com/projectcalico/calico/v3.28.3/manifests/tigera-operator.yaml

  echo "Sleeping for 10s, waiting for tigera operator to start up."
  sleep 10

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
