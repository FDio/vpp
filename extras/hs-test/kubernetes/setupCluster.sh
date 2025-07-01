#!/usr/bin/env bash
set -e

MASTER_OR_LATEST=${1-"latest"}
CALICOVPP_DIR="$HOME/vpp-dataplane"
VPP_DIR=$(pwd)
VPP_DIR=${VPP_DIR%extras*}
STASH_SAVED=0

if [ $MASTER_OR_LATEST = "master" ]; then
    if [ ! -d "$CALICOVPP_DIR" ]; then
        git clone https://github.com/projectcalico/vpp-dataplane.git $CALICOVPP_DIR
    fi
        cd $CALICOVPP_DIR
        git pull
        cd $VPP_DIR

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

        make -C $CALICOVPP_DIR kind-new-cluster N_KIND_WORKERS=2
        kubectl create -f https://raw.githubusercontent.com/projectcalico/calico/v3.28.3/manifests/tigera-operator.yaml
        make -C $CALICOVPP_DIR cherry-vpp FORCE=y BASE=origin/master VPP_DIR=$VPP_DIR
        make build
        make -C $CALICOVPP_DIR dev-kind
        make -C $CALICOVPP_DIR load-kind
        $CALICOVPP_DIR/yaml/overlays/dev/kustomize.sh up
        if ! git diff-index --quiet HEAD --; then
		      echo "Saving stash"
  		    git stash save "HST: temp stash"
          git reset --hard origin/master
          git stash pop
	      fi
    else
        echo "********"
        echo "Performance tests only work on Ubuntu 22.04 for now."
        echo "********"

        kind create cluster --config kubernetes/kind-config.yaml
        kubectl create -f https://raw.githubusercontent.com/projectcalico/calico/v3.28.3/manifests/tigera-operator.yaml

        echo "Sleeping for 10s, waiting for tigera operator to start up."
        sleep 10

        kubectl create -f https://raw.githubusercontent.com/projectcalico/vpp-dataplane/master/yaml/calico/installation-default.yaml
        kubectl create -f kubernetes/calico-config.yaml

        echo "Done. Please wait for the cluster to come fully online before running tests."
        echo "Use 'watch kubectl get pods -A' to monitor cluster status."
        echo "To delete the cluster, use 'kind delete cluster'"
    fi
