#!/usr/bin/env bash
set -e

if [ "$EUID" -eq 0 ]; then
    echo "********"
    echo "Do not run as root. Exiting."
    echo "********"
    exit 1
fi

echo "********"
echo "Performance tests only work on Ubuntu 22.04 for now."
echo "Do not run as root (untested) and make sure you have KinD and Kubectl installed!"
echo "https://kind.sigs.k8s.io/"
echo "https://kubernetes.io/docs/tasks/tools/install-kubectl-linux/#install-using-native-package-management"
echo "********"

kind create cluster --config kubernetes/kind-config.yaml
kubectl create -f https://raw.githubusercontent.com/projectcalico/calico/v3.28.3/manifests/tigera-operator.yaml

echo "Sleeping for 10s, waiting for tigera operator to start up."
sleep 10

kubectl create -f  https://raw.githubusercontent.com/projectcalico/vpp-dataplane/master/yaml/calico/installation-default.yaml
kubectl create -f kubernetes/calico-config.yaml

echo "Done. Please wait for the cluster to come fully online before running tests."
echo "Use 'watch kubectl get pods -A' to monitor cluster status."
echo "To delete the cluster, use 'kind delete cluster'"