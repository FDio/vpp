#
# 2 initiators (strongswan), 1 responder (vpp) topology
#

if [ -f ~/.vpp_sswan ]; then
  . ~/.vpp_sswan
fi

STARTUP_DIR="`pwd`"
SSWAN_CFG_DIR=/tmp/sswan

vppctl () {
  sudo $VPPCTL -s /tmp/vpp_sswan.sock $@
}

start_vpp() {
  sudo $VPP_BIN unix { \
        cli-listen /tmp/vpp_sswan.sock \
        gid $(id -g) } \
        api-segment { prefix vpp } \
        plugins { plugin dpdk_plugin.so { disable } }
  sleep 5

  echo "exec $STARTUP_DIR/configs/$TC_DIR/vpp.conf"
  vppctl exec $STARTUP_DIR/configs/$TC_DIR/vpp.conf
  sleep 3
}

initiator_conf() {
  sudo rm -r $SSWAN_CFG_DIR$1
  sudo mkdir -p $SSWAN_CFG_DIR$1
  sudo cp configs/$TC_DIR/ipsec$1.conf $SSWAN_CFG_DIR$1/ipsec.conf
  sudo cp configs/$TC_DIR/ipsec.secrets $SSWAN_CFG_DIR$1/ipsec.secrets
  sudo cp configs/strongswan.conf $SSWAN_CFG_DIR$1/strongswan.conf
}

config_topo () {
  ns_name="ns"$1
  init_name="sswan"$1
  (sudo ip link add gw$1 type veth peer name veth_gw$1
  sudo ip link set dev gw$1 up

  sudo ip netns add $ns_name
  sudo ip link add veth_priv$1 type veth peer name priv$1
  sudo ip link set dev priv$1 up
  sudo ip link set dev veth_priv$1 up netns $ns_name

  sudo ip netns exec $ns_name \
    bash -c "
      ip link set dev lo up
      ip addr add 192.168.3.2/24 dev veth_priv$1
      ip addr add fec3::2/16 dev veth_priv$1
      ip route add 192.168.5.0/24 via 192.168.3.1
      ip route add fec5::0/16 via fec3::1
      ") &> /dev/null

  initiator_conf $1

  (docker run --name $init_name -d --privileged --rm --net=none \
  -v $SSWAN_CFG_DIR$1:/conf -v $SSWAN_CFG_DIR$1:/etc/ipsec.d philplckthun/strongswan)

  pid=$(docker inspect --format "{{.State.Pid}}" $init_name)
  sudo ip link set netns $pid dev veth_gw$1

  sudo nsenter -t $pid -n ip addr add 192.168.10.1/24 dev veth_gw$1
  sudo nsenter -t $pid -n ip link set dev veth_gw$1 up

  sudo nsenter -t $pid -n ip addr add 192.168.5.2/32 dev lo
  sudo nsenter -t $pid -n ip link set dev lo up
}

initiate_from_sswan () {
  echo "start initiation.."
  sudo docker exec sswan$1 ipsec up initiator
  sleep 3
}

test_ping() {
  sudo ip netns exec $1 ping -c 1 192.168.5.2
  rc=$?
  if [ $rc -ne 0 ] ; then
    echo "Test failed!"
  else
    echo "Test passed."
  fi
  return $rc
}

unconf_topo () {
  docker stop sswan1 &> /dev/null
  docker stop sswan2 &> /dev/null
  sudo pkill vpp
  sudo ip netns delete ns1
  sudo ip netns delete ns2
  sleep 2
}

initiate_from_vpp () {
  vppctl ikev2 initiate sa-init pr1
  sleep 2
}

#vpp as an responder
run_responder_test() {
  unconf_topo
  config_topo "1"
  config_topo "2"
  start_vpp
  initiate_from_sswan "1"
  initiate_from_sswan "2"
  test_ping "ns2"
  test_ping "ns1"
}
