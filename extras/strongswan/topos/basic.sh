if [ -f ~/.vpp_sswan ]; then
  . ~/.vpp_sswan
fi

STARTUP_DIR="`pwd`"
SSWAN_CFG_DIR=/tmp/sswan

start_vpp() {
  sudo $VPP_BIN unix { \
	cli-listen /tmp/vpp_sswan.sock \
        gid $(id -g) } \
        api-segment { prefix vpp } \
        plugins { plugin dpdk_plugin.so { disable } }
}

vppctl () {
  sudo $VPPCTL -s /tmp/vpp_sswan.sock $@
}

initiator_conf() {
  sudo rm -r $SSWAN_CFG_DIR
  sudo mkdir -p $SSWAN_CFG_DIR
  sudo cp configs/$TC_DIR/ipsec.conf $SSWAN_CFG_DIR/ipsec.conf
  sudo cp configs/$TC_DIR/ipsec.secrets $SSWAN_CFG_DIR/ipsec.secrets
  sudo cp configs/strongswan.conf $SSWAN_CFG_DIR/strongswan.conf
}

config_topo () {
  (sudo ip link add vpp type veth peer name swanif
  sudo ip link set dev vpp up

  sudo ip netns add ns
  sudo ip link add veth_priv type veth peer name priv
  sudo ip link set dev priv up
  sudo ip link set dev veth_priv up netns ns

  sudo ip netns exec ns \
	bash -c "
		ip link set dev lo up
		ip addr add 192.168.3.2/24 dev veth_priv
		ip addr add fec3::2/16 dev veth_priv
                ip route add 192.168.5.0/24 via 192.168.3.1
                ip route add fec5::0/16 via fec3::1
                ") &> /dev/null

  initiator_conf
  (docker run --name sswan -d --privileged --rm --net=none \
  -v $SSWAN_CFG_DIR:/conf -v $SSWAN_CFG_DIR:/etc/ipsec.d philplckthun/strongswan)

  pid=$(docker inspect --format "{{.State.Pid}}" sswan)
  sudo ip link set netns $pid dev swanif

  sudo nsenter -t $pid -n ip addr add 192.168.10.1/24 dev swanif
  sudo nsenter -t $pid -n ip link set dev swanif up

  sudo nsenter -t $pid -n ip addr add 192.168.5.2/32 dev lo
  sudo nsenter -t $pid -n ip link set dev lo up

  start_vpp
  echo "vpp started.."
  sleep 3

  echo "exec $STARTUP_DIR/configs/$TC_DIR/vpp.conf"
  vppctl exec $STARTUP_DIR/configs/$TC_DIR/vpp.conf
  sleep 3
}

initiate_from_sswan () {
  echo "start initiation.."
  sudo docker exec sswan ipsec up initiator
  sleep 1
}

test_ping() {
  sudo ip netns exec ns ping -c 1 192.168.5.2
  rc=$?
  if [ $rc -ne 0 ] ; then
    echo "Test failed!"
  else
    echo "Test passed."
  fi
  return $rc
}

unconf_topo () {
  docker stop sswan &> /dev/null
  sudo pkill vpp
  sudo ip netns delete ns
  sleep 2
}

initiate_from_vpp () {
  vppctl ikev2 initiate sa-init pr1
  sleep 2
}

#vpp as an responder
run_responder_test() {
  config_topo
  initiate_from_sswan
  test_ping
  rc=$?
  unconf_topo
  return ${rc}
}

# vpp as an initiator
run_initiator_test() {
  config_topo
  initiate_from_vpp
  test_ping
  rc=$?
  unconf_topo
  return ${rc}
}
