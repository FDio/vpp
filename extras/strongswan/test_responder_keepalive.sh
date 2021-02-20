. topos/basic.sh

TC_DIR=responder_keepalive

config_topo
initiate_from_sswan

test_ping
sleep 30
test_ping

unconf_topo
