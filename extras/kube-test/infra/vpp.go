package kube_test

import (
	"context"
	"time"
)

const VppStartupConf string = `"unix {
  log /tmp/vpp.log
  full-coredump
  coredump-size unlimited
  cli-listen /cli.sock
  runtime-dir /tmp/vpp/var/run
}

api-trace {
  on
}

buffers {
  buffers-per-numa 8192
  default data-size 2048
  page-size 4K
}

cpu {
  workers 0
}

socksvr {
  socket-name /api.sock
}

statseg {
  socket-name /stats.sock
}

plugins {
  plugin default { enable }

  plugin af_packet_plugin.so { enable }
  plugin hs_apps_plugin.so { enable }
  plugin http_plugin.so { enable }
  plugin http_static_plugin.so { enable }
  plugin ping_plugin.so { enable }
  plugin arping_plugin.so { enable }
  plugin tap_plugin.so { enable }
  plugin memif_plugin.so { enable }
}

logging {
  default-log-level debug
  default-syslog-log-level debug
}

session {
  enable
  use-app-socket-api
}
"`

const VppCliConf string = `"create host-interface name eth0 mode ip
set int ip addr host-eth0 $(ip addr show dev eth0 | grep 'inet '| awk '{print $2}')
ip route add 0.0.0.0/0 via host-eth0
set int st host-eth0 up
"`

const VppMemifConf string = `"create memif socket id 1 filename abstract:vpp/memif-eth0
create interface memif socket-id 1 id 0 slave buffer-size 4096 rx-queues 1 tx-queues 1 mode ip
set int ip addr memif1/0 3.3.3.3/32
ip neighbor memif1/0 127.0.0.1 02:fe:e6:5b:3a:44
set int st memif1/0 up
create tap id 2 host-ip4-addr  $(ip addr show dev eth0 | grep 'inet '| awk '{print $2}') host-if-name eth8 tun
ip table add 1
set interface ip table tun2 1
set in ip address tun2 $(ip addr show dev eth0 | grep 'inet '| awk '{print $2}')
set in state tun2 up
ip route add $(ip addr show dev eth0 | grep 'inet '| awk '{print $2}') via tun2
ip route add 0.0.0.0/0 table 1 via memif1/0
"`

const VclConfIperf = "echo \"vcl {\n" +
	"rx-fifo-size 4000000\n" +
	"tx-fifo-size 4000000\n" +
	"app-scope-local\n" +
	"app-scope-global\n" +
	"app-socket-api abstract:vpp/session\n" +
	"}\" > /vcl.conf"

const VclConfNginx = "echo \"vcl {\n" +
	"heapsize 64M\n" +
	"rx-fifo-size 4000000\n" +
	"tx-fifo-size 4000000\n" +
	"segment-size 4000000000\n" +
	"add-segment-size 4000000000\n" +
	"event-queue-size 100000\n" +
	"use-mq-eventfd\n" +
	"app-socket-api abstract:vpp/session\n" +
	"}\" > /vcl.conf"

func (pod *Pod) InitVpp() {
	ctx, cancel := context.WithTimeout(pod.suite.MainContext, time.Second*10)
	defer cancel()

	o, err := pod.Exec(ctx, []string{"/bin/bash", "-c", "echo " + VppCliConf + " > /vppcliconf.conf"})
	AssertNil(err, o)

	o, err = pod.Exec(ctx, []string{"/bin/bash", "-c", "echo " + VppStartupConf + " > /startup.conf"})
	AssertNil(err, o)

	_, err = pod.ExecServer(ctx, []string{"/bin/bash", "-c", "vpp -c /startup.conf"})
	AssertNil(err)

	// temporary workaround: VPP has to start without creating interfaces (without running 'exec XYZ.conf'),
	// exec interface config
	// delete interface + route
	// exec interface config again
	// otherwise, VPP ping sends 5 packets but receives 15
	time.Sleep(time.Second * 1)
	o, err = pod.ExecVppctl(ctx, "exec /vppcliconf.conf")
	AssertNil(err, o)
	o, err = pod.ExecVppctl(ctx, "delete host-interface name eth0")
	AssertNil(err, o)
	o, err = pod.ExecVppctl(ctx, "ip route del 0.0.0.0/0")
	AssertNil(err, o)
	o, err = pod.ExecVppctl(ctx, "exec /vppcliconf.conf")
	AssertNil(err, o)
}

func (pod *Pod) InitMemifVpp() {
	ctx, cancel := context.WithTimeout(pod.suite.MainContext, time.Second*10)
	defer cancel()

	o, err := pod.Exec(ctx, []string{"/bin/bash", "-c", "echo " + VppMemifConf + " > /vppcliconf.conf"})
	AssertNil(err, o)

	o, err = pod.Exec(ctx, []string{"/bin/bash", "-c", "echo " + VppStartupConf + " > /startup.conf"})
	AssertNil(err, o)

	_, err = pod.ExecServer(ctx, []string{"/bin/bash", "-c", "vpp -c /startup.conf"})
	AssertNil(err)
	time.Sleep(time.Second * 1)
	o, err = pod.ExecVppctl(ctx, "exec /vppcliconf.conf")
	AssertNil(err, o)
}
