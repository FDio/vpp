#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Cisco Systems, Inc.

if [ $BIN_FLAVOR = "debug" ]
then
  BIN_DIR=install-vpp_debug-native
  BIN_EXEC_PREFIX="gdb --args"
else
  BIN_DIR=install-vpp-native
  BIN_EXEC_PREFIX="gdb --args"
fi

BIN_PATH=$BASE_DIR/$BIN_DIR

if [ "$#" -eq 1 ]
then
  echo $1
  CFG_FILE=$1
fi

CFG_MBUFS=""
if [ -n "$NUM_MBUFS" ]; then
  CFG_MBUFS="buffers-per-numa $NUM_MBUFS"
fi

if [ -z $HEAP_SIZE ]; then
  HEAP_SIZE=4g
fi

if [ -z $SKIP_CORE ]; then
  SKIP_CORE=0
fi

if [ -z $SKIP_CORE ]; then
  MAIN_CORE=1
fi

if [ -z $EVT_LOG_SIZE ]; then
  EVT_LOG_SIZE=0
fi

if [ -z $API_GLOBAL_SIZE ]; then
  API_GLOBAL_SIZE=64M
fi

if [ -z $API_SIZE ]; then
  API_SIZE=16M
fi

if [ -z ${WORKERS+x} ]; then
  WORKERS=0
  CFG_RX_QS=1
else
  CFG_WORKERS="workers $WORKERS"
  CFG_RX_QS=$(( $WORKERS ))
fi

SOCK_CFG=""
if [ -n "$SOCK" ]; then
  SOCK_CFG="socksvr { socket-name ${SOCK} }"
fi

if [ -z $IF_RX_DESC ]; then
  IF_RX_DESC=4096
fi

if [ -z $IF_TX_DESC ]; then
  IF_TX_DESC=4096
fi

API_PREFIX_CFG=""
if [ -n "$API_PREFIX" ]; then
  API_PREFIX_CFG="prefix $API_PREFIX"
fi

CLI_LISTEN_CFG="cli-listen localhost:5002"
if [ -n "$CLI_SOCK" ]; then
  CLI_LISTEN_CFG="cli-listen $CLI_SOCK"
fi

if [[ -z "$DPDK_DISABLE" ]]; then
  DPDK_CFG="dpdk {   	                                        \
		dev $DPDK_DEV {                                 \
                	num-tx-desc $IF_TX_DESC                 \
                        num-rx-desc $IF_RX_DESC                 \
  	       		num-rx-queues $CFG_RX_QS		\
             	}                                               \
		$SOCK_MEM_CFG					\
		$DPDK_CSUM					\
        }"
else
  DPDK_PLUGIN_DISABLE="plugin dpdk_plugin.so {disable}"
fi

if [[ -n "$QUIC_ENABLE" ]]; then
  QUIC_PLUGIN="plugin quic_plugin.so {enable}"
  QUIC_QUICLY_PLUGIN="plugin quic_quicly_plugin.so {enable}"
fi

if [[ -n "$SRTP_ENABLE" ]]; then
  SRTP_PLUGIN="plugin srtp_plugin.so {enable}"
fi

# custom openssl locally built
LD_LIBP=""
if [[ -n "${LOCAL_OSSL}" ]]; then
  LD_LIBP="LD_LIBRARY_PATH=${LOCAL_OSSL}"
fi

function start_vpp
{
  sudo $LD_LIBP $BIN_EXEC_PREFIX $BIN_PATH/vpp/bin/vpp		\
  	unix { 							\
  		interactive log /tmp/vpp.log 			\
  		full-coredump 					\
  		exec $CFG_DIR/$CFG_FILE				\
		$CLI_LISTEN_CFG					\
		poll-sleep-usec 0				\
  	}							\
  	heapsize $HEAP_SIZE					\
  	api-trace { on }					\
	api-segment {						\
	  global-size $API_GLOBAL_SIZE				\
	  api-size $API_SIZE					\
	  gid vpp						\
	  $API_PREFIX_CFG					\
	}							\
	vlib {							\
	  elog-events $EVT_LOG_SIZE				\
	  elog-post-mortem-dump					\
	}							\
  	cpu {							\
  		skip-cores $SKIP_CORE				\
		main-core $MAIN_CORE				\
                $CFG_CORELIST_WKS                               \
  	}							\
	buffers { $CFG_MBUFS }					\
	$DPDK_CFG						\
	$SESSION_CFG						\
	$TCP_CFG						\
	$UDP_CFG						\
	$SOCK_CFG						\
	$TLS_CFG						\
	plugins {						\
	  plugin unittest_plugin.so {enable}			\
	  plugin http_unittest_plugin.so {enable}		\
	  $QUIC_PLUGIN						\
	  $QUIC_QUICLY_PLUGIN			\
	  $SRTP_PLUGIN						\
	  $DPDK_PLUGIN_DISABLE					\
	}
}

