package main

import (
	"encoding/json"
	"fmt"
	"github.com/edwarnicke/exechelper"
)

const vppConfigTemplate = `unix {
  nodaemon
  log %[1]s/var/log/vpp/vpp.log
  full-coredump
  cli-listen %[1]s%[2]s
  runtime-dir %[1]s/var/run
  gid vpp
}

api-trace {
  on
}

api-segment {
  gid vpp
}

socksvr {
  socket-name %[1]s/var/run/vpp/api.sock
}

statseg {
  socket-name %[1]s/var/run/vpp/stats.sock
}

plugins {
  plugin unittest_plugin.so { enable }
  plugin dpdk_plugin.so { disable }
  plugin crypto_aesni_plugin.so { enable }
  plugin quic_plugin.so { enable }
}

`

const (
	defaultCliSocketFilePath = "/var/run/vpp/cli.sock"
)

type VppInstance struct {
	container      *Container
	config         VppConfig
	actionFuncName string
}

type VppConfig struct {
	Variant           string
	CliSocketFilePath string
}

func (vc *VppConfig) getTemplate() string {
	return fmt.Sprintf(vppConfigTemplate, "%[1]s", vc.CliSocketFilePath)
}

func (vpp *VppInstance) set2VethsServer() {
	vpp.actionFuncName = "Configure2Veths"
	vpp.config.Variant = "srv"
}

func (vpp *VppInstance) set2VethsClient() {
	vpp.actionFuncName = "Configure2Veths"
	vpp.config.Variant = "cln"
}

func (vpp *VppInstance) setVppProxy() {
	vpp.actionFuncName = "ConfigureVppProxy"
}

func (vpp *VppInstance) setEnvoyProxy() {
	vpp.actionFuncName = "ConfigureEnvoyProxy"
}

func (vpp *VppInstance) setCliSocket(filePath string) {
	vpp.config.CliSocketFilePath = filePath
}

func (vpp *VppInstance) getCliSocket() string {
	return fmt.Sprintf("%s%s", vpp.container.workDir, vpp.config.CliSocketFilePath)
}

func (vpp *VppInstance) start() error {
	if vpp.actionFuncName == "" {
		return fmt.Errorf("vpp start failed: action function name must not be blank")
	}

	serializedConfig, err := serializeVppConfig(vpp.config)
	if err != nil {
		return fmt.Errorf("serialize vpp config: %v", err)
	}
	args := fmt.Sprintf("%s '%s'", vpp.actionFuncName, serializedConfig)
	_, err = vpp.container.execAction(args)
	if err != nil {
		return fmt.Errorf("vpp start failed: %s", err)
	}

	return nil
}

func (vpp *VppInstance) vppctl(command string) (string, error) {
	cliExecCommand := fmt.Sprintf("docker exec --detach=false %[1]s vppctl -s %[2]s %[3]s",
		vpp.container.name, vpp.getCliSocket(), command)
	output, err := exechelper.CombinedOutput(cliExecCommand)
	if err != nil {
		return "", fmt.Errorf("vppctl failed: %s", err)
	}

	return string(output), nil
}

func NewVppInstance(c *Container) *VppInstance {
	var vppConfig VppConfig
	vppConfig.CliSocketFilePath = defaultCliSocketFilePath
	vpp := new(VppInstance)
	vpp.container = c
	vpp.config = vppConfig
	return vpp
}

func serializeVppConfig(vppConfig VppConfig) (string, error) {
	serializedConfig, err := json.Marshal(vppConfig)
	if err != nil {
		return "", fmt.Errorf("vpp start failed: serializing configuration failed: %s", err)
	}
	return string(serializedConfig), nil
}

func deserializeVppConfig(input string) (VppConfig, error) {
	var vppConfig VppConfig
	err := json.Unmarshal([]byte(input), &vppConfig)
	if err != nil {
		// Since input is not a  valid JSON it is going be used as a variant value
		// for compatibility reasons
		vppConfig.Variant = input
		vppConfig.CliSocketFilePath = defaultCliSocketFilePath
	}
	return vppConfig, nil
}
