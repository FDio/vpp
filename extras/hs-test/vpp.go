package main

import (
	"fmt"
	"encoding/json"
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

type Vpp struct {
	container *Container
	config VppConfig
	actionFuncName string
}

type VppConfig struct {
	Variant string
	CliSocketFilePath string
}

func (vc *VppConfig) getVariant() string {
	return vc.Variant
}

func (vc *VppConfig) getTemplate() string {
	return fmt.Sprintf(vppConfigTemplate, "%[1]s", vc.CliSocketFilePath)
}

func (vpp *Vpp) setServer() {
	vpp.actionFuncName = "2veths"
	vpp.config.Variant = "srv"
}

func (vpp *Vpp) setClient() {
	vpp.actionFuncName = "2veths"
	vpp.config.Variant = "cln"
}

func (vpp *Vpp) setCliSocket(filePath string) {
	vpp.config.CliSocketFilePath = filePath
}

func (vpp *Vpp) getCliSocket() string {
	return fmt.Sprintf("/tmp/%s/%s", vpp.actionFuncName, vpp.config.CliSocketFilePath)
}

func (vpp *Vpp) start() error {
	if vpp.config.Variant == "" {
		return fmt.Errorf("vpp start failed: variant must not be blank")
	}
	if vpp.actionFuncName == "" {
		return fmt.Errorf("vpp start failed: action function name must not be blank")
	}

	serializedConfig, err := json.Marshal(vpp.config)
	if err != nil {
		return fmt.Errorf("vpp start failed: serializing configuration failed: %s", err)
	}
	args := fmt.Sprintf("%s '%s'", vpp.actionFuncName, string(serializedConfig))
	_, err = hstExec(args, vpp.container.getName())
	if err != nil {
		return fmt.Errorf("vpp start failed: %s", err)
	}

	return nil
}

func (vpp *Vpp) vppctl(command string) (string, error) {
	dockerExecCommand := fmt.Sprintf("docker exec --detach=false %[1]s vppctl -s %[2]s %[3]s",
		vpp.container.getName(), vpp.getCliSocket(), command)
	output, err := exechelper.CombinedOutput(dockerExecCommand)
	if err != nil {
		return "", fmt.Errorf("vppctl failed: %s", err)
	}

	return string(output), nil
}

func NewVpp(c *Container) *Vpp {
	vpp := new(Vpp)
	vpp.container = c
	return vpp
}

func DeserializeVppConfig(input string) (VppConfig, error) {
	var vppConfig VppConfig
	err := json.Unmarshal([]byte(input), &vppConfig)
	if err != nil {
		// Since input is not a  valid JSON it is going be used as variant value
		// for compatibility reasons
		vppConfig.Variant = input
		vppConfig.CliSocketFilePath = "/var/run/vpp/cli.sock"
	}
	return vppConfig, nil
}
