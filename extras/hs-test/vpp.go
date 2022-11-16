package main

import (
	"fmt"
	"encoding/json"
	"github.com/edwarnicke/exechelper"
)

type Vpp struct {
	container *Container// TODO how to not name the field so that I can just use vpp.getName() instead of vpp.container.getName()?
	config VppConfig
}

type VppConfig struct {
	Variant string
	CliSocketFilePath string
}

// TODO redesign how the VPP variant is being set together with other config parameters
func (vpp *Vpp) setServer() {
	fmt.Println("Container: ", vpp.container.getName(), " Variant: srv")
	vpp.config.Variant = "srv"
}

func (vpp *Vpp) setClient() {
	vpp.config.Variant = "cln"
}

func (vpp *Vpp) setCliSocket(filePath string) {
	vpp.config.CliSocketFilePath = filePath
}

func (vpp *Vpp) getCliSocket() string {
	return "/tmp/2veths/"+vpp.config.CliSocketFilePath // TODO fix this
}

func (vpp *Vpp) start() {
	// TODO return error (even if blank) instead of nothing
	// TODO start VPP instance
	fmt.Println("Start VPP variant: ", vpp.config.Variant)
	if vpp.config.Variant == "" {
		fmt.Println("Variant must not be nil")
		return
	}

	// TODO un-hardcode "2veths"
	// TODO encapsulate config generation
	serializedConfig, err := json.Marshal(vpp.config)
	if err != nil {
		fmt.Println("serialization error: ", err)
		return
	}
	args := fmt.Sprintf("2veths '%s'", string(serializedConfig))
	_, err = hstExec(args, vpp.container.getName())
	if err != nil {
		// t.Errorf("%v", err)
		fmt.Println("vpp start error: ", err)
		return
	}
}

func (vpp *Vpp) vppctl(command string) {
	// TODO return stdout and error (even if blank) instead of nothing
	dockerExecCommand := fmt.Sprintf("docker exec --detach=false %[1]s vppctl -s %[2]s %[3]s",
		vpp.container.getName(), vpp.getCliSocket(), command)
	output, err := exechelper.CombinedOutput(dockerExecCommand)
	if err != nil {
		// t.Errorf("vppctl %s failed: %v", command, err)
		fmt.Println("vppctl error: ", err)
	}
	// return string(output)
	fmt.Println("vppctl: ", string(output))
}

func NewVpp(c *Container) *Vpp {
	vpp := new(Vpp)
	vpp.container = c
	vpp.config = VppConfig{}
	fmt.Println("Container: ", vpp.container.getName(), " Create VPP")
	return vpp
}
