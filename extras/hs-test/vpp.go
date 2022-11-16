package main

import (
	"fmt"
	"github.com/edwarnicke/exechelper"
)

type Vpp struct {
	container *Container// TODO how to not name the field so that I can just use vpp.getName() instead of vpp.container.getName()?
	variant string
	cliSocketFilePath string
}

// TODO redesign how the VPP variant is being set together with other config parameters
func (vpp *Vpp) setServer() {
	fmt.Println("Container: ", vpp.container.getName(), " Variant: srv")
	vpp.variant = "srv"
}

func (vpp *Vpp) setClient() {
	vpp.variant = "cln"
}

func (vpp *Vpp) setCliSocket(filePath string) {
	vpp.cliSocketFilePath = filePath
}

func (vpp *Vpp) start() {
	// TODO return error (even if blank) instead of nothing
	// TODO start VPP instance
	fmt.Println("Start VPP variant: ", vpp.variant)
	if vpp.variant == "" {
		fmt.Println("Variant must not be nil")
		return
	}

	_, err := hstExec("2veths " + vpp.variant, vpp.container.getName())
	if err != nil {
		// t.Errorf("%v", err)
		fmt.Println("vpp start error: ", err)
		return
	}
}

func (vpp *Vpp) vppctl(command string) {
	// TODO return stdout and error (even if blank) instead of nothing
	dockerExecCommand := fmt.Sprintf("docker exec --detach=false %[1]s vppctl -s %[2]s %[3]s",
		vpp.container.getName(), "/tmp/2veths/var/run/vpp/cli.sock", command)
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
	fmt.Println("Container: ", vpp.container.getName(), " Create VPP")
	return vpp
}
