package hst

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"text/template"
	"time"

	containerTypes "github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"
	"github.com/docker/go-units"
	"github.com/edwarnicke/exechelper"
	"github.com/google/shlex"
	"github.com/onsi/ginkgo/v2"
)

var (
	workDir, _ = os.Getwd()
)

// runLabel is set on every container so cleanup can target one run without
// matching on container names.
const runLabel = "io.fd.hs-test.run"

const (
	containerStartupTimeout     = 10 * time.Second
	containerStartupPoll        = 50 * time.Millisecond
	containerStartupDiagnostics = 2 * time.Second
)

type Volume struct {
	HostDir          string
	ContainerDir     string
	IsDefaultWorkDir bool
}

type Container struct {
	Suite       *HstSuite
	IsOptional  bool
	RunDetached bool
	// Name is the docker container name, scoped to this run and Ginkgo process.
	Name string
	// BaseName is the name as written in the topology yaml, without any scoping.
	BaseName         string
	ID               string
	Image            string
	ExtraRunningArgs string
	Volumes          map[string]Volume
	EnvVars          map[string]string
	VppInstance      *VppInstance
	AllocatedCpus    []int
	ctx              context.Context
	volumeYamlConf   []any
}

func newContainer(suite *HstSuite, yamlInput ContainerConfig) (*Container, error) {
	containerName := yamlInput["name"].(string)
	if len(containerName) == 0 {
		err := fmt.Errorf("container name must not be blank")
		return nil, err
	}

	var container = new(Container)
	container.Volumes = make(map[string]Volume)
	container.EnvVars = make(map[string]string)
	container.Name = containerName
	container.BaseName = containerName
	container.Suite = suite
	container.ctx = context.Background()

	// the topologies name images without a tag; ImageReference adds this run's tag
	// to the ones hs-test builds, so the yaml files stay free of run specifics
	if Image, ok := yamlInput["image"]; ok {
		container.Image = ImageReference(Image.(string))
	} else {
		container.Image = ImageReference("hs-test/vpp")
	}

	if args, ok := yamlInput["extra-args"]; ok {
		container.ExtraRunningArgs = args.(string)
	} else {
		container.ExtraRunningArgs = ""
	}

	if isOptional, ok := yamlInput["is-optional"]; ok {
		container.IsOptional = isOptional.(bool)
	} else {
		container.IsOptional = false
	}

	if runDetached, ok := yamlInput["run-detached"]; ok {
		container.RunDetached = runDetached.(bool)
	} else {
		container.RunDetached = true
	}

	if _, ok := yamlInput["volumes"]; ok {
		container.volumeYamlConf = yamlInput["volumes"].([]any)
	}

	if _, ok := yamlInput["vars"]; ok {
		for _, envVar := range yamlInput["vars"].([]interface{}) {
			envVarMap := envVar.(ContainerConfig)
			name := envVarMap["name"].(string)
			value := envVarMap["value"].(string)
			container.AddEnvVar(name, value)
		}
	}
	return container, nil
}

func (c *Container) getWorkDirVolume() (res Volume, exists bool) {
	for _, v := range c.Volumes {
		if v.IsDefaultWorkDir {
			res = v
			exists = true
			return
		}
	}
	return
}

func (c *Container) GetHostWorkDir() (res string) {
	if v, ok := c.getWorkDirVolume(); ok {
		res = v.HostDir
	}
	return
}

func (c *Container) GetContainerWorkDir() (res string) {
	if v, ok := c.getWorkDirVolume(); ok {
		res = v.ContainerDir
	}
	return
}

func (c *Container) PullDockerImage(name string, ctx context.Context) {
	// "func (*Client) ImagePull" doesn't work, returns "No such image"
	Log("Pulling image: " + name)
	_, err := exechelper.CombinedOutput("docker pull " + name)
	AssertNil(err)
}

// Creates a container
func (c *Container) Create() error {
	c.createVolumePaths()

	images, err := c.Suite.Docker.ImageList(c.ctx, image.ListOptions{})
	AssertNil(err)

	// compare full repository:tag references, and every tag rather than just the
	// first: matching on the repository alone would take another run's build of
	// hs-test/vpp for this one, and would send a locally built per-run tag to
	// 'docker pull', which cannot find it
	wanted := c.Image
	if !imageHasTag(wanted) {
		wanted += ":latest"
	}
	found := false
	for _, image := range images {
		if slices.Contains(image.RepoTags, wanted) {
			found = true
			break
		}
	}
	if !found {
		c.PullDockerImage(c.Image, c.ctx)
	}

	// nothing else in the output says which build was exercised, and a run pointed
	// at the wrong images passes just like a correct one
	Log("Creating container %s from image %s", c.Name, c.Image)

	c.allocateCpus()
	cpuSet := fmt.Sprintf("%d-%d", c.AllocatedCpus[0], c.AllocatedCpus[len(c.AllocatedCpus)-1])
	if *NumaPerProcess {
		cpuSet = formatCpuSet(c.AllocatedCpus)
	}
	resp, err := c.Suite.Docker.ContainerCreate(
		c.ctx,
		&containerTypes.Config{
			Image:  c.Image,
			Env:    c.getEnvVars(),
			Cmd:    strings.Split(c.ExtraRunningArgs, " "),
			Labels: map[string]string{runLabel: RunIdentity},
		},
		&containerTypes.HostConfig{
			Resources: containerTypes.Resources{
				Ulimits: []*units.Ulimit{
					{
						Name: "nofile",
						Soft: 90000,
						Hard: 90000,
					},
				},
				CpusetCpus: cpuSet,
				Devices: []containerTypes.DeviceMapping{
					{
						PathOnHost:        "/dev/net/tun",
						PathInContainer:   "/dev/net/tun",
						CgroupPermissions: "rwm",
					},
					{
						PathOnHost:        "/dev/vhost-net",
						PathInContainer:   "dev/vhost-net",
						CgroupPermissions: "rwm",
					},
				},
			},
			CapAdd:      []string{"NET_ADMIN", "SYS_RESOURCE", "IPC_LOCK", "SYS_PTRACE"},
			NetworkMode: containerTypes.NetworkMode("container:" + GinkgoContainerName()),
			Binds:       c.getVolumesAsSlice(),
		},
		nil,
		nil,
		c.Name,
	)
	c.ID = resp.ID
	return err
}

func formatCpuSet(cpus []int) string {
	cpuIds := make([]string, 0, len(cpus))
	for _, cpu := range cpus {
		cpuIds = append(cpuIds, strconv.Itoa(cpu))
	}
	return strings.Join(cpuIds, ",")
}

func (c *Container) allocateCpus() {
	c.Suite.StartedContainers = append(c.Suite.StartedContainers, c)
	c.AllocatedCpus = c.Suite.AllocateCpus(c.BaseName)
	c.Suite.ClaimCpus(c.Name, c.AllocatedCpus)
	Log("Allocated CPUs " + fmt.Sprint(c.AllocatedCpus) + " to container " + c.Name)
}

// Start waits for Docker to start the container process. Callers check application readiness.
func (c *Container) Start() error {
	ctx, cancel := context.WithTimeout(c.ctx, containerStartupTimeout)
	defer cancel()

	var state *containerTypes.State
	var err error
	startErr := c.Suite.Docker.ContainerStart(ctx, c.ID, containerTypes.StartOptions{})
	if startErr == nil {
		state, err = c.waitForStartup(ctx)
		if err == nil {
			Log("Container %s is %s", c.Name, state.Status)
			return nil
		}
	}

	// Give diagnostics their own deadline so they are available after a startup timeout.
	diagnosticCtx, cancelDiagnostics := context.WithTimeout(c.ctx, containerStartupDiagnostics)
	defer cancelDiagnostics()
	if startErr != nil {
		err = fmt.Errorf("Docker start failed: %w", startErr)
		var inspectErr error
		state, inspectErr = c.inspectState(diagnosticCtx)
		if inspectErr != nil {
			err = fmt.Errorf("%w (could not inspect state: %v)", err, inspectErr)
		}
	}

	details := "state unavailable"
	if state != nil {
		details = fmt.Sprintf("state=%q, exit code=%d, Docker error=%q, OOM killed=%t",
			state.Status, state.ExitCode, state.Error, state.OOMKilled)
	}
	err = fmt.Errorf("container %s (%s) startup failed: %w (%s)", c.Name, c.ID, err, details)
	logs, logErr := c.log(diagnosticCtx, 20)
	if logErr != nil {
		logs += fmt.Sprintf("\nDocker logs error: %v", logErr)
	}
	if logs != "" {
		return fmt.Errorf("%w\nContainer logs:\n%s", err, logs)
	}
	return err
}

func (c *Container) inspectState(ctx context.Context) (*containerTypes.State, error) {
	inspection, err := c.Suite.Docker.ContainerInspect(ctx, c.ID)
	if err != nil {
		return nil, err
	}
	if inspection.ContainerJSONBase == nil || inspection.State == nil {
		return nil, errors.New("Docker inspect response has no container state")
	}
	return inspection.State, nil
}

func (c *Container) waitForStartup(ctx context.Context) (*containerTypes.State, error) {
	var state *containerTypes.State
	for ctx.Err() == nil {
		current, err := c.inspectState(ctx)
		if err != nil {
			return state, fmt.Errorf("Docker inspect failed: %w", err)
		}
		state = current
		if state.Error != "" {
			return state, errors.New("Docker reported a container startup error")
		}
		// Foreground jobs may finish before the first inspect. The test owns
		// their result, including an intentional nonzero exit code.
		if state.Status == containerTypes.StateRunning ||
			(!c.RunDetached && state.Status == containerTypes.StateExited) {
			return state, nil
		}
		if state.Status != containerTypes.StateCreated && state.Status != containerTypes.StateRestarting {
			return state, errors.New("unexpected container state during startup")
		}
		select {
		case <-ctx.Done():
		case <-time.After(containerStartupPoll):
		}
	}
	return state, fmt.Errorf("waiting for Docker container startup: %w", ctx.Err())
}

func (c *Container) GetOutput() (string, string) {
	// Wait for the container to finish executing
	statusCh, errCh := c.Suite.Docker.ContainerWait(c.ctx, c.ID, containerTypes.WaitConditionNotRunning)
	select {
	case err := <-errCh:
		AssertNil(err)
	case <-statusCh:
	}

	// Get the logs from the container
	logOptions := containerTypes.LogsOptions{ShowStdout: true, ShowStderr: true}
	logReader, err := c.Suite.Docker.ContainerLogs(c.ctx, c.ID, logOptions)
	AssertNil(err)
	defer logReader.Close()

	var stdoutBuf, stderrBuf bytes.Buffer

	// Use stdcopy.StdCopy to demultiplex the multiplexed stream
	_, err = stdcopy.StdCopy(&stdoutBuf, &stderrBuf, logReader)
	AssertNil(err)

	stdout := stdoutBuf.String()
	stderr := stderrBuf.String()
	return stdout, stderr
}

func (c *Container) CombinedOutput() (string, error) {
	return c.execCombined(c.ctx, true, c.RunDetached, c.ExtraRunningArgs)
}

// Creates and starts a container
func (c *Container) Run() {
	AssertNil(c.Create())
	AssertNil(c.Start())
}

func (c *Container) createVolumePaths() {
	workingVolumeDir := LogDir + GetCurrentTestName() + VolumeDir
	workDirReplacer := strings.NewReplacer("$HST_DIR", workDir)
	volDirReplacer := strings.NewReplacer("$HST_VOLUME_DIR", workingVolumeDir)

	for _, volu := range c.volumeYamlConf {
		volumeMap := volu.(ContainerConfig)
		hostDir := workDirReplacer.Replace(volumeMap["host-dir"].(string))
		hostDir = volDirReplacer.Replace(hostDir)
		containerDir := volumeMap["container-dir"].(string)
		isDefaultWorkDir := false

		if isDefault, ok := volumeMap["is-default-work-dir"]; ok {
			isDefaultWorkDir = isDefault.(bool)
		}
		c.addVolume(hostDir, containerDir, isDefaultWorkDir)
	}
}

func (c *Container) addVolume(hostDir string, containerDir string, isDefaultWorkDir bool) {
	var volume Volume
	volume.HostDir = strings.Replace(hostDir, "vol", c.Suite.GetTestId()+"/"+"vol", 1)
	volume.ContainerDir = containerDir
	volume.IsDefaultWorkDir = isDefaultWorkDir
	c.Volumes[hostDir] = volume
	// sun_path is 108 bytes including the terminating NUL, so 107 is the longest
	// path connect() accepts; at 108 it fails with EINVAL rather than warning.
	if pathLen := len(volume.HostDir) + len(defaultApiSocketFilePath); volume.IsDefaultWorkDir && pathLen > 107 {
		Log("**************************************************************\n"+
			"Api socket path is %d bytes, over the %d the kernel accepts.\n"+
			"Connecting to VPP will fail. Shorten the test name or LogDir.\n"+
			"**************************************************************", pathLen, 107)
	}
}

func (c *Container) getVolumesAsSlice() []string {
	var volumeSlice []string

	if (*IsVppDebug || *IsCoverage) && *VppSourceFileDir != "" {
		volumeSlice = append(volumeSlice, fmt.Sprintf("%s:%s", *VppSourceFileDir, *VppSourceFileDir))
	}

	core_pattern_byte, err := os.ReadFile("/proc/sys/kernel/core_pattern")
	core_pattern := string(core_pattern_byte)
	if err == nil {
		if len(core_pattern) > 0 && core_pattern[0] != '|' {
			index := strings.LastIndex(core_pattern, "/")
			if index == -1 {
				Log("'core_pattern' isn't set to an absolute path. Core dump check will not work.")
			} else {
				core_pattern = core_pattern[:index]
				volumeSlice = append(volumeSlice, c.Suite.getLogDirPath()+":"+core_pattern)
			}
		} else {
			Log("core_pattern \"%s\" starts with pipe, ignoring", core_pattern)
		}
	} else {
		Log(err)
	}

	if len(c.Volumes) > 0 {
		for _, volume := range c.Volumes {
			volumeSlice = append(volumeSlice, fmt.Sprintf("%s:%s", volume.HostDir, volume.ContainerDir))
			os.Chmod(volume.HostDir, 0777)
		}
	}
	return volumeSlice
}

func (c *Container) AddEnvVar(name string, value string) {
	c.EnvVars[name] = value
}

func (c *Container) getEnvVars() []string {
	var envVars []string
	if len(c.EnvVars) == 0 {
		return envVars
	}

	for name, value := range c.EnvVars {
		envVars = append(envVars, fmt.Sprintf("%s=%s", name, value))
	}
	return envVars
}

func (c *Container) newVppInstance(cpus []int, additionalConfigs ...Stanza) (*VppInstance, error) {
	vpp := new(VppInstance)
	vpp.Container = c
	vpp.Cpus = cpus
	vpp.setDefaultCpuConfig()
	vpp.AdditionalConfig = append(vpp.AdditionalConfig, additionalConfigs...)
	c.VppInstance = vpp
	return vpp, nil
}

func (c *Container) CreateFile(destFileName string, content string) error {
	return c.createFileWithMode(destFileName, content, 0644)
}

func (c *Container) createFileWithMode(destFileName, content string, mode os.FileMode) error {
	var archive bytes.Buffer
	writer := tar.NewWriter(&archive)
	if err := writer.WriteHeader(&tar.Header{
		Name:    path.Base(destFileName),
		Mode:    int64(mode.Perm()),
		Size:    int64(len(content)),
		ModTime: time.Now().Truncate(time.Second),
	}); err != nil {
		return err
	}
	if _, err := io.WriteString(writer, content); err != nil {
		return err
	}
	if err := writer.Close(); err != nil {
		return err
	}

	if err := c.Suite.Docker.CopyToContainer(c.ctx, c.Name, path.Dir(destFileName), &archive, containerTypes.CopyToContainerOptions{}); err != nil {
		return fmt.Errorf("copy %s to %s: %w", destFileName, c.Name, err)
	}
	return nil
}

func (c *Container) CreateFileInWorkDir(fileName string, contents string) error {
	hostWorkDir := c.GetHostWorkDir()
	if hostWorkDir == "" {
		return fmt.Errorf("container %s has no shared work directory", c.Name)
	}
	filePath := filepath.Join(hostWorkDir, fileName)
	if err := os.WriteFile(filePath, []byte(contents), 0644); err != nil {
		return err
	}
	return os.Chmod(filePath, 0644)
}

func (c *Container) GetFile(sourceFileName, targetFileName string) error {
	cmd := exec.Command("docker", "cp", c.Name+":"+sourceFileName, targetFileName)
	return cmd.Run()
}

// ExecServer starts a command without waiting for it to exit.
func (c *Container) ExecServer(useEnvVars bool, command any, arguments ...any) {
	ginkgo.GinkgoHelper()
	_, err := c.execCombined(c.ctx, useEnvVars, true, formatExecCommand(command, arguments))
	AssertNil(err)
}

func (c *Container) Exec(useEnvVars bool, command any, arguments ...any) (string, error) {
	ginkgo.GinkgoHelper()
	return c.execCombined(c.ctx, useEnvVars, false, formatExecCommand(command, arguments))
}

// ExecLineBuffered runs a command with stdbuf -oL and captures stdout and stderr separately.
func (c *Container) ExecLineBuffered(ctx context.Context, useEnvVars bool, command any, arguments ...any) (string, string, error) {
	ginkgo.GinkgoHelper()
	cmd, err := shlex.Split("stdbuf -oL " + formatExecCommand(command, arguments))
	if err != nil {
		return "", "", err
	}
	var stdout, stderr bytes.Buffer
	err = c.exec(ctx, useEnvVars, false, cmd, &stdout, &stderr)
	return stdout.String(), stderr.String(), err
}

func (c *Container) ExecContext(ctx context.Context, useEnvVars bool, command any, arguments ...any) (string, error) {
	ginkgo.GinkgoHelper()
	return c.execCombined(ctx, useEnvVars, false, formatExecCommand(command, arguments))
}

func formatExecCommand(command any, arguments []any) string {
	cmd := fmt.Sprint(command)
	if len(arguments) > 0 {
		return fmt.Sprintf(cmd, arguments...)
	}
	return cmd
}

func (c *Container) execCombined(ctx context.Context, useEnvVars, detached bool, command string) (string, error) {
	cmd, err := shlex.Split(command)
	if err != nil {
		return "", err
	}
	var output bytes.Buffer
	err = c.exec(ctx, useEnvVars, detached, cmd, &output, &output)
	return output.String(), err
}

type containerExecExitError int

func (e containerExecExitError) Error() string {
	return fmt.Sprintf("exit status %d", e)
}

func (e containerExecExitError) ExitCode() int {
	return int(e)
}

func (c *Container) exec(ctx context.Context, useEnvVars, detached bool, cmd []string, stdout, stderr io.Writer) error {
	if len(cmd) == 0 {
		return errors.New("container exec requires a command")
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	Log("Exec in %s (detached=%t): %q", c.Name, detached, cmd)
	docker := c.Suite.Docker
	options := containerTypes.ExecOptions{
		Cmd:          cmd,
		Detach:       detached,
		AttachStdout: !detached,
		AttachStderr: !detached,
	}
	if useEnvVars {
		options.Env = c.getEnvVars()
	}

	created, err := docker.ContainerExecCreate(ctx, c.Name, options)
	if err != nil {
		return err
	}
	if detached {
		return docker.ContainerExecStart(ctx, created.ID, containerTypes.ExecStartOptions{Detach: true})
	}

	stream, err := attachExec(ctx, docker, created.ID)
	if err != nil {
		return err
	}
	defer stream.Close()
	if err := ctx.Err(); err != nil {
		return err
	}

	// Once the connection is upgraded, cancelling the request no longer
	// interrupts reads. Callers can explicitly cancel to finish collecting logs.
	stop := context.AfterFunc(ctx, func() { stream.Close() })
	_, err = stdcopy.StdCopy(stdout, stderr, stream)
	if !stop() {
		ctxErr := ctx.Err()
		if ctxErr != context.Canceled {
			return ctxErr
		}
		Log("'%v' error ignored (context cancelled)", ctxErr)
		return nil
	}
	if err != nil {
		return err
	}

	status, err := docker.ContainerExecInspect(ctx, created.ID)
	if err != nil {
		return err
	}
	if status.ExitCode != 0 {
		return containerExecExitError(status.ExitCode)
	}
	return nil
}

// Use the SDK's HTTP transport for the upgrade so cancellation can interrupt
// the handshake. ContainerExecAttach only uses the context while dialing.
func attachExec(ctx context.Context, docker *client.Client, id string) (io.ReadCloser, error) {
	endpoint, err := client.ParseHostURL(docker.DaemonHost())
	if err != nil {
		return nil, err
	}
	if endpoint.Scheme == "unix" || endpoint.Scheme == "npipe" {
		endpoint.Host = client.DummyHost
	}
	// The suite configures Docker with client.FromEnv, which enables TLS
	// when DOCKER_CERT_PATH is set.
	endpoint.Scheme = "http"
	if os.Getenv(client.EnvOverrideCertPath) != "" {
		endpoint.Scheme = "https"
	}
	if version := docker.ClientVersion(); version != "" {
		endpoint.Path = path.Join(endpoint.Path, "v"+strings.TrimPrefix(version, "v"))
	}
	endpoint.Path = path.Join(endpoint.Path, "exec", id, "start")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), strings.NewReader("{}"))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "tcp")

	response, err := docker.HTTPClient().Do(req)
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusSwitchingProtocols {
		response.Body.Close()
		return nil, fmt.Errorf("Docker exec attach returned %s", response.Status)
	}
	return response.Body, nil
}

func (c *Container) saveLogs() {
	// BaseName, not Name: the log directory is already per run and per test, so
	// repeating the run and process in the file name only makes it harder to read
	testLogFilePath := c.Suite.getLogDirPath() + "container-" + c.BaseName + ".log"

	logs, err := c.log(c.ctx, 0)
	if err != nil {
		Log(err)
		return
	}

	f, err := os.Create(testLogFilePath)
	if err != nil {
		Log(err)
		return
	}
	defer f.Close()
	err = os.Chmod(testLogFilePath, 0666)
	if err != nil {
		Log(err)
		return
	}
	fmt.Fprint(f, logs)
}

// Returns logs from docker containers. Set 'maxLines' to 0 to output the full log.
func (c *Container) log(ctx context.Context, maxLines int) (string, error) {
	var logOptions containerTypes.LogsOptions
	if maxLines == 0 {
		logOptions = containerTypes.LogsOptions{ShowStdout: true, ShowStderr: true, Details: true, Timestamps: true}
	} else {
		logOptions = containerTypes.LogsOptions{ShowStdout: true, ShowStderr: true, Details: true, Tail: strconv.Itoa(maxLines)}
	}

	out, err := c.Suite.Docker.ContainerLogs(ctx, c.ID, logOptions)
	if err != nil {
		Log(err)
		return "", err
	}
	defer out.Close()

	var stdoutBuf, stderrBuf bytes.Buffer

	_, err = stdcopy.StdCopy(&stdoutBuf, &stderrBuf, out)
	if err != nil {
		Log(err)
	}

	stdout := stdoutBuf.String()
	stderr := stderrBuf.String()

	re := regexp.MustCompile("(?m)^.*==> /dev/null <==.*$[\r\n]+")
	stdout = re.ReplaceAllString(stdout, "")

	re = regexp.MustCompile("(?m)^.*tail: cannot open '' for reading: No such file or directory.*$[\r\n]+")
	stderr = re.ReplaceAllString(stderr, "")

	return stdout + stderr, err
}

func (c *Container) stop() error {
	if c.VppInstance != nil && c.VppInstance.ApiStream != nil {
		c.VppInstance.saveLogs()
		c.VppInstance.Disconnect()
		c.VppInstance.Stop()
	}
	timeout := 0
	c.VppInstance = nil
	c.saveLogs()
	Log("Stopping container " + c.Name)
	if c.Suite.CoverageRun {
		timeout = 3
	}
	if err := c.Suite.Docker.ContainerStop(c.ctx, c.ID, containerTypes.StopOptions{Timeout: &timeout}); err != nil {
		return err
	}

	for n, v := range c.Volumes {
		if v.IsDefaultWorkDir {
			delete(c.Volumes, n)
		}
	}

	return nil
}

func (c *Container) CreateConfigFromTemplate(targetConfigName string, templateName string, values any) {
	template := template.Must(template.ParseFiles(templateName))

	var config strings.Builder
	AssertNil(template.Execute(&config, values))
	AssertNil(c.CreateFile(targetConfigName, config.String()))
}

func init() {
	err := os.Mkdir(LogDir, 0777)
	if err != nil && !errors.Is(err, os.ErrExist) {
		panic(err)
	} else {
		os.Chmod(LogDir, 0777)
	}
}
