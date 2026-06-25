package hst

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"

	"github.com/onsi/ginkgo/v2"
)

const (
	cpuClaimsPath     = LogDir + "cpu-claims"
	cpuClaimsLockPath = LogDir + "cpu-claims.lock"
)

type cpuClaim struct {
	owner string
	cpus  []int
}

func withCpuClaimsLock(fn func() error) error {
	lockFile, err := os.OpenFile(cpuClaimsLockPath, os.O_CREATE|os.O_RDWR, 0666)
	if err != nil {
		return err
	}
	defer lockFile.Close()

	if err = syscall.Flock(int(lockFile.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN)

	return fn()
}

func readCpuClaims() ([]cpuClaim, error) {
	data, err := os.ReadFile(cpuClaimsPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	var claims []cpuClaim
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		fields := strings.SplitN(line, "\t", 2)
		if len(fields) != 2 {
			return nil, fmt.Errorf("invalid CPU claim line %q", line)
		}

		cpus, err := parseLinuxList(fields[1])
		if err != nil {
			return nil, fmt.Errorf("invalid CPU claim %q: %w", fields[1], err)
		}
		claims = append(claims, cpuClaim{owner: fields[0], cpus: cpus})
	}
	return claims, nil
}

func (s *HstSuite) ClaimCpus(containerName string, cpus []int) {
	if !*NumaPerProcess {
		return
	}

	owner := s.cpuClaimOwner(containerName)

	err := withCpuClaimsLock(func() error {
		claims, err := readCpuClaims()
		if err != nil {
			return err
		}

		claimedByCpu := make(map[int]string)
		for _, claim := range claims {
			for _, cpu := range claim.cpus {
				claimedByCpu[cpu] = claim.owner
			}
		}

		for _, cpu := range cpus {
			if existingOwner, ok := claimedByCpu[cpu]; ok {
				return fmt.Errorf("CPU allocation overlap: %s wants CPU %d, already claimed by %s",
					owner, cpu, existingOwner)
			}
		}

		claimFile, err := os.OpenFile(cpuClaimsPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0666)
		if err != nil {
			return err
		}
		defer claimFile.Close()

		_, err = fmt.Fprintf(claimFile, "%s\t%s\n", owner, formatCpuSet(cpus))
		return err
	})
	AssertNil(err)

	Log("CPU claim: %s cpus=%s", owner, formatCpuSet(cpus))
}

func (s *HstSuite) ReleaseCpuClaims() {
	if !*NumaPerProcess {
		return
	}

	ownerPrefix := fmt.Sprintf("ppid=%s process=%s ", Ppid, s.ProcessIndex)

	err := withCpuClaimsLock(func() error {
		claims, err := readCpuClaims()
		if err != nil {
			return err
		}

		var remaining []string
		for _, claim := range claims {
			if strings.HasPrefix(claim.owner, ownerPrefix) {
				continue
			}
			remaining = append(remaining, claim.owner+"\t"+formatCpuSet(claim.cpus))
		}

		output := ""
		if len(remaining) > 0 {
			output = strings.Join(remaining, "\n") + "\n"
		}
		return os.WriteFile(cpuClaimsPath, []byte(output), 0666)
	})
	AssertNil(err)
}

func (s *HstSuite) cpuClaimOwner(containerName string) string {
	return fmt.Sprintf("ppid=%s process=%s suite=%s test=%s container=%s",
		Ppid, s.ProcessIndex, currentSuiteName(), GetCurrentTestName(), containerName)
}

func currentSuiteName() string {
	report := ginkgo.CurrentSpecReport()
	if len(report.ContainerHierarchyTexts) == 0 {
		return "unknown"
	}
	return report.ContainerHierarchyTexts[0]
}
