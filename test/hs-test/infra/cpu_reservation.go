package hst

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
)

// Concurrent test runs share one machine's CPUs by recording what they hold in a
// table under LogDir, guarded by an flock. Container CPUs are pinned and handed out
// from the start of the allocator's list, so without this two runs pin to the same
// cores while the rest of the machine idles.
//
// Settling a share rewrites the whole table under the lock: every live run is cut
// back to an even share and this run takes what that frees. The arriving run does
// the arithmetic for everybody, because the others only look between tests while it
// needs cores before its first one. A row lives as long as the run's Ginkgo
// container: no run deletes its own, and rows whose container is gone are dropped
// by whichever run reads them next. Releasing at suite teardown instead would drop
// the row while the run is still going, since teardown runs once per suite in every
// Ginkgo process.
//
// Cores already pinned stay pinned until the test that created them ends, so a run
// just cut back can briefly overlap with the newcomer.

const (
	reservationPath     = LogDir + "cpu-reservations"
	reservationLockPath = LogDir + "cpu-reservations.lock"

	// A run using MW parallelism allocates per NUMA node and needs whole nodes, so
	// it takes the machine instead of a share and is never asked to give any back.
	reservationModeMW    = "mw"
	reservationModePlain = "plain"
)

// busyError means another run holds the cores this one needs. Nothing is wrong
// with the tests, so the suite skips rather than fails on it.
type busyError struct{ reason string }

func (e busyError) Error() string { return e.reason }

type cpuReservation struct {
	runIdentity string
	cpus        []int
	mode        string
}

func withReservationLock(fn func() error) error {
	if err := os.MkdirAll(filepath.Dir(reservationLockPath), 0777); err != nil {
		return err
	}
	// O_RDONLY is enough for flock and does not need write permission on the file,
	// which a run started by hand would not have: the lock is created by a run
	// inside the Ginkgo container, so it belongs to root.
	lockFile, err := os.OpenFile(reservationLockPath, os.O_CREATE|os.O_RDONLY, 0666)
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

func readReservations() ([]cpuReservation, error) {
	data, err := os.ReadFile(reservationPath)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	var reservations []cpuReservation
	for line := range strings.SplitSeq(string(data), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) < 3 {
			return nil, fmt.Errorf("invalid reservation line %q", line)
		}
		var cpus []int
		if fields[1] != "" {
			if cpus, err = parseLinuxList(fields[1]); err != nil {
				return nil, fmt.Errorf("invalid reservation %q: %w", fields[1], err)
			}
		}
		reservations = append(reservations, cpuReservation{fields[0], cpus, fields[2]})
	}
	return reservations, nil
}

// writeReservations publishes the table by rename, so a reader that does not take
// the lock cannot observe a half written file.
func writeReservations(reservations []cpuReservation) error {
	var b strings.Builder
	for _, r := range reservations {
		fmt.Fprintf(&b, "%s\t%s\t%s\n", r.runIdentity, formatCpuSet(r.cpus), r.mode)
	}

	tmp, err := os.CreateTemp(filepath.Dir(reservationPath), "cpu-reservations")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())

	if _, err = tmp.WriteString(b.String()); err != nil {
		tmp.Close()
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	// runs may belong to different users; all of them have to be able to rewrite it
	if err = os.Chmod(tmp.Name(), 0666); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), reservationPath)
}

// runIsLive reports whether a run still has its Ginkgo container. Selection is by
// label rather than by name because a run identity may contain characters that
// docker's name filter treats as a pattern.
func (s *HstSuite) runIsLive(runIdentity string) bool {
	containers, err := s.Docker.ContainerList(context.Background(), container.ListOptions{
		Filters: filters.NewArgs(filters.Arg("label", runLabel+"="+runIdentity)),
	})
	if err != nil {
		// assume it is alive: leaving a run its cores is safer than handing them out twice
		Log("could not check whether run %s is live: %v", runIdentity, err)
		return true
	}
	return len(containers) > 0
}

// liveReservationsOf returns the rows of other runs that still exist, dropping this
// run's own row and the rows of runs that are gone.
func (s *HstSuite) liveReservationsOf(all []cpuReservation) (others []cpuReservation) {
	for i := range all {
		if all[i].runIdentity != RunIdentity && s.runIsLive(all[i].runIdentity) {
			others = append(others, all[i])
		}
	}
	return others
}

// reserveCpus settles this run's share of allocatable and returns it. Called once
// per suite and again at every test, so that a share which changed because another
// run started or finished is picked up.
func (s *HstSuite) reserveCpus(allocatable []int) ([]int, error) {
	var reserved []int

	err := withReservationLock(func() error {
		all, err := readReservations()
		if err != nil {
			return err
		}
		others := s.liveReservationsOf(all)

		if *NumaPerProcess {
			// An MW run wants whole NUMA nodes. Record the machine so plain runs stay
			// away, and return everything: nothing is filtered for such a run.
			for _, other := range others {
				return busyError{fmt.Sprintf("MW parallelism needs the whole machine, but run %s holds CPUs %s",
					other.runIdentity, formatCpuSet(other.cpus))}
			}
			reserved = allocatable
			return writeReservations([]cpuReservation{{RunIdentity, allocatable, reservationModeMW}})
		}

		for _, other := range others {
			if other.mode == reservationModeMW {
				return busyError{fmt.Sprintf("run %s is using the whole machine with MW parallelism; wait for it to finish",
					other.runIdentity)}
			}
		}

		// An even split of what the machine offers, this run included.
		share := len(allocatable) / (len(others) + 1)
		if share < 1 {
			share = 1
		}

		// Cut every run that holds more than its share back to it. What they give up
		// needs no bookkeeping: whatever no run still holds counts as free below.
		held := make(map[int]bool)
		for i := range others {
			if len(others[i].cpus) > share {
				others[i].cpus = others[i].cpus[:share]
			}
			for _, cpu := range others[i].cpus {
				held[cpu] = true
			}
		}

		// Take our share from the cores no run holds.
		for _, cpu := range allocatable {
			if len(reserved) == share {
				break
			}
			if !held[cpu] {
				reserved = append(reserved, cpu)
			}
		}

		if len(reserved) == 0 {
			return busyError{fmt.Sprintf("no CPUs are free for this run; %d other run(s) hold all %d of them",
				len(others), len(allocatable))}
		}

		return writeReservations(append(others,
			cpuReservation{RunIdentity, reserved, reservationModePlain}))
	})

	return reserved, err
}
