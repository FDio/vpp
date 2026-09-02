package hst

import (
	"debug/elf"
	"path/filepath"
	"strings"
	"sync"
)

var (
	asanBuildOnce sync.Once
	asanBuild     bool
)

// IsAsanBuild reports whether VPP was built with AddressSanitizer. The
// detection works by checking whether the copied libvppinfra shared object
// imports (leaves undefined) __asan_* runtime symbols, which are normally
// satisfied by the statically-sanitized VPP executable at runtime.
func IsAsanBuild() bool {
	asanBuildOnce.Do(func() {
		matches, _ := filepath.Glob("vpp-data/lib/libvppinfra.so*")
		for _, m := range matches {
			f, err := elf.Open(m)
			if err != nil {
				continue
			}
			syms, err := f.ImportedSymbols()
			f.Close()
			if err != nil {
				continue
			}
			for _, s := range syms {
				if strings.HasPrefix(s.Name, "__asan_") {
					asanBuild = true
					return
				}
			}
		}
	})
	return asanBuild
}
