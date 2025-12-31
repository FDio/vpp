# Compatibility wrapper for CI jobs that expect hs-test under test/hs-test
.PHONY: build test clean

build:
	$(MAKE) -C ../../extras/hs-test build

test:
	$(MAKE) -C ../../extras/hs-test test

clean:
	$(MAKE) -C ../../extras/hs-test clean
