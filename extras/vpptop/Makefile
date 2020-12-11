# Manage VPPTop

.PHONY: install
install:
	@ cd ../../ && $(MAKE) json-api-files
	@./vpptop.sh install

.PHONY: start
start:
	@./vpptop.sh start

.PHONY: cleanup
cleanup:
	@./vpptop.sh cleanup

.PHONY: help
help:
	@./vpptop.sh help