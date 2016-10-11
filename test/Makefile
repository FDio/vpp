PYTHON_VENV_PATH=$(PYTHON_PATH)/virtualenv

test: clean
	@virtualenv $(PYTHON_VENV_PATH)
	@bash -c "source $(PYTHON_VENV_PATH)/bin/activate && pip install scapy"
	@bash -c "source $(PYTHON_VENV_PATH)/bin/activate && pip install pexpect"
	@bash -c "source $(PYTHON_VENV_PATH)/bin/activate && cd $(WS_ROOT)/vpp-api/python && python setup.py install"
	@bash -c "source $(PYTHON_VENV_PATH)/bin/activate && python run_tests.py discover -p test_$(TEST)\"*.py\""

retest: clean
	@bash -c "source $(PYTHON_VENV_PATH)/bin/activate && python run_tests.py discover -p test_$(TEST)\"*.py\""

.PHONY: clean doc

clean:
	@rm -f /dev/shm/vpp-unittest-*
	@rm -rf /tmp/vpp-unittest-*

doc:
	@virtualenv $(PYTHON_VENV_PATH)
	@bash -c "source $(PYTHON_VENV_PATH)/bin/activate && pip install sphinx"
	@bash -c "source $(PYTHON_VENV_PATH)/bin/activate && make -C doc html"
