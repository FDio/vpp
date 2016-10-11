PYTHON_VENV_PATH=$(PYTHON_PATH)/virtualenv

test:
	@virtualenv $(PYTHON_VENV_PATH)
	@bash -c "source $(PYTHON_VENV_PATH)/bin/activate && pip install scapy"
	@bash -c "source $(PYTHON_VENV_PATH)/bin/activate && cd $(WS_ROOT)/vpp-api/python && python setup.py install"
	@bash -c "source $(PYTHON_VENV_PATH)/bin/activate && python run_tests.py discover -p test_$(TEST)\"*.py\""

retest:
	@bash -c "source $(PYTHON_VENV_PATH)/bin/activate && python run_tests.py discover -p test_$(TEST)\"*.py\""

	

