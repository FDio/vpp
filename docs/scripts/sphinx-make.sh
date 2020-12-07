#!/bin/bash -ex

# Not refactored to root Makefile because CI calls this from
# makefile in /docs (as if 'make -C docs').
if [ -z "$PYTHON" ]
then
PYTHON_INTERP=python3
else
PYTHON_INTERP=$(PYTHON)
fi

# Get the OS
OS_ID=$(grep '^ID=' /etc/os-release  | cut -f2- -d= | sed -e 's/\"//g')
OS_VERSION=$(grep '^VERSION_ID=' /etc/os-release  | cut -f2- -d= | sed -e 's/\"//g')

if [ "$1" == "venv" ]
then
    # We need to install the venv package on new systems
    if [ "$OS_ID" == "ubuntu" ]
    then
	sudo apt-get install $CONFIRM python3-venv
    fi
    if [ "$OS_ID" == "centos" ]
    then
	if [ "$OS_VERSION" == "8" ]
	then
	    sudo yum install $CONFIRM python3-virtualenv
	else
	    sudo yum install $CONFIRM python3-venv
	fi
    fi

    # Install the virtual environment
    $PYTHON_INTERP -m venv $VENV_DIR
    source $VENV_DIR/bin/activate;
    $PYTHON_INTERP -m pip install wheel==0.34.2
    $PYTHON_INTERP -m pip install -r $DOCS_DIR/etc/requirements.txt
else
    source $VENV_DIR/bin/activate;
    VERSION=`source $WS_ROOT/src/scripts/version`
    TM=`TZ=GMT date`
    sed -ie "s/**VPP Version:\*\* .*/**VPP Version:** $VERSION/" $DOCS_DIR/about.rst
    sed -ie "s/**Built on:\*\* .*/**Built on:** $TM/" $DOCS_DIR/about.rst
    rm $DOCS_DIR/about.rste
    make -C $DOCS_DIR $1
fi

deactivate
