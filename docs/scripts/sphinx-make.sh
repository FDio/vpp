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
PIP_VERSION=$(grep 'PIP_VERSION=' $WS_ROOT/test/Makefile | cut -d'=' -f2)
PIP_TOOLS_VERSION=$(grep 'PIP_TOOLS_VERSION=' $WS_ROOT/test/Makefile | cut -d'=' -f2)

if [ "$1" == "venv" ]
then

    # Install the virtual environment
    $PYTHON_INTERP -m venv $VENV_DIR
    source $VENV_DIR/bin/activate;
    $PYTHON_INTERP -m pip install pip==$PIP_VERSION
    $PYTHON_INTERP -m pip install pip-tools==$PIP_TOOLS_VERSION
    $PYTHON_INTERP -m pip install -r $WS_ROOT/test/requirements-3.txt
else
    [ -n "$(declare -f deactivate)" ] && deactivate
    source $VENV_DIR/bin/activate;
    VERSION=`source $WS_ROOT/src/scripts/version`
    TM=`TZ=GMT date`
    sed -ie "s/**VPP Version:\*\* .*/**VPP Version:** $VERSION/" $DOCS_DIR/about.rst
    sed -ie "s/**Built on:\*\* .*/**Built on:** $TM/" $DOCS_DIR/about.rst
    rm $DOCS_DIR/about.rste
    make -C $DOCS_DIR $1
fi

deactivate
