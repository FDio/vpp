#!/bin/bash

if [ "$1" == "venv" ]
then
    OS_ID=$(grep '^ID=' /etc/os-release  | cut -f2- -d= | sed -e 's/\"//g')
    if [ "$OS_ID" == "ubuntu" ]
    then
	sudo apt-get install -y python3-pip
    fi
    if [ "$OS_ID" == "centos" ]
    then
	sudo yum install -y python3-pip
    fi
    pip3 install --user virtualenv
    python3 -m virtualenv $VENV_DIR
    source $VENV_DIR/bin/activate;
    pip3 install -r $DOCS_DIR/etc/requirements.txt
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
