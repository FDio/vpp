#!/bin/bash

if [ "$1" == "venv" ]
then
    python -m pip install --user virtualenv
    python -m virtualenv $VENV_DIR
    source $VENV_DIR/bin/activate;
    pip install -r $DOCS_DIR/etc/requirements.txt
else
    source $VENV_DIR/bin/activate;
    make -C $DOCS_DIR $1
fi

deactivate
