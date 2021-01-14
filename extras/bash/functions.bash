# Copyright (c) 2021 Cisco and/or its affiliates.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


# This file is meant to be sourced in a .bashrc file to add useful
# bash functions to an interactive shell

# Bash function to run vpp 'make test' testcases
# repeatedly, stopping on test failure or when
# a test log contains the optionally specified text
vpp-make-test()
{
    local options
    local usage
    local all
    local debug
    local grep_for
    local show_grep
    local run_make_test
    local old_pwd
    local test_desc
    local is_feature="false"
    local retry_count=100
    local tester=${GERRIT_USER:-$USER}
    local jobs="auto"

    if [ -z "$WS_ROOT" ] ; then
        echo "ERROR: WS_ROOT is not set!"
        return
    elif [ ! -d "$WS_ROOT/src/vppinfra" ] ; then
        echo "ERROR: WS_ROOT is not set to a VPP workspace!"
        return
    fi

    options=$(getopt -o "adfg:j:r:" -- "$@")
    if [ $? -eq 1 ] ; then
        usage=true
    else
        eval set -- $options
    fi
    while [ -z "$usage" ] ; do
        case "$1" in
            -a)
                all="-all"
                ;;
            -d)
                debug="-debug"
                ;;
            -f)
                is_feature="true"
                retry_count=1
                ;;
            -g)
                shift
                show_grep=$1
                grep_for="${1//-/\\-}"
                ;;
            -j)
                shift
                jobs=$1
                if [ $((jobs)) != $jobs ] ; then
                    echo "ERROR: Invalid option value for -j option ($jobs)!"
                    usage=true;
                fi
                ;;
            -r)
                shift
                retry_count=$1
                if [ $((retry_count)) != $retry_count ] ; then
                    echo "ERROR: Invalid option value for -r option ($retry_count)!"
                    usage=true;
                fi
                ;;
            --)
                shift
                break
                ;;
        esac
        shift
    done

    if [ -n "$usage" ] || [ -z "$1" ] ; then
        if [ -z "$1" ] ; then
            echo "ERROR: no testcase specified!"
        fi
        echo "Usage: vpp-make-test [-a][-d][-f][-g <text>][-j <jobs>][-r <retry count>] <testcase> [<retry_count>]"
        echo "         -a                Run extended tests"
        echo "         -d                Run vpp debug image (i.e. with ASSERTS)"
        echo "         -f                Testcase is a feature set (e.g. tcp)"
        echo "         -g <text>         Text to grep for in log, FAIL on match."
        echo "                           Enclose <text> in single quotes when it contains any dashes:"
        echo "                           e.g.  vpp-make-test -g 'goof-bad-' test_xyz"
        echo "         -j <# jobs>       Set TEST_JOBS (default = auto) for feature set"
        echo "         -r <retry count>  Retry Count (default = 100 for individual test | 1 for feature set)"
        return
    fi

    if [ $retry_count -le 0 ] ; then
        retry_count=1
    fi
    if [ "$is_feature" == "true" ] ; then
        run_make_test="make test$all$debug TEST=$1 SANITY=no TEST_JOBS=$jobs"
    else
        run_make_test="make test$all$debug TEST=*.*.$1 SANITY=no"
    fi

    old_pwd=$(pwd)
    cd $WS_ROOT
    line="------------------------------------------------------------------------------"
    test_desc="'$run_make_test'"
    if [ -n "$grep_for" ] ; then
        test_desc="$test_desc [grep '$show_grep']"
    fi
    for ((i=1; i<=retry_count; i++)) ; do
        echo -e "\n$line"
        echo -e "ITERATION [$i/$retry_count]: $test_desc\n$line"
        result=$($run_make_test)
        if [ ! -d /tmp/vpp-unittest* ] ; then
            echo -e "\nERROR: No testcase(s) executed!\n"
            return
        fi
        echo "$result"
        if [ -n "$grep_for" ] ; then
            grep_results=$(grep -sHn $grep_for /tmp/vpp-u*/log.txt)
        fi
        if [ -n "$(echo $result | grep FAILURE)" ] || [ -n "$grep_results" ] ; then
            if [ -n "$grep_results" ] ; then
                fail="FAIL (grep)"
            else
                fail="FAIL"
            fi
            echo -e "\n$line\n$fail [$i/$retry_count]: $test_desc\n$line\n"
            return
        fi
    done

    echo -e "\n$line\nPASS [$((i-1))/$retry_count]: $test_desc\n$line\n"
    echo -e "Hey $tester, Life is good!!! :D\n"
    cd $old_pwd
}

# bash function to set up csit python virtual environment
csit-env()
{
    if [ -f "$WS_ROOT/VPP_REPO_URL" ] && [ -f "$WS_ROOT/requirements.txt" ]; then
        if [ -n "$(declare -f deactivate)" ]; then
            echo "Deactivating Python Virtualenv!"
            deactivate
        fi
        local PIP=pip
        local setup_framework=$WS_ROOT/resources/libraries/python/SetupFramework.py
        if [ -n "$(grep pip3 $setup_framework)" ]; then
            PIP=pip3
            local VENV_OPTS="-p python3"
        fi
        export CSIT_DIR=$WS_ROOT
        export PYTHONPATH=$CSIT_DIR
        rm -rf $PYTHONPATH/env && virtualenv $VENV_OPTS $PYTHONPATH/env \
            && source $PYTHONPATH/env/bin/activate \
            && $PIP install --upgrade -r $PYTHONPATH/requirements.txt \
            && $PIP install --upgrade -r $PYTHONPATH/tox-requirements.txt
    else
        echo "ERROR: WS_ROOT not set to a CSIT workspace!"
    fi
}
