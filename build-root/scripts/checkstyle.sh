#!/bin/bash

# Copyright (c) 2015 Cisco and/or its affiliates.
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

VPP_DIR=`dirname $0`/../../
EXIT_CODE=0
FIX="0"
FULL="0"
CHECKSTYLED_FILES=""
UNCHECKSTYLED_FILES=""

# If the user provides --fix, then actually fix things
# Note: this is meant for use outside of the CI Jobs, by users cleaning things up

while true; do
	case ${1} in
		--fix)
			FIX="1"
			;;
		--full)
			FULL="1"
			;;
	esac
	shift || break
done

if [ "${FULL}" == "1" ]; then
	FILELIST=$(git ls-tree -r HEAD --name-only)
else
	FILELIST=$((git diff HEAD~1.. --name-only; git ls-files -m ) | sort -u)
fi

# Check to make sure we have indent.  Exit if we don't with an error message, but
# don't *fail*.
command -v dirname > /dev/null
if [ $? != 0 ]; then
    echo "Cound not find required command \"dirname\".  Checkstyle aborted"
    exit ${EXIT_CODE}
fi
command -v indent > /dev/null
if [ $? != 0 ]; then
    echo "Cound not find required command \"indent\".  Checkstyle aborted"
    exit ${EXIT_CODE}
fi

# Check that the installed indent has the correct version.
# if not - the checkstyle job will fail upon upload, bringing a lot of pain..
REQUIRED_INDENT_VERSION="GNU indent 2.2.11"
INDENT_VERSION="$(indent --version)"
if [ "${INDENT_VERSION}" != "${REQUIRED_INDENT_VERSION}" ]; then
    LOCAL_INDENT="$(find $(pwd) -name indent -type f -executable | head -n 1)"
    if [ "${LOCAL_INDENT}" != "" ]; then
        PATH="$(dirname ${LOCAL_INDENT}):$PATH"
        INDENT_VERSION=$(indent --version)
    fi
fi
echo "${INDENT_VERSION}"
if [ "${INDENT_VERSION}" != "${REQUIRED_INDENT_VERSION}" ]; then
	echo "Wrong indent version. Need ${REQUIRED_INDENT_VERSION}. Please run 'make install-checkstyle'"
	exit 1
fi

# Check to make sure we have clang-format.  Exit if we don't with an error message, but
# don't *fail*.
HAVE_CLANG_FORMAT=0
command -v clang-format > /dev/null
if [ $? != 0 ]; then
    echo "Could not find command \"clang-format\". Checking C++ files will cause abort"
else
    clang-format --version
    x=$(echo "" | clang-format 2>&1)
    if [[ "$x" == "" ]]; then
        HAVE_CLANG_FORMAT=1
    else
	echo "Output produced while formatting empty file (expected empty string):"
	echo "$x"
        echo "Could not find working \"clang-format\". Checking C++ files will cause abort"
    fi
fi

cd ${VPP_DIR}
git status
for i in ${FILELIST}; do
    if [ -f ${i} ] && [ ${i} != "build-root/scripts/checkstyle.sh" ] && [ ${i} != "extras/emacs/fix-coding-style.el" ]; then
        grep -q '>>>>>>>' ${i}
        if [ $? == 0 ]; then
            echo "Unresolved merge conflict detected in" ${i} "... Abort."
            exit 1
        fi
        grep -q "fd.io coding-style-patch-verification: ON" ${i}
        if [ $? == 0 ]; then
            EXTENSION=`basename ${i} | sed 's/^\w\+.//'`
            case ${EXTENSION} in
                hpp|cpp|cc|hh)
                    CMD="clang-format"
                    if [ ${HAVE_CLANG_FORMAT} == 0 ]; then
                            echo "C++ file detected. Abort. (missing clang-format)"
                            exit ${EXIT_CODE}
                    fi
                    ;;
                *)
                    CMD="indent"
                    ;;
            esac
            CHECKSTYLED_FILES="${CHECKSTYLED_FILES} ${i}"
            if [ ${FIX} == 0 ]; then
                if [ "${CMD}" == "clang-format" ]
                then
                    clang-format ${i} > ${i}.out2
                else
                    indent ${i} -o ${i}.out1 > /dev/null 2>&1
                    indent ${i}.out1 -o ${i}.out2 > /dev/null 2>&1
                fi
                # Remove trailing whitespace
                sed -i -e 's/[[:space:]]*$//' ${i}.out2
                diff -q ${i} ${i}.out2
            else
                if [ "${CMD}" == "clang-format" ]; then
                    clang-format -i ${i} > /dev/null 2>&1
                else
                    indent ${i}
                    indent ${i}
                fi
                # Remove trailing whitespace
                sed -i -e 's/[[:space:]]*$//' ${i}
            fi
            if [ $? != 0 ]; then
                EXIT_CODE=1
                echo
                echo "Checkstyle failed for ${i}."
                if [ "${CMD}" == "clang-format" ]; then
                    echo "Run clang-format as shown to fix the problem:"
                    echo "clang-format -i ${VPP_DIR}${i}"
                else
                    echo "Run indent (twice!) as shown to fix the problem:"
                    echo "indent ${VPP_DIR}${i}"
                    echo "indent ${VPP_DIR}${i}"
                fi
            fi
            if [ -f ${i}.out1 ]; then
                rm ${i}.out1
            fi
            if [ -f ${i}.out2 ]; then
                rm ${i}.out2
            fi
        else
            UNCHECKSTYLED_FILES="${UNCHECKSTYLED_FILES} ${i}"
        fi
    else
        UNCHECKSTYLED_FILES="${UNCHECKSTYLED_FILES} ${i}"
    fi
done

if [ ${EXIT_CODE} == 0 ]; then
    echo "*******************************************************************"
    echo "* VPP CHECKSTYLE SUCCESSFULLY COMPLETED"
    echo "*******************************************************************"
else
    echo "*******************************************************************"
    echo "* VPP CHECKSTYLE FAILED"
    echo "* CONSULT FAILURE LOG ABOVE"
    echo "* NOTE: Running 'build-root/scripts/checkstyle.sh --fix' *MAY* fix the issue"
    echo "*******************************************************************"
fi
exit ${EXIT_CODE}
