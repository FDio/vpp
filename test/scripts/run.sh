#!/bin/bash

items=
for i in "$@"
do
case $i in
	--venv-dir=*)
		venv_dir="${i#*=}"
		if [ -d $venv_dir ]
		then
			venv_dir=$(cd $venv_dir; pwd)
		else
			echo "ERROR: '$venv_dir' is not a directory"
			exit 1
		fi
		items="$items --venv-dir=\"$venv_dir\""
		;;
	--vpp-ws-dir=*)
		ws_dir="${i#*=}"
		if [ -d $ws_dir ]
		then
			ws_dir=$(cd $ws_dir; pwd)
		else
			echo "ERROR: '$ws_dir' is not a directory"
			exit 1
		fi
		items="$items --vpp-ws-dir=\"$ws_dir\""
		;;
	--force-foreground=*)
		ff="${i#*=}"
		items="$items \"$i\""
		;;
	--vpp-tag=*)
		tag="${i#*=}"
		items="$items \"$i\""
		;;
	--python-opts=*)
		python_opts="${i#*=}"
		;;
	*)
		# unknown option - skip
		items="$items \"$i\""
		;;
esac
done

extra_args=""
if [ -z "$ws_dir" ]
then
	ws_dir=$(pwd)
	echo "Argument --vpp-ws-dir not specified, defaulting to '$ws_dir'"
	extra_args="$extra_args --vpp-ws-dir=$ws_dir"
fi

if [ -z "$venv_dir" ]
then
	venv_dir="$ws_dir/test/venv"
	echo "Argument --venv-path not specified, defaulting to '$venv_dir'"
	extra_args="$extra_args --venv-dir=$venv_dir"
fi

if [ -z "$ff" ]
then
	ff="0"
	echo "Argument --force-foreground not specified, defaulting to '$ff'"
fi

if [ -z "$tag" ]
then
	tag="vpp_debug"
	echo "Argument --vpp-tag not specified, defaulting to '$tag'"
	extra_args="$extra_args --vpp-tag=$tag"
fi

eval set -- $items
$ws_dir/test/scripts/setsid_wrapper.sh $ws_dir/test/scripts/run_in_venv_with_cleanup.sh $ff $venv_dir/bin/activate python3 $python_opts $ws_dir/test/run_tests.py $extra_args $*
