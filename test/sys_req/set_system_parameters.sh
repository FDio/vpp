#!/bin/bash

file="$1"

usage(){
	echo "Usage: $0 <requirements file>"
}

if [ "$file" == "" ]
then
	echo "Invalid parameters specified."
	usage
	exit 1
fi

if [ ! -f $file ]
then
	echo "File '$file' does not exist."
	usage
	exit 1
fi

if test "$DOCKER_TEST" = "True"
then
	echo "=============================================================================="
	echo "DOCKER_TEST is set to '$DOCKER_TEST'."
	echo "Skipping verification of some system parameters."
	echo "Make sure these are set properly, otherwise tests might fail."
	echo "Required values/criteria are in '`readlink -e $file`'."
	echo "=============================================================================="
	exit 0
fi

cat $file | grep -v -e '^#.*$' | grep -v -e '^ *$' | while read line
do
	value_file=`echo $line | awk '{print $1}'`
	operator=`echo $line | awk '{print $2}'`
	value=`echo $line | awk '{print $3}'`
	set_value=`echo $line | awk '{print $4}'`
	if [[ "$value_file" == "" || "$operator" == "" || "$value" == "" || "$set_value" == "" ]]
	then
		echo "Syntax error in requirements file."
		exit 1
	fi
	current_value=`cat $value_file`
	if test "$current_value" $operator "$value"
	then
		if test "$V" = "2"
		then
			echo "Requirement '$value_file $operator $value' satisfied."
		fi
	else
		echo "Requirement '$value_file $operator $value' not satisfied."
		echo "Writing '$set_value' to '$value_file'."
		echo "$set_value" | tee "$value_file" > /dev/null
		if ! test "`cat $value_file`" = "$set_value"
		then
			echo "Repeating the write using sudo..."
			echo "$set_value" | sudo -n tee "$value_file" > /dev/null
			if ! test "`cat $value_file`" = "$set_value"
			then
				echo "Couldn't set the required value. Is that value allowed? Is sudo working?"
				exit 1
			fi
		fi
		echo "Succesfully wrote '$set_value' to '$value_file'."
	fi
done
