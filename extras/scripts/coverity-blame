#!/bin/sh

# Read coverity email on stdin
# whenever we find a filename & line number reference, go git-blame it

file=
start=
end=

while read line; do
	if echo "$line" | grep -q '^/.*: '; then
		echo "$line"
		file=$(echo "$line" | cut -d: -f1)
	elif echo "$line" | grep -q '^[*]'; then
		echo "$line"
		file=
		start=
		end=
	elif echo "$line" | grep -q '^[0-9][0-9]*'; then
		num=$(echo "$line" | awk '{print $1}')
		[ -z "$start" ] && start=$num
		#git blame -L "$num,+1" ".$file" | cat
	elif [ -z "$line" ]; then
		if [ "$start" -a "$num" -a "$file" ]; then
			end=$num
			git blame --date=short -L "$start,$end" ".$file" | cat
			start=
			end=
			num=
		else
			echo "$line"
		fi
	else
		echo "$line"
	fi
done
