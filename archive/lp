#!/bin/bash

# temp file so that we can do the data transformation
temp_file=$(mktemp)
total=$(mktemp)
out=$(mktemp)

ls -al | grep total > ${total}

readVal=4
writeVal=2
exVal=1
noVal=0
cat ${total}

# just get the file permissions for each of the files 
ls -al | sed 's/total//' >> ${temp_file}


calculatePermission() {
		permTarget=$1
		valTarget=$2
		for var in 0 1 2
		do
			if [[ ${permTarget:var:1} == r ]]; then
				valTarget=$(( $valTarget + $readVal ))
			elif [[ ${permTarget:var:1} == w ]]; then
				valTarget=$(( $valTarget + $writeVal ))
			elif [[ ${permTarget:var:1} == x ]]; then
				valTarget=$(( $valTarget + $exVal ))
			else
				valTarget=$(( $valTarget + $noVal ))
			fi
		done
		echo $valTarget
		
}

cat ${temp_file} | while read line
do
	if [[ ${line:0:1} == d ]]; then
		perms=$(echo ${line} | awk '{print $1}' | sed 's/d//') 
		user=${perms:0:3}
		group=${perms:2:3}
		other=${perms:5:3}
		userTotal=0
		groupTotal=0
		otherTotal=0
		permissions=$({ calculatePermission $user $userTotal ; calculatePermission $group $groupTotal ; calculatePermission $other $otherTotal ; } | sed ':a;N;$!ba;s/\n/ /g' | sed 's/^/dir /')
		echo $permissions $line
	else
		if [[ ${line:0:1} == - ]]; then
			perms=$(echo ${line} | awk '{print $1}' | sed 's/-//')
			user=${perms:0:3}
			group=${perms:2:3}
			other=${perms:5:3}
			userTotal=0
			groupTotal=0
			otherTotal=0
			permissions=$({ calculatePermission $user $userTotal ; calculatePermission $group $groupTotal ; calculatePermission $other $otherTotal ; } | sed ':a;N;$!ba;s/\n/ /g' | sed 's/^/--- /')
			echo $permissions $line
		fi
	fi
done

# cleanup
rm ${temp_file}
rm ${out}
rm ${total}