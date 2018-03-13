#!/bin/bash

sudo ./virtwol | while read mac
do
    for dom in $(virsh list --all --name)
    do
	state=$(virsh domif-getlink --domain "$dom" --interface "$mac" 2>&1)
	rv=$?
	if [[ $rv != 0 ]]; then continue; fi
	if [[ ${state##*$line } == "up" ]]
	then
	    virsh start "$dom" || :
	    break
	fi
    done
done
