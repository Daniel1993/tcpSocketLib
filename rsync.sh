#!/bin/bash

DIR=projs
NAME="tcp-socket-lib"

### use the node name as parameter for this script
NODE="pascal"

DM=$DIR/$NAME

CMAKE=cmake

command -v $CMAKE >/dev/null 2>&1 || { CMAKE=~/bins/cmake; }
command -v $CMAKE >/dev/null 2>&1 || { echo "cmake not installed. Aborting." >&2; exit 1; }

if [[ $# -gt 0 ]] ; then
	NODE=$1
fi

find . -name ".DS_Store" -delete
find . -name "._*" -delete

ssh $NODE "mkdir -p $DM "
make clean
echo "rsync -avz . $NODE:$DM"
rsync -avz . $NODE:$DM

ssh $NODE "                                              \
	echo -e '\n <<<< tcp-sockets-lib >>>> ' ;              \
	cd $DM ;                                               \
	make clean ;                                           \
	make DEBUG=1 -j4"
