#!/bin/bash
make clean ; make

make setup_keys
tmux new -d "make start_node0"
tmux new -d "make start_node1"
tmux new -d "make start_node2"
tmux new -d "make start_node3"
tmux new -d "make start_node4"
tmux new -d "make start_node5"
