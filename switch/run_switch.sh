#!/bin/bash

THIS_DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

source $THIS_DIR/../env.sh

SWITCH_PATH=$BMV2_PATH/targets/simple_switch/simple_switch

CLI_PATH=$THIS_DIR/simple_switch_CLI

p4c-bm2-ss --p4v 14 p4src/switch.p4 -o switch.json
sudo PYTHONPATH=$PYTHONPATH:$BMV2_PATH/mininet/ python script/topo.py \
    --behavioral-exe $SWITCH_PATH \
    --json switch.json \
    --cli $CLI_PATH \
    --mode l3
