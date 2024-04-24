#!/bin/bash
# Network Setup script for testing

# Check if the user provided a network configuration
if [ "$#" -ne 1 ]; then
    echo "Usage: $0 \"<network configuration>\""
    exit 1
fi

# Extract the network configuration from the command-line argument
NETWORK_CONFIG=$1

# Execute the tc commands
sudo tc qdisc del dev eth1 root
sudo tc qdisc add dev eth1 root netem $NETWORK_CONFIG
sudo tc qdisc show dev eth1