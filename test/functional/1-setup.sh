#!/bin/sh

# Mounts sandbox/ as a tmpfs; minimizes SSD teardown for 2-test.sh.

mkdir -p sandbox
sudo mount -o size=16M -t tmpfs none sandbox
