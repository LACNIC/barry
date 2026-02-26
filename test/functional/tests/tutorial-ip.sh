#!/bin/sh

check_output_contains "tutorial-ip" -Fx \
	"roa1.roa,obj.content.encapContentInfo.eContent.ipAddrBlocks,IP Resources (ROA),\"[ [ 192.0.2.0/24, 203.0.113.0/32 ], [ 2001:db8::/40-48 ] ]\""
