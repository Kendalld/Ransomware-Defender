#!/bin/sh

#echo "Starting buffer"
exec tshark -i any -f "tcp" -w /tmp/tcapture/capCont.pcap -b files:2 -b filesize:10 > /dev/null 2>&1 &
