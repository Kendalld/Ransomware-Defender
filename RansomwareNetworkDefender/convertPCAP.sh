#!/bin/sh

latestpcap="$(ls -t /tmp/tcapture/ | head -n 1)"
echo "${latestpcap}"
# /tmp/tcapture/capCont*.pcap

echo "Moved latest pcap log to /home/vboxuser/RansomwareNetworkDefender/tsharkLog.txt"
tshark -r /tmp/tcapture/${latestpcap} -Y "data.len" -Tfields -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport -e data | cat -n > /home/vboxuser/RansomwareNetworkDefender/tsharkLog.txt
