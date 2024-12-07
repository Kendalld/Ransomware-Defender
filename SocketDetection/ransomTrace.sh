#!/bin/bash

ImportantFiles=ImportantInfo
executable=SocketEncrypt

sudo strace -tt -o ./ransometrace -e fault=sendmsg:error=EINTR ./$executable