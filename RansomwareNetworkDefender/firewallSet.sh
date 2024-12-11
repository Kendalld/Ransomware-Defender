#!/bin/sh

statusCommand="$(sudo ufw status)"
setupCommand="$(sudo ufw deny out from any to $1)"
enableCommand="$(sudo ufw enable)"

echo "${statusCommand}"
echo "Applying deny rules to $1"
echo "${setupCommand}"
echo "${enableCommand}"

