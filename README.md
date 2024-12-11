Trevor Schwarz, EEP 595 Project, Fall 2024
-

This directory contains the python files and bash scripts comprising the network based detection, defense and recovery against ransomware attacks.

This readme file is intended to only provide instructions for running the script. For full details, see the team project report.

Instructions for running 
---

WARNING! - running this code will ENCRYPT FILES inside the rw_target folder contained in the attached directory; tampering with the code has the risk of encrypting other files on the system you run this on...

Prequisites:
- Ransomwaresim project running (using virtual machine)
    - ControlServer.py should be launched and listener active on any port
- Virtual machine should be running unix based OS (Ubuntu)
    - Requires packages: python3, pip3, wireshark, tshark, ufw
    - Wireshark: If using non-root privelaged user account, add your user to the wireshark group and enable non sudoers to use the tool
- Python library dependencies:
    - apscheduler, cryptography

(OPTIONAL) Load the virtual box image .ovf file instead

Steps

1: Copy the RansomwareNetworkDefender folder into the VM user folder

2: Launch a shell from the RansomwareNetworkDefender folder and run "python3 NetworkMonitor.py"

3: Now run Encoder.py from the Ransomwaresim folder to simulate the ransomware attack execution (ControlServer.py should already be running)

4: Follow prompts in shell for network monitor tool
- Y/N to setup a firewall blocking incoming/outgoing traffic to the control server (simulated locally)
- Y/N to decode the encrypted ransomware target files using the captured key

5: Script execution ends after completing step 4; restart to begin monitoring for new key transfers over TCP