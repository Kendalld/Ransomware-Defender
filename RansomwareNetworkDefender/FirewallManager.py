# Trevor Schwarz, EEP 595 Project, Fall2024
import subprocess

def EnableFirewall(src_ip, src_port, dst_ip, dst_port):
    print('*** Firewall setup launched ***')

    # Need to run a bash script with root execute privelages instead of ufw due to permissions
    bashVar = dst_ip
    varsIn = subprocess.Popen(['/bin/echo', bashVar], stdout=subprocess.PIPE) # Writing setup script inputs to stream with /bin/echo
    procResult = subprocess.check_output(['bash', './firewallSet.sh', bashVar], stdin=varsIn.stdout) # setup script with inputs
    print(procResult.decode("utf-8"))



    
