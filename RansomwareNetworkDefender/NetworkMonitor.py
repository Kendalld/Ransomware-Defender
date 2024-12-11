# Trevor Schwarz, EEP 595 Project, Fall2024
import subprocess
import os, glob

from apscheduler.schedulers.blocking  import BlockingScheduler

from ModifiedDecoder import DecoderFunc
from FirewallManager import EnableFirewall

ransomWareKey = "none"
ipsrc = 0
ipdst = 0
srcport = 0
dstport = 0

jt = 0
schedulerJobId = 0
runCounter = 0
bufferProc = 0


def setupScheduler():
    jobtimer = BlockingScheduler(standalone = True)    
    return jobtimer

def checkPcapUpdate():
    global runCounter, jt, schedulerJobId, bufferProc
    runCounter += 1
    
    #print("Checking pcap file here") # Debug flag

    # wrap the whole scheduler function in a try/except for graceful exit
    try:

        fileChange = True
        if(fileChange):
            jt.pause_job(schedulerJobId.id)

            #TODO
            procResult = subprocess.run("./convertPCAP.sh", stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            #print(procResult.stdout)
            #print(procResult.stderr)      

            # parse the txt file
            logFile = open("./tsharkLog.txt", 'r')
            lines = logFile.readlines()

            keyCaptured = False
            capturedKey = 'none'
            for line in lines:
                items = line.split() # split by whitespace
                tcpData = bytearray.fromhex(items[5]).decode()
                if 'key' in tcpData:
                    print("\nSuspect log message found: %s\n" % tcpData)                    
                    
                    # eval as dict and take the key entry
                    valPairs = eval(tcpData)
                    if(type(valPairs) is dict):                             
                        capturedKey = valPairs.get('key')             

                    print("*** contains key: %s" % capturedKey)
                    keyCaptured = True
                    
                    # also capture the IP/TCP info
                    ipsrc = items[1]
                    srcport = items[2]                  
                    ipdst = items[3]
                    dstport = items[4]                    

            # capturedKey contains latest 'key' transferred over tcp since last pcap save
            
            #keyCaptured = False #DEBUG
            if keyCaptured:
                global ransomWareKey
                ransomWareKey = capturedKey  

                attackResponse(ipsrc, srcport, ipdst, dstport)
                print("\n\nResponse complete, ending monitoring...")
                for f in glob.glob('/tmp/tcapture/*'):
                    os.remove(f)
                bufferProc.kill() # stop monitoring
                jt.shutdown(wait=False)                
            else:
                print('No key transmission detected. Check count %d' % runCounter)
                jt.resume_job(schedulerJobId.id)

    except Exception as e:
        print(e)
        print("...shutting it down")
        print(bufferProc.pid)
        bufferProc.kill() # stop monitoring        
        jt.shutdown(wait=False)        

        


def attackResponse(src_ip, src_port, dst_ip, dst_port):
    global ransomWareKey
    
    ''' # Debug help
    print("ipinfos")
    print(src_ip)
    print(src_port)
    print(dst_ip)
    print(dst_port)            
    '''    

    # Firewall command
    print("\n*** SUSPICIOUS TRAFFIC IDENTIFIED ***")
    print("Outgoing from %s port %s to %s on port %s" % (src_ip, src_port, dst_ip, dst_port))
    inputAccepted = False
    firewallFlag = False    
    while not inputAccepted:
        try:
            capture = input("Block all traffic to destination IP? Enter Y/N")
            if(capture.lower()=='y'):
                inputAccepted = True
                firewallFlag = True
            elif (capture.lower()=='n'):
                inputAccepted = True
                print('No firewall action selected...')
            else:
                print('Invalid input')
        except Exception as e:
            print(f"An error occurred: {e}\n Check your input")
    if(firewallFlag):
        EnableFirewall(src_ip, src_port, dst_ip, dst_port)

    # Decrypt
    DecoderFunc(ransomWareKey, './rw_target/')


def startMonitor():
    print('Starting network traffic logging using tshark...')
    print('Packet pcap buffer files saved in /tmp/tcapture')
    
    global bufferProc
    bufferProc = subprocess.Popen("./startMonitor.sh")
    #print(bufferProc.pid)

# Main function
if __name__ == '__main__':

    # Process args
    #args = sys.argv # Not required for this implementation

    # Run tshark setup command to save packet files to buffer
    startMonitor()
    
    # Setup python app scheduler for regular interval checking
    jt = setupScheduler()
    period = 5 # 5 seconds
    schedulerJobId = jt.add_job(checkPcapUpdate, 'interval', seconds=period)
    
    # Need to ensure killing works
    print("Ctrl+C to exit")
    try:
        jt.start()
    except (KeyboardInterrupt):
        bufferProc.kill() # stop monitoring
        jt.shutdown(wait=False)       
   
    print('Network monitor app closing...')             
