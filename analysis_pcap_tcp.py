import dpkt

def analysis_pcap_tcp(filename):

    print('welcome')
    senderIP = '130.245.145.12'
    receiverIP = '128.208.2.198'

    tcpFlows = {} #use a dict to store the tcp flows
   
    with open(filename, 'rb') as file:  #open and read the pcap file
        pcap = dpkt.pcap.Reader(file)
        
        currFlow = None  # Variable to track the current TCP flow being processed
        
        for timestamp, buffer in pcap:      #loop through data in file

            ether = dpkt.ethernet.Ethernet(buffer)
            
            if isinstance(ether.data, dpkt.ip.IP): #check if non ip pakcet type

                ip = ether.data
                
                if isinstance(ip.data, dpkt.tcp.TCP):   #if valid tcp packet
                    tcp = ip.data

                    #we do not need to count the flows coming from port 80, also flows are bi-directional
                    if tcp.sport == 80:
                        continue #traffic from port 80 is just ACK packets for seq #1
                    
                    #get le tuple
                    flowTuple = (tcp.sport, senderIP, tcp.dport, receiverIP)
                    
                    #new flow?
                    if flowTuple not in tcpFlows:
                        tcpFlows[flowTuple] = []
                        currFlow = flowTuple
                    
                    #append flow
                    tcp.ts = timestamp #mabyue delete this
                    tcpFlows[currFlow].append(tcp)
    
    for flowTuple, tcpPackets in tcpFlows.items():
        print("tcp flow:", flowTuple)

        print("first 2 transactions:")

        print("this is the tcp len", len(tcpPackets))

        for i in range(min(2, len(tcpPackets))):

            print("sequence number:", tcpPackets[i].seq)
            print("acknowledgment number:", tcpPackets[i].ack)
            print("receive Window size:", tcpPackets[i].win)

            print()  #new ljne
        
        
        
        print()  # Add a newline between flows


def main():
    analysis_pcap_tcp('assignment2.pcap')


if __name__ == "__main__":
    main()
