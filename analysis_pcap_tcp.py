import dpkt

def analysis_pcap_tcp(filename):

    print('welcome')
    senderIP = '130.245.145.12'
    receiverIP = '128.208.2.198'

    tcpFlows = {} #use a dict to store the tcp flows
    synfinFlag = False
   
    with open(filename, 'rb') as file:  #open and read the pcap file
        pcap = dpkt.pcap.Reader(file)
        
        for timestamp, buffer in pcap:      #loop through data in file

            ether = dpkt.ethernet.Ethernet(buffer)
            
            if isinstance(ether.data, dpkt.ip.IP): #check if non ip pakcet type

                ip = ether.data
                
                if isinstance(ip.data, dpkt.tcp.TCP):   #if valid tcp packet
                    tcp = ip.data

                    #we do not need to count the flows coming from port 80, also flows are bi-directional
                    if tcp.sport == 80:
                        continue #traffic from port 80 is just ACK packets for seq #1

                    if senderIP != dpkt.utils.inet_to_str(ip.src):
                        continue #if the source and dest ip addresses dont match
                    
                    #get le tuple
                    flowTuple = (tcp.sport, senderIP, tcp.dport, receiverIP)
                    
                    #new flow? add it to the dict with flowtuple as key
                    if flowTuple not in tcpFlows:
                        tcpFlows[flowTuple] = []
                    
                    tcp.ts = timestamp #mabyue delete this
                    tcpFlows[flowTuple].append(tcp)  #add the tcp packet to our flow

                    
        
    print("Number of TCP Flows:", len(tcpFlows))
    print()

    for flowTuple, tcpPackets in tcpFlows.items():
        print("TCP flow:", flowTuple)

        # print("first 2 transactions:")

        print("this is the tcp len", len(tcpPackets))

        count = 1

        for tcpPkt in tcpPackets:
            
            print("this is transaction", count, ":")
            print("sequence number:", tcpPkt.seq)
            print("acknowledgment number:", tcpPkt.ack)
            print("receive Window size:", tcpPkt.win)

            print()  #new ljne

            count += 1
            if(count == 3):
                break
        
        
        
        print()  # Add a newline between flows


def main():
    analysis_pcap_tcp('assignment2.pcap')


if __name__ == "__main__":
    main()
