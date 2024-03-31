import dpkt

def analysis_pcap_tcp(filename):

    print('welcome')
    senderIP = '130.245.145.12'
    receiverIP = '128.208.2.198'

    tcpFlows = {} #use a dict to store the tcp flows
   
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

                    if senderIP != '.'.join(str(ip) for ip in ip.src) or receiverIP != '.'.join(str(ip) for ip in ip.dst):
                        continue #if the source and dest ip addresses dont match
                    
                    #get le tuple
                    flowTuple = (tcp.sport, '.'.join(str(ip) for ip in ip.src), '.'.join(str(ip) for ip in ip.dst))
                    
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

            seq_num_bytes = tcpPkt.data[4:8]
            seq_num = int.from_bytes(seq_num_bytes, byteorder='big')
            # Extract acknowledgment number (4 bytes, starting at byte 8 in TCP header)
            ack_num_bytes = tcpPkt.data[8:12]
            ack_num = int.from_bytes(ack_num_bytes, byteorder='big')
            print("Sequence number:", seq_num)
            print("Acknowledgment number:", ack_num)
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
