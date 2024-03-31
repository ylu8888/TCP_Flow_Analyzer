import dpkt
from datetime import datetime

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
                    print('is tcp')

                    if ip.src == senderIP:
                        print('is valid ips')
                        #we do not need to count the flows coming from port 80, also flows are bi-directional
                        if tcp.dport == 80:
                            continue #traffic from port 80 is just ACK packets for seq #1
                        
                        #get le tuple
                        flowTuple = (ip.src, tcp.sport, ip.dst, tcp.dport)
                        
                        #new flow?
                        if flowTuple not in tcpFlows:
                            tcpFlows[flowTuple] = []
                            currFlow = flowTuple
                        
                        #append flow
                        tcp.ts = timestamp #mabyue delete this
                        tcpFlows[currFlow].append(tcp)
    
    for flowTuple, tcpPackets in tcpFlows.items():
        print("TCP Flow:", flowTuple)

        print("First two transactions:")
        
        for i in range(min(2, len(tcpPackets))):

            tcpPkt = tcpPackets[i]

            print("Sequence number:", tcpPkt.seq)
            print("Acknowledgment number:", tcpPkt.ack)
            print("Receive Window size:", tcpPkt.win)

            print()  #new ljne
        
        # Calculate sender throughput
        # if len(tcp_packets) > 0:
        #     start_time = datetime.fromtimestamp(tcp_packets[0].ts)
        #     end_time = datetime.fromtimestamp(tcp_packets[-1].ts)
        #     time_diff = (end_time - start_time).total_seconds()
        #     total_bytes_sent = sum(len(tcp.data) for tcp in tcp_packets)
        #     throughput = total_bytes_sent / time_diff
        #     print("Sender throughput:", throughput, "bytes/sec")
        # else:
        #     print("No TCP packets in this flow")
        
        print()  # Add a newline between flows


def main():
    analysis_pcap_tcp('assignment2.pcap')


if __name__ == "__main__":
    main()

