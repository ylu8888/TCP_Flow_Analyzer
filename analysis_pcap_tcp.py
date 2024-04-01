import dpkt

def analysis_pcap_tcp(filename):
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

                    #we dont count tcp from source port80
                    if tcp.sport == 80:
                        continue 

                    if senderIP != '.'.join(str(ip) for ip in ip.src):
                        continue #if the source and dest ip addresses dont match
                    
                    #get le tuple
                    flowTuple = (tcp.sport, '.'.join(str(ip) for ip in ip.src), tcp.dport, '.'.join(str(ip) for ip in ip.dst))
                    
                    #new flow? add it to the dict with flowtuple as key
                    if flowTuple not in tcpFlows:
                        tcpFlows[flowTuple] = []
                    
                    #IF ITS NOT NEW TUPLE THEN ADD TCP To THE LIST OF OF OUR TUPLE
                    tcp.ts = timestamp #mabyue delete this
                    tcpFlows[flowTuple].append(tcp)  #add the tcp packet to our flow

                    
        
    print("Number of TCP Flows:", len(tcpFlows)) #first thing we want to answewr
    print()

    for flowTuple, tcpPackets in tcpFlows.items():
        print("TCP flow:", flowTuple)

        # print("first 2 transactions:")

        #print("this is the tcp len", len(tcpPackets))

        count = 1
        scaleFactor = 0

        for tcpPkt in tcpPackets:
            
            #WE GOTAT GET THE WINDOW SCALEING FACTOR FROM THE SYNNNNNN PACKET
            if (tcpPkt.flags & dpkt.tcp.TH_SYN != 0) and (tcpPkt.flags & dpkt.tcp.TH_ACK == 0): 
                leOptions = dpkt.tcp.parse_opts(tcpPkt.opts) #PARSE THE OPTIONS INTO (TYPE/DATA) TUPLES
               # print('thIS LE OPTIONS', leOptions)

                for optType, optData in leOptions: #LOOK THRU THE TUPLE 
                    if optType == dpkt.tcp.TCP_OPT_WSCALE: #CHECK FOR THE WSCALE OPTION
                        
                        #look through options to get the window scaling factor TIMES the window value
                         #scalefactor = 2 to the power of window factor and THEN multiply that by the tcp.win xD
                        scaleFactor = optData[0] 
                        scaleFactor = 2 ** scaleFactor 
                        #print('scale factr', scaleFactor)
                        break
            
            #check if NOT syn
            #check if HAS ack
            #check if has payload
            if (tcpPkt.flags & dpkt.tcp.TH_SYN == 0) and (tcpPkt.flags & dpkt.tcp.TH_ACK != 0):
                paylen =  len(tcpPkt.data) #THIS THE PAYLOAD LENGTH

                if paylen <= 0: #IF NO PAYLOAD THEN THIS NOT THE ONE
                    continue

                print("this is transaction", count, ":")

                print("sequence number:", tcpPkt.seq)
                print("acknowledgment number:", tcpPkt.ack)
                print("receive window size:", tcpPkt.win * scaleFactor) 
                print()  #new ljne

                count += 1
                if(count == 3): #only want the first 2 transactions
                    break

def main():
    analysis_pcap_tcp('assignment2.pcap')


if __name__ == "__main__":
    main()
