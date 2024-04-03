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

                    #this another check just in case
                    # if senderIP != '.'.join(str(ip) for ip in ip.src):
                    #     continue #if the source and dest ip addresses dont match

                    #we dont count tcp from source port80
                    # if tcp.sport == 80:
                    #     continue 
                    
                    #get le tuple
                    flowTuple = (tcp.sport, '.'.join(str(ip) for ip in ip.src), tcp.dport, '.'.join(str(ip) for ip in ip.dst))
                    
                    #new flow? add it to the dict with flowtuple as key
                    if flowTuple not in tcpFlows:
                        tcpFlows[flowTuple] = []
                    
                    #IF ITS NOT NEW TUPLE THEN ADD TCP To THE LIST OF OF OUR TUPLE
                    tcp.ts = timestamp #mabyue delete this
                   
                    tcp.sourceIP = '.'.join(str(ip) for ip in ip.src)
                    tcpFlows[flowTuple].append(tcp)  #add the tcp packet to our flow
                    
        
    print("Number of TCP Flows:", len(tcpFlows)) #first thing we want to answewr
    print("Number of TCP Flows from Sender:", len(tcpFlows) - 3)
    print()
    byteSum = 0
    firstAck = True
    rtt = 0

    recvPkts = []
    senderPkts = []

    for flowTuple, tcpPackets in tcpFlows.items():
        for index, tcpPkt in enumerate(tcpPackets):
            if(flowTuple[1] == senderIP):
                senderPkts.append(tcpPkt)
            if(flowTuple[1] == receiverIP):
                recvPkts.append(tcpPkt)

    for flowTuple, tcpPackets in tcpFlows.items():

        # if(flowTuple[1] == receiverIP):
        #     # print('this is a receiver flowtuple')
        #     # print()
        #     continue

        if(flowTuple[1] == senderIP):
            print("TCP flow:", flowTuple)
            print()

        #print("first 2 transactions:")
        #print("this is the tcp len", len(tcpPackets))

        count = 1
        scaleFactor = 0
        startTime = 0
        endTime = 0
        firstSyn = True
        almostLast = False
        throughput = 0
        totalBytes = 0

        #cwnd is the number of packets u can send before u get an ack
        #for each rtt count the number of packets before u get the ack number
        #do that 3 times for the 3 congestion windows
        #based on the timestamps we count the number of packets within the rtt
        rttCount = rtt
        firstAckTime = 0
        congestCount = 1
        byteSum = 0

        #counting retransmissions
        tripDupe = []
        totalTrans = 0
        transArr = []
        seqSet = set()

        for index, tcpPkt in enumerate(tcpPackets):

            if(flowTuple[1] == senderIP):  

                #ADD THE TOTAL BYTES FOR THE THRUPUT 
                totalBytes +=  len(tcpPkt.data) # add the payload
                totalBytes += (tcpPkt.off * 4) # add the header 

                #IF WE HIT AN ACK
                if(tcpPkt.flags & dpkt.tcp.TH_SYN == 0) and (tcpPkt.flags & dpkt.tcp.TH_ACK != 0):
                    if(firstAck):
                        firstAckTime = tcpPkt.ts
                        rtt = firstAckTime - startTime
                        rtt = round(rtt, 2)
                        rttCount = rtt
                        #print('this the rtt', rtt)
                        firstAck = False 

                #GETTING THE LAST ACKKKKKK
                if index == len(tcpPackets) - 1:
                    if(almostLast == True) and (tcpPkt.flags & dpkt.tcp.TH_ACK != 0):
                        #print('ACKKKKKKKKKKKKKKKKKKKKK')
                        endTime = tcpPkt.ts
                        #print('le end time', endTime)

                #WE GOTAT GET THE WINDOW SCALEING FACTOR FROM THE SYNNNNNN PACKET
                if (tcpPkt.flags & dpkt.tcp.TH_SYN != 0) and (tcpPkt.flags & dpkt.tcp.TH_ACK == 0): 
                    if(firstSyn):   #we want the time from when the FIRST syn packet is sent
                        startTime = tcpPkt.ts
                        firstSyn = False
                    # print('le start time', startTime)

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
                
                #GETTING THE FIRST TWO TRANSACTIONS
                #check if NOT syn
                #check if HAS ack
                #check if has payload
                if (tcpPkt.flags & dpkt.tcp.TH_SYN == 0) and (tcpPkt.flags & dpkt.tcp.TH_ACK != 0):
                    paylen =  len(tcpPkt.data) #THIS THE PAYLOAD LENGTH

                    if paylen <= 0: #IF NO PAYLOAD THEN THIS NOT THE ONE
                        continue
                    
                    byteSum += 1

                    #loop over the sender packets
                    # count all of those
                    # track this packet and the previous packet as u loop
                    # if the diff between the two packets is below a certain alpha
                    # then u would call it congestion
                    # and u would count that packet as a congestion tcpPacket and thats it
                    #it's the count which is the number of packets
                                        
                    #if(index < 10):
                        #print('this the rtt + rttCount', round(rtt + rttCount, 2))
                    if((firstAck == False) and (tcpPkt.ts - startTime) >= round((rtt + rttCount),2)):
                            if(congestCount < 4):
                                #print('this the tcpPkt tiemstamp', tcpPkt.ts - startTime)
                                print('Congestion Window', congestCount, ':', byteSum)
                                byteSum = 0 #reset the bytesum
                                congestCount += 1 #incremnt congestCount by 1 cus we only want 3
                                rttCount += rtt #double the rtt now
                                #print('this the new rtt', rttCount)

                    if(count < 3): #only want the first 2 transactions
                        print("transaction", count, ":")

                        print("sequence number:", tcpPkt.seq)
                        print("acknowledgment number:", tcpPkt.ack)
                        print("receive window size:", tcpPkt.win * scaleFactor) 
                        
                        print()  #new ljne

                        count += 1
                    
                #gettiNG THE LAST FIN / ACK
                if (tcpPkt.flags & dpkt.tcp.TH_FIN != 0) and (tcpPkt.flags & dpkt.tcp.TH_ACK != 0): 
                    #print('HIT THE ACKKK', endTime)
                    almostLast = True
                
                #FINDING THE RETRANSMISSIONS
                if tcpPkt.seq in seqSet:
                    transArr.append(tcpPkt)
                    totalTrans += 1
                
                seqSet.add(tcpPkt.seq)
                
                            
        if(flowTuple[1] == senderIP):
            #throughput is total bytes of header + payload divided by the total time
            #the time is just the time between the FIRST syn
            #and the LAST ack, which comes AFTER the FIN/ACK
            totalTime = endTime - startTime
            #print('le total time', totalTime)

            throughput = totalBytes / totalTime
           # print('LE TOTAL BYTES', totalBytes)
            print('throughput:', throughput)
            print()  #new ljne

            #for dupe acks retransmission
            #inspect both the receiver and sender flows
            #identify all the packets that have been retransmitted frm the sender
            #lets loop over the receiver packets and try to line up those ack numbers
            #line up the 3 ack numbers
            #loop over receiver and sender packets with i in range
            #use that i to identify what those acks are
            for tran in transArr:
                tripCount = 0
                # print('len of recvPkts', len(recvPkts))
                # print('len of senderPkts', len(senderPkts))
                for i in range(0, len(recvPkts)):
                    #print('INNER FOR LOOP')
                    if tran.seq == recvPkts[i].ack:
                        tripCount += 1
                if tripCount > 2:
                    tripDupe.append(tran)

            print('Total retransmissions', len(transArr))
            print('Triple dupes acks', len(tripDupe))
            print('Total timeouts', totalTrans - len(tripDupe))


def main():
    analysis_pcap_tcp('assignment2.pcap')


if __name__ == "__main__":
    main()
