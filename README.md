# TCP_Flow_Analyzer

**PCAP TCP Flows Parsing and Analysis: Python Dpkt Library**

## **How to Run the Program**
  
1) In the terminal type: pip install dpkt
   
2) This will install the dpkt library from Python
   
3) Then, click on top right arrow to run the .py program

4) NOTE: The main method calls analysis_pcap_tcp('assignment2.pcap') so if your pcap file is another name for example 'testcase.pcap' then you should change that in order to run the code properly.

## **Calculations**

## **Finding the Flows**

The code loops through the packets in the pcap file and creates tuples for each flow with source and destination IP addresses and port numbers. These get stored into a dictionary which maps flow tuples to lists of packets. The code only prints out the tcp flows from the sender and doesn't count the receiver flows from source port 80, so there's only 3 flows we care about.

## **Sequence and Ack Numbers**

The code loops through each TCP flow in the dictionary and iterates through the respective packets. For each packet we check if the syn flag is not set and if ACK is set. Then we check if it has a valid payload by checking the length len(tcpPkt.data). We print the seq and ack numbers for the first two transactions using tcpPkt.seq and tcpPkt.ack

## **Received Window Size**

For the window size we can't just print out the raw window value from our tcp packet. We have to get the window scaling factor from the specific packets with syn flag set. We use the built in dpkt function dpkt.tcp.parse_opts(tcpPkt.opts) which parses the options into (type/data) tuples. We loop through all the options and check for the TCP_OPT_WSCALE option. We obtain the scalefactor and calculate 2 raised to the power of the scalefactor. Finally we multiply this with our window value to get the received window size.

## **Calculating Throughput**

To calculate the throughput you have to find the total bytes over the all the sender flows divided by the total time. To get the total bytes you just loop through each tcp packet for the sender flows and add the payload which is len(tcpPkt.data) as well as the header which is (tcp.off * 4). To get the total time you have to find the difference in time between the last ACK packet and the first SYN packet. This can be done by utilizing the ts (timestamp) field of the tcp packets, then subtracting (endTime - startTime) to get totalTime. Lastly just divide (totalBytes / totalTime) to get the throughput.

## **Congestion Window Size**

To calculate the congestion window size: within each rtt, we have to count the number of packets we can send before we get an ACK. Now we just do that 3 times for the 3 congestion windows of each flow. We loop through the tcp packets of each flow, when we find an ACK packet that has payload data we increment our packetCount by 1. Then we check the timestamp field of that tcp packet, if it's greater than or equal to double the rtt we have, then we print our congestion window size which is equal to packetCount. After printing, we have to reset our packetCount and also increase our rtt by adding itself again. 

## **Finding Retransmissions**

To calculate the total retransmissions, we loop through the packets for each sender flow and use a set that stores all the sequence numbers for each packet. Since sets store unique values, if we find duplicate sequence numbers it means we found a retransmission so we increment our totalRetransmission count and append it to reTransmission array. To calculate the triple duplicate Ack, I store all the packets from the receiver flows into an array. Using a nested for-loop, I iterate through all the retransmissions in the outer for-loop and iterate through all the receiver packets in the inner for-loop. If the ack number of the recvPacket is equal to the seq number of the retransmission pkt, then I increment a counter. If this counter becomes greater than or equal to 3, that means we found a triple duplicate ack, so I append it to an array. At the end, I print the length of this array to represent the total triple duplicate acks, and to get the timeouts I simply subtract the total retranmissions minus the total triple dupes because that's the only two ways for a retransmission.
