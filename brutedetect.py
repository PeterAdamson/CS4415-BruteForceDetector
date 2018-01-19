#!/usr/bin/env python


#imports
import socket
import struct
import binascii
import textwrap
import os
import time
import errno

#packet class
class packet:
	sourceIP = ""
	destinationIP = "" 
	sourcePort = "" 
	destinationPort = ""
	protocol = ""
	
#summary variables
totalList = 0
startingTime = time.time()
numOfAttacks = 0

#host to lsiten on
#host = socket.gethostbyname(socket.gethostname())
host = raw_input("enter IP of your machine:")
print('IP being monitored: {}'.format(host))

#create a raw socket and bind it to the public interface
if os.name == "nt": #windows
	socket_protocol = socket.IPPROTO_IP
else:	#not windows
	socket_protocol = socket.IPPROTO_TCP

#create the sniffer
sniffer = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket_protocol)

#bind the sniffer to the host
sniffer.bind((host,0))

#get the IP headers in the capture
sniffer.setsockopt(socket.IPPROTO_IP,socket.IP_HDRINCL,1)

#check if using windows, if so need to send input/output control to set up promiscuous mode
if os.name == "nt":
	sniffer.ioctl(socket.SIO_RCVALL,socket.RCVALL_ON)

#set the packet sniffer to be non blocking
sniffer.setblocking(0)

#loop until keyboard interrupt
while True:	
	try:
		#list of packets seen over time period
		monitorList = []

		#time period
		t_end = time.time() + 10

		#loop for time period
		while time.time() < t_end:
			try:
				#read a packet
				raw_data =  sniffer.recvfrom(65565)
			except socket.error, e:
				err = e.args[0]
				if err == errno.EAGAIN or err == errno.EWOULDBLOCK: #no packet to be read
					continue;
				else:	#real error
					print e
					sys.exit(1)
			else:	#we have read a packet

				#pull out the raw data
				raw_data = raw_data[0]

				#create an instance of packet class
				newPacket = packet()

				#IP Header
				ipHeader = raw_data[0:20]
				ipHdr = struct.unpack('!BBHHHBBH4s4s',ipHeader)
	
				#formatting for ntoa
				version_ihl = ipHdr[0]
				version = version_ihl >> 4
				ihl = version_ihl & 0xF
				iph_length = ihl * 4

				#assign packet class variables
				proto = ipHdr[6]
				newPacket.sourceIP = socket.inet_ntoa(ipHdr[8])
				newPacket.destinationIP = socket.inet_ntoa(ipHdr[9])
				if proto == 6:	#tcp
					newPacket.protocol = 'TCP'
				elif proto == 1:	#icmp
					newPacket.protocol = 'ICMP'
				elif proto == 17:	#udp
					newPacket.protocol = 'UDP'
				else:	#undefined protocol, just return protocol number
					newPacket.protocol = ipHdr[6]

				#TCP Header
				tcpHeader = raw_data[iph_length:iph_length+20]
				tcpHdr = struct.unpack('!HHLLBBHHH',tcpHeader)
				newPacket.sourcePort = tcpHdr[0]
				newPacket.destinationPort = tcpHdr[1]
				monitorList.append(newPacket)
				totalList += 1

		#set up attack variables
		matchesIP = 0
		matchesPort = 0
		attackIP = 0
		attackPort = 0
		attackerSource = ""
		attackerDestination = ""
		attackerSourcePort = ""
		attackerDestinationPort = ""
		attackerProtocol = ""
		
		#loop through packets seen during time period
		for i in range(0,len(monitorList) - 2):
			#loop through packets seen during time period
			for j in range(i + 1, len(monitorList) - 1):
				if monitorList[i].sourceIP == monitorList[j].sourceIP: #we have an IP match
					matchesIP += 1
				if monitorList[i].destinationPort == monitorList[j].destinationPort:	#we have a port match
					matchesPort += 1
			if matchesIP >= 10 and matchesPort >= 10:	#we have an IP and port attack
				attackIP = 1
				attackPort = 1
				attackerSource = monitorList[i].sourceIP
				attackerDestination = monitorList[i].destinationIP
				attackerSourcePort = monitorList[i].sourcePort
				attackerDestinationPort = monitorList[i].destinationPort
				attackerProtocol = monitorList[i].protocol
				matchesIP = 0
				matchesPort = 0
				break
			elif matchesIP >= 10:	#we have an IP attack
				attackIP = 1
				attackerSource = monitorList[i].sourceIP
				attackerDestination = monitorList[i].destinationIP
				attackerProtocol = monitorList[i].protocol
				matchesIP = 0
				matchesPort = 0
			elif matchesPort >= 10:	#we have a port attack
				attackPort = 1
				attackerSourcePort = monitorList[i].sourcePort
				attackerDestinationPort = monitorList[i].destinationPort
				attackerProtocol = monitorList[i].protocol
				matchesIP = 0
				matchesPort = 0
		if attackIP == 1 and attackPort == 1:	#port and IP attack
			print "possible brute force attack coming from IP",attackerSource,"and port",attackerSourcePort,"going to IP",attackerDestination,"and port",attackerDestinationPort,"and protocol",attackerProtocol
			attackIP = 0
			attackPort = 0
			numOfAttacks += 1
		elif attackIP == 1: 	#IP attack
			print "possible brute force attack coming from IP",attackerSource,"and going to IP",attackerDestination,"and protocol",attackerProtocol
			attackIP = 0
			attackPort = 0
			numOfAttacks += 1
		elif attackPort == 1:	#port attack
			"possible brute force attack coming from port",attackerSourcePort,"and going to port",attackerDestinationPort,"and protocol",attackerProtocol
			attackIP = 0
			attackPort = 0
			numOfAttacks += 1

		#clear out our list
		for i in monitorList:
			del i
	except KeyboardInterrupt:
		break;	#go to finish procedure

#ending summary
endingTime = time.time()
print ""
print "summary"
print "run time:",float('%.1g' % ((endingTime - startingTime)/60)),"minutes"
print "total number of packets seen:",totalList
print "number of potential attacks:",numOfAttacks
