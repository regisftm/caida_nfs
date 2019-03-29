#!/usr/bin/python2.7

from scapy.all import *
import crcmod
import md5
import csv
import os
import ipaddress

def crc32_comp(str_):
	str_ = bytearray(str_)
	crc32 = crcmod.mkCrcFun(0x104C11DB7, rev=False, initCrc=0xFFFFFFFF, xorOut=0xFFFFFFFF)
	answer = crc32(str(str_))
	return answer

def hashing(pkt):
	
	hashlst=[pkt[0],  				#version,ihl
			pkt[2],pkt[3],			#totallenght
			pkt[4],pkt[5],			#identification
			pkt[6],pkt[7], 			#flag,fragOffset
			pkt[9],        			#protocol
			pkt[12],pkt[13],pkt[14],pkt[15], #srcAddr
			pkt[16],pkt[17],pkt[18],pkt[19], #dstAddr
			pkt[20],pkt[21],pkt[22],pkt[23], #payld bytes 1-4
			pkt[24],pkt[25],pkt[26],pkt[27]] #payld bytes 5-8

	hash_crc32 = crc32_comp(hashlst)

 	return hash_crc32

def routing_table(ten_a, ten_b):
	for row in rtable:
		if (row[0] == ten_a and row[1] == ten_b):
			while 0 in row:
				row.remove(0)
			return row[2:]


def lookup_tenant(tenant_ip):
	for row in topo:
		if (ipaddress.ip_address(unicode(tenant_ip)) in \
			ipaddress.ip_network(unicode(row[0]))):
			print 'row[1]' + str(row[1])
			return	row[1]


def bitmatrix(router, ten, hash):
	a = 'bm_rtr_' + str(router) + '[' + str(hash%bm_len) + '] += ' +str(2**ten)
	print a



def setup():

	#define global variable to:

	
	global 	rtable, \
			topo, \
			pkt_counter, \
			bm_len, \
			bm_pkt_size


#	global 	rtable, \		# load src, dst tenants routing table in memory
#			topo, \   		# to load tenant's src ip in memory
#			pkt_counter, \	# number of packet processed
#			bm_len, \		# bitmatrix lenght
#			bm_pkt_size		# number of packet to process per bitmatrix


	pkt_counter = 0
	bm_len = 65536
	pkt_per_epoc= 16384

	# create global variable for bitmatrixes 
	for i in xrange(16):
		a = 'global bm_rtr_' + str(i+1)
		b = 'bm_rtr_' + str(i+1) + ' = [0] * 65536'
		exec(a)
		exec(b)


	# load src, dst tenants routing table in memory
	with open('routing.csv', 'rb') as csvfile:
		reader = csv.reader(csvfile, delimiter=',')
		rtable = [[int(row[0]), int(row[1]), int(row[2]), int(row[3]), \
				int(row[4]), int(row[5]), int(row[6]), int(row[7])] \
				for row in reader]

	# load tenant's src ip in memory
	with open('topology.csv', 'rb') as csvfile:
		reader = csv.reader(csvfile, delimiter=',')
		topo = [[ipaddress.ip_network(unicode(row[0]), strict=False), int(row[1])] \
				for row in reader]



def ppu(pkts):

	for i in xrange(len(pkts)):
		pkt = [ord(c) for c in raw(pkts[i])]
		print 'pkt number ' + str(i)
		hash = hashing(pkt)
		ten_A = lookup_tenant(pkts[i].src)
		ten_B = lookup_tenant(pkts[i].dst)
		routers = routing_table(ten_A, ten_B)
		print ten_A
		print pkts[i].src
		print ten_B
		print pkts[i].dst
		print routers
		for router in routers:
			bitmatrix(router, ten_A, hash)

		 
		print (hash)	


def loader():
	cap_files = []
	for (dirpath, dirnames, filenames) in os.walk("./captures"):
		cap_files.extend(filenames)
		print cap_files
		return cap_files


def main():
	setup()
	cap_files = loader()
	for cap_file in cap_files:
		pkts=rdpcap(cap_file)
		ppu(pkts)



#	ten_A = lookup_tenant('61.167.20.133')
#	print ten_A

#	pkt_route = routing_table(3,4)
#	print pkt_route

#	pkts=rdpcap("50_caida.pcap")

#	for i in xrange(1,45):
#		a = 'cur_pkt = captura.pkt' + str(i)
#		exec (a)
#		print (cur_pkt)
#		pkt_dissecat(cur_pkt,ip_bgn)
#		cur_pktscapy=[ord(c) for c in raw(pkts[i])]
#		pkt_dissecapy(cur_pktscapy,ip_bgn)
#		verify_checksum(cur_pktscapy)
#		a=hashing(cur_pktscapy)
#		print (a)


				
#	for row in rtable:
#		if (row[0] == 10 and row[1] == 2):
#			print row
#	#print table

#	file = open("routing.csv","r")
##	num_lines = 0
##	for i in file:
##		num_lines += 1
##	print (num_lines)
#	table=[]
##	print file
#
#	for line in file:
##		print (line)
#		route = [line]
#		table.append (route)
#	file.close()
#
#	a = 1
#	b = 2
#
#
##	print table
#	print a
#	print b
#
#	for line in table:
#		#print (line)
#		#print line[0]
#		if (line[0]==str(1) and line[1]==str(2)):
#				print (line)





main ()