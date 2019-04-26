#!/usr/bin/python2.7

from scapy.all import *
import crcmod
import md5
import csv
import os
import ipaddress
import datetime
import time

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
			#print 'row[1]' + str(row[1])
			return	row[1]


def bitmatrix(router, ten, hash):
	load = 0
	comm_1 = 'load = bm_rtr_' + str(router) + '[' + str(hash%bm_len) + ']'
	#print comm_1
	exec(comm_1)
	#print (load)
	if (2**(ten-1))&load:
		now = datetime.datetime.now().strftime("%Y%m%d_%H%M%S_%f")
		file = open("collisions_register.csv","a")
		file.write(str(now) + ","+
				   str(router) + ","+ 
				   str(ten) + "\n")
		file.close()
	comm_2 = 'bm_rtr_' + str(router) + '[' + str(hash%bm_len) + '] = ' + str(load|(2**(ten-1)))
	print comm_2
	exec(comm_2)


def setup():

	#define global variable to:

	
	global 	rtable, \
			topo, \
			pkt_counter, \
			bm_len, \
			bm_pkt_size, \
			pkt_per_epoc, \
			bm_rtr_1, \
			bm_rtr_2, \
			bm_rtr_3, \
			bm_rtr_4, \
			bm_rtr_5, \
			bm_rtr_6, \
			bm_rtr_7, \
			bm_rtr_8, \
			bm_rtr_9, \
			bm_rtr_10, \
			bm_rtr_11, \
			bm_rtr_12

#	global 	rtable, \		# load src, dst tenants routing table in memory
#			topo, \   		# to load tenant's src ip in memory
#			pkt_counter, \	# number of packet processed
#			bm_len, \		# bitmatrix lenght
#			bm_pkt_size		# number of packet to process per bitmatrix

	pkt_counter = 1
	bm_len = 65536 #65536
	pkt_per_epoc = 6553 #16384
	bm_rtr_1 = [0] * bm_len
	bm_rtr_2 = [0] * bm_len
	bm_rtr_3 = [0] * bm_len
	bm_rtr_4 = [0] * bm_len
	bm_rtr_5 = [0] * bm_len
	bm_rtr_6 = [0] * bm_len
	bm_rtr_7 = [0] * bm_len
	bm_rtr_8 = [0] * bm_len
	bm_rtr_9 = [0] * bm_len
	bm_rtr_10 = [0] * bm_len
	bm_rtr_11 = [0] * bm_len
	bm_rtr_12 = [0] * bm_len

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

def save_bitmatrix():
	now = datetime.datetime.now().strftime("%Y%m%d_%H%M%S_%f")
	for i in xrange(12):
		a = 'file = open("bm_rtr_' + str(i+1) + '_' + str(now) + '","w")'
		exec(a)
		b = 'file.write(str(bm_rtr_' + str(i+1)+ '))'
		exec(b)
		file.close()
	setup()
	return


def ppu(pkts):
	for i in xrange(len(pkts)):
		try:
			pkt = [ord(c) for c in raw(pkts[i])]
			#print 'pkt number ' + str(i)
			global pkt_counter, pkt_per_epoc, pkt_counter_master
			pkt_counter_master += 1
			pkt_counter += 1
			#print 'pkt_counter ' + str(pkt_counter)	

			if pkt_counter > 430000:
				save_bitmatrix()
			hash = hashing(pkt)
			ten_A = lookup_tenant(pkts[i].src)
			ten_B = lookup_tenant(pkts[i].dst)
			routers = routing_table(ten_A, ten_B)
			#print ten_A
			#print pkts[i].src
			#print ten_B
			#print pkts[i].dst
			#print routers
			for router in routers:
				bitmatrix(router, ten_A, hash)
		 
			#print (hash)	

		except Exception as e:
			print ("pkt%d does not exists or cant be processed" % i)


def loader():
	cap_files = []
	for (dirpath, dirnames, filenames) in os.walk("../traffic"):
		cap_files.extend(filenames)
		print cap_files
		return cap_files


def main():
	setup()
	global pkt_counter_master
	pkt_counter_master = 1
	cap_files = loader()
	for cap_file in cap_files:
		startload = time.time()
		pkts=rdpcap("../traffic/" + cap_file)
		endload = time.time()
		print ("Levou " + str(endload-startload) + \
			   " segundos para carregar a captura " + str(cap_file))
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