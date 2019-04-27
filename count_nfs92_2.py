#!/usr/bin/python2.7

from scapy.all import *
import csv
import crcmod
import os
import ipaddress
import datetime
import time
import sys

def crc16_comp(str_):
	str_ = bytearray(str_)
	crc16 = crcmod.mkCrcFun(0x18005, rev=False, initCrc=0xFFFF, xorOut=0x0000)
	answer = crc16(str(str_))
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
	hash_crc16 = crc16_comp(hashlst)
 	return hash_crc16

def setup():

	#define global variable to:
	global 	rtable, \
			topo, \
			pkt_counter, \
			bm_len, \
			bm_pkt_size, \
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
			bm_rtr_12, \
			colision_rtr_0, \
			colision_rtr_1, \
			colision_rtr_2, \
			colision_rtr_3, \
			colision_rtr_4, \
			colision_rtr_5, \
			colision_rtr_6, \
			colision_rtr_7, \
			colision_rtr_8, \
			colision_rtr_9, \
			colision_rtr_10, \
			colision_rtr_11, \
			colision_rtr_12, \
			pktcounter_rtr_1, \
			pktcounter_rtr_2, \
			pktcounter_rtr_3, \
			pktcounter_rtr_4, \
			pktcounter_rtr_5, \
			pktcounter_rtr_6, \
			pktcounter_rtr_7, \
			pktcounter_rtr_8, \
			pktcounter_rtr_9, \
			pktcounter_rtr_10, \
			pktcounter_rtr_11, \
			pktcounter_rtr_12

#	global 	rtable, \		# load src, dst tenants routing table in memory
#			topo, \   		# to load tenant's src ip in memory
#			pkt_counter, \	# number of packet processed
#			bm_len, \		# bitmatrix lenght
#			bm_pkt_size		# number of packet to process per bitmatrix

	pkt_counter = 0
	bm_len = 65536 #65536
	num_of_tenants = 17
	bm_rtr_1 = [[0 for x in range(bm_len)] for y in range(num_of_tenants)]
	bm_rtr_2 = [[0 for x in range(bm_len)] for y in range(num_of_tenants)]
	bm_rtr_3 = [[0 for x in range(bm_len)] for y in range(num_of_tenants)]
	bm_rtr_4 = [[0 for x in range(bm_len)] for y in range(num_of_tenants)]
	bm_rtr_5 = [[0 for x in range(bm_len)] for y in range(num_of_tenants)]
	bm_rtr_6 = [[0 for x in range(bm_len)] for y in range(num_of_tenants)]
	bm_rtr_7 = [[0 for x in range(bm_len)] for y in range(num_of_tenants)]
	bm_rtr_8 = [[0 for x in range(bm_len)] for y in range(num_of_tenants)]
	bm_rtr_9 = [[0 for x in range(bm_len)] for y in range(num_of_tenants)]
	bm_rtr_10 = [[0 for x in range(bm_len)] for y in range(num_of_tenants)]
	bm_rtr_11 = [[0 for x in range(bm_len)] for y in range(num_of_tenants)]
	bm_rtr_12 = [[0 for x in range(bm_len)] for y in range(num_of_tenants)]
	colision_rtr_1 = [0] * num_of_tenants
	colision_rtr_2 = [0] * num_of_tenants
	colision_rtr_3 = [0] * num_of_tenants
	colision_rtr_4 = [0] * num_of_tenants
	colision_rtr_5 = [0] * num_of_tenants
	colision_rtr_6 = [0] * num_of_tenants
	colision_rtr_7 = [0] * num_of_tenants
	colision_rtr_8 = [0] * num_of_tenants
	colision_rtr_9 = [0] * num_of_tenants
	colision_rtr_10 = [0] * num_of_tenants
	colision_rtr_11 = [0] * num_of_tenants
	colision_rtr_12 = [0] * num_of_tenants
	pktcounter_rtr_1 = [0] * num_of_tenants
	pktcounter_rtr_2 = [0] * num_of_tenants
	pktcounter_rtr_3 = [0] * num_of_tenants
	pktcounter_rtr_4 = [0] * num_of_tenants
	pktcounter_rtr_5 = [0] * num_of_tenants
	pktcounter_rtr_6 = [0] * num_of_tenants
	pktcounter_rtr_7 = [0] * num_of_tenants
	pktcounter_rtr_8 = [0] * num_of_tenants
	pktcounter_rtr_9 = [0] * num_of_tenants
	pktcounter_rtr_10 = [0] * num_of_tenants
	pktcounter_rtr_11 = [0] * num_of_tenants
	pktcounter_rtr_12 = [0] * num_of_tenants


	# bm_rtr [tenant] [position]

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
			return	row[1]

def bitmatrix(router, ten, hash):
	comm = 'pktcounter_rtr_' + str(router) + \
		 	 '[' + str(ten) + ']'+ \
		     ' += 1'
	exec(comm)
	load = 0
	comm = 'load = bm_rtr_' + str(router) + \
			 '[' + str(ten) + ']'+ \
			 '[' + str(hash%bm_len) + ']'
	exec(comm)
	if load == 1:
		comm = 'colision_rtr_' + str(router) + \
			 	 '[' + str(ten) + ']'+ \
			     ' += 1'
		exec(comm)
	comm = 'bm_rtr_' + str(router) + \
			 '[' + str(ten) + ']'+ \
			 '[' + str(hash%bm_len) + '] = 1' 
	exec(comm)

def print_counters_bitmatrix():
	global recordtime
	recordtime = recordtime + datetime.timedelta(seconds=10)
	file = open("bitmatrix.stats.csv","a")
	for i in range(1,17):
		for j in xrange(1,13):
			pkt_cnt = 0
			comm0 = 'pkt_cnt = pktcounter_rtr_'+ str(j) + '[' + str(i) +']'
			colli = 0
			comm1 = 'colli = colision_rtr_'+ str(j) + '[' + str(i) +']'
			sumbm = 0
			comm2 = 'sumbm = sum(bm_rtr_' + str(j) + '[' + str(i) +'])'
			exec(comm0)
			exec(comm1)
			exec(comm2)
			file.write(str(recordtime) + ","+
					   str(i) + ","+ 
					   str(j) + ","+ 
					   str(pkt_cnt) + ","+ 
					   str(colli) + ","+ 
					   str(sumbm) + ","+ 
					   str("{:3.2f}".format((pkt_cnt/float(bm_len))*100)) + '%' + ","+ 
					   str("{:3.2f}".format((colli/float(pkt_cnt))*100)) + '%' + "\n")
	file.close()
	

def ppu(pkts):
	for i in xrange(len(pkts)):
		try:
			global pkt_counter, pkt_counter_master
			# 43,000 pkts corresponds to 1 second of traffic
			if pkt_counter > 430000:
				print_counters_bitmatrix()
				setup()
			pkt = [ord(c) for c in raw(pkts[i])]
			for f in range(28-len(pkt)):
				pkt.append(0)
			hash = hashing(pkt)
			ten_A = lookup_tenant(pkts[i].src)
			ten_B = lookup_tenant(pkts[i].dst)
			routers = routing_table(ten_A, ten_B)
			for router in routers:
				bitmatrix(router, ten_A, hash)
			pkt_counter_master += 1
			pkt_counter += 1
			
		except Exception as e:
			sys.stdout.write("\r pkt %d does not exists or cant be processed"  % i)
			sys.stdout.flush()



def loader():
	cap_files = []
	for (dirpath, dirnames, filenames) in os.walk("../traffic"):
		cap_files.extend(filenames)
		print cap_files
		return cap_files

def main():
	setup()
	global pkt_counter_master, recordtime 
	recordtime = datetime.datetime(2020, 1, 1, 0, 0, 0)
	pkt_counter_master = 0
	cap_files = loader()
	for cap_file in cap_files:
		startload = time.time()
		print 'loading capture file "' + cap_file + '" please, be patient...'
		pkts=rdpcap("../traffic/" + cap_file)
		endload = time.time()
		print 'capture file "' + str(cap_file) + \
			  '" were loadede in ' + str("{:10.2f}".format(float(endload-startload))) + ' seconds'
		print  str(len(pkts)) + ' packets were loaded from ' + str(cap_file)
		ppu(pkts)


main ()