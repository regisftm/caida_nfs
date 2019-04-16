#!/usr/bin/python2.7

from scapy.all import *
import csv
import os
import ipaddress
import datetime
import time
import sys

def setup():

	#define global variable to:

	
	global 	rtable, \
			ltable, \
			topo, \
			pkt_counter, \
			bm_len, \
			bm_pkt_size, \
			pkt_per_epoc, \
			link_pkt_counter, \
			link_byte_counter

#	global 	rtable, \		# load src, dst tenants routing table in memory
#			topo, \   		# to load tenant's src ip in memory
#			pkt_counter, \	# number of packet processed
#			bm_len, \		# bitmatrix lenght
#			bm_pkt_size		# number of packet to process per bitmatrix

	pkt_counter = 0
	bm_len = 65536 #65536
	pkt_per_epoc = 6553 #16384
	link_pkt_counter = [0] * 33
	link_byte_counter = [0] * 33

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


	# load src, dst tenants link routing table in memory
	with open('link_route.csv', 'rb') as csvfile:
		reader = csv.reader(csvfile, delimiter=',')
		ltable = [[int(row[0]), int(row[1]), int(row[2]), int(row[3]), \
				int(row[4]), int(row[5]), int(row[6]), int(row[7]), int(row[8])] \
				for row in reader]


def link_table(ten_a, ten_b):
	for row in ltable:
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

def ppu(pkts):
	for i in xrange(len(pkts)):
		try:
#			pkt = [ord(c) for c in raw(pkts[i])]
#			print 'pkt number ' + str(i)
			global pkt_counter, link_pkt_counter, link_byte_counter 
#			pkt_counter_master += 1
			pkt_counter += 1
			sys.stdout.write("\r%d processed packets                                        " % pkt_counter)
			sys.stdout.flush()
			#print 'pkt_counter ' + str(pkt_counter)	
			#print ('r\processados ' + str(pkt_counter) + ' pacote.')
#
			if pkt_counter > 430000:
				#print ('r\processados ' + str(pkt_counter) + ' pacote.')
				i = 0
				for counter in link_byte_counter:
					print 'link #' + str(i) + ': ' + str("{:10.2f}".format(((float(counter)*8)/10)/1000000))  + ' Mbps | ' + str(counter) + ' bytes em 10 segundos' 
					i += 1
				i = 0
				for counter in link_pkt_counter:
					print 'link #' + str(i) + ': ' + str(counter) + ' pacotes trafegados'
					i += 1
				exit()
#				save_bitmatrix()
#			hash = hashing(pkt)
			ten_A = lookup_tenant(pkts[i].src)
			ten_B = lookup_tenant(pkts[i].dst)
			links = link_table(ten_A, ten_B)
			#print ten_A
			#print pkts[i].src
			#print ten_B
			#print pkts[i].dst
			#print routers
			#print pkts[i].len
			#print links
			for link in links:
				#print link
				#global link_pkt_counter, link_byte_counter 
				link_pkt_counter[link] += 1
				link_byte_counter[link] += pkts[i].len			

		 
			#print (hash)	

		except Exception as e:
			#print ("pkt%d does not exists or cant be processed" % i)
			sys.stdout.write("\rpkt%d does not exists or cant be processed" % i)
			sys.stdout.flush()

			
			


def loader():
	cap_files = []
	for (dirpath, dirnames, filenames) in os.walk("./captures"):
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
		pkts=rdpcap("./captures/" + cap_file)
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