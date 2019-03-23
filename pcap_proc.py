#!/usr/bin/python2.7

from scapy.all import *
import hexdump as r

pkts = rdpcap('./50_caida.pcap')

pkt = pkts[0]

print r.restore(str(hexdump(pkt.src)))
print str(pkt)
for byte in str(hexdump(pkt)):
	print byte

#print raw(pkt)
#print hexdump(pkt.)
#print ls(pkt) 
#print pkt.summary()
#print pkt.show()
#print pkt.show2()
##print pkt.sprintf()
##print pkt.decode_payload_as()
##print pkt.psdump()
##print pkt.pdfdump()
#print pkt.command()
# 


#import pyshark
#import os

#capture = pyshark.FileCapture('./50_caida.pcap')

#pkt = capture[0]

#print dir (pkt.ip)
#print dir (pkt.tcp)

#print pkt.ip.raw_mode
#
#print pkt.ip.payload
#print dir (pkt)


#for i in xrange(10):
#	print capture[i].ip.proto


#print capture[0].ip.dst
#
#print capture[0].ip.src
#
#print capture[0].ip.proto
#print capture[0].tcp.field_names
#print capture[3].udp.field_names
#"{0:8b}".format(pkt[bgn+24],16)


#for i in xrange(50):



	#print '**********'
	#print '*** IP ***'
	#print '**********'
	#print 'version = ' + capture[i].ip.version
	#print 'hdr_len = ' + capture[i].ip.hdr_len
	#print 'dsfield = ' + capture[i].ip.dsfield
	#print 'len = ' + capture[i].ip.len
	#print 'id = ' + capture[i].ip.id
	#print 'flags = ' + capture[i].ip.flags
	#print 'frag_offset = ' + capture[i].ip.frag_offset
	#print 'ttl = ' + capture[i].ip.ttl
	#print 'proto = ' + capture[i].ip.proto
	#print 'checksum = ' + capture[i].ip.checksum
	#print 'src = ' + capture[i].ip.src
	#print 'dst = ' + capture[i].ip.dst

#print 'geodst_lon = ' + capture[0].ip.geodst_lon
#print 'geodst_lat = ' + capture[0].ip.geodst_lat
#print 'geosrc_lon = ' + capture[0].ip.geosrc_lon
#print 'flags_mf = ' + capture[0].ip.flags_mf
#print 'ttl = ' + capture[0].ip.ttl
#print 'version = ' + capture[0].ip.version
#print 'geolon = ' + capture[0].ip.geolon
#print 'dst_host = ' + capture[0].ip.dst_host
#print 'flags_df = ' + capture[0].ip.flags_df
#print 'flags = ' + capture[0].ip.flags
#print 'dsfield = ' + capture[0].ip.dsfield
#print 'src_host = ' + capture[0].ip.src_host
#print 'id = ' + capture[0].ip.id
#print 'geolat = ' + capture[0].ip.geolat
#print 'checksum = ' + capture[0].ip.checksum
#print 'dsfield_ecn = ' + capture[0].ip.dsfield_ecn
#print 'geosrc_city = ' + capture[0].ip.geosrc_city
#print 'hdr_len = ' + capture[0].ip.hdr_len
#print 'geosrc_lat = ' + capture[0].ip.geosrc_lat
#print 'dst = ' + capture[0].ip.dst
#print 'geodst_country = ' + capture[0].ip.geodst_country
#print 'dsfield_dscp = ' + capture[0].ip.dsfield_dscp
#print 'frag_offset = ' + capture[0].ip.frag_offset
#print 'geosrc_country = ' + capture[0].ip.geosrc_country
#print 'host = ' + capture[0].ip.host
#print 'flags_rb = ' + capture[0].ip.flags_rb
#print 'addr = ' + capture[0].ip.addr
#print 'len = ' + capture[0].ip.len
#print 'src = ' + capture[0].ip.src
#print 'checksum_status = ' + capture[0].ip.checksum_status
#print 'geocountry = ' + capture[0].ip.geocountry
#print 'geodst_asnum = ' + capture[0].ip.geodst_asnum
#print 'geoasnum = ' + capture[0].ip.geoasnum
#print 'geodst_city = ' + capture[0].ip.geodst_city
#print 'geocity = ' + capture[0].ip.geocity
#print 'proto = ' + capture[0].ip.proto
#print 'geosrc_asnum = ' + capture[0].ip.geosrc_asnum


#print '***********'
#print '*** TCP ***'
#print '***********'

#print 'flags_urg = ' + capture[0].tcp.flags_urg
#print 'ack = ' + capture[0].tcp.ack
#print 'options_type_class = ' + capture[0].tcp.options_type_class
#print 'stream = ' + capture[0].tcp.stream
#print 'options_type_number = ' + capture[0].tcp.options_type_number
#print 'checksum_status = ' + capture[0].tcp.checksum_status
#print 'seq = ' + capture[0].tcp.seq
#print 'len = ' + capture[0].tcp.len
#print 'flags_res = ' + capture[0].tcp.flags_res
#print 'hdr_len = ' + capture[0].tcp.hdr_len
#print 'dstport = ' + capture[0].tcp.dstport
#print 'flags_push = ' + capture[0].tcp.flags_push
#print 'options_type_copy = ' + capture[0].tcp.options_type_copy
#print 'window_size = ' + capture[0].tcp.window_size
#print 'flags_ns = ' + capture[0].tcp.flags_ns
#print 'flags_ack = ' + capture[0].tcp.flags_ack
#print 'flags_str = ' + capture[0].tcp.flags_str
#print 'flags_fin = ' + capture[0].tcp.flags_fin
#print 'port = ' + capture[0].tcp.port
#print 'window_size_scalefactor = ' + capture[0].tcp.window_size_scalefactor
#print 'window_size_value = ' + capture[0].tcp.window_size_value
#print 'options_type = ' + capture[0].tcp.options_type
#print 'options = ' + capture[0].tcp.options
#print 'flags = ' + capture[0].tcp.flags
#print 'flags_ecn = ' + capture[0].tcp.flags_ecn
#print 'srcport = ' + capture[0].tcp.srcport
#print 'checksum = ' + capture[0].tcp.checksum
#print 'urgent_pointer = ' + capture[0].tcp.urgent_pointer
#print 'flags_syn = ' + capture[0].tcp.flags_syn
#print 'flags_cwr = ' + capture[0].tcp.flags_cwr
#print 'flags_reset = ' + capture[0].tcp.flags_reset