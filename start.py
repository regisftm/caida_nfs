#!/usr/bin/python2.7

import captura
import os
from scapy.all import *


def pkt_dissecat(pkt,bgn):
	print '*******  Packet Dissecation *******'
	print '* Layer 3 * '
	print 'ip version : ' + str(int("{0:8b}".format(pkt[bgn],16)[:4],2))
	pre_ihl = "{0:8b}".format(pkt[bgn],16)[4:]
	ip_ihl = int(('0b' + str(int(pre_ihl)).zfill(4) + '00'),2)
	print 'ip ihl     : ' + str(ip_ihl)
	pkt_ip_bgn2 = "{0:8b}".format(pkt[bgn+2],16)
	pkt_ip_bgn3 = "{0:8b}".format(pkt[bgn+3],16)
	totlen = int(('0b' + str(str(int(pkt_ip_bgn2)) + str(int(pkt_ip_bgn3)).zfill(8))),2)
	print 'totallength: ' + str(totlen)
	pkt_ip_bgn4 = "{0:8b}".format(pkt[bgn+4],16)
	pkt_ip_bgn5 = "{0:8b}".format(pkt[bgn+5],16)
	ident = int(('0b' + str(str(int(pkt_ip_bgn4)) + str(int(pkt_ip_bgn5)).zfill(8))),2)
	print 'identif    : ' + str(hex(ident)) + ' (' + str(ident) +')'
	pkt_ip_bgn6 = "{0:8b}".format(pkt[bgn+6],16)
	pkt_ip_bgn7 = "{0:8b}".format(pkt[bgn+7],16)
	flags = int(('0b' + str(str(int(pkt_ip_bgn6)) + str(int(pkt_ip_bgn7)).zfill(8))),2)
	print 'flags      : ' + str(hex(flags)) 
	print 'time 2 live: ' + str(pkt[bgn+8])
	print 'protocol   : ' + str(pkt[bgn+9])
	pkt_ip_bgn10 = "{0:8b}".format(pkt[bgn+10],16)
	pkt_ip_bgn11 = "{0:8b}".format(pkt[bgn+11],16)
	checksum = int(('0b' + str(str(int(pkt_ip_bgn10)) + str(int(pkt_ip_bgn11)).zfill(8))),2)
	print 'checksum   : ' + str(hex(checksum)) 
	print 'source addr: ' + str(pkt[bgn+12]) + '.'+ str(pkt[bgn+13]) + '.' + \
							str(pkt[bgn+14]) + '.'+ str(pkt[bgn+15])
	print 'destin addr: ' + str(pkt[bgn+16]) + '.'+ str(pkt[bgn+17]) + '.' + \
							str(pkt[bgn+18]) + '.'+ str(pkt[bgn+19])
	print 'options    : ' + str(ip_ihl-20) + ' bytes'

	if pkt[bgn+9] == 6:
		bgn = bgn+(ip_ihl-20)
		print '* Layer 4 * (protocol = 6 (TCP))'
		pkt_bgn20 = "{0:8b}".format(pkt[bgn+20],16)
		pkt_bgn21 = "{0:8b}".format(pkt[bgn+21],16)
		src_port = int(('0b' + str(str(int(pkt_bgn20)) + str(int(pkt_bgn21)).zfill(8))),2)
		print 'source port: ' + str(src_port)
		pkt_bgn22 = "{0:8b}".format(pkt[bgn+22],16)
		pkt_bgn23 = "{0:8b}".format(pkt[bgn+23],16)
		dst_port = int(('0b' + str(str(int(pkt_bgn22)) + str(int(pkt_bgn23)).zfill(8))),2)
		print 'destin port: ' + str(dst_port)
		pkt_bgn24 = "{0:8b}".format(pkt[bgn+24],16)
		pkt_bgn25 = "{0:8b}".format(pkt[bgn+25],16)
		pkt_bgn26 = "{0:8b}".format(pkt[bgn+26],16)
		pkt_bgn27 = "{0:8b}".format(pkt[bgn+27],16)
		sequen_num = int(('0b' + str(str(int(pkt_bgn24)) + \
							   str(int(pkt_bgn25)).zfill(8) + \
							   str(int(pkt_bgn26)).zfill(8) + \
							   str(int(pkt_bgn27)).zfill(8))),2)
		print 'sequec num : ' + str(sequen_num)
		pkt_bgn28 = "{0:8b}".format(pkt[bgn+28],16)
		pkt_bgn29 = "{0:8b}".format(pkt[bgn+29],16)
		pkt_bgn30 = "{0:8b}".format(pkt[bgn+30],16)
		pkt_bgn31 = "{0:8b}".format(pkt[bgn+31],16)
		ack_num = int(('0b' + str(str(int(pkt_bgn28)) + \
							   str(int(pkt_bgn29)).zfill(8) + \
							   str(int(pkt_bgn30)).zfill(8) + \
							   str(int(pkt_bgn31)).zfill(8))),2)
		print 'ack num    : ' + str(ack_num)
		pre_hl = "{0:8b}".format(pkt[bgn+32],16)[:4]
		print 'header len : ' + str(int(('0b' + str(int(pre_hl)).zfill(4) + '00'),2))
		pkt_bgn32_end = "{0:8b}".format(pkt[bgn+32],16)[4:]
		pkt_bgn33 = "{0:8b}".format(pkt[bgn+33],16)
		flags_l4 = int(('0b' + str(str(int(pkt_bgn32_end)).zfill(8) + \
							   str(int(pkt_bgn33)).zfill(8))),2)
		print 'flags      : ' + str(hex(flags_l4))
		pkt_bgn34 = "{0:8b}".format(pkt[bgn+34],16)
		pkt_bgn35 = "{0:8b}".format(pkt[bgn+35],16)
		win_sz = int(('0b' + str(str(int(pkt_bgn34)) + str(int(pkt_bgn35)).zfill(8))),2)
		print 'win size   : ' + str(win_sz)
		pkt_bgn36 = "{0:8b}".format(pkt[bgn+36],16)
		pkt_bgn37 = "{0:8b}".format(pkt[bgn+37],16)
		cksum = int(('0b' + str(str(int(pkt_bgn36)) + str(int(pkt_bgn37)).zfill(8))),2)
		print 'checksum   : ' + str(hex(cksum))
		pkt_bgn38 = "{0:8b}".format(pkt[bgn+38],16)
		pkt_bgn39 = "{0:8b}".format(pkt[bgn+39],16)
		urg_point = int(('0b' + str(str(int(pkt_bgn38)) + str(int(pkt_bgn39)).zfill(8))),2)
		print 'urgent pntr: ' + str(urg_point)
		print 'options    : ' + str(int(('0b' + str(int(pre_hl)).zfill(4) + '00'),2)-20) + ' bytes'
	elif pkt[bgn+9] == 17:
		bgn = bgn+(ip_ihl-20)
		print '* Layer 4 * (protocol = 17 (UDP))'
		pkt_bgn20 = "{0:8b}".format(pkt[bgn+20],16)
		pkt_bgn21 = "{0:8b}".format(pkt[bgn+21],16)
		src_port = int(('0b' + str(str(int(pkt_bgn20)) + str(int(pkt_bgn21)).zfill(8))),2)
		print 'source port: ' + str(src_port)
		pkt_bgn22 = "{0:8b}".format(pkt[bgn+22],16)
		pkt_bgn23 = "{0:8b}".format(pkt[bgn+23],16)
		dst_port = int(('0b' + str(str(int(pkt_bgn22)) + str(int(pkt_bgn23)).zfill(8))),2)
		print 'destin port: ' + str(dst_port)
		pkt_bgn24 = "{0:8b}".format(pkt[bgn+24],16)
		pkt_bgn25 = "{0:8b}".format(pkt[bgn+25],16)
		length = int(('0b' + str(str(int(pkt_bgn24)) + str(int(pkt_bgn25)).zfill(8))),2)
		print 'length     : ' + str(length)
		pkt_bgn26 = "{0:8b}".format(pkt[bgn+26],16)
		pkt_bgn27 = "{0:8b}".format(pkt[bgn+27],16)
		cksum = int(('0b' + str(str(int(pkt_bgn26)) + str(int(pkt_bgn27)).zfill(8))),2)
		print 'checksum   : ' + str(hex(cksum))
	else:
		print '* Layer 4 * not tcp neither upd'

	print '**** End of Packet Dissecation ****'



def pkt_dissecapy(pkt,bgn):
	print '*******  Scapy Packet Dissecation *******'
	print '* Layer 3 * '
	print 'ip version : ' + str(int("{0:8b}".format(pkt[bgn],16)[:4],2))
	pre_ihl = "{0:8b}".format(pkt[bgn],16)[4:]
	ip_ihl = int(('0b' + str(int(pre_ihl)).zfill(4) + '00'),2)
	print 'ip ihl     : ' + str(ip_ihl)
	pkt_ip_bgn2 = "{0:8b}".format(pkt[bgn+2],16)
	pkt_ip_bgn3 = "{0:8b}".format(pkt[bgn+3],16)
	totlen = int(('0b' + str(str(int(pkt_ip_bgn2)) + str(int(pkt_ip_bgn3)).zfill(8))),2)
	print 'totallength: ' + str(totlen)
	pkt_ip_bgn4 = "{0:8b}".format(pkt[bgn+4],16)
	pkt_ip_bgn5 = "{0:8b}".format(pkt[bgn+5],16)
	ident = int(('0b' + str(str(int(pkt_ip_bgn4)) + str(int(pkt_ip_bgn5)).zfill(8))),2)
	print 'identif    : ' + str(hex(ident)) + ' (' + str(ident) +')'
	pkt_ip_bgn6 = "{0:8b}".format(pkt[bgn+6],16)
	pkt_ip_bgn7 = "{0:8b}".format(pkt[bgn+7],16)
	flags = int(('0b' + str(str(int(pkt_ip_bgn6)) + str(int(pkt_ip_bgn7)).zfill(8))),2)
	print 'flags      : ' + str(hex(flags)) 
	print 'time 2 live: ' + str(pkt[bgn+8])
	print 'protocol   : ' + str(pkt[bgn+9])
	pkt_ip_bgn10 = "{0:8b}".format(pkt[bgn+10],16)
	pkt_ip_bgn11 = "{0:8b}".format(pkt[bgn+11],16)
	checksum = int(('0b' + str(str(int(pkt_ip_bgn10)) + str(int(pkt_ip_bgn11)).zfill(8))),2)
	print 'checksum   : ' + str(hex(checksum)) 
	print 'source addr: ' + str(pkt[bgn+12]) + '.'+ str(pkt[bgn+13]) + '.' + \
							str(pkt[bgn+14]) + '.'+ str(pkt[bgn+15])
	print 'destin addr: ' + str(pkt[bgn+16]) + '.'+ str(pkt[bgn+17]) + '.' + \
							str(pkt[bgn+18]) + '.'+ str(pkt[bgn+19])
	print 'options    : ' + str(ip_ihl-20) + ' bytes'

	if pkt[bgn+9] == 6:
		bgn = bgn+(ip_ihl-20)
		print '* Layer 4 * (protocol = 6 (TCP))'
		pkt_bgn20 = "{0:8b}".format(pkt[bgn+20],16)
		pkt_bgn21 = "{0:8b}".format(pkt[bgn+21],16)
		src_port = int(('0b' + str(str(int(pkt_bgn20)) + str(int(pkt_bgn21)).zfill(8))),2)
		print 'source port: ' + str(src_port)
		pkt_bgn22 = "{0:8b}".format(pkt[bgn+22],16)
		pkt_bgn23 = "{0:8b}".format(pkt[bgn+23],16)
		dst_port = int(('0b' + str(str(int(pkt_bgn22)) + str(int(pkt_bgn23)).zfill(8))),2)
		print 'destin port: ' + str(dst_port)
		pkt_bgn24 = "{0:8b}".format(pkt[bgn+24],16)
		pkt_bgn25 = "{0:8b}".format(pkt[bgn+25],16)
		pkt_bgn26 = "{0:8b}".format(pkt[bgn+26],16)
		pkt_bgn27 = "{0:8b}".format(pkt[bgn+27],16)
		sequen_num = int(('0b' + str(str(int(pkt_bgn24)) + \
							   str(int(pkt_bgn25)).zfill(8) + \
							   str(int(pkt_bgn26)).zfill(8) + \
							   str(int(pkt_bgn27)).zfill(8))),2)
		print 'sequec num : ' + str(sequen_num)
		pkt_bgn28 = "{0:8b}".format(pkt[bgn+28],16)
		pkt_bgn29 = "{0:8b}".format(pkt[bgn+29],16)
		pkt_bgn30 = "{0:8b}".format(pkt[bgn+30],16)
		pkt_bgn31 = "{0:8b}".format(pkt[bgn+31],16)
		ack_num = int(('0b' + str(str(int(pkt_bgn28)) + \
							   str(int(pkt_bgn29)).zfill(8) + \
							   str(int(pkt_bgn30)).zfill(8) + \
							   str(int(pkt_bgn31)).zfill(8))),2)
		print 'ack num    : ' + str(ack_num)
		pre_hl = "{0:8b}".format(pkt[bgn+32],16)[:4]
		print 'header len : ' + str(int(('0b' + str(int(pre_hl)).zfill(4) + '00'),2))
		pkt_bgn32_end = "{0:8b}".format(pkt[bgn+32],16)[4:]
		pkt_bgn33 = "{0:8b}".format(pkt[bgn+33],16)
		flags_l4 = int(('0b' + str(str(int(pkt_bgn32_end)).zfill(8) + \
							   str(int(pkt_bgn33)).zfill(8))),2)
		print 'flags      : ' + str(hex(flags_l4))
		pkt_bgn34 = "{0:8b}".format(pkt[bgn+34],16)
		pkt_bgn35 = "{0:8b}".format(pkt[bgn+35],16)
		win_sz = int(('0b' + str(str(int(pkt_bgn34)) + str(int(pkt_bgn35)).zfill(8))),2)
		print 'win size   : ' + str(win_sz)
		pkt_bgn36 = "{0:8b}".format(pkt[bgn+36],16)
		pkt_bgn37 = "{0:8b}".format(pkt[bgn+37],16)
		cksum = int(('0b' + str(str(int(pkt_bgn36)) + str(int(pkt_bgn37)).zfill(8))),2)
		print 'checksum   : ' + str(hex(cksum))
		pkt_bgn38 = "{0:8b}".format(pkt[bgn+38],16)
		pkt_bgn39 = "{0:8b}".format(pkt[bgn+39],16)
		urg_point = int(('0b' + str(str(int(pkt_bgn38)) + str(int(pkt_bgn39)).zfill(8))),2)
		print 'urgent pntr: ' + str(urg_point)
		print 'options    : ' + str(int(('0b' + str(int(pre_hl)).zfill(4) + '00'),2)-20) + ' bytes'
	elif pkt[bgn+9] == 17:
		bgn = bgn+(ip_ihl-20)
		print '* Layer 4 * (protocol = 17 (UDP))'
		pkt_bgn20 = "{0:8b}".format(pkt[bgn+20],16)
		pkt_bgn21 = "{0:8b}".format(pkt[bgn+21],16)
		src_port = int(('0b' + str(str(int(pkt_bgn20)) + str(int(pkt_bgn21)).zfill(8))),2)
		print 'source port: ' + str(src_port)
		pkt_bgn22 = "{0:8b}".format(pkt[bgn+22],16)
		pkt_bgn23 = "{0:8b}".format(pkt[bgn+23],16)
		dst_port = int(('0b' + str(str(int(pkt_bgn22)) + str(int(pkt_bgn23)).zfill(8))),2)
		print 'destin port: ' + str(dst_port)
		pkt_bgn24 = "{0:8b}".format(pkt[bgn+24],16)
		pkt_bgn25 = "{0:8b}".format(pkt[bgn+25],16)
		length = int(('0b' + str(str(int(pkt_bgn24)) + str(int(pkt_bgn25)).zfill(8))),2)
		print 'length     : ' + str(length)
		pkt_bgn26 = "{0:8b}".format(pkt[bgn+26],16)
		pkt_bgn27 = "{0:8b}".format(pkt[bgn+27],16)
		cksum = int(('0b' + str(str(int(pkt_bgn26)) + str(int(pkt_bgn27)).zfill(8))),2)
		print 'checksum   : ' + str(hex(cksum))
	else:
		print '* Layer 4 * not tcp neither upd'

	print '**** End of Packet Dissecation ****'


def main():
	print ('Iniciando o processamento dos hashs')
	pkts=rdpcap("50_caida.pcap")
	ip_bgn = 0
	for i in xrange(1,2):
		a = 'cur_pkt = captura.pkt' + str(i)
		exec (a)
		print (cur_pkt)
		pkt_dissecat(cur_pkt,ip_bgn)
		cur_pktscapy=[ord(c) for c in raw(pkts[i-1])]
		pkt_dissecapy(cur_pktscapy,ip_bgn)

main()
