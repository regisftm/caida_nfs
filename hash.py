#!/usr/bin/python2.7

from scapy.all import *
import crcmod
import md5
import os


def checksum(str_):
    str_ = bytearray(str_)
    csum = 0
    countTo = (len(str_) // 2) * 2

    for count in range(0, countTo, 2):
        thisVal = str_[count+1] * 256 + str_[count]
        csum = csum + thisVal
        csum = csum & 0xffffffff

    if countTo < len(str_):
        csum = csum + str_[-1]
        csum = csum & 0xffffffff

    csum = (csum >> 16) + (csum & 0xffff)
    csum = csum + (csum >> 16)
    answer = ~csum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer

def crc32_comp(str_):
	str_ = bytearray(str_)
	crc32 = crcmod.mkCrcFun(0x104C11DB7, rev=False, initCrc=0xFFFFFFFF, xorOut=0xFFFFFFFF)
	answer = crc32(str(str_))
	return answer


def verify_checksum(pkt):

	#calculando o checksum com os campos do pacote
	csum_list = [pkt[0], pkt[1], pkt[2], pkt[3], 
				 pkt[4], pkt[5], pkt[6], pkt[7], 
				 pkt[8], pkt[9],
				 pkt[12], pkt[13], pkt[14], pkt[15],
				 pkt[16], pkt[17], pkt[18], pkt[19]]

	calc_checksum = checksum(csum_list)

	#lendo o checksum do pacote
	csum1 = "{0:8b}".format(pkt[10],16)
	csum2 = "{0:8b}".format(pkt[11],16)
	pkt_csum = int(('0b' + str(str(int(csum1)) + str(int(csum2)).zfill(8))),2)

	#comparando os 2 checksums
	if calc_checksum == pkt_csum:
		result = "csum_ok"
		print result
		return result
	else:
		result = "csum_not_ok"
		print result
		return result


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




def main():

#	Defina o tamanho da bitmatrix a ser usada
	bm_size


	print ('Iniciando o processamento dos hashs')
	pkts=rdpcap("50_caida.pcap")
	ip_bgn = 0
	for i in xrange(1,45):
#		a = 'cur_pkt = captura.pkt' + str(i)
#		exec (a)
#		print (cur_pkt)
#		pkt_dissecat(cur_pkt,ip_bgn)
		cur_pktscapy=[ord(c) for c in raw(pkts[i])]
#		pkt_dissecapy(cur_pktscapy,ip_bgn)
		verify_checksum(cur_pktscapy)
		a=hashing(cur_pktscapy)
		print (a)

main()
