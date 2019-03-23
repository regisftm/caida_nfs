#!/usr/bin/python3.6

import captura
import crcmod
#import md5
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

def crc16_comp(str_):
	str_ = bytearray(str_)
	crc16 = crcmod.mkCrcFun(0x18005, rev=False, initCrc=0xFFFF, xorOut=0x0000)
	answer = crc16(str(str_))
	return answer

def crc32_comp(str_):
	str_ = bytearray(str_)
	crc32 = crcmod.mkCrcFun(0x104C11DB7, rev=False, initCrc=0xFFFFFFFF, xorOut=0xFFFFFFFF)
	answer = crc32(str(str_))
	return answer

#def md5_comp(str_):
#	str_ = bytearray(str_)
#	m = md5.new()
#	m.update(str(str_))
#	answer = int(("0x" + m.hexdigest()[:4]),16)
#	return answer

def check_gtp_flag(flag):
	if flag == 48:
		result = 54
	elif flag == 50:
		result = 58
	else:
		#print("payload not 30 either 32")
		result = "error on gtp header"
	return result

def verify_checksum(pkt):
	##print pkt

	##print ('o pkt[46] e = ' + str(pkt[46]))

	#ip_bgn = check_gtp_flag(pkt[46])
	ip_bgn = 14

	if isinstance(ip_bgn, basestring):
		return ip_bgn
	else:
		pass

	#calculando o checksum com os campos do pacote
	csum_list = [pkt[ip_bgn], pkt[ip_bgn+1], pkt[ip_bgn+2], pkt[ip_bgn+3], 
				 pkt[ip_bgn+4], pkt[ip_bgn+5], pkt[ip_bgn+6], pkt[ip_bgn+7], 
				 pkt[ip_bgn+8], pkt[ip_bgn+9],
				 pkt[ip_bgn+12], pkt[ip_bgn+13], pkt[ip_bgn+14], pkt[ip_bgn+15],
				 pkt[ip_bgn+16], pkt[ip_bgn+17], pkt[ip_bgn+18], pkt[ip_bgn+19]]

	calc_checksum = checksum(csum_list)

	#lendo o checksum do pacote
	csum1 = "{0:8b}".format(pkt[ip_bgn+10],16)
	csum2 = "{0:8b}".format(pkt[ip_bgn+11],16)
	pkt_csum = int(('0b' + str(str(int(csum1)) + str(int(csum2)).zfill(8))),2)

	#comparando os 2 checksums
	if calc_checksum == pkt_csum:
		result = "csum_ok"
		#print result
		return result
	else:
		result = "csum_not_ok"
		#print result
		return result

def pkt_dissecat(pkt,bgn):
	print ('*******  Packet Dissecation *******')
	print ('* Layer 3 * ')
	print ('ip version : ' + str(int("{0:8b}".format(pkt[bgn],16)[:4],2)))
	pre_ihl = "{0:8b}".format(pkt[bgn],16)[4:]
	ip_ihl = int(('0b' + str(int(pre_ihl)).zfill(4) + '00'),2)
	print ('ip ihl     : ' + str(ip_ihl))
	pkt_ip_bgn2 = "{0:8b}".format(pkt[bgn+2],16)
	pkt_ip_bgn3 = "{0:8b}".format(pkt[bgn+3],16)
	totlen = int(('0b' + str(str(int(pkt_ip_bgn2)) + str(int(pkt_ip_bgn3)).zfill(8))),2)
	print ('totallength: ' + str(totlen))
	pkt_ip_bgn4 = "{0:8b}".format(pkt[bgn+4],16)
	pkt_ip_bgn5 = "{0:8b}".format(pkt[bgn+5],16)
	ident = int(('0b' + str(str(int(pkt_ip_bgn4)) + str(int(pkt_ip_bgn5)).zfill(8))),2)
	print ('identif    : ' + str(hex(ident)) + ' (' + str(ident) +')')
	pkt_ip_bgn6 = "{0:8b}".format(pkt[bgn+6],16)
	pkt_ip_bgn7 = "{0:8b}".format(pkt[bgn+7],16)
	flags = int(('0b' + str(str(int(pkt_ip_bgn6)) + str(int(pkt_ip_bgn7)).zfill(8))),2)
	print ('flags      : ' + str(hex(flags)))
	print ('time 2 live: ' + str(pkt[bgn+8]))
	print ('protocol   : ' + str(pkt[bgn+9]))
	pkt_ip_bgn10 = "{0:8b}".format(pkt[bgn+10],16)
	pkt_ip_bgn11 = "{0:8b}".format(pkt[bgn+11],16)
	checksum = int(('0b' + str(str(int(pkt_ip_bgn10)) + str(int(pkt_ip_bgn11)).zfill(8))),2)
	print ('checksum   : ' + str(hex(checksum)))
	print ('source addr: ' + str(pkt[bgn+12]) + '.'+ str(pkt[bgn+13]) + '.' + \
							str(pkt[bgn+14]) + '.'+ str(pkt[bgn+15]))
	print ('destin addr: ' + str(pkt[bgn+16]) + '.'+ str(pkt[bgn+17]) + '.' + \
							str(pkt[bgn+18]) + '.'+ str(pkt[bgn+19]))
	print ('options    : ' + str(ip_ihl-20) + ' bytes')

	if pkt[bgn+9] == 6:
		bgn = bgn+(ip_ihl-20)
		print ('* Layer 4 * (protocol = 6 (TCP))')
		pkt_bgn20 = "{0:8b}".format(pkt[bgn+20],16)
		pkt_bgn21 = "{0:8b}".format(pkt[bgn+21],16)
		src_port = int(('0b' + str(str(int(pkt_bgn20)) + str(int(pkt_bgn21)).zfill(8))),2)
		print ('source port: ' + str(src_port))
		pkt_bgn22 = "{0:8b}".format(pkt[bgn+22],16)
		pkt_bgn23 = "{0:8b}".format(pkt[bgn+23],16)
		dst_port = int(('0b' + str(str(int(pkt_bgn22)) + str(int(pkt_bgn23)).zfill(8))),2)
		print ('destin port: ' + str(dst_port))
		pkt_bgn24 = "{0:8b}".format(pkt[bgn+24],16)
		pkt_bgn25 = "{0:8b}".format(pkt[bgn+25],16)
		pkt_bgn26 = "{0:8b}".format(pkt[bgn+26],16)
		pkt_bgn27 = "{0:8b}".format(pkt[bgn+27],16)
		sequen_num = int(('0b' + str(str(int(pkt_bgn24)) + \
							   str(int(pkt_bgn25)).zfill(8) + \
							   str(int(pkt_bgn26)).zfill(8) + \
							   str(int(pkt_bgn27)).zfill(8))),2)
		print ('sequec num : ' + str(sequen_num))
		pkt_bgn28 = "{0:8b}".format(pkt[bgn+28],16)
		pkt_bgn29 = "{0:8b}".format(pkt[bgn+29],16)
		pkt_bgn30 = "{0:8b}".format(pkt[bgn+30],16)
		pkt_bgn31 = "{0:8b}".format(pkt[bgn+31],16)
		ack_num = int(('0b' + str(str(int(pkt_bgn28)) + \
							   str(int(pkt_bgn29)).zfill(8) + \
							   str(int(pkt_bgn30)).zfill(8) + \
							   str(int(pkt_bgn31)).zfill(8))),2)
		print ('ack num    : ' + str(ack_num))
		pre_hl = "{0:8b}".format(pkt[bgn+32],16)[:4]
		print ('header len : ' + str(int(('0b' + str(int(pre_hl)).zfill(4) + '00'),2)))
		pkt_bgn32_end = "{0:8b}".format(pkt[bgn+32],16)[4:]
		pkt_bgn33 = "{0:8b}".format(pkt[bgn+33],16)
		flags_l4 = int(('0b' + str(str(int(pkt_bgn32_end)).zfill(8) + \
							   str(int(pkt_bgn33)).zfill(8))),2)
		print ('flags      : ' + str(hex(flags_l4)))
		pkt_bgn34 = "{0:8b}".format(pkt[bgn+34],16)
		pkt_bgn35 = "{0:8b}".format(pkt[bgn+35],16)
		win_sz = int(('0b' + str(str(int(pkt_bgn34)) + str(int(pkt_bgn35)).zfill(8))),2)
		print ('win size   : ' + str(win_sz))
		pkt_bgn36 = "{0:8b}".format(pkt[bgn+36],16)
		pkt_bgn37 = "{0:8b}".format(pkt[bgn+37],16)
		cksum = int(('0b' + str(str(int(pkt_bgn36)) + str(int(pkt_bgn37)).zfill(8))),2)
		print ('checksum   : ' + str(hex(cksum)))
		pkt_bgn38 = "{0:8b}".format(pkt[bgn+38],16)
		pkt_bgn39 = "{0:8b}".format(pkt[bgn+39],16)
		urg_point = int(('0b' + str(str(int(pkt_bgn38)) + str(int(pkt_bgn39)).zfill(8))),2)
		print ('urgent pntr: ' + str(urg_point))
		print ('options    : ' + str(int(('0b' + str(int(pre_hl)).zfill(4) + '00'),2)-20) + ' bytes')
	elif pkt[bgn+9] == 17:
		bgn = bgn+(ip_ihl-20)
		print ('* Layer 4 * (protocol = 17 (UDP))')
		pkt_bgn20 = "{0:8b}".format(pkt[bgn+20],16)
		pkt_bgn21 = "{0:8b}".format(pkt[bgn+21],16)
		src_port = int(('0b' + str(str(int(pkt_bgn20)) + str(int(pkt_bgn21)).zfill(8))),2)
		print ('source port: ' + str(src_port))
		pkt_bgn22 = "{0:8b}".format(pkt[bgn+22],16)
		pkt_bgn23 = "{0:8b}".format(pkt[bgn+23],16)
		dst_port = int(('0b' + str(str(int(pkt_bgn22)) + str(int(pkt_bgn23)).zfill(8))),2)
		print ('destin port: ' + str(dst_port))
		pkt_bgn24 = "{0:8b}".format(pkt[bgn+24],16)
		pkt_bgn25 = "{0:8b}".format(pkt[bgn+25],16)
		length = int(('0b' + str(str(int(pkt_bgn24)) + str(int(pkt_bgn25)).zfill(8))),2)
		print ('length     : ' + str(length))
		pkt_bgn26 = "{0:8b}".format(pkt[bgn+26],16)
		pkt_bgn27 = "{0:8b}".format(pkt[bgn+27],16)
		cksum = int(('0b' + str(str(int(pkt_bgn26)) + str(int(pkt_bgn27)).zfill(8))),2)
		print ('checksum   : ' + str(hex(cksum)))
	else:
		print ('* Layer 4 * not tcp neither upd')

	print ('**** End of Packet Dissecation ****')


def hashing(pkt):
	
	payload=[]

	##print ('o pkt[46] e = ' + str(pkt[46]))

	#ip_bgn = check_gtp_flag(pkt[46])
	ip_bgn = 14



	if isinstance(ip_bgn, basestring):
		return [0,0,0,0,0,0,0,0,0,0,0,0,0]
	else:
		pass

	#pkt_dissecat(pkt,ip_bgn)

	if pkt[ip_bgn+9] == 6:  #pacote tcp
		#print ('protocolo tcp')
		#print ('octeto do tamanho do header = ' + str(pkt[ip_bgn+32]))
		ihl_part = "{0:8b}".format(pkt[ip_bgn+32],16)[:4]
		#print ihl_part
		ihl = int(('0b'+ str(int(ihl_part)).zfill(4) + '00'),2)
		#print ihl
		#print ('protocolo = ' + str(pkt[ip_bgn+9]))
		#print ('header length = ' + str(ihl))
		for i in range (ip_bgn+20+ihl,ip_bgn+28+ihl):
			#print ("payload tcp" + str(i))
			try: 
				payload.append(pkt[i])
			except Exception as e:
				payload.append(0)
	elif pkt[ip_bgn+9] == 17:  #pacote udp
		for i in range (ip_bgn+28,ip_bgn+36):
			#print ("payload udp" + str(i))
			try: 
				payload.append(pkt[i])
			except Exception as e:
				payload.append(0)
	else: # other packet not udp or tcp
		#print ("neither UDP or TCP packet")
		for i in xrange(8):
			payload.append(0)

	
	##print(payload)
	if sum(payload) == 0:
		payld = 'zero'
		#print ('payload zero')
	else:
		payld = 'non_zero'
		#print ('payload non_zero')


	hlst_l4_pld = [pkt[ip_bgn],  				#version,ihl
				pkt[ip_bgn+2],pkt[ip_bgn+3],	#totallenght
				pkt[ip_bgn+4],pkt[ip_bgn+5],	#identification
				pkt[ip_bgn+6],pkt[ip_bgn+7], 	#flag,fragOffset
				pkt[ip_bgn+9],        			#protocol
				pkt[ip_bgn+12],pkt[ip_bgn+13],pkt[ip_bgn+14],pkt[ip_bgn+15], #srcAddr
				pkt[ip_bgn+16],pkt[ip_bgn+17],pkt[ip_bgn+18],pkt[ip_bgn+19]  #dstAddr
				] + payload						#payload

	hlst_l3_pld = [pkt[ip_bgn],  				#version,ihl
				pkt[ip_bgn+2],pkt[ip_bgn+3],	#totallenght
				pkt[ip_bgn+4],pkt[ip_bgn+5],	#identification
				pkt[ip_bgn+6],pkt[ip_bgn+7], 	#flag,fragOffset
				pkt[ip_bgn+9],        			#protocol
				pkt[ip_bgn+12],pkt[ip_bgn+13],pkt[ip_bgn+14],pkt[ip_bgn+15], #srcAddr
				pkt[ip_bgn+16],pkt[ip_bgn+17],pkt[ip_bgn+18],pkt[ip_bgn+19], #dstAddr
				pkt[ip_bgn+20],pkt[ip_bgn+21],pkt[ip_bgn+22],pkt[ip_bgn+23], #payld bytes 1-4
				pkt[ip_bgn+24],pkt[ip_bgn+25],pkt[ip_bgn+26],pkt[ip_bgn+27]] #payld bytes 5-8
	
	hlst_l34_pld = [pkt[ip_bgn],  				#version,ihl
				pkt[ip_bgn+2],pkt[ip_bgn+3],	#totallenght
				pkt[ip_bgn+4],pkt[ip_bgn+5],	#identification
				pkt[ip_bgn+6],pkt[ip_bgn+7], 	#flag,fragOffset
				pkt[ip_bgn+9],        			#protocol
				pkt[ip_bgn+12],pkt[ip_bgn+13],pkt[ip_bgn+14],pkt[ip_bgn+15], #srcAddr
				pkt[ip_bgn+16],pkt[ip_bgn+17],pkt[ip_bgn+18],pkt[ip_bgn+19], #dstAddr
				pkt[ip_bgn+20],pkt[ip_bgn+21],pkt[ip_bgn+22],pkt[ip_bgn+23], #payld bytes 1-4
				pkt[ip_bgn+24],pkt[ip_bgn+25],pkt[ip_bgn+26],pkt[ip_bgn+27], #payld bytes 5-8
				] + payload						#payload
	pkt_csum16_l4 = checksum(hlst_l4_pld)
	pkt_crc16_l4 = crc16_comp(hlst_l4_pld)
	pkt_crc32_l4 = crc32_comp(hlst_l4_pld)
#	pkt_md5_l4 = md5_comp(hlst_l4_pld)
	pkt_csum16_l3 = checksum(hlst_l3_pld)
	pkt_crc16_l3 = crc16_comp(hlst_l3_pld)
	pkt_crc32_l3 = crc32_comp(hlst_l3_pld)
#	pkt_md5_l3 = md5_comp(hlst_l3_pld)
	pkt_csum16_l34 = checksum(hlst_l34_pld)
	pkt_crc16_l34 = crc16_comp(hlst_l34_pld)
	pkt_crc32_l34 = crc32_comp(hlst_l34_pld)
#	pkt_md5_l34 = md5_comp(hlst_l34_pld)
 	##print payld


	return [pkt_csum16_l4, pkt_crc16_l4, pkt_crc32_l4, pkt_md5_l4,
 		    pkt_csum16_l3, pkt_crc16_l3, pkt_crc32_l3, pkt_md5_l3,
 		    pkt_csum16_l34, pkt_crc16_l34, pkt_crc32_l3, pkt_md5_l34,
 		    payld]


def main():
	bm_csum16_l4_payld = [0] * 65536
	bm_crc16_l4_payld = [0] * 65536
	bm_crc32_l4_payld = [0] * 65536
#	bm_md5_l4_payld = [0] * 65536
	bm_csum16_l3_payld = [0] * 65536
	bm_crc16_l3_payld = [0] * 65536
	bm_crc32_l3_payld = [0] * 65536
#	bm_md5_l3_payld = [0] * 65536
	bm_csum16_l34_payld = [0] * 65536
	bm_crc16_l34_payld = [0] * 65536
	bm_crc32_l34_payld = [0] * 65536
#	bm_md5_l34_payld = [0] * 65536
	
	colisions_csum16_l4 = 0
	colisions_crc16_l4 = 0
	colisions_crc32_l4 = 0
#	colisions_md5_l4 = 0	
	colisions_csum16_l3 = 0
	colisions_crc16_l3 = 0
	colisions_crc32_l3 = 0
#	colisions_md5_l3 = 0
	colisions_csum16_l34 = 0
	colisions_crc16_l34 = 0
	colisions_crc32_l34 = 0
#	colisions_md5_l34 = 0

	print ('Iniciando o processamento dos hashs')

	#file = open("pkt_hashed.csv","w")
	#file.write("pkt_number;hash_l4_csum16;collided_l4_csum16;"+
	#		   "hash_l4_crc16;collided_l4_crc16;"+
	#		   "hash_l3_csum16;collided_l3_csum16;"+
	#		   "hash_l3_crc16;collided_l3_crc16;"+
	#		   "pkt_csum_verific;payload"+"\n")
	for i in range(0,9):
		a = 'cur_pkt = captura.pkt' + str(i)
		#print ('processando pacote #' + str(i))
		try:
			exec(a)
				#cur_pkt = captura.pkt200  # para processar um pacote especifico.
			csum_result = verify_checksum(cur_pkt)

			pkt_hash_l4_csum16, \
			pkt_hash_l4_crc16, \
			pkt_hash_l4_crc32, \
#			pkt_hash_l4_md5, \
			pkt_hash_l3_csum16, \
			pkt_hash_l3_crc16, \
			pkt_hash_l3_crc32, \
#			pkt_hash_l3_md5, \
			pkt_hash_l34_csum16, \
			pkt_hash_l34_crc16, \
			pkt_hash_l34_crc32, \
#			pkt_hash_l34_md5, \
			payld = hashing(cur_pkt)

			pkt_hash_l4_crc32_h = int(hex(pkt_hash_l4_crc32)[:6],16)
			pkt_hash_l3_crc32_h = int(hex(pkt_hash_l3_crc32)[:6],16)
			pkt_hash_l34_crc32_h = int(hex(pkt_hash_l3_crc32)[:6],16)

			#print ('o hash payld l4 csum16 do pacote e: ' + str(pkt_hash_l4_csum16))
			#print ('o hash payld l4 crc16 do pacote e: ' + str(pkt_hash_l4_crc16))
			#print ('o hash payld l4 crc32 do pacote e: ' + str(pkt_hash_l4_crc32_h))
			#print ('o hash payld l4 md5 do pacote e: ' + str(pkt_hash_l4_md5))
			#print ('o hash payld l3 csum16 do pacote e: ' + str(pkt_hash_l3_csum16))
			#print ('o hash payld l3 crc16 do pacote e: ' + str(pkt_hash_l3_crc16))
			#print ('o hash payld l3 crc32 do pacote e: ' + str(pkt_hash_l3_crc32_h))
			#print ('o hash payld l3 md5 do pacote e: ' + str(pkt_hash_l3_md5))
			#print ('o hash payld l34 csum16 do pacote e: ' + str(pkt_hash_l34_csum16))
			#print ('o hash payld l34 crc16 do pacote e: ' + str(pkt_hash_l34_crc16))
			#print ('o hash payld l34 crc32 do pacote e: ' + str(pkt_hash_l34_crc32_h))
			#print ('o hash payld l34 md5 do pacote e: ' + str(pkt_hash_l34_md5))

			# l4

			#print bm_csum16_l4_payld[pkt_hash_l4_csum16]
			if bm_csum16_l4_payld[pkt_hash_l4_csum16] == 0:
				#print ('bm_csum16_l4_payld[%d] is == %d' %(pkt_hash_l4_csum16, bm_csum16_l4_payld[pkt_hash_l4_csum16]))
				bm_csum16_l4_payld[pkt_hash_l4_csum16] = i
				collided_csum16_l4 = 0
			else:
				#print ('bm_csum16_l4_payld[%d] is == %d' %(pkt_hash_l4_csum16, bm_csum16_l4_payld[pkt_hash_l4_csum16]))
				#print 'packet %d has collided to packet %d' %(i, bm_csum16_l4_payld[pkt_hash_l4_csum16])
				colisions_csum16_l4 += 1
				collided_csum16_l4 = bm_csum16_l4_payld[pkt_hash_l4_csum16]
			
			#print bm_crc16_l4_payld[pkt_hash_l4_crc16]
			if bm_crc16_l4_payld[pkt_hash_l4_crc16] == 0:
				#print ('bm_crc16_l4_payld[%d] is == %d' % (pkt_hash_l4_crc16, bm_crc16_l4_payld[pkt_hash_l4_crc16]))
				bm_crc16_l4_payld[pkt_hash_l4_crc16] = i
				collided_crc16_l4 = 0
			else:
				#print ('bm_crc16_l4_payld[%d] is == %d' % (pkt_hash_l4_crc16, bm_crc16_l4_payld[pkt_hash_l4_crc16]))
				#print 'packet %d has collided to packet %d' %(i, bm_crc16_l4_payld[pkt_hash_l4_crc16])
				colisions_crc16_l4 += 1
				collided_crc16_l4 = bm_crc16_l4_payld[pkt_hash_l4_crc16]
			
			#print bm_crc32_l4_payld[pkt_hash_l4_crc32_h]
			if bm_crc32_l4_payld[pkt_hash_l4_crc32_h] == 0:
				#print ('bm_crc32_l4_payld[%d] is == %d' % (pkt_hash_l4_crc32_h, bm_crc32_l4_payld[pkt_hash_l4_crc32_h]))
				bm_crc32_l4_payld[pkt_hash_l4_crc32_h] = i
				collided_crc32_l4 = 0
			else:
				#print ('bm_crc32_l4_payld[%d] is == %d' % (pkt_hash_l4_crc32_h, bm_crc32_l4_payld[pkt_hash_l4_crc32_h]))
				#print 'packet %d has collided to packet %d' %(i, bm_crc32_l4_payld[pkt_hash_l4_crc32_h])
				colisions_crc32_l4 += 1
				collided_crc32_l4 = bm_crc32_l4_payld[pkt_hash_l4_crc32_h]

#			if bm_md5_l4_payld[pkt_hash_l4_md5] == 0:
#				bm_md5_l4_payld[pkt_hash_l4_md5] = i
#				collided_md5_l4 = 0
#			else:
#				colisions_md5_l4 += 1
#				collided_md5_l4 = bm_md5_l4_payld[pkt_hash_l4_md5]
#			
			# l3 

			#print bm_csum16_l3_payld[pkt_hash_l3_csum16]
			if bm_csum16_l3_payld[pkt_hash_l3_csum16] == 0:
				#print ('bm_csum16_l3_payld[%d] is == %d' % (pkt_hash_l3_csum16, bm_csum16_l3_payld[pkt_hash_l3_csum16]))
				bm_csum16_l3_payld[pkt_hash_l3_csum16] = i
				collided_csum16_l3 = 0
			else:
				#print ('bm_csum16_l3_payld[%d] is == %d' % (pkt_hash_l3_csum16, bm_csum16_l3_payld[pkt_hash_l3_csum16]))
				#print 'packet %d has collided to packet %d' %(i, bm_csum16_l3_payld[pkt_hash_l3_csum16])
				colisions_csum16_l3 += 1
				collided_csum16_l3 = bm_csum16_l3_payld[pkt_hash_l3_csum16]
			
			#print bm_crc16_l3_payld[pkt_hash_l3_crc16]
			if bm_crc16_l3_payld[pkt_hash_l3_crc16] == 0:
				#print ('bm_crc16_l3_payld[%d] is == %d' % (pkt_hash_l3_crc16,bm_crc16_l3_payld[pkt_hash_l3_crc16]))
				bm_crc16_l3_payld[pkt_hash_l3_crc16] = i
				collided_crc16_l3 = 0
			else:
				#print ('bm_crc16_l3_payld[%d] is == %d' % (pkt_hash_l3_crc16,bm_crc16_l3_payld[pkt_hash_l3_crc16]))
				#print 'packet %d has collided to packet %d' %(i, bm_crc16_l3_payld[pkt_hash_l3_crc16])
				colisions_crc16_l3 += 1
				collided_crc16_l3 = bm_crc16_l3_payld[pkt_hash_l3_crc16]
			
			#print bm_crc32_l3_payld[pkt_hash_l3_crc32_h]
			if bm_crc32_l3_payld[pkt_hash_l3_crc32_h] == 0:
				#print ('bm_crc32_l3_payld[%d] is == %d' % (pkt_hash_l3_crc32_h,bm_crc32_l3_payld[pkt_hash_l3_crc32_h]))
				bm_crc32_l3_payld[pkt_hash_l3_crc32_h] = i
				collided_crc32_l3 = 0
			else:
				#print ('bm_crc32_l3_payld[%d] is == %d' % (pkt_hash_l3_crc32_h,bm_crc32_l3_payld[pkt_hash_l3_crc32_h]))
				#print 'packet %d has collided to packet %d' %(i, bm_crc32_l3_payld[pkt_hash_l3_crc32_h])
				colisions_crc32_l3 += 1
				collided_crc32_l3 = bm_crc32_l3_payld[pkt_hash_l3_crc32_h]
			
#			if bm_md5_l3_payld[pkt_hash_l3_md5] == 0:
#				bm_md5_l3_payld[pkt_hash_l3_md5] = i
#				collided_md5_l3 = 0
#			else:
#				colisions_md5_l3 += 1
#				collided_md5_l3 = bm_md5_l3_payld[pkt_hash_l3_md5]

			# l34 


			if bm_csum16_l34_payld[pkt_hash_l34_csum16] == 0:
				bm_csum16_l34_payld[pkt_hash_l34_csum16] = i
				collided_csum16_l34 = 0
			else:
				colisions_csum16_l34 += 1
				collided_csum16_l34 = bm_csum16_l34_payld[pkt_hash_l34_csum16]
			
			if bm_crc16_l34_payld[pkt_hash_l34_crc16] == 0:
				bm_crc16_l34_payld[pkt_hash_l34_crc16] = i
				collided_crc16_l34 = 0
			else:
				colisions_crc16_l34 += 1
				collided_crc16_l34 = bm_crc16_l34_payld[pkt_hash_l34_crc16]
			
			if bm_crc32_l34_payld[pkt_hash_l34_crc32_h] == 0:
				bm_crc32_l34_payld[pkt_hash_l34_crc32_h] = i
				collided_crc32_l34 = 0
			else:
				colisions_crc32_l34 += 1
				collided_crc32_l34 = bm_crc32_l34_payld[pkt_hash_l34_crc32_h]

#			if bm_md5_l34_payld[pkt_hash_l34_md5] == 0:
#				bm_md5_l34_payld[pkt_hash_l34_md5] = i
#				collided_md5_l34 = 0
#			else:
#				colisions_md5_l34 += 1
#				collided_md5_l34 = bm_md5_l34_payld[pkt_hash_l34_md5]
		
			#file.write(str(i)+";"+
			#		   str(pkt_hash_l4_csum16)+";"+
			#		   str(collided_csum16_l4)+";"+
			#		   str(pkt_hash_l4_crc16)+";"+
			#		   str(collided_crc16_l4)+";"+
			#		   str(pkt_hash_l3_csum16)+";"+
			#		   str(collided_csum16_l3)+";"+
			#		   str(pkt_hash_l3_crc16)+";"+
			#		   str(collided_crc16_l3)+";"+
			#		   str(csum_result)+";"+
			#		   str(payld)+"\n")
		except Exception as e:
			print ("pkt%d does not exists or cant be processed" % i)
	
	#file.close()
	print ('# of collisions using l4 payload and csum16 = ' +str(colisions_csum16_l4))
	print ('# of collisions using l4 payload and crc16 = ' +str(colisions_crc16_l4))
	print ('# of collisions using l4 payload and crc32 = ' +str(colisions_crc32_l4))
#	print ('# of collisions using l4 payload and md5 = ' +str(colisions_md5_l4))	
	print ('# of collisions using l3 payload and csum16 = ' +str(colisions_csum16_l3))
	print ('# of collisions using l3 payload and crc16 = ' +str(colisions_crc16_l3))
	print ('# of collisions using l3 payload and crc23 = ' +str(colisions_crc32_l3))
#	print ('# of collisions using l3 payload and md5 = ' +str(colisions_md5_l3))
	print ('# of collisions using l34 payload and csum16 = ' +str(colisions_csum16_l34))
	print ('# of collisions using l34 payload and crc16 = ' +str(colisions_crc16_l34))
	print ('# of collisions using l34 payload and crc23 = ' +str(colisions_crc32_l34))
#	print ('# of collisions using l34 payload and md5 = ' +str(colisions_md5_l34))

main()