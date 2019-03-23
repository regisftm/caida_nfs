#!/usr/bin/python2.7

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
#	#answer = int(("0x" + m.hexdigest()[:4]),16)
#	answer = int(("0x" + m.hexdigest()),16)
#	return answer

def verify_checksum(pkt):
	ip_bgn = 0

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
	
	ip_bgn = 0

	#pkt_dissecat(pkt,ip_bgn)

	hlst 	 = [pkt[ip_bgn],  				#version,ihl
				pkt[ip_bgn+2],pkt[ip_bgn+3],	#totallenght
				pkt[ip_bgn+4],pkt[ip_bgn+5],	#identification
				pkt[ip_bgn+6],pkt[ip_bgn+7], 	#flag,fragOffset
				pkt[ip_bgn+9],        			#protocol
				pkt[ip_bgn+12],pkt[ip_bgn+13],pkt[ip_bgn+14],pkt[ip_bgn+15], #srcAddr
				pkt[ip_bgn+16],pkt[ip_bgn+17],pkt[ip_bgn+18],pkt[ip_bgn+19], #dstAddr
				pkt[ip_bgn+20],pkt[ip_bgn+21],pkt[ip_bgn+22],pkt[ip_bgn+23], #payld bytes 1-4
				pkt[ip_bgn+24],pkt[ip_bgn+25],pkt[ip_bgn+26],pkt[ip_bgn+27]] #payld bytes 5-8

	print (hlst)
 	#pkt_hashed = checksum(hlst)				# calcula o hash csum16
	pkt_hashed = crc32_comp(hlst)				# calcula o hash crc32
 	#pkt_hashed = md5_comp(hlst)				# calcula o hash md5

	pkt_hashed = pkt_hashed % 2**18			# calcula o mod para caber em 18 bits
	#pkt_hashed = int(bin(pkt_hashed)[:2]+bin(pkt_hashed)[16:],2) #ultimos 18 bits crc32
	#pkt_hashed = int(bin(pkt_hashed)[:2]+bin(pkt_hashed)[112:],2) #ultimos 18 bits md5

 	#pkt_hashed = int(bin(pkt_hashed)[:20],2)	# pega os 18 primeiros bits

	return (pkt_hashed)


def main():

	bm_len = 18
	test_list = [0.05, 0.1, 0.2, 0.5, 1]
	print ('bitmap lenght = ' + str(2**bm_len))

	for t in range (len(test_list)):

		total_pkts = int(float(test_list[t])*(2**bm_len))
		bm = [0] * 2**bm_len
		collisions = 0
		num_pkts = 0
		i = 0
		max_hash = 0 
		print ('ate aqui')

		while num_pkts < total_pkts:
			i += 1
			a = 'cur_pkt = captura.pkt' + str(i)
			num_pkts += 1
			try:
				exec(a)
				csum_result = verify_checksum(cur_pkt)
				pkt_hash = hashing(cur_pkt)
				print (pkt_hash)

				#if pkt_hash > max_hash:
				#	max_hash = pkt_hash
				#	print max_hash

				if bm[pkt_hash] == 0:
					bm[pkt_hash] = i
					collided = 0
				else:
					collisions += 1
					collided = bm[pkt_hash]
					
			except Exception as e:
				#print ("pkt%d does not exists or cant be processed" % i)
				num_pkts -= 1
		
		print ('-------------------------------------------')
		print ('# of collisions = ' +str(collisions))
		print ('# of packets processed = ' +str(num_pkts))
		print ('% of bitmatrix occupation = ' + str(float((num_pkts-collisions))/(2**bm_len)*100) + '%')
		print ('% of collisions = ' + str(float(collisions)/num_pkts*100) + '%')
	print ('-------------------------------------------')

main()