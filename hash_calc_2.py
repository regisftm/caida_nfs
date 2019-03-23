#!/usr/bin/python2.7

import capture3
import random
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


def hashing(pkt):
	
	payload=[]
	if pkt[63] == 6:  #pacote tcp
		#print ('protocolo tcp')
		ihl = int(('0b'+ str(("{0:8b}".format(pkt[86],16)))[:4] + '00'),2)
		#print (ihl)
		#print ('protocolo = ' + str(pkt[63]))
		#print ('header length = ' + str(ihl))
		for i in xrange (ihl+74,ihl+82):
			#print ("payload tcp" + str(i))
			try: 
				payload.append(pkt[i])
			except Exception as e:
				payload.append(0)
	elif pkt[63] == 17:  #pacote udp
		for i in xrange (82,90):
			#print ("payload udp" + str(i))
			try: 
				payload.append(pkt[i])
			except Exception as e:
				payload.append(0)
	else: # other packet not udp or tcp
		#print ("neither UDP or TCP packet")
		for i in xrange(8):
			payload.append(0)

	
	#print(payload)

	hash_lst = [pkt[54],  			#version,ihl
				pkt[56],pkt[57],	#totallenght
				pkt[58],pkt[59],	#identification
				pkt[60],pkt[61], 	#flag,fragOffset
				pkt[63],        	#protocol
				pkt[66],pkt[67],pkt[68],pkt[69],	#srcAddr
				pkt[70],pkt[71],pkt[72],pkt[73]     #dstAddr
				] + payload			#payload

 	pkt_csum = checksum(hash_lst)

 	return pkt_csum


def verify_checksum(pkt):
	#calculando o checksum com os campos do pacote
	csum_list = [pkt[54], pkt[55], pkt[56], pkt[57], 
				 pkt[58], pkt[59], pkt[60], pkt[61], 
				 pkt[62], pkt[63],
				 pkt[66], pkt[67], pkt[68], pkt[69],
				 pkt[70], pkt[71], pkt[72], pkt[73]]

	calc_checksum = checksum(csum_list)

	#lendo o checksum do pacote
	csum1 = "{0:8b}".format(pkt[64],16)
	csum2 = "{0:8b}".format(pkt[65],16)
	pkt_csum = int(('0b' + str(str(int(csum1)) + str(int(csum2)).zfill(8))),2)

	#comparando os 2 checksums
	if calc_checksum == pkt_csum:
		result = "csum_ok"
		return result
	else:
		result = "csum_not_ok"
		return result

def main():

	file = open("pkt_hashed.csv","w")
	for i in xrange(1,51076):
		a = 'cur_pkt = capture3.pkt' + str(i)
		#print i
		try:
			exec(a)
			csum_result = verify_checksum(cur_pkt)
			bitmatrix = hashing(cur_pkt)
			file.write(str(i)+";"+str(bitmatrix)+";"+str(csum_result)+"\n")
		except Exception as e:
			print ("pkt%d does not exists" % i)
	file.close()

main()