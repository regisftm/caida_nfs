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
	for i in xrange (70,78):
		try: 
			payload.append(pkt[i])
		except Exception as e:
			payload.append(0)

	hash_lst = [pkt[18],  			#version,ihl
				pkt[20],pkt[21],	#totallenght
				pkt[22],pkt[23],	#identification
				pkt[24],pkt[25], 	#flag,fragOffset
				pkt[27],        	#protocol
				pkt[30],pkt[31],pkt[32],pkt[33],	#srcAddr
				pkt[34],pkt[35],pkt[36],pkt[37]    #dstAddr
				] + payload			#payload

 	pkt_csum = checksum(hash_lst)

 	return pkt_csum


def verify_checksum(pkt):
	#calculando o checksum com os campos do pacote
	csum_list = [pkt[18], pkt[19], pkt[20], pkt[21], 
				 pkt[22], pkt[23], pkt[24], pkt[25], 
				 pkt[26], pkt[27],
				 pkt[30], pkt[31], pkt[32], pkt[33],
				 pkt[34], pkt[35], pkt[36], pkt[37]]
	calc_checksum = checksum(csum_list)

	#lendo o checksum do pacote
	csum1 = "{0:8b}".format(pkt[28],16)
	csum2 = "{0:8b}".format(pkt[29],16)
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
	for i in xrange(1,17094):
		a = 'cur_pkt = capture3.pkt' + str(i)
		print i
		exec(a)

		csum_result = verify_checksum(cur_pkt)

		bitmatrix = hashing(cur_pkt)
		file.write(str(i)+";"+str(bitmatrix)+";"+str(csum_result)+"\n")
	file.close()

main()