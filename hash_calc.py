#!/usr/bin/python2.7


import capture2
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
		#print i

		try: 
			payload.append(pkt[i])
		except Exception as e:
			payload.append(0)
			#return
	#print payload


	hash_lst = [pkt[18],  		#version,ihl
				pkt[20],pkt[21],	#totallenght
				pkt[22],pkt[23],	#identification
				pkt[24],pkt[25], 	#flag,fragOffset
				pkt[27],        	#protocol
				pkt[30],pkt[31],pkt[32],pkt[33],	#srcAddr
				pkt[34],pkt[35],pkt[36],pkt[37]    #dstAddr
				] + payload			#payload

	#print hash_lst

 	pkt_csum = checksum(hash_lst)

 	#print ('pkt_csum = ' + str(pkt_csum))

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
		#print ('CSUM OK')
		result = "csum_ok"
		return result
	else:
		#print ('CSUM NOT OK!')
		result = "csum_not_ok"
		return result




def main():

	# f1st = "{0:8b}".format(capture.pkt1[0],16)
	# f3rd = "{0:8b}".format(capture.pkt1[2],16)
	# f4th = "{0:8b}".format(capture.pkt1[3],16)
	# f5th = "{0:8b}".format(capture.pkt1[4],16)
	# f6th = "{0:8b}".format(capture.pkt1[5],16)
	# f7th = "{0:8b}".format(capture.pkt1[6],16)
	# f8th = "{0:8b}".format(capture.pkt1[7],16)

	# print (capture.pkt1)

	# print ("version: " + str(f1st)[:4])
	# print ("ihl: " + str(f1st)[-4:])
	# print ("total lenght: " + str(f3rd+f4th))
	# print ("identification: " + str(f5th+f6th))
	# print ("flags: " + str(f5th)[:3])
	# print ("flags: " + str(int(str(f5th)[-5:]))+f6th)

	# list_csum = [capture.pkt1[0], 
	# 					   capture.pkt1[1] , 
	# 					   capture.pkt1[2] ,
	# 					   capture.pkt1[3] ,
	# 					   capture.pkt1[4] ,
	# 					   capture.pkt1[5] ,
	# 					   capture.pkt1[6] ,
	# 					   capture.pkt1[7] ,
	# 					   capture.pkt1[8] ,
	# 					   capture.pkt1[9] ,
	# 					   capture.pkt1[12],
	# 					   capture.pkt1[13],
	# 					   capture.pkt1[14],
	# 					   capture.pkt1[15],
	# 					   capture.pkt1[16],
	# 					   capture.pkt1[17],
	# 					   capture.pkt1[18],
	# 					   capture.pkt1[19]]

	# pktchecksum = checksum(list_csum)
	# print (pktchecksum)

	# hashing(capture.pkt1)
	file = open("pkt_hashed.csv","w")
	for i in xrange(1,10):
		a = 'cur_pkt = capture2.pkt' + str(i)
		#print a
		exec(a)
		#print b

		csum_result = verify_checksum(cur_pkt)
		#print (csum_result)


		# list_csum = [b[18], 
		# 			 b[19], 
		# 			 b[20],
		# 			 b[21],
		# 			 b[22],
		# 			 b[23],
		# 			 b[24],
		# 			 b[25],
		# 			 b[26],
		# 			 b[27],
		# 			 b[30],
		# 			 b[31],
		# 			 b[32],
		# 			 b[33],
		# 			 b[34],
		# 			 b[35],
		# 			 b[36],
		# 			 b[37]]

		# pktchecksum = checksum(list_csum)
		# print (pktchecksum)
		
		# csum1 = "{0:8b}".format(b[28],16)
		# csum2 = "{0:8b}".format(b[29],16)
		# csumsum = int(csum1 + csum2)
		# csum_tot = '0b' + str(csumsum)


	

		# print(csum1)
		# print(csum2)
		# print(csum_tot)
		# print(int(csum_tot,2))

		bitmatrix = hashing(cur_pkt)
		#print (bitmatrix)
		file.write(str(i)+";"+str(csum_result)+";"+str(bitmatrix)+"\n")




main()