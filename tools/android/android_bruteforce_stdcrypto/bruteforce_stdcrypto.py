#!/usr/bin/env python

# Authors: Thomas Cannon <tcannon@viaforensics.com>
# 		   Seyton Bradford <sbradford@viaforensics.com>
# TAGS: Android, Device, Decryption, Crespo, Bruteforce
#
# Parses the footer from the encrypted userdata partition
# Decrypts the master key found in the footer using a supplied password
# Bruteforces the pin number using the header from the encrypted partition 
# Written for Nexus S (crespo) running Android 4.0.4
# Footer is located in file userdata_footer on the efs partition
#
# --
# Revision 0.3 (shipped with Santoku Alpha 0.3)
# ------------
# Added support for more than 4-digit PINs
# Speed improvements
# -- 

from os import path
import sys, itertools
import time
from struct import Struct
from M2Crypto import EVP
import hashlib


HASH_COUNT    = 2000
KEY_LEN_BYTES = 16
IV_LEN_BYTES  = 16
SECTOR_START  = 1


def main(args):
	# default value 
	maxpin_digits = 4

	if len(args) < 3:
		print 'Usage: python bruteforce_stdcrypto.py [header file] [footer file] (max PIN digits)'
		print ''
		print '[] = Mandatory'
		print '() = Optional (default is 4)'
	else:
		# use inputed filenames for the two files
		footerFile    = args[2]
		headerFile    = args[1]
		try:
			if args[3] != None: 
				try:
					maxpin_digits = int(args[3])
					if maxpin_digits <= 3: 
						print 'PIN has to be >= to 4 digits - defaulting your entered value to 4'
						time.sleep(2)
						maxpin_digits = 4
				except: 
					print 'You did not entered a valid maximum number of digits to bruteforce'
					print '=> Defaulting your value to 4.'
					time.sleep(2)
					maxpin_digits = 4
			else: 
			# default value
				maxpin_digits = 4
		except:
			print 'Defaulting max PIN digits to 4'
			time.sleep(2)
			maxpin_digits = 4


		assert path.isfile(footerFile), "Footer file '%s' not found." % footerFile
		assert path.isfile(headerFile), "Header file '%s' not found." % headerFile
		fileSize = path.getsize(footerFile)
		assert (fileSize >= 16384), "Input file '%s' must be at least 16384 bytes" % footerFile
		
		for n in xrange(4, maxpin_digits+1):
			result = bruteforcePIN(headerFile, footerFile, n)
			if result: 
				print 'Found PIN!: ' + result
				break

def bruteforcePIN(headerFile, footerFile, maxdigits):
	# retrive the key and salt from the footer file
	cryptoKey,cryptoSalt = getCryptoData(footerFile)

	# load the header data for testing the password
	headerData = open(headerFile, 'rb').read(32)

	print 'Trying to Bruteforce Password... please wait'

	# try all possible 4 to maxdigits digit PINs, returns value immediately when found 
	for j in itertools.product(xrange(10),repeat=maxdigits):
		
		# decrypt password
		passwdTry = ''.join(str(elem) for elem in j)		
		print 'Trying: ' + passwdTry 

		# -- In case you prefer printing every 100 
		#try: 
		#	if (int(passwdTry) % 100) == 0:
		#		print 'ok'
		#		print 'Trying passwords from %d to %d' %(int(passwdTry),int(passwdTry)+100)
		#except:
		#	pass
		
		# make the decryption key from the password
		decKey = decryptDecodeKey(cryptoKey,cryptoSalt,passwdTry)
		
		# try to decrypt the frist 32 bytes of the header data (we don't need the iv)
		decData = decryptData(decKey,"",headerData)

		# has the test worked?
		if decData[16:32] == "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0":
			return passwdTry
			
	return None


def getCryptoData(filename):
	data = open(filename, 'rb').read()
	
	# structure taken from cryptfs.h in crespo source.
	s = Struct('<'+'L H H L L L L L L L 64s')
	ftrMagic, majorVersion, minorVersion, ftrSize, flags, keySize, spare1, fsSize1, fsSize2, failedDecrypt, cryptoType = s.unpack(data[0:100])

	cryptoSalt = data[ftrSize+keySize+32:ftrSize+keySize+32+16]
	cryptoKey = data[ftrSize:ftrSize+keySize]

	print 'Footer File    :', filename;
	print 'Magic          :', "0x%0.8X" % ftrMagic
	print 'Major Version  :', majorVersion
	print 'Minor Version  :', minorVersion
	print 'Footer Size    :', ftrSize, "bytes"
	print 'Flags          :', "0x%0.8X" % flags
	print 'Key Size       :', keySize * 8, "bits"
	print 'Failed Decrypts:', failedDecrypt
	print 'Crypto Type    :', cryptoType.rstrip("\0")
	print 'Encrypted Key  :', "0x" + cryptoKey.encode("hex").upper()
	print 'Salt           :', "0x" + cryptoSalt.encode("hex").upper()
	print '----------------'

	return cryptoKey,cryptoSalt

def decryptDecodeKey(cryptoKey,cryptoSalt,password):
	# make the key from the password
	pbkdf2 = EVP.pbkdf2(password, cryptoSalt, iter=HASH_COUNT, keylen=KEY_LEN_BYTES+IV_LEN_BYTES)

	key = pbkdf2[:KEY_LEN_BYTES]
	iv = pbkdf2[KEY_LEN_BYTES:]

	# do the decrypt
	cipher = EVP.Cipher(alg='aes_128_cbc', key=key, iv=iv, op=0) # 0 is DEC
	cipher.set_padding(padding=0)
	decKey = cipher.update(cryptoKey)
	decKey = decKey + cipher.final()
	
	return decKey

def decryptData(decKey,essiv,data):
	# try to decrypt the actual data 
	cipher = EVP.Cipher(alg='aes_128_cbc', key=decKey, iv=essiv, op=0) # 0 is DEC
	cipher.set_padding(padding=0)
	decData = cipher.update(data)
	decData = decData + cipher.final()
	return decData

if __name__ == "__main__": 
    main(sys.argv)		
