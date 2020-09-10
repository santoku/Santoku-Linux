#!/usr/bin/env python

# Authors: Thomas Cannon <tcannon@viaforensics.com>
#          Seyton Bradford <sbradford@viaforensics.com>
# TAGS: Android, Device, Decryption, Crespo, Bruteforce
#
# Parses the footer from the encrypted userdata partition
# Decrypts the master key found in the footer using a supplied password
# Bruteforces the pin number using the header from the encrypted partition
# Written for Nexus S (crespo) running Android 4.0.4
# Footer is located in file userdata_footer on the efs partition
#
# --
# Revision 0.6 (Revision 0.3 shipped with Santoku Alpha 0.3)
# ------------
# Added support for more than 4-digit PINs
# Speed improvements
# ------------
# 2014/05/14 Added 4.4 support (scrypt, etc.) [Nikolay Elenkov]
# ------------
# 2015/06/29 Implemented ext4 Magic comparison [Oliver Kunz]
# ------------
# 2015/07/09  Changed length check for header file [Oliver Kunz]
#           Added more tests for decryption
# ------------
# 2020/09/10  Made script automated and added decryption [TROUNCE - HN]
#             Removed the need for seperate header or footer file
#             Swapped out M2Crypto library for pycryptodome for windows compatibility
#             Updated script for Python3
# -- 

import sys
import itertools
from struct import Struct
import scrypt
from Crypto.Cipher import AES
from binascii import hexlify
import hashlib
import struct


HASH_COUNT    = 2000
KEY_LEN_BYTES = 16
IV_LEN_BYTES  = 16
SECTOR_START  = 1

SCRYPT_ADDED_MINOR = 2
KDF_PBKDF = 1
KDF_SCRYPT = 2
KDF_SCRYPT_KEYMASTER_UNPADDED = 3
KDF_SCRYPT_KEYMASTER_BADLY_PADDED = 4
KDF_SCRYPT_KEYMASTER = 5
KDF_NAMES = dict()
KDF_NAMES[KDF_PBKDF] = "PBKDF2"
KDF_NAMES[KDF_SCRYPT] = "scrypt"
KDF_NAMES[KDF_SCRYPT_KEYMASTER_UNPADDED] =  "scrypt+keymaster (padded)"
KDF_NAMES[KDF_SCRYPT_KEYMASTER_BADLY_PADDED] = "scrypt+keymaster (badly padded)"
KDF_NAMES[KDF_SCRYPT_KEYMASTER] =  "scrypt+keymaster"

CRYPT_TYPES = ('password', 'default', 'pattern', 'PIN')

EXT4_MAGIC = "53ef"

class QcomKmKeyBlob:
    def parse(self,data):
        s = Struct('<'+'L L 512s L 512s L 16s 512s L 32s')
        (self.magic_num, self.version_num, 
         self.modulus, self.modulus_size, 
         self.pub_exp, self.pub_exp_size, 
         self.iv, 
         self.enc_priv_exp, self.enc_priv_exp_size,
         self.hmac) = s.unpack_from(data)

        self.modulus = self.modulus[0:self.modulus_size]
        self.pub_exp = self.pub_exp[0:self.pub_exp_size]
        self.enc_priv_exp = self.enc_priv_exp[0:self.enc_priv_exp_size]

    def dump(self):
        print("QCOM key blob")
        print('-------------------------')
        print("magic num    : 0x%0.4X" % self.magic_num)
        print("version num  : %u" % self.version_num)
        print("modulus      : %s... [%d]" % (self.modulus.encode("hex").upper()[0:32], self.modulus_size))
        print("pub exp      : %s" % self.pub_exp.encode("hex").upper())
        print("IV           : %s" % self.iv.encode("hex").upper())
        print("encr priv exp: %s...[%d]" % (self.enc_priv_exp.encode("hex").upper()[0:32], self.enc_priv_exp_size))
        print("HMAC         : %s" % self.hmac.encode("hex").upper())



class CryptoFooter:

    def __init__(self):
        self.kdf = KDF_PBKDF

    def unpack(self, data):
        # st(ucture taken from cryptfs.h in crespo source.
        s = Struct('<'+'L H H')
        ftrMagic, majorVersion, minorVersion = s.unpack_from(data)
        if minorVersion < SCRYPT_ADDED_MINOR:
            s = Struct('<'+'L H H L L L L L L L 64s L 48s 16s')
            (self.ftrMagic, self.majorVersion, self.minorVersion, 
            self.ftrSize, self.flags, self.keySize, self.spare1, 
            self.fsSize1, self.fsSize2, self.failedDecrypt, self.cryptoType, 
            self.spare2, self.cryptoKey, self.cryptoSalt) = s.unpack_from(data)

            self.cryptoKey = self.cryptoKey[0:self.keySize]
        elif minorVersion == SCRYPT_ADDED_MINOR:
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
        else:
            s = Struct('<'+'L H H L L L L Q L 64s L 48s 16s 2Q L B B B B Q 32s 2048s L 32s')
            (self.ftrMagic, self.majorVersion, self.minorVersion, self.ftrSize,
            self.flags, self.keySize, self.crypt_type, self.fsSize, 
            self.failedDecrypt, self.cryptoType, self.spare2, self.cryptoKey, 
            self.cryptoSalt, self.persistDataOffset1, self.persistDataOffset2, 
            self.persistDataSize, self.kdf, self.N_factor, self.r_factor, 
            self.p_factor, 
            self.encrypted_upto, 
            self.hash_first_block, 
            self.km_blob, self.km_blob_size, 
            self.scrypted_intermediate_key) = s.unpack_from(data)

            self.cryptoKey = self.cryptoKey[0:self.keySize]
            self.N = 1 << self.N_factor
            self.r = 1 << self.r_factor
            self.p = 1 << self.p_factor
            self.km_blob = self.km_blob[0:self.km_blob_size]

    def dump(self):
        print("Android FDE crypto footer")
        print('-------------------------')
        print('Magic              :', "0x%0.8X" % self.ftrMagic)
        print('Major Version      :', self.majorVersion)
        print('Minor Version      :', self.minorVersion)
        print('Footer Size        :', self.ftrSize, "bytes")
        print('Flags              :', "0x%0.8X" % self.flags)
        print('Key Size           :', self.keySize * 8, "bits")
        print('Failed Decrypts    :', self.failedDecrypt)
        print('Crypto Type        :', self.cryptoType.rstrip(b"\0"))
        print('Encrypted Key      :', "0x" + self.cryptoKey.hex().upper())
        print('Salt               :', "0x" + self.cryptoSalt.hex().upper())
        if self.minorVersion >= SCRYPT_ADDED_MINOR:
            if self.kdf in KDF_NAMES.keys():
                print('KDF                : %s' % KDF_NAMES[self.kdf])
            else:
                print('KDF                :', ("unknown (%d)" % self.kdf))
            print('N_factor           :', "%u   (N=%u)" % (self.N_factor, self.N))
            print('r_factor           :', "%u   (r=%u)" % (self.r_factor, self.r))
            print('p_factor(          :', "%u   (p=%u)" % (self.p_factor, self.p))
        if self.minorVersion >= KDF_SCRYPT_KEYMASTER_UNPADDED:
            print('crypt type         : %s' % CRYPT_TYPES[self.crypt_type])
            print('FS size            : %u' % self.fsSize)
            print('encrypted upto     : %u' % self.encrypted_upto)
            print('hash first block   : %s' % self.hash_first_block.encode("hex").upper())
            print('keymaster blob     : %s...[%d]' % (self.km_blob.encode("hex").upper()[0:32], self.km_blob_size))
            print('scrypted IK        : %s' % self.scrypted_intermediate_key.encode("hex").upper())

            print("\n")
            qb = QcomKmKeyBlob()
            qb.parse(self.km_blob)
            qb.dump()
        print('-------------------------')


def bruteforcePIN(headerData, cryptoFooter, maxdigits):
    print('[+] - Trying to Bruteforce Password')
    mes = 0

    # try all possible 4 to maxdigits digit PINs, returns value immediately when found 
    for j in itertools.product(range(10),repeat=maxdigits):
        
        # decrypt password
        passwdTry = ''.join(str(elem) for elem in j)

        # -- In case you prefer printing every 100 
        #try: 
        #   if (int(passwdTry) % 100) == 0:
        #       print 'ok'
        #       print 'Trying passwords from %d to %d' %(int(passwdTry),int(passwdTry)+100)
        #except:
        #   pass
        
        # make the decryption key from the password
        decKey = ''
        if cryptoFooter.kdf == KDF_PBKDF:
            if mes == 0:
                mes = 1
                print('[+] - Potential master encryption key is being generated by hashing (sha1) the salted password ' + str(HASH_COUNT) + ' times')
                print('[+] - This potential master encryption key is then used to decrypt the encrypted master key')
            decKey = decryptDecodePbkdf2Key(cryptoFooter, passwdTry)
        elif cryptoFooter.kdf == KDF_SCRYPT:
            if mes == 0:
                mes = 1
                print('[+] - Potential master encryption key is being generated by scrypting the password with the salt')
            decKey = decryptDecodeScryptKey(cryptoFooter, passwdTry)
        else:
            raise "Unknown KDF: " + cf.kdf
        
        # try to decrypt the frist 32 bytes of the header data (we don't need the iv)
        decData = decryptData(decKey,"",headerData)

        # has the test worked?
        if decData[16:32] == b"\0" * 16:
            print('[+] - Cracked password: ' + passwdTry) 
            #print('[+] - Master key was generated by hashing the cracked password that was salted with the value found in the footer')
            print('[+] - The master key decrypts the partition header and the data after the first 16 bytes was zeros')
            print('[+] - This indicates a correct password was found / correct master key was generated')
            return passwdTry
        if int(passwdTry) % 100 == 0:
            print('[+] - ' + 'Tested: ' + str(int(passwdTry)) + ' passwords')
            
    return None


def getCryptoData(data):
    print('[+] - Parsing Footer')
    cf = CryptoFooter()

    cf.unpack(data)
    cf.dump()

    return cf

def decryptDecodePbkdf2Key(cf,password):
    password = password.encode()
    # make the key from the passwor

    pbkdf2 = hashlib.pbkdf2_hmac('SHA1', password, cf.cryptoSalt, HASH_COUNT, KEY_LEN_BYTES+IV_LEN_BYTES)

    key = pbkdf2[:KEY_LEN_BYTES]
    iv = pbkdf2[KEY_LEN_BYTES:]

    cipher = AES.new(key, AES.MODE_CBC, iv)
    deckey = cipher.decrypt(cf.cryptoKey)
    return deckey

def decryptDecodeScryptKey(cf,password):
    derived = scrypt.hash(password, cf.cryptoSalt, cf.N, cf.r, cf.p)

    key = derived[:KEY_LEN_BYTES]
    iv = derived[KEY_LEN_BYTES:]

    # do the decrypt
    cipher = AES.new(key, AES.MODE_CBC, iv)
    deckey = cipher.decrypt(cf.cryptoKey)
    return deckey

def decryptData(decKey,essiv,data):
    essiv = essiv.encode()
    # try to decrypt the actual data 

    cipher = AES.new(decKey, AES.MODE_CBC, b'\x00' * 16)
    decdata = cipher.decrypt(data)
    return decdata


def main():
    print()
    if len(sys.argv) == 3:
        maxpin_digits = int(sys.argv[2])
    else:
        maxpin_digits = 4

    image = sys.argv[1]
    image_data = open(image, 'rb').read()
    print('[+] - Opening Disk Image')

    header = image_data[:32]
    footer = image_data[-16384:]

    print('[+] - Header is the first 32 Bytes of Disk Image')
    print('[+] - Footer is the last 0x4000 Bytes of Disk Image')

    cf = getCryptoData(footer)

    for n in range(4, maxpin_digits + 1):
            result = bruteforcePIN(header, cf, n)
            if result:
                pin = result
                break
    deckey = b''
    if cf.kdf == KDF_PBKDF:
        deckey = decryptDecodePbkdf2Key(cf, pin)
    elif cf.kdf == KDF_SCRYPT:
        deckey = decryptDecodeScryptKey(cf, pin)
    else:
        raise Exception("Unknown or unsupported KDF: " + str(cf.kdf))

    print('[+] - File Decryption can now take place using the decrypted master key')
    file = open('decrypted.bin', 'wb')
    salt = hashlib.sha256(deckey).digest()
    nob = int((len(image_data) - len(footer)) / 512)
    hasher = hashlib.sha256()
    print('[+] - Encryption mode is AES-CBC-ESSIV:SHA256 for the userdata')
    print('[+] - This mode is not standard in open source python libaries and is implemented as explained below')
    print('[+] - The decrypted master key is hashed using sha-256 and used as "essiv encryption key"')
    print('[+] - "essiv encryption key" is then used to encrypt the sector number ( represened as 16 bytes )')
    print('[+] - This encrypted sector number is used as the IV (essiv) for the decryption of each block of 512 bytes')
    print('[+] - The master key is used to decrypt the data along with the essiv to initilise the state')
    print('[+] - As each block of 512 bytes is decrypted, the ongoing forensic hash is updated with the decrypted data')
    for secnum in range(0, nob):
        if secnum % 10000 == 0:
            print('[+] - decrypting block ' + str(secnum) + ' of ' + str(nob))
        sector_number = struct.pack("<I", secnum) + b"\x00" * 12

        cipher = AES.new(salt, AES.MODE_ECB)
        essiv = cipher.encrypt(sector_number)

        cipher2 = AES.new(deckey, AES.MODE_CBC, essiv)

        decdata = cipher2.decrypt(image_data[512 * secnum: (secnum + 1) * 512])

        file.write(decdata)
        hasher.update(decdata)
    print('[+] - Decrypting block ' + str(nob) + ' of ' + str(nob))
    print('[+] - Decryption of userdata complete')
    print('[+] - Footer does not need to be decrypted and is written to the end of the decrypted data')
    file.write(footer)
    hasher.update(footer)
    print('[+] - SHA-256 of DATA (including the footer): ' + hexlify(hasher.digest()).decode())


if __name__ == '__main__':
    main()
