import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes, hmac


def MyencryptMAC(message,EncKey,HMACKey):
	backend = default_backend()
	padder = padding.PKCS7(128).padder() #set up padding
	padded_data = padder.update(message) + padder.finalize() #padding = setUP + remainder
	iv = os.urandom(16) # initialize vector
	cipher = Cipher(algorithms.AES(EncKey), modes.CBC(iv), backend=backend) # Cipher objects combine an algorithm such as AES with a mode like CBC or CTR
	encryptor = cipher.encryptor() # set up encryption block
	ct = encryptor.update(padded_data) + encryptor.finalize()#create cipher text
	h = hmac.HMAC(HMACKey, hashes.SHA256(), backend=default_backend()) #HASH Generated
	h.update(ct)#pass cypher text into hash 
	return ct,iv,h.finalize() #return cypher text, initialize vector, hash

def MyfileEncryptMAC(filepath):
    HMACKey = os.urandom(32) # generate 32byte secret key
    EncKey = os.urandom(32) #Generate encryption key
    days_file = open(filepath,'rb') #open file and read string 
    extension = filepath.split(".") # seperate the file name from extension 
    extension = extension[1] 
    with open(filepath,'rb') as binary_file: #read file in bytes
            data = binary_file.read() #Read the whole file at once
    answer = MyencryptMAC(data,EncKey,HMACKey) #pass message,key
    return answer,EncKey,HMACKey,extension #return cypher, iv, hash, encryption key, hash key


path = "./b.jpeg" #path for file
EncryInfo = MyfileEncryptMAC(path) #call file encryption


def MyDecryptMAC(EncryptionInfo): 
	ct = EncryptionInfo[0][0]#cypher text
	iv = EncryptionInfo[0][1]#initialize vector
	tag = EncryptionInfo[0][2]#hash 
	Enckey= EncryptionInfo[1]#encryption key
	HMACKey = EncryptionInfo[2]#hash key
	extension = EncryptionInfo[3]#extension
	backend = default_backend()
	cipher = Cipher(algorithms.AES(Enckey), modes.CBC(iv), backend=backend)#Setting up cypher
	h = hmac.HMAC(HMACKey, hashes.SHA256(), backend=default_backend())#Setting up hash 
	h.update(ct)#pass cypher text to hash
	print("MY FILE Verify:", h.verify(tag))#verify match
	decryptor = cipher.decryptor()#set up decryption box
	data = decryptor.update(ct) + decryptor.finalize() #decrypt
	unpadder = padding.PKCS7(128).unpadder() 
	message = unpadder.update(data) + unpadder.finalize()#pad the decryption
	return message

MyDecryptMAC(EncryInfo)

