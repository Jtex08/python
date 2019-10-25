#Jonathan Noland
#Term Project
#4/3/2018
#Client Server Programming + Security
#Client-Server Application over UDP to transport files

#Server

#import socket library & names
from socket import *
#import hash libray
import hashlib


#Create function for hashing data sent or received
def createhash(data):
    #Block size in bytes 
    blk=65536
    #Create variable using SHA-512
    hashfile=hashlib.sha512()  
    #Read file binary. Hash data and add to hashfile variable
    with open(data,'rb') as afile:
        buf = afile.read(blk)
        while len(buf) > 0:
            hashfile.update(buf)
            buf = afile.read(blk)
        #Return completed hashvalue
        hshval=(hashfile.hexdigest())
        return(hshval)

#Create function for symmetric algorithm.                
def xor(data, key):
    #xor data with key and return as bytearray
    l = len(key)
    return bytearray((
        (data[i] ^ key[i % l]) for i in range(0,len(data))
    ))

#Key to be used by server and client
key = bytearray([0x3c,0x4b,0x3a,0x55,0xff,0xca])

#Create UDP server socket
serverSocket=socket(AF_INET, SOCK_DGRAM)
#IP address of server aka IP address of local machine
host='192.168.0.104'
#Port to be used for socket
port=5500
#Bind server socket to host, and port
serverSocket.bind((host, port))
address=(host,port)



while True:
    #Receive file from client
    data,caddr = serverSocket.recvfrom(64000)
    #Decode binary data of file name
    recv1=data.decode("utf-8")
    #Receive file data
    data,caddr = serverSocket.recvfrom(64000)
    #Decrypt data
    received=xor(data,key)
    #Write decrypted to file 
    with open(recv1, "wb") as f:
                f.write(received)
    #Receive hash data from Client
    data,caddr = serverSocket.recvfrom(64000)
    #Decode binary data of hash
    rcvhsh=data.decode("utf-8")
    #Create hash of received file
    hash1=createhash(recv1)
    #Compare hash values to check for data integrity
    if rcvhsh==hash1:
        print("Hash values matched: Data Integrity Confirmed")
    else:
        print("Hash values not matched: Data Integrity Unconfirmed")

    #Receive File Send Request
    data,caddr = serverSocket.recvfrom(64000)
    #Prep File to Send
    message1=data.decode("utf-8")
    #Read desired file
    dat=bytearray(open(message1,"rb").read())
    #Encrypt Data
    data_send=xor(dat,key)
    #send requested file
    serverSocket.sendto(data_send,caddr)
    #create Hash of file sent
    hash2=createhash(message1)
    hash2=hash2.encode("utf-8")
    #send Hash
    serverSocket.sendto(hash2,caddr)
    
