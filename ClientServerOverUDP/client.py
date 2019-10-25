#Jonathan Noland
#Term Project
#4/3/2018
#Client Server Programming + Security
#Client-Server Application over UDP to transport files

#Client

#import socket library & names
from socket import*
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

#Create UDP client socket
clientSocket=socket(AF_INET, SOCK_DGRAM)

#IP address of server
host='192.168.0.104'
#Port to be used
port=5500
address=(host,port)

#name of file to be sent
message1=(b"sampleJson.json.")
#name of file to be requested
message2=(b"get.txt")


#Send File: Put
#Send name of file to be transferred
clientSocket.sendto(message1,(host,port))
#Open file to be sent
messageplain=message1.decode("utf-8")
dat=bytearray(open(messageplain,"rb").read())
#Encrypt Data
data_send=xor(dat,key)
#Send file to server
clientSocket.sendto(data_send,(host,port))
#Create hash of file
hash1=createhash(messageplain)
#Send hash data to server
hash1=hash1.encode("utf-8")
clientSocket.sendto(hash1,(host,port))

#Receive File: Get
#Send File Request to server
clientSocket.sendto(message2,(host,port))
requested=message2.decode("utf-8")
#Receive File Data
data,addr=clientSocket.recvfrom(64000)
#Decode File Data 
received=xor(data,key)
#Write data to file
with open(requested, "wb") as f:
    f.write(received)
#Recieve Hash data from server for file received
data,addr=clientSocket.recvfrom(64000)
rcvhsh=data.decode("utf-8")
#Create Hash of Received File
hash2=createhash(requested)
#Compare Hash Values for Data Integrity
if rcvhsh==hash2:
    print("Hash values matched: Data Integrity Confirmed")
else:
    print("Hash values not matched: Data Integrity Unconfirmed")




