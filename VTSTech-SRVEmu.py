#BACKUP-2021-02-24 6:14:51 AM
import codecs, os, sys, socket, struct, select, time, string, random, hashlib, array, math
from pythonping import ping
from _thread import *

GameSocket = socket.socket()
BuddySocket = socket.socket()
LISTENERSocket = socket.socket()

TOTALARGS = len(sys.argv)
BUILD="0.1-ALPHA R0.6"
SERVER_IP = '192.168.0.228'
SERVER_IP_BIN = b'ADDR=192.168.0.228'
SERVER_PORT_BIN= b'PORT=10901'
PORT_NFSU_PS2 = 10900 #ps2nfs04.ea.com:10900
PORT_BO3U_PS2 = 21800	#ps2burnout05.ea.com:21800
PORT_BO3R_PS2 = 21840 #ps2lobby02.beta.ea.com:21840
PORT_BOP_PS3 = 21870  #ps3burnout08.ea.com:21870
PORT_BOP_PC = 21841  #ps3burnout08.ea.com:21870
LISTENER = 10901
BUDDY_PORT = 10899
THREADCOUNT = 0
EMU_MODE = "nfsu"
SKEYREPLY = b''
SKEYSENT=0
authsent=0
SKEY = ''
z=0
a=''

ping_cnt=0
ping_sent=0
ping_start=time.time()
ping_time=time.time()
curr_time=time.time()

msgType=b''
msgSize=b''
clientNAME=''
clientVERS=''
clientMAC=''
clientPERS=''
clientLAST=''
clientPLAST=''
clientMAIL=''
clientADDR=''
clientMADDR=''
clientBORN=''
clientPASS=''
clientUSER=''

pad = codecs.decode('00000000000000','hex_codec')
pad2 = codecs.decode('00000038','hex_codec')
oddByte = codecs.decode('00','hex_codec')
x0A = codecs.decode('0A','hex_codec')
x00 = codecs.decode('00','hex_codec')
reply=''
SKEY="$5075626c6963204b6579"

def usage():
	print("Usage:")
	print("-nfsu Run in Need for Speed Underground Mode (PS2)")
	print("-bo3r Run in Burnout 3 Takedown Review Copy Mode (PS2)")
	print("-bo3u Run in Burnout 3 Takedown Retail Copy Mode (PS2)")
	print("-bop3 Run in Burnout Paradise Mode (PS3)")
	print("-bopc Run in Burnout Paradise Mode (PC)")
	print("-p 12345 Run in Custom Game Mode on this TCP Port")
	quit()
	
def bind():
	global GameSocket, BuddySocket, LISTENERSocket, SERVER_IP, PORT_NFSU_PS2, PORT_BO3U_PS2, PORT_BO3R_PS2, PORT_BO3P_PS2, PORT_BOP_PS3, TOTALARGS
	for x in range(0,TOTALARGS,1):
		if (TOTALARGS >= 4):	
			print("Too many arguments! Check command line.")
			usage()
		elif (TOTALARGS==1):
			usage()
		elif (sys.argv[x] == "-nfsu"):
			EMU_MODE = "nfsu"
			GameSocket.bind((SERVER_IP, PORT_NFSU_PS2))
			print("Now running in Need for Speed: Underground Mode\n")
		elif (sys.argv[x] == "-bo3r"):
			EMU_MODE = "bo3r"
			print("IP: "+SERVER_IP+" Port: "+str(PORT_BO3U_PS2))
			GameSocket.bind((SERVER_IP, PORT_BO3R_PS2))
			print("Now running in Burnout 3 Review Mode (PS2)\n")
		elif (sys.argv[x] == "-bo3u"):
			EMU_MODE = "bo3u"
			GameSocket.bind((SERVER_IP, PORT_BO3U_PS2))
			print("Now running in Burnout 3 Retail Mode (PS2)\n")
		elif (sys.argv[x] == "-bop3"):
			EMU_MODE = "bop"
			GameSocket.bind((SERVER_IP, PORT_BOP_PS3))
			print("Now running in Burnout Paradise Mode (PS3)\n")   
		elif (sys.argv[x] == "-bopc"):
			EMU_MODE = "bop"
			GameSocket.bind((SERVER_IP, PORT_BOP_PC))
			print("Now running in Burnout Paradise Mode (PC)\n")   
		elif (sys.argv[x] == "-p"):
			EMU_MODE = "custom"
			GameSocket.bind((SERVER_IP, int(sys.argv[x+1])))
			print("Now running in Custom Game Mode\n")   
	LISTENERSocket.bind((SERVER_IP, LISTENER))
	BuddySocket.bind((SERVER_IP, BUDDY_PORT))
	LISTENERSocket.listen(1)
	GameSocket.listen(1)
	BuddySocket.listen(1)
	print("Bind complete.\n")

print("VTSTech-SRVEmu v"+BUILD+"\nGitHub: https://github.com/Veritas83/VTSTech-SRVEmu\nContributors: No23\n")
bind()
print('Waiting for connections.. ')
reply=b''

def parse_data(data):
	tmp = data.split(codecs.decode('0A','hex_codec'))
	global clientALTS, clientNAME, clientVERS, clientMAC, clientPERS, clientBORN, clientMAIL, clientSKU, clientDEFPER, clientLAST, clientPLAST, clientMADDR, clientUSER
	global pad,pad2,x00,x0A,oddByte,reply,msgType,msgSize

	for x in range(0,len(tmp)):
		#print("DEBUG: "+str(x))
		if (tmp[x].decode('latin1')[:3] == "MID") | (tmp[x].decode('latin1')[:3] == "MAC"):
			clientMAC = tmp[x].decode('latin1')[4:]
		elif (tmp[x].decode('latin1')[:3] == "SKU"):
			clientSKU = tmp[x].decode('latin1')[4:]
		elif (tmp[x].decode('latin1')[:4] == "ALTS"):
			clientALTS = tmp[x].decode('latin1')[5:]	
		elif (tmp[x].decode('latin1')[:4] == "BORN"):
			clientBORN = tmp[x].decode('latin1')[5:]
		elif (tmp[x].decode('latin1')[:4] == "SLUS"):
			clientSLUS = tmp[x].decode('latin1')[5:]				
		elif (tmp[x].decode('latin1')[:4] == "VERS"):
			clientVERS = tmp[x].decode('latin1')[5:]
		elif (tmp[x].decode('latin1')[:4] == "NAME"):
			clientNAME = tmp[x].decode('latin1')[5:]
		elif (tmp[x].decode('latin1')[:4] == "PASS"):
			clientPASS = tmp[x].decode('latin1')[5:]	
		elif (tmp[x].decode('latin1')[:4] == "PERS"):
			clientPERS = tmp[x].decode('latin1')[5:]	
		elif (tmp[x].decode('latin1')[:4] == "MAIL"):
			clientMAIL = tmp[x].decode('latin1')[5:]
		elif (tmp[x].decode('latin1')[:4] == "LAST"):
			clientLAST = tmp[x].decode('latin1')[5:]
		elif (tmp[x].decode('latin1')[:5] == "PLAST"):
			clientPLAST = tmp[x].decode('latin1')[6:]
		elif (tmp[x].decode('latin1')[:5] == "MADDR"):
			clientMADDR = tmp[x].decode('latin1')[6:]
		elif (tmp[x].decode('latin1')[:6] == "DEFPER"):
			clientDEFPER = tmp[x].decode('latin1')[7:]
		elif (tmp[x].decode('latin1')[:6] == "SDKVER"):
			clientSDKVER = tmp[x].decode('latin1')[7:]
		elif (tmp[x].decode('latin1')[:9] == "PERSONAS"):
			clientPERS = tmp[x].decode('latin1')[10:]				

#Thx No23
def create_packet(cmd, subcmd, payload):
    payload += '\0'
    size = len(payload)
    return struct.pack(">4s4sL%ds" % size, bytearray(cmd, 'ascii'), bytearray(subcmd, 'ascii'), size + 12, bytearray(payload, 'ascii'))
#Thx No23
def cmd_news(payload):
    print("News Payload: "+str(payload))
    if (payload == "NAME=7") | (payload == "BP"):
	    p = 'NEWS_URL=http://www.vts-ps2.org/test.txt\n'
	    p+= 'BUDDY_SERVER=192.168.0.228\n'
	    p+= 'BUDDY_PORT='+str(BUDDY_PORT)+'\n'
	    packet = create_packet('news', 'new7', p)
	    #payload=''
	    if (clientVERS =='BURNOUT5/ISLAND'):
	    	packet = create_packet('news', 'new8', p)
	    else:
	    	packet = create_packet('news', 'new1', p)
    return packet
        
def reply_skey():
	oddByte = codecs.decode('99','hex_codec')
	replyTmp=b'skey'+pad
	#skeyStr="SKEY="+SKEY+str(random.randint(1000,9999))+"f570e6"+str(random.randint(10,99))
	#skeyStr="PLATFORM=PS2"
	#reply=skeyStr.encode('ascii')+x0A
	skeyStr="SKEY=$37940faf2a8d1381a3b7d0d2f570e6a7"
	reply=skeyStr.encode('ascii')+codecs.decode('0A00','hex_codec') #repeat me 0A6E6577736E6577370000000d00
	oddByte=len(codecs.decode(replyTmp+reply,'latin1'))+1
	#oddByte=51
	oddByte = codecs.decode('{0:x}'.format(int(oddByte)),'hex_codec')
	reply=replyTmp+oddByte+reply
	SKEYSENT=1
	print("Debug: skey sent")
	return reply
	
def reply_acct(data):
	tmp = data[11:].split(codecs.decode('0A','hex_codec'))
	global clientALTS, clientNAME, clientVERS, clientMAC, clientPERS, clientBORN, clientMAIL, clientSKU, clientDEFPER, clientLAST, clientPLAST, clientMADDR, clientUSER
	global pad,pad2,x00,x0A,oddByte,reply,msgType,msgSize
	reply=b''
	MD5=hashlib.md5()
	MD5.update(clientPASS.encode('ascii'))
	db = open("acct.db","a+")
	if sys.getsizeof(db)>1:
		line = db.readlines()
		for x in list(line):
			clientUSER = x.split("#")[0]
			if (clientNAME == clientUSER):
				reply=b'authimst'#if account exists, cannot create
				return reply
			print("DEBUG: "+clientUSER)
		clientUSER = x.split("#")[0]
		clientMAIL = x.split("#")[2]
		acctStr="TOS=1"
		reply=acctStr.encode('ascii')+x0A
		acctStr="NAME="+clientNAME.lower()
		reply+=acctStr.encode('ascii')+x0A
		acctStr="AGE=21"
		reply+=acctStr.encode('ascii')+x0A   
		acctStr="PERSONAS="+clientNAME.lower()		
		reply+=acctStr.encode('ascii')+x0A
		clientLAST=time.strftime("%Y.%m.%d %I:%M:%S",time.localtime())
		acctStr="SINCE="+clientLAST
		reply+=acctStr.encode('ascii')+x0A
		acctStr="LAST="+clientLAST
		reply+=acctStr.encode('ascii')+x0A+x00
		db.write(clientNAME+"#"+clientBORN+"#"+clientMAIL+"#"+MD5.hexdigest()+"#"+clientPERS+"#"+clientLAST)
		db.close
		return reply			
	else:
		acctStr="TOS=1"+x0A
		reply=acctStr.encode('ascii')+x0A
		acctStr="NAME="+clientNAME.lower()
		reply+=acctStr.encode('ascii')+x0A
		acctStr="AGE=21"
		reply+=acctStr.encode('ascii')+x0A   
		acctStr="PERSONAS="+clientNAME.lower()		
		reply+=acctStr.encode('ascii')+x0A
		acctStr="SINCE="+time.strftime("%Y.%m.%d-%I:%M:%S",time.localtime())
		reply+=authStr.encode('ascii')+x0A        	
		acctStr="LAST="+time.strftime("%Y.%m.%d-%I:%M:%S",time.localtime())			
		reply+=codecs.decode('00','hex_codec')
		db.write(clientNAME+"#"+clientBORN+"#"+clientMAIL+"#"+MD5.hexdigest()+"#"+clientPERS+"#"+clientLAST)
		db.close
		return reply		

def reply_auth(data):
	tmp = data[11:].split(codecs.decode('0A','hex_codec'))
	global clientALTS, clientNAME, clientVERS, clientMAC, clientPERS, clientBORN, clientMAIL, clientSKU, clientDEFPER, clientLAST, clientPLAST, clientMADDR, clientUSER
	global pad,pad2,x00,x0A,oddByte,reply,msgType,msgSize,authsent
	reply=b''

	if (clientVERS == 'BURNOUT5/ISLAND'): #Burnout Paradise
		clientNAME = clientMADDR.split("$")
		#authStr="TOS=1"
		#reply=authStr.encode('ascii')+x0A
		authStr="NAME=VTSTech"
		reply=authStr.encode('ascii')+x0A
		authStr="MAIL=nospam@vts-tech.org"
		reply+=authStr.encode('ascii')+x0A
		authStr="PERSONAS=VTSTech"
		reply+=authStr.encode('ascii')+x0A
		authStr="BORN=19800325"
		reply+=authStr.encode('ascii')+x0A   
		authStr="GEND=M"
		reply+=authStr.encode('ascii')+x0A        	
		authStr="FROM=US"
		reply+=authStr.encode('ascii')+x0A        	
		authStr="LANG=en"
		reply+=authStr.encode('ascii')+x0A
		authStr="SPAM=NN"
		reply+=authStr.encode('ascii')+x0A        	
		authStr="SINCE="+time.strftime("%Y.%m.%d-%I:%M:%S",time.localtime())
		reply+=authStr.encode('ascii')+x0A       	
		authStr="LAST="+time.strftime("%Y.%m.%d-%I:%M:%S",time.localtime())
		reply+=authStr.encode('ascii')+x0A
		authStr="ADDR=24.141.39.62"
		reply+=authStr.encode('ascii')+x0A
		authStr="_LUID=$000000000b32588d"
		reply+=authStr.encode('ascii')
		#authStr="DEFPER=1"
		#reply+=authStr.encode('ascii')+x0A        			
		reply+=codecs.decode('0A00','hex_codec')
		print("AUTHSENT: ",authsent)
		if authsent >=3:
			reply=b''
		return reply
			
	if (clientVERS == '"ps2/1.1001-Oct 15 2003"'): #NFSU
		authStr="TOS=1"
		reply=authStr.encode('ascii')+x0A
		authStr="NAME="+clientNAME.lower()
		reply+=authStr.encode('ascii')+x0A
		authStr="BORN=19800325"
		reply+=authStr.encode('ascii')+x0A        	
		authStr="GEND=M"
		reply+=authStr.encode('ascii')+x0A        	
		authStr="FROM=US"
		reply+=authStr.encode('ascii')+x0A        	
		authStr="LANG=en"
		reply+=authStr.encode('ascii')+x0A
		authStr="SPAM=NN"
		reply+=authStr.encode('ascii')+x0A        	
		authStr="PERSONAS="+clientNAME.lower()
		reply+=authStr.encode('ascii')+x0A        	
		authStr="DEFPER=1"
		reply+=authStr.encode('ascii')+x0A        			
		authStr="SINCE="+time.strftime("%Y.%m.%d-%I:%M:%S",time.localtime())
		reply+=authStr.encode('ascii')+x0A        	
		authStr="LAST=2003"+time.strftime(".%m.%d %I:%M:%S",time.localtime())
		reply+=authStr.encode('ascii')        	
		reply+=codecs.decode('0A00','hex_codec')				
		return reply

	authStr="TOS=1"
	reply=authStr.encode('ascii')+x0A
	authStr="NAME="+clientNAME.lower()
	reply+=authStr.encode('ascii')+x0A
	authStr="MAIL="+clientMAIL
	reply+=authStr.encode('ascii')+x0A
	authStr="PERSONAS="+clientNAME.lower()
	reply+=authStr.encode('ascii')+x0A
	authStr="BORN=19800325"
	reply+=authStr.encode('ascii')+x0A   
	authStr="GEND=M"
	reply+=authStr.encode('ascii')+x0A        	
	authStr="FROM=US"
	reply+=authStr.encode('ascii')+x0A        	
	authStr="LANG=en"
	reply+=authStr.encode('ascii')+x0A
	authStr="SPAM=NN"
	reply+=authStr.encode('ascii')+x0A        	
	authStr="SINCE="+time.strftime("%Y.%m.%d-%I:%M:%S",time.localtime())
	reply+=authStr.encode('ascii')+x0A       	
	authStr="LAST="+time.strftime("%Y.%m.%d-%I:%M:%S",time.localtime())
	#reply+=authStr.encode('ascii')+x0A
	#authStr="ADDR=24.143.43.66"
	reply+=authStr.encode('ascii')
	#authStr="_LUID=$000000000b32588d"
	#authStr="DEFPER=1"
	#reply+=authStr.encode('ascii')+x0A        			
	reply+=codecs.decode('0A00','hex_codec')
	print("AUTHSENT: ",authsent)
	if authsent >=3:
		reply=b''
	return reply		

def reply_cper(data):
	tmp = data[11:].split(codecs.decode('0A','hex_codec'))
	global clientALTS, clientNAME, clientVERS, clientMAC, clientPERS, clientBORN, clientMAIL, clientSKU, clientDEFPER, clientLAST, clientPLAST, clientMADDR, clientUSER
	global pad,pad2,x00,x0A,oddByte,reply,msgType,msgSize,authsent
	reply=b''
	cperStr="PERS="+clientPERS
	reply=cperStr.encode('ascii')+x0A
	cperStr="ALTS="+clientALTS
	reply+=cperStr.encode('ascii')+x0A
	reply+=codecs.decode('00','hex_codec')
	return reply
	
def reply_rom():
	global clientALTS, clientNAME, clientVERS, clientMAC, clientPERS, clientBORN, clientMAIL, clientSKU, clientDEFPER, clientLAST, clientPLAST, clientMADDR, clientUSER
	global pad,pad2,x00,x0A,oddByte,reply,msgType,msgSize	
	oddByte = codecs.decode('00','hex_codec')          
	replyTmp=b'+rom'+pad
	romStr="TI=1001"
	reply=romStr.encode('ascii')+x0A
	romStr="N=room"
	reply+=romStr.encode('ascii')+x0A
	romStr="H=vtstech"
	reply+=romStr.encode('ascii')+x0A
	romStr="D=burnout 3 revival"
	reply+=romStr.encode('ascii')+x0A
	romStr="F=CK"
	reply+=romStr.encode('ascii')+x0A
	romStr="A=192.168.0.222"
	reply+=romStr.encode('ascii')+x0A
	romStr="T=0"
	reply+=romStr.encode('ascii')+x0A
	romStr="L=5"
	reply+=romStr.encode('ascii')+x0A
	romStr="P=0"
	reply+=romStr.encode('ascii')+x0A						
	reply+=romStr.encode('ascii')+codecs.decode('0A00','hex_codec')
	oddByte=len(codecs.decode(reply,'latin1'))+12
	oddByte = codecs.decode('{0:x}'.format(int(oddByte)),'hex_codec')
	reply=replyTmp+oddByte+reply
	print("REPLY: "+reply.decode('latin1'))
	if (clientVERS == "BURNOUT5/ISLAND"):
		reply=b''
	return reply
	
def reply_who():
	global pad,pad2,x00,x0A,oddByte,reply,msgType,msgSize	
	oddByte = codecs.decode('00','hex_codec')          
	replyTmp=b'+who'+pad
	uatrStr="M=VTSTech"
	reply=uatrStr.encode('ascii')+x0A
	uatrStr="N=VTSTech"
	reply+=uatrStr.encode('ascii')+x0A
	uatrStr="MA="+clientMAC
	reply+=uatrStr.encode('ascii')+x0A
	uatrStr="A=24.141.39.62"
	reply+=uatrStr.encode('ascii')+x0A
	uatrStr="LA=192.168.0.222"
	reply+=uatrStr.encode('ascii')+x0A
	uatrStr="G=0"
	reply+=uatrStr.encode('ascii')+x0A
	uatrStr="HW=0"
	reply+=uatrStr.encode('ascii')+x0A
	uatrStr="I=71615"
	reply+=uatrStr.encode('ascii')+x0A
	uatrStr="LO=enUS"
	reply+=uatrStr.encode('ascii')+x0A
	uatrStr="LV=1049601"
	reply+=uatrStr.encode('ascii')+x0A        	
	uatrStr="MD=0"
	reply+=uatrStr.encode('ascii')+x0A        	
	uatrStr="PRES="
	reply+=uatrStr.encode('ascii')+x0A        	
	uatrStr="RP=0"
	reply+=uatrStr.encode('ascii')+x0A        	
	uatrStr="S="
	reply+=uatrStr.encode('ascii')+x0A        	
	uatrStr="X="        	
	reply+=uatrStr.encode('ascii')+x0A        	        	        	
	uatrStr="P=1"
	reply+=uatrStr.encode('ascii')+codecs.decode('0A00','hex_codec')
	oddByte=len(codecs.decode(reply,'latin1'))+12
	oddByte = codecs.decode('{0:x}'.format(int(oddByte)),'hex_codec')
	reply=replyTmp+oddByte+reply
	print("REPLY: "+reply.decode('latin1'))
	return reply

def reply_ping(data):
	global clientALTS, clientNAME, clientVERS, clientMAC, clientPERS, clientBORN, clientMAIL, clientSKU, clientDEFPER, clientLAST, clientPLAST, clientMADDR, clientUSER
	global SKEYREPLY, SKEYSENT, z, ping_cnt, ping_start, curr_time, ping_time, msgType, msgSize, ping_sent, pad
	print("Ping Recv: "+str(ping_cnt)+" Ping Sent: "+str(ping_sent))
	oddByte = codecs.decode('00','hex_codec')          
	replyTmp = b'~png'+pad
	reply = b'REF'+bytes(time.strftime("%Y.%m.%d-%I:%M:%S",time.localtime()),'ascii')+b'\n'
	reply += b'TIME=2\n'+x00
	oddByte=len(codecs.decode(reply,'latin1'))+12
	oddByte = codecs.decode('{0:x}'.format(int(oddByte)),'hex_codec')
	reply=replyTmp+oddByte+reply
	if (ping_sent>=1):
		ping_sent+=1
	else:
		ping_sent=1
	msgType=b''
	return reply
	
def build_reply(data):
        global SKEYREPLY, SKEY
        global clientALTS, clientNAME, clientVERS, clientMAC, clientPERS, clientBORN, clientMAIL, clientSKU, clientDEFPER, clientLAST, clientPLAST, clientMADDR, clientUSER
        global pad,pad2,x00,x0A,oddByte,reply,msgType,msgSize
        global ping_cnt,ping_start,curr_time,ping_time,ping_sent,authsent
        reply=b''
        if (msgType == codecs.decode('801C0100','hex_codec')):
        	print("DEBUG: enc in")
        	reply = codecs.decode('83DA04000A00','hex_codec')
        if (msgType == b'@dir'):
	        tmp = data.split(codecs.decode('0A','hex_codec'))
	        clientVERS = tmp[0].decode('latin1')[6:]
	        if (clientVERS == "nfs-ps2-2003"):
	        	clientVersion = tmp[1].decode('latin1')[6:-1]
	        	clientSLUS = tmp[4].decode('latin1')[5:]
	       	elif (clientVERS == "FLM/A1"):
	       		clientVersion = tmp[1].decode('latin1')[4:]
	       		clientSLUS = tmp[2].decode('latin1')[5:]
	       	elif (clientVERS == "BURNOUT5/ISLAND"):
		        clientSLUS = tmp[2].decode('latin1')[5:]
	        
	       	sessStr="SESS="+str(random.randint(1000,9999))+str(random.randint(1000,9999))+str(random.randint(10,99))
	       	maskStr="MASK="+str(random.randint(1000,9999))+"f3f70ecb1757cd7001b9a7a"+str(random.randint(1000,9999))	        
	       	replyTmp=msgType+pad
	       	reply=SERVER_IP_BIN+x0A+SERVER_PORT_BIN+x0A
	       	reply+=bytes(sessStr.encode("ascii"))+x0A+bytes(maskStr.encode("ascii"))+x0A+x00
	       	oddByte=len(codecs.decode(reply+replyTmp,'latin1'))+1
	       	oddByte = codecs.decode('{0:x}'.format(int(oddByte)),'hex_codec')
	       	reply=replyTmp+oddByte+SERVER_IP_BIN+x0A+SERVER_PORT_BIN+x0A
	       	reply+=bytes(sessStr.encode("ascii"))+x0A+bytes(maskStr.encode("ascii"))+x0A+x00      	
        	print("REPLY: "+reply.decode('latin1'))
        if (msgType == b'skey'):
        	tmp = data.split(codecs.decode('0A','hex_codec'))
        	SKEY = tmp[0].decode('latin1')[5:]
        	print("Client sKey: "+SKEY)       	     	
        	reply = reply_skey()
        if (msgType == b'fget'):
        	reply = reply_who()
        	print("REPLY: "+reply.decode('latin1'))      	
        if (msgType == b'sele'):
        	parse_data(data)
        if ((msgType == b'auth')):
        	authsent=authsent+1					
        	replyTmp=msgType+pad
        	parse_data(data)
        	reply = reply_auth(data)
        	if len(reply) > 1:
        		oddByte=len(codecs.decode(reply+replyTmp,'latin1'))+1
        		oddByte = codecs.decode('{0:x}'.format(int(oddByte)),'hex_codec')
        		reply=replyTmp+oddByte+reply
        		print("REPLY: "+reply.decode('latin1'))
        if (msgType == b'acct'):
        	replyTmp=b'acct'+pad
        	parse_data(data)
        	reply = reply_acct(data)
        	oddByte=len(codecs.decode(reply+replyTmp,'latin1'))+1
        	oddByte = codecs.decode('{0:x}'.format(int(oddByte)),'hex_codec')
        	reply=replyTmp+oddByte+reply
        	print("REPLY: "+reply.decode('latin1'))
        if (msgType == b'pers'):
        	parse_data(data)
        	oddByte = codecs.decode('00','hex_codec')
        	replyTmp=b'pers'+pad
        	persStr="PERS="+clientNAME.lower()
        	reply=persStr.encode('ascii')+x0A
        	persStr="LKEY=3fcf27540c92935b0a66fd3b0000283c"       	
        	reply+=persStr.encode('ascii')+codecs.decode('0A00','hex_codec')
        	oddByte=len(codecs.decode(replyTmp+reply,'latin1'))+1
        	oddByte = codecs.decode('{0:x}'.format(int(oddByte)),'hex_codec')
        	reply=replyTmp+oddByte+reply
        	print("REPLY: "+reply.decode('latin1'))	
        if (msgType == b'sviw'):
        	oddByte = codecs.decode('00','hex_codec')
        	replyTmp=b'sviw'+pad        	
        	sviwStr="N=5"
        	reply=sviwStr.encode('ascii')+x0A
        	sviwStr="NAMES=0,3,4,5,6"
        	reply+=sviwStr.encode('ascii')+x0A
        	sviwStr="DESCS=1,1,1,1,1"
        	reply+=sviwStr.encode('ascii')+x0A
        	sviwStr="PARAMS=2,2,2,2,2"
        	reply+=sviwStr.encode('ascii')+codecs.decode('0A00','hex_codec')
        	oddByte=len(codecs.decode(reply,'latin1'))+12
        	oddByte = codecs.decode('{0:x}'.format(int(oddByte)),'hex_codec')
        	reply=replyTmp+oddByte+reply
        	print("REPLY: "+reply.decode('latin1'))
        if (msgType == b'uatr'):
        	time.sleep(1)
        	reply = reply_who()
        	print("REPLY: "+reply.decode('latin1'))
        	time.sleep(1)
        if (msgType == b'cper'):
        	parse_data(data)
        	replyTmp=b'cper'+pad
        	reply = reply_cper(data)
        	oddByte=len(codecs.decode(reply,'latin1'))+12
        	oddByte = codecs.decode('{0:x}'.format(int(oddByte)),'hex_codec')
        	reply=replyTmp+oddByte+reply
        	print("REPLY: "+reply.decode('latin1'))
        	time.sleep(1)
        if (msgType == b'gsea'):
        	replyTmp=b'gsea'+pad
        	gseaStr="COUNT=0"        	
        	reply=gseaStr.encode('ascii')+codecs.decode('0A00','hex_codec')
        	oddByte=len(codecs.decode(reply,'latin1'))+12
        	oddByte = codecs.decode('{0:x}'.format(int(oddByte)),'hex_codec')
        	reply=replyTmp+oddByte+reply
        	print("REPLY: "+reply.decode('latin1'))
        	time.sleep(1)
				#ping				
        if (msgType == b'~png'):
        	ping_start=time.time()
       		if (ping_cnt>=1):
       			ping_cnt+=1
       		else:
       			ping_cnt=1       		
       		reply = reply_ping(data)
       		time.sleep(2)

       	return reply

def htosi(val):
    uintval = int(val,16)
    bits = 4 * (len(val) - 2)
    if uintval >= math.pow(2,bits-1):
        uintval = int(0 - (math.pow(2,bits) - uintval))
    return uintval
        
def threaded_client(connection):
    global SKEYREPLY, SKEYSENT, z, ping_cnt, ping_start, curr_time, ping_time, msgType, msgSize, ping_sent, icmp, x00,x0A
    connection.settimeout(500)
    while True:        
        curr_time=time.time()
        msgSize = 0
        try:
        	tmp = connection.recv(4)
        	msgType = tmp[:4]
        	print("RECV: "+str(msgType))
	        if (msgType == b'NAME'):
	        	msgSize = 3
	        	connection.recv(int(msgSize))
	        	reply = cmd_news('NAME=7')
	        elif (msgType == b'sele'):
	        	tmp = connection.recv(65)
        		packet = create_packet('sele', '', '')
	        	connection.sendall((packet))
	        	time.sleep(1)
	        	reply = cmd_news(1)
	        	connection.sendall((reply))
	        elif (msgType == b'ient'):
	        	msgSize = 5
	        	connection.recv(int(msgSize))
	        	reply = cmd_news('BP')
	        elif (msgType == b'TIME'):
	        	msgSize = 4
	        	print("SIZE: "+str(msgSize))
	        	data = connection.recv(int(msgSize))               	
	        #Add Buddy Socket replies here
	        elif (msgType == b'RGET'):
	        	msgSize = 200
	        	connection.recv(int(msgSize))
	        	reply = reply_ping(data)
	        elif (msgType == b'PSET'):
	        	tmp = connection.recv(104)
        		packet = create_packet('PSET', '', '')
	        	connection.sendall((packet))
	        	reply = reply_ping(data)
	        	connection.sendall((reply))
	        elif (msgType == b'USCH'):
	        	tmp = connection.recv(8)
	        	msgSize = tmp[7]
	        	print("SIZE: "+(str(msgSize)))
	        	data = connection.recv(int(msgSize))
	        	replyTmp=b'user'+pad
	        	uschStr="PERS=VTSTech"+x0A
	        	reply=uschStr.encode('ascii')
	        	uschStr="LAST="+time.strftime("%Y.%m.%d-%I:%M:%S",time.localtime())+x0A 
	        	reply+=uschStr.encode('ascii')+codecs.decode('00','hex_codec')
	        	oddByte=len(codecs.decode(reply,'latin1'))+12
	        	oddByte = codecs.decode('{0:x}'.format(int(oddByte)),'hex_codec')
	        	reply=replyTmp+oddByte+reply
	        	print("REPLY: "+reply.decode('latin1'))
	        	connection.sendall((reply))     	
	        else:
	        	try:
	        		tmp = connection.recv(8)
		        except:
		        	print("Exception_RECV\n")
	        	if (len(tmp) == 0):
	        		msgSize = 0
	        	elif (len(tmp) <= 5):
	        		msgSize = tmp[4]
	        	elif(len(tmp) == 8):
	        		if (tmp[6] >= 1) & (clientVERS == 'BURNOUT5/ISLAND'):
	        			msgSize = tmp[6]
	        			msgSize +=tmp[7]
	        			msgSize = htosi(hex(msgSize))
	        		else:        		
	        			msgSize = tmp[7]
	        	print("SIZE: "+(str(msgSize)))
	        	data = connection.recv(int(msgSize))
	        	reply = build_reply(data)
	        connection.sendall((reply))

	        if ((curr_time - ping_start) > 5):
	        	reply = reply_ping(data)
	        	connection.sendall((reply))
					#Or .. Add Buddy Socket replies here
	        if (msgType == b'AUTH'):
	        	packet = create_packet('AUTH','','')
	        	connection.sendall((packet))
	        	reply = reply_ping(data)
	        	print("REPLY: "+reply.decode('latin1'))
	        	connection.sendall((reply))

	        if (msgType == b'auth') & (clientVERS == 'FLM/A1'):
	        	reply = reply_rom()
	        	print("REPLY: "+reply.decode('latin1'))
	        	connection.sendall((reply))       	

	        if (msgType == b'sviw') & (clientVERS == 'FLM/A1'):
	        	reply = reply_who()
	        	print("REPLY: "+reply.decode('latin1'))
	        	connection.sendall((reply))
	        	time.sleep(1)
	        	reply = reply_ping(data)
	        	connection.sendall((reply))		        	
        except:
        	time.sleep(0.5)
        	curr_time=time.time()
                					
        reply=b''
        if not data:
            print("! end of data ... let's wait for some...")
            for x in range(0,60):
            	try:
            		tmp = connection.recv(4)
            	except:
            		time.sleep(1)
while True:
		CLIENT, ADDRESS = GameSocket.accept()
		print('Player Connected from: ' + ADDRESS[0] + ':' + str(ADDRESS[1]))
		start_new_thread(threaded_client, (CLIENT, ))
		THREADCOUNT += 1
		print('Thread Number: ' + str(THREADCOUNT))
		CLIENT, ADDRESS = LISTENERSocket.accept()
		print('LISTENER Connected from: ' + ADDRESS[0] + ':' + str(ADDRESS[1]))
		start_new_thread(threaded_client, (CLIENT, ))
		THREADCOUNT += 1
		print('Thread Number: ' + str(THREADCOUNT))    
		CLIENT, ADDRESS = BuddySocket.accept()
		print('Buddy Connected from: ' + ADDRESS[0] + ':' + str(ADDRESS[1]))
		start_new_thread(threaded_client, (CLIENT, ))
		THREADCOUNT += 1
		print('Thread Number: ' + str(THREADCOUNT))