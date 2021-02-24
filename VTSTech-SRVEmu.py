#BACKUP-2021-01-28 3:52:13 AM
import socket, sys, codecs, time, os, string, random, time, hashlib
from _thread import *

GameSocket = socket.socket()
LISTENERSocket = socket.socket()

TOTALARGS = len(sys.argv)
BUILD="0.1-ALPHA r0"
SERVER_IP = '192.168.0.228'
SERVER_IP_BIN = b'ADDR=192.168.0.228'
SERVER_PORT_BIN= b'PORT=10901'
PORT_NFSU_PS2 = 10900 #ps2nfs04.ea.com:10900
PORT_BO3P_PS2 = 21800 #ps2burnout05.ea.com:21800
PORT_BO3U_PS2 = 21801	#ps2burnout05.ea.com:21801
PORT_BO3R_PS2 = 21840 #ps2lobby02.beta.ea.com:21840
PORT_BOP_PS3 = 21870  #ps3burnout08.ea.com:21870
LISTENER = 10901
THREADCOUNT = 0
EMU_MODE = "nfsu"
SKEYREPLY = b''
SKEYSENT=0
SKEY = ''
z=0
a=''

clientNAME=''
clientVERS=''
clientMAC=''
clientPERS=''
clientLAST=''
clientPLAST=''
clientMAIL=''
clientADDR=''
clientBORN=''
clientPASS=''
clientUSER=''

pad = codecs.decode('00000000000000','hex_codec')
pad2 = codecs.decode('000000','hex_codec')
x0A = codecs.decode('0A','hex_codec')
x00 = codecs.decode('00','hex_codec')
def usage():
	print("Usage:")
	print("-nfsu Run in Need for Speed Underground Mode (PS2)")
	print("-bo3r Run in Burnout 3 Takedown Review Copy Mode (PS2)")
	print("-bo3u  Run in Burnout 3 Takedown Retail Copy Mode (PS2)")
	print("-bo3p  Run in Burnout 3 Takedown Retail Copy Mode (PS2)")	
	print("-bop  Run in Burnout Paradise Mode (PS3)")
	print("-p 12345 Run in Custom Game Mode on this TCP Port")
	quit()
	
print("VTSTech-SRVEmu v"+BUILD+"\n")

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
		GameSocket.bind((SERVER_IP, PORT_BO3R_PS2))
		print("Now running in Burnout 3 Review Copy Mode\n")
	elif (sys.argv[x] == "-bo3u"):
		EMU_MODE = "bo3u"
		GameSocket.bind((SERVER_IP, PORT_BO3U_PS2))
		print("Now running in Burnout 3 NTSC Retail Mode\n")
	elif (sys.argv[x] == "-bo3p"):
		EMU_MODE = "bo3p"
		GameSocket.bind((SERVER_IP, PORT_BO3P_PS2))
		print("Now running in Burnout 3 PAL Retail Mode\n")
	elif (sys.argv[x] == "-bop"):
		EMU_MODE = "bop"
		GameSocket.bind((SERVER_IP, PORT_BOP_PS3))
		print("Now running in Burnout Paradise Mode\n")   
	elif (sys.argv[x] == "-p"):
		EMU_MODE = "custom"
		GameSocket.bind((SERVER_IP, int(sys.argv[x+1])))
		print("Now running in Custom Game Mode\n")   
LISTENERSocket.bind((SERVER_IP, LISTENER))

print('Waiting for connections.. ')
reply=b''

GameSocket.listen(5)
LISTENERSocket.listen(1)

def parse_data(data):
	tmp = data[11:].split(codecs.decode('0A','hex_codec'))
	global clientNAME, clientVERS, clientMAC, clientPERS, clientBORN, clientMAIL, clientSKU, clientDEFPER, clientLAST, clientPLAST, clientMADDR, clientUSER
	global pad,pad2,x00,x0A,oddByte,reply

	for x in range(0,len(tmp)):
		#print("DEBUG: "+str(x))
		if (tmp[x].decode('latin1')[:3] == "MID") | (tmp[x].decode('latin1')[:3] == "MAC"):
			clientMAC = tmp[x].decode('latin1')[4:]
		elif (tmp[x].decode('latin1')[:3] == "SKU"):
			clientSKU = tmp[x].decode('latin1')[4:]
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

def reply_acct(data):
	tmp = data[11:].split(codecs.decode('0A','hex_codec'))
	global clientNAME, clientVERS, clientMAC, clientPERS, clientBORN, clientMAIL, clientSKU, clientDEFPER, clientLAST, clientPLAST, clientMADDR, clientUSER
	global pad,pad2,x00,x0A,oddByte,reply,a 
	reply=b''
	MD5=hashlib.md5()
	MD5.update(clientPASS.encode('ascii'))
	db = open("acct.db","a+")
	if sys.getsizeof(db)>1:
		line = db.readlines()
		for x in list(line):
			clientUSER = x.split("#")[0]
			if (clientNAME == clientUSER):
				reply=b'authimst'
				return reply
			print("DEBUG: "+clientUSER)
		acctStr="TOS=1"
		reply=acctStr.encode('ascii')+x0A
		acctStr="NAME="+clientNAME.lower()
		reply+=acctStr.encode('ascii')+x0A
		acctStr="AGE=21"
		reply+=acctStr.encode('ascii')+x0A   
		acctStr="PERSONAS="+clientNAME.lower()		
		reply+=acctStr.encode('ascii')+x0A
		clientLAST=time.strftime("%Y.%m.%d-%I:%M:%S",time.localtime())
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
		acctStr="SINCE="+time.strftime("%Y.%m.%d %I:%M:%S",time.localtime())
		reply+=authStr.encode('ascii')+x0A        	
		acctStr="LAST="+time.strftime("%Y.%m.%d %I:%M:%S",time.localtime())			
		reply+=codecs.decode('00','hex_codec')
		db.write(clientNAME+"#"+clientBORN+"#"+clientMAIL+"#"+MD5.hexdigest()+"#"+clientPERS+"#"+clientLAST)
		db.close
		return reply		

def reply_auth(data):
	tmp = data[11:].split(codecs.decode('0A','hex_codec'))
	global clientNAME, clientVERS, clientMAC, clientPERS, clientBORN, clientMAIL, clientSKU, clientDEFPER, clientLAST, clientPLAST, clientMADDR, clientUSER
	global pad,pad2,x00,x0A,oddByte,reply
	reply=b''
	authStr="TOS=1"
	reply=authStr.encode('ascii')+x0A
	authStr="NAME="+clientNAME.lower()
	reply+=authStr.encode('ascii')+x0A
	authStr="MAIL="+clientMAIL
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
	#authStr="DEFPER=1"
	#reply+=authStr.encode('ascii')+x0A        			
	#authStr="SINCE="+time.strftime("%Y.%m.%d %I:%M:%S",time.localtime())
	reply+=authStr.encode('ascii')+x0A        	
	authStr="LAST="+time.strftime("%Y.%m.%d %I:%M:%S",time.localtime())
	reply+=authStr.encode('ascii')        	
	reply+=codecs.decode('00','hex_codec')
	return reply

	if (clientVERS == "BURNOUT5/ISLAND"):
		tmp = clientMADDR.split("$")
		clientNAME=tmp[0]
		#reply=b'auth'+pad
		authStr="TOS=1"
		reply=authStr.encode('ascii')+x0A
		authStr="NAME="+clientNAME.lower()
		reply+=authStr.encode('ascii')+x0A
		authStr="MAIL="+clientMAIL	     	
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
		authStr="ADDR=24.14.35.60"
		reply+=authStr.encode('ascii')+x0A
		authStr="SINCE="+time.strftime("%Y.%m.%d-%I:%M:%S",time.localtime())
		reply+=authStr.encode('ascii')+x0A        	
		authStr="LAST="+time.strftime("%Y.%m.%d-%I:%M:%S",time.localtime())
		reply+=authStr.encode('ascii')+x0A
		authStr="_LUID=$000000000b32588d"
		reply+=authStr.encode('ascii')		
		reply+=codecs.decode('0A00','hex_codec')
	if (clientVERS == '"ps2/1.1001-Oct 15 2003"'):
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
		authStr="SINCE="+time.strftime("%Y.%m.%d %I:%M:%S",time.localtime())
		reply+=authStr.encode('ascii')+x0A        	
		authStr="LAST="+time.strftime("%Y.%m.%d %I:%M:%S",time.localtime())
		reply+=authStr.encode('ascii')        	
		reply+=codecs.decode('0A00','hex_codec')				
	return reply

def send_newds():
	global SKEYSENT
	global clientNAME, clientVERS, clientMAC
	global pad,pad2,x00,x0A
	global reply
	if (SKEYSENT==1):
		oddByte = codecs.decode('00','hex_codec')
		replyTmp=b'newsnew0'+pad2 #pad2 3 bytes
		newsStr="VTSTECH.IS.REVIVING.GAMES"
		reply=newsStr.encode('ascii')+codecs.decode('0A00','hex_codec')
		oddByte=len(codecs.decode(reply+replyTmp,'latin1'))+1
		print("DEBUG: "+str(oddByte))
		oddByte = codecs.decode('{0:x}'.format(int(oddByte)),'hex_codec')
		reply=replyTmp+oddByte+reply
		#reply = codecs.decode('6e6577736e6577370000005e436f6f6c206e6577732068657265210a506c656173652c206d6f64696679206e6577732e747874206f6e20746865207365727665720a0a2f5c5f2f5c0a283d27205f2720290a282c20282229202822290a00','hex_codec') #news reply
		print("REPLY: "+reply.decode('latin1'))
		return reply
		
def build_reply(data):
        pad = codecs.decode('00000000000000','hex_codec')
        pad2 = codecs.decode('000000','hex_codec')
        msgType = bytes(data[:4])
        oddByte = codecs.decode('00','hex_codec')
        x0A = codecs.decode('0A','hex_codec')
        x00 = codecs.decode('00','hex_codec')
        global SKEYREPLY
        global SKEY
        global clientNAME
        global clientVERS
        global clientMAC
        reply=''
        SKEY="$5075626c6963204b6579"
        #if (msgType == b'@tic'):
        	#oddByte hex 17
        	#print("\n--\n"+data.hex()+"\n--")
        if (msgType == codecs.decode('801C0100','hex_codec')):
        	print("DEBUG: enc in")
        	reply = codecs.decode('83DA04000A00','hex_codec')
        	#reply = codecs.decode('1000203BC00030010308203B830820321A00302010202021000300D06092A864886F70D01010405003081C9310B3009060355040613025553311330110603550408130A43616C69666F726E6961311530130603550407130C526564776F6F642043697479311E301C060355040A1315456C656374726F6E696320417274732C20496E632E3120301E060355040B13174F6E6C696E6520546563686E6F6C6F67792047726F7570312330210603550403131A4F54473320436572746966696361746520417574686F726974793127302506092A864886F70D01090116186469727479736F636B2D636F6E746163744065612E636F6D301E170D3133303532323231303331345A170D3333303531373231303331345A308196310B3009060355040613025553311330110603550408130A43616C69666F726E6961311E301C060355040A1315456C656374726F6E696320417274732C20496E632E3120301E060355040B13174F6E6C696E6520546563686E6F6C6F67792047726F7570311430120603550403130B6665736C2E65612E636F6D311A301806092A864886F70D010901160B6665736C4065612E636F6D305A300D06092A864886F70D01010105000349003046024100DFA200A7BA55613FAE13FB20040A529EDCC1D1F42BE5A198586A4D64AF9B8D6AC4C16B32AFEC03FE554CDA1084922FDA6695F006C81D51A562EAC9560BF5D4C3020103A382012430820120301D0603551D0E04160414A22B8C0CE5A96F36651EEB37C6733DCEE529C93C3081FE0603551D230481F63081F3801446A47E594954217E2D75D70E4D54D6A61D03B8F3A181CFA481CC3081C9310B3009060355040613025553311330110603550408130A43616C69666F726E6961311530130603550407130C526564776F6F642043697479311E301C060355040A1315456C656374726F6E696320417274732C20496E632E3120301E060355040B13174F6E6C696E6520546563686E6F6C6F67792047726F7570312330210603550403131A4F54473320436572746966696361746520417574686F726974793127302506092A864886F70D01090116186469727479736F636B2D636F6E746163744065612E636F6D820900899ED0A621034892300D06092A864886F70D0101040500038181006FC51C32A3F741866D17A922B40F31D3DE6E5D693EDAF40FBF131EC682CCC0057EC95F05548BAE844A3514BAFB44978EBB7D341FDD87FCF74556DB97D1D94C74B95C79D8F2A921FF5925EADBF0E30EC85A4314B979CC96911E567B8264C716D5A3DDBE63AC68C4FBB2C6D0FEE4895927E643ACB1BEEC00E87A5CD1F1120250A1010080DB69B3404D1330DE29ACC4C0C1016E42','hex_codec')
        	time.sleep(2)
        if (msgType == b'@dir'):
	        #oddByte hex 55
	        tmp = data[11:].split(codecs.decode('0A','hex_codec'))
	        clientVERS = tmp[0].decode('latin1')[6:]
	        #print("DEBUG: "+clientVERS)
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
	       	reply+=bytes(sessStr.encode("ascii"))+x0A+bytes(maskStr.encode("ascii"))+x00
	       	oddByte=len(codecs.decode(reply+replyTmp,'latin1'))+1
	       	oddByte = codecs.decode('{0:x}'.format(int(oddByte)),'hex_codec')
	       	reply=replyTmp+oddByte+SERVER_IP_BIN+x0A+SERVER_PORT_BIN+x0A
	       	reply+=bytes(sessStr.encode("ascii"))+x0A+bytes(maskStr.encode("ascii"))+x00
        	time.sleep(1)
        	print("REPLY: "+reply.decode('latin1'))
        if (msgType == b'addr'):
        	#oddByte inc 2b
					#SKEY=$37940faf2a8d1381a3b7d0d2f570e6a7
					######$5075626c6963204b6579
        	#reply = codecs.decode('7e706e670000002f0000001454494d453d310a00','hex_codec') #ping reply
        	#print("REPLY: "+reply.decode('latin1'))      	
        	oddByte = codecs.decode('99','hex_codec')
        	replyTmp=b'skey'+pad
        	#skeyStr="SKEY="+SKEY+str(random.randint(1000,9999))+"f570e6"+str(random.randint(10,99))
        	#skeyStr="PLATFORM=PS2"
        	#reply=skeyStr.encode('ascii')+x0A
        	skeyStr="SKEY=$37940faf2a8d1381a3b7d0d2f570e6a7"
        	reply=skeyStr.encode('ascii')+codecs.decode('0A00','hex_codec') #repeat me 0A6E6577736E6577370000000d00
        	oddByte=len(codecs.decode(reply,'latin1'))+12
        	oddByte = codecs.decode('{0:x}'.format(int(oddByte)),'hex_codec')
        	reply=replyTmp+oddByte+reply
        	SKEYSENT=0
        if (msgType == b'skey'):
        	#oddByte hex 28
        	tmp = data[11:].split(codecs.decode('0A','hex_codec'))
        	SKEY = tmp[0].decode('latin1')[6:]
        	print("Client sKey: "+SKEY)
        	time.sleep(1)
        if (msgType == b'fget'):
        	oddByte = codecs.decode('00','hex_codec')
        	replyTmp=b'+fup'+pad
        	fgetStr="FLUP=0"        	
        	reply=fgetStr.encode('ascii')+x0A        	
        	fgetStr="PRES="        	
        	reply+=fgetStr.encode('ascii')+codecs.decode('00','hex_codec')
        	oddByte=len(codecs.decode(reply,'latin1'))+12
        	oddByte = codecs.decode('{0:x}'.format(int(oddByte)),'hex_codec')        	
        	reply=replyTmp+oddByte+reply     	
        	#reply = codecs.decode('2B77686F00000000000000AD3D7674730A4E3D7674730A4D413D243761373930353534323232630A413D3139322E3136382E302E3232380A4C413D3139322E3136382E302E3232380A503D310A433D343030302C2C372C312C312C2C312C312C353535330A434C3D3531310A463D550A473D300A48573D3A493D37313631350A4C4F3D656E55530A4C563D313034393630310A4D443D3A505245533D310A52503D300A55533D3A5645523D3500','hex_codec') #fget reply
        	print("REPLY: "+reply.decode('latin1'))      	
        if (msgType == b'sele'):
        	oddByte = codecs.decode('00','hex_codec')
        	replyTmp=b'sele'+pad
        	
        	#seleStr="DP=PS3/BURNOUT5/ISLAND"
        	#reply=seleStr.encode('ascii')+x0A
        	seleStr="ASYNC=0"
        	reply=seleStr.encode('ascii')+x0A
        	#seleStr="CTRL=0"
        	#reply+=seleStr.encode('ascii')+x0A
        	seleStr="GAMES=1"        	
        	reply+=seleStr.encode('ascii')+x0A
        	seleStr="ROOMS=0"       	
        	reply+=seleStr.encode('ascii')+x0A
        	seleStr="USERS=0"
        	reply+=seleStr.encode('ascii')+x0A        	
        	seleStr="MYGAME=1"
        	reply+=seleStr.encode('ascii')+x0A        	
        	seleStr="MESGS=1"
        	reply+=seleStr.encode('ascii')+x0A
        	#seleStr="PLATFORM=PS2"
        	#reply+=seleStr.encode('ascii')+x0A        	
        	seleStr="RANKS=0"
        	reply+=seleStr.encode('ascii')+x0A
        	seleStr="STATS=1"
        	reply+=seleStr.encode('ascii')+x0A
        	seleStr="MORE=1"
        	reply+=seleStr.encode('ascii')+x0A
        	seleStr="SLOTS=4"
        	reply+=seleStr.encode('ascii')+codecs.decode('0A00','hex_codec')
        	oddByte=len(codecs.decode(reply,'latin1'))+12
        	oddByte = codecs.decode('{0:x}'.format(int(oddByte)),'hex_codec')
        	reply=replyTmp+oddByte+reply
        	#reply = codecs.decode('73656c65000000000000004347414D45533D310A524F4F4D533D310A55534552533D310A4D455347533D310A52414E4B533D300A4D4F52453D310A534C4F54533D340A00','hex_codec') #sele reply
        	print("REPLY: "+reply.decode('latin1')) 
        	time.sleep(2)     	
        if (msgType == b'auth'):					
        	replyTmp=b'auth'+pad
        	parse_data(data)
        	reply = reply_auth(data)
        	oddByte=len(codecs.decode(reply+replyTmp,'latin1'))+1
        	oddByte = codecs.decode('{0:x}'.format(int(oddByte)),'hex_codec')
        	reply=replyTmp+oddByte+reply
        	print("REPLY: "+reply.decode('latin1'))
        	time.sleep(2)
        if (msgType == b'acct'):
        	oddByte = codecs.decode('00','hex_codec')
        	replyTmp=b'acct'+pad
        	parse_data(data)
        	reply = reply_acct(data)
        	oddByte=len(codecs.decode(reply+replyTmp,'latin1'))+1
        	oddByte = codecs.decode('{0:x}'.format(int(oddByte)),'hex_codec')
        	reply=replyTmp+oddByte+reply
        	print("REPLY: "+reply.decode('latin1'))
        	time.sleep(2)        	
        if (msgType == b'pers'):
					#--NFSU RESP
					#NAME=0000
					#PERS=vts
					#LAST=2003.12.8 15:51:58
					#PLAST=2003.12.8 16:51:40
					#LKEY=3fcf27540c92935b0a66fd3b0000283c
        	
        	oddByte = codecs.decode('00','hex_codec')
        	replyTmp=b'pers'+pad
        	persStr="A=24.14.35.60"
        	reply=persStr.encode('ascii')+x0A
        	persStr="NAME="+clientNAME.lower()
        	reply+=persStr.encode('ascii')+x0A
        	persStr="PERS="+clientNAME.lower()
        	reply+=persStr.encode('ascii')+x0A
        	persStr="LAST="+time.strftime("%Y.%m.%d %I:%M:%S",time.localtime())
        	reply+=persStr.encode('ascii')+x0A
        	persStr="LKEY=3fcf27540c92935b0a66fd3b0000283c"
        	reply+=persStr.encode('ascii')+x0A
        	persStr="LOC=enUS"
        	reply+=persStr.encode('ascii')+x0A
        	persStr="MA="+clientMAC
        	reply+=persStr.encode('ascii')+x0A
        	persStr="PLAST="+time.strftime("%Y.%m.%d %I:%M:%S",time.localtime())
        	reply+=persStr.encode('ascii')+x0A
        	persStr="PSINCE="+time.strftime("%Y.%m.%d %I:%M:%S",time.localtime())
        	reply+=persStr.encode('ascii')+codecs.decode('00','hex_codec')
        	oddByte=len(codecs.decode(reply,'latin1'))+12
        	oddByte = codecs.decode('{0:x}'.format(int(oddByte)),'hex_codec')
        	reply=replyTmp+oddByte+reply
        	#reply = codecs.decode('7065727300000000000000794e414d453d7a7a7a7a7a7a0a504552533d7674730a4c4153543d323030332e31322e382031353a35313a35380a504c4153543d323030332e31322e382031363a35313a34300a4c4b45593d33666366323735343063393239333562306136366664336230303030323833630a00','hex_codec') #pers reply
        	print("REPLY: "+reply.decode('latin1'))	
        	time.sleep(1)
        if (msgType == b'sviw'):
        	oddByte = codecs.decode('00','hex_codec')
        	replyTmp=b'sviw'+pad        	
        	sviwStr="N=5"
        	reply=sviwStr.encode('ascii')+x0A
        	sviwStr="NAMES=\"0,3,4,5,6\""
        	reply+=sviwStr.encode('ascii')+x0A
        	sviwStr="DESCS=\"1,1,1,1,1\""
        	reply+=sviwStr.encode('ascii')+x0A
        	sviwStr="PARAMS=\"2,2,2,2,2\""
        	reply+=sviwStr.encode('ascii')+codecs.decode('0A00','hex_codec')
        	oddByte=len(codecs.decode(reply,'latin1'))+12
        	oddByte = codecs.decode('{0:x}'.format(int(oddByte)),'hex_codec')
        	reply=replyTmp+oddByte+reply
        	print("REPLY: "+reply.decode('latin1'))
        	time.sleep(1)
        if (msgType == b'uatr'):
        	oddByte = codecs.decode('00','hex_codec')
        	
        	replyTmp=b'+who'+pad        	
        	uatrStr="M="+clientNAME
        	reply=uatrStr.encode('ascii')+x0A
        	uatrStr="N="+clientNAME
        	reply+=uatrStr.encode('ascii')+x0A
        	uatrStr="MA="+clientMAC
        	reply+=uatrStr.encode('ascii')+x0A
        	uatrStr="A=24.14.35.60"
        	reply+=uatrStr.encode('ascii')+x0A
        	uatrStr="LA=192.168.0.133"
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
        if (msgType == b'news'):
        	oddByte = codecs.decode('00','hex_codec')
        	replyTmp=b'newsnew1'+pad2 #pad2 3 bytes
        	newsStr="VTSTECH.IS.REVIVING.GAMES"
        	reply=newsStr.encode('ascii')+codecs.decode('0A00','hex_codec')
        	oddByte=len(codecs.decode(reply+replyTmp,'latin1'))+1
        	print("DEBUG: "+str(oddByte))
        	oddByte = codecs.decode('{0:x}'.format(int(oddByte)),'hex_codec')
        	reply=replyTmp+oddByte+reply
        	print("REPLY: "+reply.decode('latin1'))
        	time.sleep(2)       	
				#ping				
        if (msgType == b'~png'):
       		reply = codecs.decode('7e706e670000002f0000001454494d453d310a00','hex_codec') #ping reply
       		print("REPLY: "+reply.decode('latin1'))	
        	#time.sleep(0.1)
       	return reply
    
def threaded_client(connection):
    #connection.send(str.encode('Welcome to the Server\n'))
    global SKEYREPLY
    global SKEYSENT
    global z
    while True:
        data = connection.recv(4096)
        msgType = data[:4]
        print("RECV: "+str(msgType))
        reply=''
        reply = build_reply(data)
              	
        if (sys.getsizeof(reply) > 0):
        	print("DEBUG: "+str(type(reply)))
        	if (type(reply) == str):
        		reply = bytes(reply,'utf-8')
        connection.sendall((reply))

        if (msgType == b'addr'):
        	print("Debug: skey sent")
        	SKEYSENT=1
        	reply = send_newds()
        	connection.sendall((reply))
					
        #no more data
        reply = ''
        if not data:
            print("! end of data")
            time.sleep(10)
            break
        reply = bytes(reply,'utf-8')
        #connection.sendall((reply))

    connection.close()
	
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
    
GameSocket.close()
LISTENERSocket.close()
LISTENERSocket.listen(1)
GameSocket.listen(1)