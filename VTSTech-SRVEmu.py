import codecs, os, sys, socket, struct, select, time, string, random, hashlib, array, math
from _thread import *

GameSocket = socket.socket()
BuddySocket = socket.socket()
LISTENERSocket = socket.socket()

TOTALARGS = len(sys.argv)
BUILD="0.1-ALPHA R0.69 (BO3)"
SERVER_IP = ''
SERVER_IP_BIN = b'ADDR='+bytes(SERVER_IP,'ascii')
SERVER_PORT_BIN= b'PORT=10901'

PORT_NFSU_PS2 = 10900 #ps2nfs04.ea.com:10900
PORT_BO3U_PS2 = 21800  #ps2burnout05.ea.com:21800
PORT_BO3R_PS2 = 21840 #ps2lobby02.beta.ea.com:21840
PORT_NFL05_PS2 = 20000  #ps2madden05.ea.com:20000
PORT_BOP_PS3 = 21870  #ps3burnout08.ea.com:21870
PORT_BOP_PC = 21840  #pcburnout08.ea.com:21871
PORT_SSX3_PS2 = 11000 #ps2ssx04.ea.com:11000
PORT_NC04_PS2 = 10600 #ps2nascar04.ea.com:10600

LISTENER = 10901
BUDDY_PORT = 10899
THREADCOUNT = 0
SKEYREPLY = b''
SKEYSENT=0
authsent=0
SKEY = ''
z=0
a=''
NO_DATA=False
news_cnt=0
ping_cnt=0
ping_sent=0
ping_start=time.time()
ping_time=time.time()
curr_time=time.time()

msgType=b''
msgSize=b''

clientALTS=''
clientNAME=''
clientVERS=''
clientMAC=''
clientSKU=''
clientPERS=''
clientLAST=''
clientLKEY=''
clientPLAST=''
clientMAIL=''
clientADDR=''
clientMADDR=''
clientBORN=''
clientPASS=''
clientPROD=''
clientSESS=''
clientSLUS=''
clientUSER=''
clientMINSIZE=''
clientMAXSIZE=''
clientCUSTFLAGS=''
clientPARAMS=''
clientPRIV=''
clientPERSONAS=''
clientSEED=''
clientSYSFLAGS=''

pingREF=''
pingTIME='2'

roomNAME=''

NEWS_PAYLOAD=0

pad = codecs.decode('00000000000000','hex_codec')
pad2 = codecs.decode('00000038','hex_codec')
oddByte = codecs.decode('00','hex_codec')
x0A = codecs.decode('0A','hex_codec')
x00 = codecs.decode('00','hex_codec')
reply=''
SKEY="$5075626c6963204b6579"

def usage():
	print("Usage:")
	print("-bo3r  Run in Burnout 3 Takedown Review Copy Mode (PS2)")
	print("-bo3u  Run in Burnout 3 Takedown Retail Copy Mode (PS2)")
	print("-bop3  Run in Burnout Paradise Mode (PS3)")
	print("-bopc  Run in Burnout Paradise Mode (PC)")
	print("-nfsu  Run in Need for Speed Underground Mode (PS2)")
	print("-nfl05 Run in Madden NFL 05 Mode (PS2)")
	print("-nc04  Run in Nascar Thunder 04 Mode (PS2)")
	print("-ssx3  Run in SSX3 Mode (PS2)")
	print("-p 123 Run in Custom Game Mode on this TCP Port")
	print("-i ip  Run on this IPv4 Address")
	quit()
	
def bind():
  global SERVER_IP, GameSocket, BuddySocket, LISTENERSocket, SERVER_IP, PORT_NFSU_PS2, PORT_BO3U_PS2, PORT_BO3R_PS2, PORT_BO3P_PS2, PORT_BOP_PS3, TOTALARGS
  
  for x in range(0,TOTALARGS,1):
    if (TOTALARGS >= 6):  
      print("Too many arguments! Check command line.")
      usage()
      exit()    
    if (TOTALARGS==1):
      usage()
    elif (sys.argv[x] == "-nfl05"):
      print("IP: "+SERVER_IP+" Port: "+str(PORT_NFL05_PS2))
      GameSocket.bind((SERVER_IP, PORT_NFL05_PS2))
      print("Now running in Madden NFL 2005 Mode\n")
    elif (sys.argv[x] == "-nc04"):
      print("IP: "+SERVER_IP+" Port: "+str(PORT_NC04_PS2))
      GameSocket.bind((SERVER_IP, PORT_NC04_PS2))
      print("Now running in NASCAR Thunder 2004 Mode\n")
    elif (sys.argv[x] == "-nfsu"):
      print("IP: "+SERVER_IP+" Port: "+str(PORT_NFSU_PS2))
      GameSocket.bind((SERVER_IP, PORT_NFSU_PS2))
      print("Now running in Need for Speed: Underground Mode\n")
    elif (sys.argv[x] == "-ssx3"):
      print("IP: "+SERVER_IP+" Port: "+str(PORT_SSX3_PS2))
      GameSocket.bind((SERVER_IP, PORT_SSX3_PS2))
      print("Now running in SSX3 Mode\n")
    elif (sys.argv[x] == "-bo3r"):
      print("IP: "+SERVER_IP+" Port: "+str(PORT_BO3U_PS2))
      GameSocket.bind((SERVER_IP, PORT_BO3R_PS2))
      print("Now running in Burnout 3 Review Mode (PS2)\n")
    elif (sys.argv[x] == "-bo3u"):
      print("IP: "+SERVER_IP+" Port: "+str(PORT_BO3U_PS2))
      GameSocket.bind((SERVER_IP, PORT_BO3U_PS2))
      print("Now running in Burnout 3 Retail Mode (PS2)\n")
    elif (sys.argv[x] == "-bop3"):
      print("IP: "+SERVER_IP+" Port: "+str(PORT_BOP_PS3))
      GameSocket.bind((SERVER_IP, PORT_BOP_PS3))
      print("Now running in Burnout Paradise Mode (PS3)\n")   
    elif (sys.argv[x] == "-bopc"):
      print("IP: "+SERVER_IP+" Port: "+str(PORT_BOP_PC))
      GameSocket.bind((SERVER_IP, PORT_BOP_PC))
      print("Now running in Burnout Paradise Mode (PC)\n")   
    elif (sys.argv[x] == "-p"):
      print("IP: "+SERVER_IP+" Port: "+str(int(sys.argv[x+1])))
      GameSocket.bind((SERVER_IP, int(sys.argv[x+1])))
      print("Now running in Custom Game Mode\n")   
      
  LISTENERSocket.bind((SERVER_IP, LISTENER))
  BuddySocket.bind((SERVER_IP, BUDDY_PORT))
  LISTENERSocket.listen(8)
  GameSocket.listen(8)
  BuddySocket.listen(8)
  print("Bind complete.\n")

def parse_data(data):
  tmp = data.split(codecs.decode('0A','hex_codec'))
  global clientALTS, clientNAME, clientVERS, clientMAC, clientPERS, clientPERSONAS, clientBORN, clientMAIL, clientSKU, clientDEFPER, clientLAST
  global clientPLAST, clientMADDR, clientUSER, clientMINSIZE, clientMAXSIZE, clientPARAMS, clientCUSTFLAGS, clientPRIV, clientMINSIZE, clientMAXSIZE
  global clientPARAMS, clientCUSTFLAGS, clientPRIV, clientSEED, clientSEED, clientSYSFLAGS,clientSESS, clientSKU, clientSLUS, clientUSER, clientPID, NEWS_PAYLOAD, clientLKEY, clientPROD, pingREF, pingTIME, roomNAME
  global pad,pad2,x00,x0A,oddByte,reply,msgType,msgSize,authsent,NO_DATA,news_cnt,news_cnt
  
  if (msgType == b'news'):
    for x in range(0,len(tmp)):  
      if (tmp[x].decode('latin1')[:4] == "NAME"):
        NEWS_PAYLOAD = tmp[x].decode('latin1')[5:]
        break
  elif (msgType == b'~png'):
    for x in range(0,len(tmp)):  
      if (tmp[x].decode('latin1')[:3] == "REF"):
        pingREF = tmp[x].decode('latin1')[4:]
      if (tmp[x].decode('latin1')[:4] == "TIME"):
        pingTIME = tmp[x].decode('latin1')[5:]
      break
  elif (msgType == b'room'):
    for x in range(0,len(tmp)):  
      if (tmp[x].decode('latin1')[:4] == "NAME"):
        roomNAME = tmp[x].decode('latin1')[5:]
      break
  else:
	  for x in range(0,len(tmp)):
	    #print("DEBUG: "+str(x))
	    if (tmp[x].decode('latin1')[:3] == "MID") | (tmp[x].decode('latin1')[:3] == "MAC"):
	      clientMAC = tmp[x].decode('latin1')[4:]
	    elif (tmp[x].decode('latin1')[:3] == "PID"):
	      clientPID = tmp[x].decode('latin1')[4:]
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
	    elif (tmp[x].decode('latin1')[:4] == "USER"):
	      clientUSER = tmp[x].decode('latin1')[5:]  
	    elif (tmp[x].decode('latin1')[:4] == "PASS"):
	      clientPASS = tmp[x].decode('latin1')[5:]  
	    elif (tmp[x].decode('latin1')[:4] == "PERS"):
	      clientPERS = tmp[x].decode('latin1')[5:]  
	    elif (tmp[x].decode('latin1')[:4] == "PROD"):
	      clientPROD = tmp[x].decode('latin1')[5:]  
	    elif (tmp[x].decode('latin1')[:4] == "SEED"):
	      clientSEED = tmp[x].decode('latin1')[5:]  
	    elif (tmp[x].decode('latin1')[:4] == "MAIL"):
	      clientMAIL = tmp[x].decode('latin1')[5:]
	    elif (tmp[x].decode('latin1')[:4] == "LAST"):
	      clientLAST = tmp[x].decode('latin1')[5:]
	    elif (tmp[x].decode('latin1')[:4] == "LKEY"):
	      clientLKEY = tmp[x].decode('latin1')[5:]
	    elif (tmp[x].decode('latin1')[:4] == "PRIV"):
	      clientPRIV = tmp[x].decode('latin1')[5:]
	    elif (tmp[x].decode('latin1')[:5] == "PLAST"):
	      clientPLAST = tmp[x].decode('latin1')[6:]
	    elif (tmp[x].decode('latin1')[:5] == "MADDR"):
	      clientMADDR = tmp[x].decode('latin1')[6:]
	    elif (tmp[x].decode('latin1')[:6] == "HWFLAG"):
	      clientHWFLAG = tmp[x].decode('latin1')[7:]
	    elif (tmp[x].decode('latin1')[:6] == "HWMASK"):
	      clientHWMASK = tmp[x].decode('latin1')[7:]
	    elif (tmp[x].decode('latin1')[:6] == "DEFPER"):
	      clientDEFPER = tmp[x].decode('latin1')[7:]
	    elif (tmp[x].decode('latin1')[:6] == "PARAMS"):
	      clientPARAMS = tmp[x].decode('latin1')[7:]
	    elif (tmp[x].decode('latin1')[:6] == "SDKVER"):
	      clientSDKVER = tmp[x].decode('latin1')[7:]
	    elif (tmp[x].decode('latin1')[:7] == "MINSIZE"):
	      clientMINSIZE = tmp[x].decode('latin1')[8:]
	    elif (tmp[x].decode('latin1')[:7] == "MAXSIZE"):
	      clientMAXSIZE = tmp[x].decode('latin1')[8:]
	    elif (tmp[x].decode('latin1')[:8] == "SYSFLAGS"):
	      clientSYSFLAGS = tmp[x].decode('latin1')[9:]
	    elif (tmp[x].decode('latin1')[:9] == "CUSTFLAGS"):
	      clientCUSTFLAGS = tmp[x].decode('latin1')[10:]
	    elif (tmp[x].decode('latin1')[:9] == "PERSONAS"):
	      clientPERSONAS = tmp[x].decode('latin1')[10:]  			

#Thx No23
def create_packet(cmd, subcmd, payload):
    payload += '\0'
    size = len(payload)
    return struct.pack(">4s4sL%ds" % size, bytearray(cmd, 'ascii'), bytearray(subcmd, 'ascii'), size + 12, bytearray(payload, 'ascii'))
#Thx No23
def cmd_news(payload):
    global SERVER_IP, NEWS_PAYLOAD
    
    print("News Payload: "+str(NEWS_PAYLOAD))
	
    if (NEWS_PAYLOAD == 1):
    	print("fired!")
    	p='VTSTech-SRVEmu R0.66\n'
    	p+='===================\n'
    	p+='Written by Veritas Technical Solutions www.VTS-Tech.org\n'
    	p+='GitHub: https://github.com/Veritas83/VTSTech-SRVEmu\n'
    	p+='Changelog:\n'
    	p+='R0.66\n'
    	p+='Added SSX3 Mode\n'
    	p+='Specify IPv4 with -i now\n'
    	p+='New Command Handler: ONLN\n'
    	p+='\n'
    	p+='R0.65\n'
    	p+='Added Madden NFL 05 mode.\n'
    	p+='Confirmed working connect/login/acct commands.\n'
    	p+='New Commands Handlers: USSV CUSR USER\n'
    	p+='\n'
    	p+='R0.64\n'
    	p+='New Command Handlers: RVUP, SDTA, FUPD\n'
    	p+='\n'
    	p+='R0.63\n'
    	p+='Now at "Entering Game" as host on Burnout Paradise.\n'
    	p+='New Command Handlers:\n'
    	p+='+mgm, SLST, CATE, GPSC\n'
    	p+='\n'
    	p+='R0.62\n'
    	p+='New Command Handlers:\n'
    	p+='USLD, GQWK\n'
    	p+='Expanded SELE reply\n'
    	p+='Now counting news requests (news_cnt)\n'
    	p+='\n'
    	p+='R0.61\n'
    	p+='New packet logic\n'
    	p+='Added NO_DATA flag\n'
    	p+='Re-indented script\n'
    	p+='Added missing = from last commit in ~png\n'
    	p+='\n'
    	p+='R0.6\n'
    	p+='Uniform Timestamps\n'
    	p+='Comment cleanup\n'
    	p+='NEWS command improvements\n'
    	p+='Added USCH handler\n'
    	p+='\n'
    	p+='R0.57:\n'
    	p+='~png tentatively stablized\n'
    	p+='Buddy Port now set globally\n'
    	p+='PAL/NTSU Retail use same port. Params reduced.\n'
    	p+='Now sending empty SELE reply\n'
    	p+='Now sending empty PGET reply\n'
    	p+='\n'
    	p+='R0.56:\n'
    	p+='News NEWS sub command implemented (new1)\n'
    	p+='Now includes changelog\n'
    	p+='\n'
    	p+='R0.55:\n'
    	p+='CPER Command Implemented\n'
    	p+='\n'
    	p+='R0.54:\n'
    	p+='+rom reply\n'
    	p+='remove quotes on sviw\n'
    	p+='no longer starting ~png conversation\n'
    else:
    	p = 'BUDDY_SERVER='+SERVER_IP+'\n'
    	p+= 'BUDDY_PORT='+str(BUDDY_PORT)+'\n'
    	#p+= 'LIVE_NEWS_URL=https://gos.ea.com/easo/editorial/Burnout/2008/livedata/main.jsp?lang=en&from=enUS&game=Burnout&platform=PS3&env=live\n'
    	p+= 'EACONNECT_WEBOFFER_URL=http://ps3burnout08.ea.com/EACONNECT.txt\n'
    	p+= 'ETOKEN_URL=http://ps3burnout08.ea.com/ETOKEN.txt\n'
    	p+= 'TOSAC_URL=http://ps3burnout08.ea.com/TOSAC.txt\n'
    	p+= 'TOSA_URL=http://ps3burnout08.ea.com/TOSA.txt\n'
    	p+= 'TOS_URL=http://ps3burnout08.ea.com/TOS.txt\n'    	    	   
    	p+= 'LIVE_NEWS_URL=http://ps3burnout08.ea.com/LIVE.txt\n'
    	p+= 'LIVE_NEWS2_URL=http://ps3burnout08.ea.com/LIVE2.txt\n'
    	p+= 'PRODUCT_SEARCH_URL=http://ps3burnout08.ea.com/PROD.txt\n'
    	p+= 'AVATAR_URL=http://ps3burnout08.ea.com/AV.txt\n'
    	p+= 'STORE_URL=http://ps3burnout08.ea.com/STORE.txt\n'
    	p+= 'LIVE_NEWS_URL_IMAGE_PATH=.\n'
    	#p+= 'USE_GLOBAL_ROAD_RULE_SCORES=0\n'
    	p+= 'NEWS_TEXT=VTSTech.is.reviving.games\n'
    	p+= 'TOS_TEXT=VTSTech.is.reviving.games\n'
    	p+= 'ROAD_RULES_SKEY=frscores\n'
    	p+= 'CHAL_SKEY=chalscores\n'
    	p+= 'NEWS_DATE='+time.strftime("%Y.%m.%d-%I:%M:%S",time.localtime())+'\n'
    	p+= 'NEWS_URL=http://ps3burnout08.ea.com/news.txt\n'
    	p+= 'USE_ETOKEN=0\n'
    news_cmd='new'+str(NEWS_PAYLOAD)
    packet = create_packet('news', news_cmd, p)

    if (payload == "NAME=7") | (payload == "BP"):
      packet = create_packet('news', 'new7', p)
      #payload=''
    if (clientVERS =='BURNOUT5/ISLAND'):
      packet = create_packet('news', 'new8', p)
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
  global clientALTS, clientNAME, clientVERS, clientMAC, clientPERS, clientPERSONAS, clientBORN, clientMAIL, clientSKU, clientDEFPER, clientLAST
  global clientPLAST, clientMADDR, clientUSER, clientMINSIZE, clientMAXSIZE, clientPARAMS, clientCUSTFLAGS, clientPRIV, clientMINSIZE, clientMAXSIZE
  global clientPARAMS, clientCUSTFLAGS, clientPRIV, clientSEED, clientSEED, clientSYSFLAGS,clientSESS, clientSKU, clientSLUS, clientUSER, clientPID, NEWS_PAYLOAD, clientLKEY, clientPROD, pingREF, pingTIME, roomNAME
  global pad,pad2,x00,x0A,oddByte,reply,msgType,msgSize,authsent,NO_DATA,news_cnt,news_cnt
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
    clientUSER = clientNAME
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
  global clientALTS, clientNAME, clientVERS, clientMAC, clientPERS, clientPERSONAS, clientBORN, clientMAIL, clientSKU, clientDEFPER, clientLAST
  global clientPLAST, clientMADDR, clientUSER, clientMINSIZE, clientMAXSIZE, clientPARAMS, clientCUSTFLAGS, clientPRIV, clientMINSIZE, clientMAXSIZE
  global clientPARAMS, clientCUSTFLAGS, clientPRIV, clientSEED, clientSEED, clientSYSFLAGS,clientSESS, clientSKU, clientSLUS, clientUSER, clientPID, NEWS_PAYLOAD, clientLKEY, clientPROD, pingREF, pingTIME, roomNAME
  global pad,pad2,x00,x0A,oddByte,reply,msgType,msgSize,authsent,NO_DATA,news_cnt
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
  #reply+=authStr.encode('ascii')
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
	global clientALTS, clientNAME, clientVERS, clientMAC, clientPERS, clientPERSONAS, clientBORN, clientMAIL, clientSKU, clientDEFPER, clientLAST, clientPLAST, clientMADDR, clientUSER, clientMINSIZE, clientMAXSIZE, clientPARAMS, clientCUSTFLAGS, clientPRIV, clientMINSIZE, clientMAXSIZE, clientPARAMS, clientCUSTFLAGS, clientPRIV, clientSEED, clientSEED, clientSYSFLAGS,clientSESS, clientSKU, clientSLUS, clientUSER
	global pad,pad2,x00,x0A,oddByte,reply,msgType,msgSize,authsent,NO_DATA,news_cnt
	reply=b''
	cperStr="PERS="+clientPERS
	reply=cperStr.encode('ascii')+x0A
	cperStr="ALTS="+clientALTS
	reply+=cperStr.encode('ascii')+x0A
	reply+=codecs.decode('00','hex_codec')
	return reply
	
def reply_rom():
	global clientALTS, clientNAME, clientVERS, clientMAC, clientPERS, clientPERSONAS, clientBORN, clientMAIL, clientSKU, clientDEFPER, clientLAST
	global clientPLAST, clientMADDR, clientUSER, clientMINSIZE, clientMAXSIZE, clientPARAMS, clientCUSTFLAGS, clientPRIV, clientMINSIZE, clientMAXSIZE
	global clientPARAMS, clientCUSTFLAGS, clientPRIV, clientSEED, clientSEED, clientSYSFLAGS,clientSESS, clientSKU, clientSLUS, clientUSER, clientPID, NEWS_PAYLOAD, clientLKEY, clientPROD
	global pad,pad2,x00,x0A,oddByte,reply,msgType,msgSize,authsent,NO_DATA,news_cnt
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
	romStr="A=24.141.39.62"
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
	global clientALTS, clientNAME, clientVERS, clientMAC, clientPERS, clientPERSONAS, clientBORN, clientMAIL, clientSKU, clientDEFPER, clientLAST
	global clientPLAST, clientMADDR, clientUSER, clientMINSIZE, clientMAXSIZE, clientPARAMS, clientCUSTFLAGS, clientPRIV, clientMINSIZE, clientMAXSIZE
	global clientPARAMS, clientCUSTFLAGS, clientPRIV, clientSEED, clientSEED, clientSYSFLAGS,clientSESS, clientSKU, clientSLUS, clientUSER, clientPID, NEWS_PAYLOAD, clientLKEY, clientPROD
	global pad,pad2,x00,x0A,oddByte,reply,msgType,msgSize,authsent,NO_DATA,news_cnt
	oddByte = codecs.decode('00','hex_codec')
	replyTmp=b'+who'+pad
	whoStr="M=VTSTech"
	reply=whoStr.encode('ascii')+x0A
	whoStr="N=VTSTech"
	reply+=whoStr.encode('ascii')+x0A
	whoStr="MA="+clientMAC
	reply+=whoStr.encode('ascii')+x0A
	whoStr="A=24.141.39.62"
	reply+=whoStr.encode('ascii')+x0A
	whoStr="LA=192.168.0.222"
	reply+=whoStr.encode('ascii')+x0A
	whoStr="P=1"
	reply+=whoStr.encode('ascii')+x0A
	whoStr="CL=511"
	reply+=whoStr.encode('ascii')+x0A
	whoStr="F=U"
	reply+=whoStr.encode('ascii')+x0A
	whoStr="G=0"
	reply+=whoStr.encode('ascii')+x0A
	whoStr="HW=0"
	reply+=whoStr.encode('ascii')+x0A
	whoStr="I=71615"
	reply+=whoStr.encode('ascii')+x0A
	whoStr="LO=enUS"
	reply+=whoStr.encode('ascii')+x0A
	whoStr="LV=1049601"
	reply+=whoStr.encode('ascii')+x0A
	whoStr="MD=0"
	reply+=whoStr.encode('ascii')+x0A
	whoStr="PRES="
	reply+=whoStr.encode('ascii')+x0A
	#whoStr="SESS="+clientSESS
	#reply+=whoStr.encode('ascii')+x0A
	whoStr="RP=0"
	reply+=whoStr.encode('ascii')+x0A
	whoStr="S="
	reply+=whoStr.encode('ascii')+x0A
	whoStr="US=0"
	reply+=whoStr.encode('ascii')+x0A
	whoStr="VER=5"
	reply+=whoStr.encode('ascii')+x0A
	whoStr="X="
	reply+=whoStr.encode('ascii')+codecs.decode('0A00','hex_codec')
	oddByte=len(codecs.decode(reply,'latin1'))+12
	oddByte = codecs.decode('{0:x}'.format(int(oddByte)),'hex_codec')
	reply=replyTmp+oddByte+reply
	print("REPLY: "+reply.decode('latin1'))
	return reply

def reply_mgm():
	global clientALTS, clientNAME, clientVERS, clientMAC, clientPERS, clientPERSONAS, clientBORN, clientMAIL, clientSKU, clientDEFPER, clientLAST
	global clientPLAST, clientMADDR, clientUSER, clientMINSIZE, clientMAXSIZE, clientPARAMS, clientCUSTFLAGS, clientPRIV, clientMINSIZE, clientMAXSIZE
	global clientPARAMS, clientCUSTFLAGS, clientPRIV, clientSEED, clientSEED, clientSYSFLAGS,clientSESS, clientSKU, clientSLUS, clientUSER, clientPID, NEWS_PAYLOAD, clientLKEY, clientPROD
	global pad,pad2,x00,x0A,oddByte,reply,msgType,msgSize,authsent,NO_DATA,news_cnt
	p =  'CUSTFLAGS='+clientCUSTFLAGS+'\n'
	p += 'MINSIZE='+clientMINSIZE+'\n'
	p += 'MAXSIZE='+clientMAXSIZE+'\n'
	p += 'NAME=VTSTech\n'
	p += 'PARAMS='+clientPARAMS+'\n'
	p += 'PRIV='+clientPRIV+'\n'
	p += 'SEED=12345\n'
	p += 'SYSFLAGS='+clientSYSFLAGS+'\n'
	p += 'MADDR='+clientMAC+'\n'
	p += 'COUNT=1\n'
	p += 'NUMPART=1\n'
	p += 'PARTSIZE='+clientMINSIZE+'\n'
	p += 'GPSREGION=2\n'
	p += 'GAMEPORT=9657\n'
	p += 'VOIPPORT=9667\n'
	p += 'EVGID=0\n'
	p += 'EVID=0\n'
	p += 'IDENT=6450\n'
	p += 'GAMEMODE=0\n'
	p += 'PARTPARAMS=0\n'
	p += 'ROOM=0\n'
	p += 'SESS='+clientSESS+'\n'
	p += 'OPGUEST=0\n'
	p += 'WHEN='+time.strftime("%Y.%m.%d-%I:%M:%S",time.localtime())+'\n'
	p += 'WHENC='+time.strftime("%Y.%m.%d-%I:%M:%S",time.localtime())+'\n'
	p += 'GPSHOST=VTSTech\n'
	p += 'HOST=VTSTech\n'
	packet = create_packet('+mgm', '', p)
	print("REPLY: "+packet.decode('latin1'))
	return packet

def reply_gam():
	global clientALTS, clientNAME, clientVERS, clientMAC, clientPERS, clientPERSONAS, clientBORN, clientMAIL, clientSKU, clientDEFPER, clientLAST
	global clientPLAST, clientMADDR, clientUSER, clientMINSIZE, clientMAXSIZE, clientPARAMS, clientCUSTFLAGS, clientPRIV, clientMINSIZE, clientMAXSIZE
	global clientPARAMS, clientCUSTFLAGS, clientPRIV, clientSEED, clientSEED, clientSYSFLAGS,clientSESS, clientSKU, clientSLUS, clientUSER, clientPID, NEWS_PAYLOAD, clientLKEY, clientPROD
	global pad,pad2,x00,x0A,oddByte,reply,msgType,msgSize,authsent,NO_DATA,news_cnt	
	p =  'CUSTFLAGS='+clientCUSTFLAGS+'\n'
	p += 'MINSIZE='+clientMINSIZE+'\n'
	p += 'MAXSIZE='+clientMAXSIZE+'\n'
	p += 'NAME=VTSTech\n'
	p += 'PARAMS='+clientPARAMS+'\n'
	p += 'PRIV='+clientPRIV+'\n'
	p += 'SEED=12345\n'
	p += 'SYSFLAGS='+clientSYSFLAGS+'\n'
	p += 'MADDR='+clientMAC+'\n'
	p += 'COUNT=1\n'
	p += 'NUMPART=1\n'
	p += 'PARTSIZE='+clientMINSIZE+'\n'
	p += 'GPSREGION=2\n'
	p += 'GAMEPORT=9657\n'
	p += 'VOIPPORT=9667\n'
	p += 'EVGID=0\n'
	p += 'EVID=0\n'
	p += 'IDENT=6450\n'
	p += 'GAMEMODE=0\n'
	p += 'PARTPARAMS=0\n'
	p += 'ROOM=0\n'
	p += 'SESS='+clientSESS+'\n'
	p += 'OPGUEST=0\n'
	p += 'WHEN='+time.strftime("%Y.%m.%d-%I:%M:%S",time.localtime())+'\n'
	p += 'WHENC='+time.strftime("%Y.%m.%d-%I:%M:%S",time.localtime())+'\n'
	p += 'GPSHOST=VTSTech\n'
	p += 'HOST=VTSTech\n'
	packet = create_packet('+gam', '', p)
	print("REPLY: "+packet.decode('latin1'))
	return packet		
	
def reply_ping(data):
  global clientALTS, clientNAME, clientVERS, clientMAC, clientPERS, clientPERSONAS, clientBORN, clientMAIL, clientSKU, clientDEFPER, clientLAST
  global clientPLAST, clientMADDR, clientUSER, clientMINSIZE, clientMAXSIZE, clientPARAMS, clientCUSTFLAGS, clientPRIV, clientMINSIZE, clientMAXSIZE
  global clientPARAMS, clientCUSTFLAGS, clientPRIV, clientSEED, clientSEED, clientSYSFLAGS,clientSESS, clientSKU, clientSLUS, clientUSER, clientPID, NEWS_PAYLOAD, clientLKEY, clientPROD, pingREF, pingTIME
  global SKEYREPLY, SKEYSENT, z, ping_cnt, ping_start, curr_time, ping_time, msgType, msgSize, ping_sent, pad, NO_DATA
  oddByte = codecs.decode('00','hex_codec')          
  replyTmp = b'~png'+pad
  reply = b'REF='+bytes(time.strftime("%Y.%m.%d-%I:%M:%S",time.localtime()),'ascii')+x0A
  reply += b'TIME='+bytes(pingTIME,'ascii')+x0A+x00
  oddByte=len(codecs.decode(reply,'latin1'))+12
  oddByte = codecs.decode('{0:x}'.format(int(oddByte)),'hex_codec')
  reply=replyTmp+oddByte+reply
  if (ping_sent>=1):
    ping_sent+=1
    return reply
  else:
    ping_sent=1
    return reply
  time.sleep(1.1)
  #msgType=b''
	
def build_reply(data):
  global SKEYREPLY, SKEY
  global clientALTS, clientNAME, clientVERS, clientMAC, clientPERS, clientPERSONAS, clientBORN, clientMAIL, clientSKU, clientDEFPER, clientLAST
  global clientPLAST, clientMADDR, clientUSER, clientMINSIZE, clientMAXSIZE, clientPARAMS, clientCUSTFLAGS, clientPRIV, clientMINSIZE, clientMAXSIZE
  global clientPARAMS, clientCUSTFLAGS, clientPRIV, clientSEED, clientSEED, clientSYSFLAGS,clientSESS, clientSKU, clientSLUS, clientUSER, clientPID, NEWS_PAYLOAD, clientLKEY, clientPROD
  global pad,pad2,x00,x0A,oddByte,reply,msgType,msgSize,authsent,NO_DATA,news_cnt,ping_cnt
  reply=b''
  if (msgType == codecs.decode('801C0100','hex_codec')):
    print("** 0x80 Encryption Detected **")
    reply = codecs.decode('83DA04000A00','hex_codec')
  elif (msgType == b'@dir'):
    parse_data(data)
    print("@dir: "+data.decode('latin1'))
    tmp = data.split(codecs.decode('0A','hex_codec'))    
    clientSESS=str(random.randint(1000,9999))+str(random.randint(1000,9999))+str(random.randint(10,99))
    sessStr="SESS="+clientSESS
    maskStr="MASK="+str(random.randint(1000,9999))+"f3f70ecb1757cd7001b9a7a"+str(random.randint(1000,9999))         	
    replyTmp=msgType+pad
    #print("Debug"+str(SERVER_IP_BIN))
    reply=SERVER_IP_BIN+x0A+SERVER_PORT_BIN+x0A
    reply+=bytes(sessStr.encode("ascii"))+x0A+bytes(maskStr.encode("ascii"))+x0A+x00
    oddByte=len(codecs.decode(reply+replyTmp,'latin1'))+1
    oddByte = codecs.decode('{0:x}'.format(int(oddByte)),'hex_codec')
    reply=replyTmp+oddByte+SERVER_IP_BIN+x0A+SERVER_PORT_BIN+x0A
    reply+=bytes(sessStr.encode("ascii"))+x0A+bytes(maskStr.encode("ascii"))+x0A+x00       
    print("REPLY: "+reply.decode('latin1'))
  #ping        
  if (msgType == b'~png'):
    parse_data(data)
    ping_start=time.time()
    if (ping_cnt>=1):
     ping_cnt+=1
    else:
     ping_cnt=1
    reply = reply_ping(data)
    time.sleep(1)
  elif (msgType == b'acct'):
    replyTmp=b'acct'+pad
    parse_data(data)
    reply = reply_acct(data)
    oddByte=len(codecs.decode(reply+replyTmp,'latin1'))+1
    oddByte = codecs.decode('{0:x}'.format(int(oddByte)),'hex_codec')
    reply=replyTmp+oddByte+reply
    print("REPLY: "+reply.decode('latin1'))
  elif ((msgType == b'auth')):
    authsent=authsent+1					
    replyTmp=msgType+pad
    parse_data(data)
    reply = reply_auth(data)
    if len(reply) > 1:
     oddByte=len(codecs.decode(reply+replyTmp,'latin1'))+1
     oddByte = codecs.decode('{0:x}'.format(int(oddByte)),'hex_codec')
     reply=replyTmp+oddByte+reply
     print("REPLY: "+reply.decode('latin1'))
  elif (msgType == b'AUTH'):     
    parse_data(data)
    time.sleep(0.5)
    p = 'NAME='+clientNAME+'\n'
    p += 'USER='+clientNAME+'\n'
    p += 'PROD='+clientVERS+'\n'
    p += 'LKEY='+clientLKEY+'\n'
    reply = create_packet('AUTH', '', p)
  elif (msgType == b'cate'):
    parse_data(data)
    reply = create_packet('cate', '', '')
  elif (msgType == b'cper'):
    parse_data(data)
    replyTmp=b'cper'+pad
    reply = reply_cper(data)
    oddByte=len(codecs.decode(reply,'latin1'))+12
    oddByte = codecs.decode('{0:x}'.format(int(oddByte)),'hex_codec')
    reply=replyTmp+oddByte+reply
    print("REPLY: "+reply.decode('latin1'))
    time.sleep(1)
  elif (msgType == b'cusr'):
    parse_data(data)
    reply = create_packet('cusr', '', '')
  if (msgType == b'edit'):
    parse_data(data)
    p='NAME='+clientNAME+'\n'
    p+='MAIL='+clientMAIL+'\n'
    reply = create_packet('edit', '', p)
  elif (msgType == b'fget'):
    parse_data(data)
    reply = create_packet('fget', '', '')    
  elif (msgType == b'fupd'):
    parse_data(data)
    reply = reply_rom()
  elif (msgType == b'gsea'):
    p='COUNT=0\n'
    p+='CANCEL=1\n'
    reply = create_packet('gsea', '', p)
    print("REPLY: "+reply.decode('latin1'))
    #time.sleep(1)
  elif (msgType == b'gpsc'):
    parse_data(data)
    reply = reply_mgm()
  elif (msgType == b'gqwk'):
    parse_data(data)
    p='COUNT=0\n'
    reply = create_packet('gqwk', '', p)
  elif (msgType == b'news'):
    parse_data(data)
    news_cnt+=1
    reply = cmd_news(NEWS_PAYLOAD)
    #if news_cnt == 1:
      #reply = cmd_news(7)
    #if news_cnt == 2:
      #reply = cmd_news(8)      
    print("REPLY: "+reply.decode('latin1'))    
  elif (msgType == b'onln'):
    parse_data(data)
    p='PERS='+clientNAME+'\n'
    reply = create_packet('onln', '', p)
  elif (msgType == b'pers'):
    parse_data(data)
    #persStr="A=24.141.39.62\n"
    #if (clientVERS == 'BURNOUT5/ISLAND'):
    	#print("fired")
    	#persStr+='EX-telemetry='+SERVER_IP+',9983,enUS\n'
    	#persStr+="IDLE=10000\n"
    #persStr+="LA=24.141.39.62\n"
    persStr="LOC=enUS\n"
    persStr+="MA="+clientMAC+"\n"
    if isinstance(clientNAME,str):
      persStr+="PERS="+clientNAME.lower()+"\n"
      persStr+="NAME="+clientNAME.lower()+"\n"
    else:
      persStr+="PERS="+clientNAME[0].lower()+"\n"
      persStr+="NAME="+clientNAME[0].lower()+"\n"
    persStr+="LAST="+time.strftime("%Y.%m.%d-%I:%M:%S",time.localtime())+"\n"
    persStr+="PLAST="+time.strftime("%Y.%m.%d-%I:%M:%S",time.localtime())+"\n"
    persStr+="SINCE="+time.strftime("%Y.%m.%d-%I:%M:%S",time.localtime())+"\n"
    persStr+="PSINCE="+time.strftime("%Y.%m.%d-%I:%M:%S",time.localtime())+"\n"
    persStr+="LKEY=3fcf27540c92935b0a66fd3b0000283c\n"
    reply = create_packet('pers', '', persStr)
    print("REPLY: "+reply.decode('latin1'))  
  elif (msgType == b'PGET'):
    parse_data(data)
    #p='PERS='+clientNAME+'\n'
    reply = create_packet('PGET', '', '')
  elif (msgType == b'PSET'):
    parse_data(data)
    #p='PERS='+clientNAME+'\n'
    reply = create_packet('PSET', '', '')
  elif (msgType == b'rvup'):
    parse_data(data)
    reply = create_packet('rvup', '', '')
  elif (msgType == b'sele'):
    parse_data(data)
    p =  'VERS='+clientVERS+'\n'
    p += 'SKU='+clientSKU+'\n'
    p += 'USERS=0\n'
    p += 'GAMES=0\n'
    p += 'MYGAME=1\n'
    p += 'ROOMS=0\n'
    p += 'MESGS=0\n'
    p += 'ASYNC=1\n'
    p += 'USERSETS=0\n'
    p += 'MESGTYPES=100728964\n'    
    p += 'STATS=0\n'
    packet = create_packet('sele', '', p)
    return packet
  elif (msgType == b'skey'):
    tmp = data.split(codecs.decode('0A','hex_codec'))
    SKEY = tmp[0].decode('latin1')[5:]
    print("Client sKey: "+SKEY)              
    reply = reply_skey()
    time.sleep(1)
  elif (msgType == b'slst'):
    parse_data(data)
    p='COUNT=27\n'                                     
    p+='VIEW0=lobby,"Online Lobby Stats View"\n'      
    p+='VIEW1=DLC,"DLC Lobby Stats View"\n'           
    p+='VIEW2=RoadRules,"Road Rules"\n'               
    p+='VIEW3=DayBikeRRs,"Day Bike Road Rules"\n'     
    p+='VIEW4=NightBikeRR,"Night Bike Road Rules"\n'  
    p+='VIEW5=PlayerStatS,"Player Stats Summary"\n'   
    p+='VIEW6=LastEvent1,"Recent Event 1 Details"\n'  
    p+='VIEW7=LastEvent2,"Recent Event 2 Details"\n'  
    p+='VIEW8=LastEvent3,"Recent Event 3 Details"\n'  
    p+='VIEW9=LastEvent4,"Recent Event 4 Details"\n'  
    p+='VIEW10=LastEvent5,"Recent Event 5 Details"\n' 
    p+='VIEW11=OfflineProg,"Offline Progression"\n'   
    p+='VIEW12=Rival1,"Rival 1 information"\n'        
    p+='VIEW13=Rival2,"Rival 2 information"\n'        
    p+='VIEW14=Rival3,"Rival 3 information"\n'        
    p+='VIEW15=Rival4,"Rival 4 information"\n'        
    p+='VIEW16=Rival5,"Rival 5 information"\n'        
    p+='VIEW17=Rival6,"Rival 6 information"\n'        
    p+='VIEW18=Rival7,"Rival 7 information"\n'        
    p+='VIEW19=Rival8,"Rival 8 information"\n'        
    p+='VIEW20=Rival9,"Rival 9 information"\n'        
    p+='VIEW21=Rival10,"Rival 10 information"\n'      
    p+='VIEW22=DriverDetai,"Driver details"\n'        
    p+='VIEW23=RiderDetail,"Rider details"\n'         
    p+='VIEW24=IsldDetails,"Island details"\n'        
    p+='VIEW25=Friends,"Friends List"\n'              
    p+='VIEW26=PNetworkSta,"Paradise Network Stats"\n'
    packet = create_packet('slst', '', p)
    return packet
  elif (msgType == b'sdta'):
    parse_data(data)
    p='SLOT=0\n'
    p+='STATS=0,0,0,0,0,0,0,0,0\n'
    reply = create_packet('sdta', '', p)
    return reply
  elif (msgType == b'sviw'):
    oddByte = codecs.decode('00','hex_codec')
    replyTmp=b'sviw'+pad         
    sviwStr="N=9"
    reply=sviwStr.encode('ascii')+x0A
    sviwStr="DESCS=1,1,1,1,1,1,1,1,1"
    reply+=sviwStr.encode('ascii')+x0A
    sviwStr="NAMES=0,3,4,5,6,7,8,9,10"
    reply+=sviwStr.encode('ascii')+x0A
    sviwStr="PARAMS=2,2,2,2,2,2,2,2,2"
    reply+=sviwStr.encode('ascii')+x0A
    sviwStr="SYMS=TOTCOM,a,0,TAKEDNS,RIVALS,ACHIEV,FBCHAL,RANK,WINS,SNTTEAM,SNTFFA"
    reply+=sviwStr.encode('ascii')+x0A
    sviwStr="TYPES=~num,~num,~num,~num,~rnk,~num,~pts,~pts"
    reply+=sviwStr.encode('ascii')+x0A
    sviwStr="SS=65"
    reply+=sviwStr.encode('ascii')+codecs.decode('0A00','hex_codec')
    oddByte=len(codecs.decode(reply,'latin1'))+12
    oddByte = codecs.decode('{0:x}'.format(int(oddByte)),'hex_codec')
    reply=replyTmp+oddByte+reply
    print("REPLY: "+reply.decode('latin1'))
  elif (msgType == b'uatr'):
    time.sleep(1)
    #reply = reply_who()
    #print("REPLY: "+reply.decode('latin1'))
  elif (msgType == b'usld'):
    parse_data(data)
    p =  'IMGATE=0\n'
    p += 'QMSG0=TEST0\n'
    p += 'QMSG1=TEST1\n'
    p += 'QMSG2=TEST2\n'
    p += 'QMSG3=TEST3\n'
    p += 'QMSG4=TEST4\n'
    p += 'QMSG5=TEST5\n'
    p += 'SPM_EA=0\n'
    p += 'SPM_PART=0\n'
    p += 'UID=$000000000b32588d\n'
    packet = create_packet('usld', '', p)
    return packet
    time.sleep(1)
  elif (msgType == b'user'):
    parse_data(data)
    p="NAME="+clientNAME+"\n"
    reply = create_packet('user', '', p)
  if (msgType == b'USCH'):
    parse_data(data)    
    p="NAME=test\n"
    reply = create_packet('USER', '', p)    

  return reply
       
def threaded_client(connection):
  global SKEYREPLY, SKEYSENT, z, ping_cnt, ping_start, curr_time, ping_time, ping_sent,pingTIME
  global pad,pad2,x00,x0A,oddByte,reply,msgType,msgSize,authsent,NO_DATA,news_cnt
  connection.settimeout(500)
  while True:        
    curr_time=time.time()
    print("Ping Diff: "+str(curr_time - ping_start))
    if (((curr_time - ping_start) > 2.5)):
      reply = reply_ping('')
      connection.sendall((reply))
      ping_start=time.time()
    try:           	
     tmp = connection.recv(12)
     NO_DATA=False     
    except:
     print("D3")
     NO_DATA=True     
     curr_time=time.time()     
    if len(tmp) != 0:
      msgType = tmp[:4]
      if msgType != b'~png':
      	print("RECV: "+str(msgType))
      #print("Debug: "+str(len(tmp)))
      if tmp[10] == 0:
        msgSize=tmp[11]
        #print("SIZE1: "+(str(msgSize)))
      else:
        msgSize = tmp[10]
        msgSize +=tmp[11]
        print("Debug: "+(str(msgSize)))
        if msgSize == 1:
          msgSize+=255
        else:
          msgSize = int(struct.unpack(">h",bytes(str(msgSize),'ascii'))[0])
          #print("SIZE2: "+(str(msgSize)))    
      msgSize = msgSize - 12
      data = connection.recv(msgSize)
      if msgType != b'~png':
      	print("SIZE: "+(str(msgSize)))
      reply = build_reply(data)
      connection.sendall((reply))
      if (msgType == b'pers'):
        time.sleep(1)
        reply = reply_who()
        connection.sendall((reply))
      if (msgType == b'AUTH') | (msgType == b'onln'):
        reply = reply_ping(data)
        time.sleep(1)
        connection.sendall((reply))
      if (msgType == b'sviw'):
        reply = reply_who()
        connection.sendall((reply))        
        ping_cnt=1
        ping_start=time.time()
        reply = reply_ping(data)
        time.sleep(1)
        connection.sendall((reply))
      if (msgType == b'gsea'):
        reply = reply_rom()
        connection.sendall((reply))
      if (msgType == b'room'):
        reply = reply_rom()
        connection.sendall((reply))
      if (msgType == b'move'):
        reply = reply_pop()
        connection.sendall((reply))
        reply = reply_usr()
        connection.sendall((reply))              
    #print("D5")
    #if (msgType == b'fget'):
      #parse_data(data)
      #p =  'FLUP=0\n'
      #packet = create_packet('+fup', '', p)
      #connection.sendall((packet))

# *** START *** #
print("VTSTech-SRVEmu v"+BUILD+"\nGitHub: https://github.com/Veritas83/VTSTech-SRVEmu\nContributors: No23\n")

for x in range(0,TOTALARGS,1):
  if (TOTALARGS >= 6):  
    print("Too many arguments! Check command line.")
    usage()
    exit()
  if (sys.argv[x] == "-i"):
    SERVER_IP = sys.argv[x+1]
    SERVER_IP_BIN = b'ADDR='+bytes(SERVER_IP,'ascii')    

bind()
print('Waiting for connections.. ')
reply=b''

while True:
    print("D6")
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
    print("D7")