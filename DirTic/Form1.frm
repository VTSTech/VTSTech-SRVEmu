VERSION 5.00
Object = "{248DD890-BB45-11CF-9ABC-0080C7E7B78D}#1.0#0"; "MSWINSCK.OCX"
Begin VB.Form Form1 
   BackColor       =   &H00000000&
   Caption         =   "SRVEmu GUI v0.1"
   ClientHeight    =   7440
   ClientLeft      =   60
   ClientTop       =   345
   ClientWidth     =   9255
   LinkTopic       =   "Form1"
   ScaleHeight     =   7440
   ScaleWidth      =   9255
   StartUpPosition =   1  'CenterOwner
   Begin VB.TextBox Text5 
      BeginProperty Font 
         Name            =   "Verdana"
         Size            =   9
         Charset         =   0
         Weight          =   400
         Underline       =   0   'False
         Italic          =   0   'False
         Strikethrough   =   0   'False
      EndProperty
      Height          =   315
      Left            =   120
      TabIndex        =   16
      Text            =   "222.222.222.222"
      Top             =   480
      Width           =   1695
   End
   Begin VB.ComboBox Combo1 
      BeginProperty Font 
         Name            =   "Verdana"
         Size            =   9
         Charset         =   0
         Weight          =   400
         Underline       =   0   'False
         Italic          =   0   'False
         Strikethrough   =   0   'False
      EndProperty
      Height          =   330
      Left            =   120
      TabIndex        =   15
      Text            =   "Combo1"
      Top             =   120
      Width           =   3975
   End
   Begin VB.CheckBox Check3 
      BackColor       =   &H80000007&
      Caption         =   "Binary"
      BeginProperty Font 
         Name            =   "Verdana"
         Size            =   9
         Charset         =   0
         Weight          =   400
         Underline       =   0   'False
         Italic          =   0   'False
         Strikethrough   =   0   'False
      EndProperty
      ForeColor       =   &H8000000A&
      Height          =   195
      Left            =   7560
      TabIndex        =   14
      Top             =   600
      Width           =   975
   End
   Begin MSWinsockLib.Winsock Winsock1 
      Left            =   8160
      Top             =   6960
      _ExtentX        =   741
      _ExtentY        =   741
      _Version        =   393216
   End
   Begin VB.CommandButton Command4 
      Caption         =   "Convert"
      BeginProperty Font 
         Name            =   "Verdana"
         Size            =   9
         Charset         =   0
         Weight          =   400
         Underline       =   0   'False
         Italic          =   0   'False
         Strikethrough   =   0   'False
      EndProperty
      Height          =   255
      Left            =   6480
      TabIndex        =   12
      Top             =   600
      Width           =   975
   End
   Begin VB.TextBox Text4 
      BeginProperty Font 
         Name            =   "Verdana"
         Size            =   9
         Charset         =   0
         Weight          =   400
         Underline       =   0   'False
         Italic          =   0   'False
         Strikethrough   =   0   'False
      EndProperty
      Height          =   5775
      Left            =   6600
      MultiLine       =   -1  'True
      ScrollBars      =   2  'Vertical
      TabIndex        =   11
      Text            =   "Form1.frx":0000
      Top             =   960
      Width           =   2535
   End
   Begin VB.TextBox Text3 
      BeginProperty Font 
         Name            =   "Verdana"
         Size            =   9
         Charset         =   0
         Weight          =   400
         Underline       =   0   'False
         Italic          =   0   'False
         Strikethrough   =   0   'False
      EndProperty
      Height          =   855
      Left            =   120
      MultiLine       =   -1  'True
      ScrollBars      =   2  'Vertical
      TabIndex        =   10
      Text            =   "Form1.frx":0006
      Top             =   960
      Width           =   6375
   End
   Begin VB.CommandButton Command3 
      Caption         =   "Reset"
      BeginProperty Font 
         Name            =   "Verdana"
         Size            =   9
         Charset         =   0
         Weight          =   400
         Underline       =   0   'False
         Italic          =   0   'False
         Strikethrough   =   0   'False
      EndProperty
      Height          =   255
      Left            =   5760
      TabIndex        =   9
      Top             =   600
      Width           =   735
   End
   Begin VB.CommandButton Command2 
      Caption         =   "Send"
      BeginProperty Font 
         Name            =   "Verdana"
         Size            =   9
         Charset         =   0
         Weight          =   400
         Underline       =   0   'False
         Italic          =   0   'False
         Strikethrough   =   0   'False
      EndProperty
      Height          =   255
      Left            =   5010
      TabIndex        =   7
      Top             =   600
      Width           =   735
   End
   Begin VB.Timer Timer1 
      Left            =   8640
      Top             =   6960
   End
   Begin VB.TextBox Text2 
      BeginProperty Font 
         Name            =   "Verdana"
         Size            =   9
         Charset         =   0
         Weight          =   400
         Underline       =   0   'False
         Italic          =   0   'False
         Strikethrough   =   0   'False
      EndProperty
      Height          =   4815
      Left            =   120
      MultiLine       =   -1  'True
      ScrollBars      =   2  'Vertical
      TabIndex        =   4
      Text            =   "Form1.frx":000C
      Top             =   1920
      Width           =   6375
   End
   Begin VB.CheckBox Check2 
      BackColor       =   &H00000000&
      Caption         =   "UDP"
      BeginProperty Font 
         Name            =   "Verdana"
         Size            =   9
         Charset         =   0
         Weight          =   400
         Underline       =   0   'False
         Italic          =   0   'False
         Strikethrough   =   0   'False
      EndProperty
      ForeColor       =   &H00808080&
      Height          =   255
      Left            =   5040
      TabIndex        =   3
      Top             =   120
      Width           =   735
   End
   Begin VB.CheckBox Check1 
      BackColor       =   &H00000000&
      Caption         =   "TCP"
      BeginProperty Font 
         Name            =   "Verdana"
         Size            =   9
         Charset         =   0
         Weight          =   400
         Underline       =   0   'False
         Italic          =   0   'False
         Strikethrough   =   0   'False
      EndProperty
      ForeColor       =   &H00808080&
      Height          =   255
      Left            =   4280
      TabIndex        =   2
      Top             =   120
      Width           =   735
   End
   Begin VB.CommandButton Command1 
      Caption         =   "Listen"
      BeginProperty Font 
         Name            =   "Verdana"
         Size            =   9
         Charset         =   0
         Weight          =   400
         Underline       =   0   'False
         Italic          =   0   'False
         Strikethrough   =   0   'False
      EndProperty
      Height          =   255
      Left            =   4260
      TabIndex        =   1
      Top             =   600
      Width           =   735
   End
   Begin VB.TextBox Text1 
      BeginProperty Font 
         Name            =   "Verdana"
         Size            =   9
         Charset         =   0
         Weight          =   400
         Underline       =   0   'False
         Italic          =   0   'False
         Strikethrough   =   0   'False
      EndProperty
      Height          =   315
      Left            =   1800
      TabIndex        =   0
      Text            =   "Port"
      Top             =   480
      Width           =   735
   End
   Begin MSWinsockLib.Winsock Winsock2 
      Left            =   7680
      Top             =   6960
      _ExtentX        =   741
      _ExtentY        =   741
      _Version        =   393216
   End
   Begin MSWinsockLib.Winsock Winsock3 
      Left            =   7200
      Top             =   6960
      _ExtentX        =   741
      _ExtentY        =   741
      _Version        =   393216
   End
   Begin VB.Label Label4 
      AutoSize        =   -1  'True
      BackColor       =   &H00000000&
      Caption         =   "1ByfBujg9bnmk1XXY2rxY6obhqHMUNiDuP"
      BeginProperty Font 
         Name            =   "Verdana"
         Size            =   9
         Charset         =   0
         Weight          =   400
         Underline       =   0   'False
         Italic          =   0   'False
         Strikethrough   =   0   'False
      EndProperty
      ForeColor       =   &H00FFFF00&
      Height          =   210
      Left            =   2677
      TabIndex        =   13
      Top             =   7200
      Width           =   3900
   End
   Begin VB.Label Label3 
      AutoSize        =   -1  'True
      BackColor       =   &H00000000&
      Caption         =   "VTSTech Veritas Technical Solutions"
      BeginProperty Font 
         Name            =   "Verdana"
         Size            =   9
         Charset         =   0
         Weight          =   400
         Underline       =   0   'False
         Italic          =   0   'False
         Strikethrough   =   0   'False
      EndProperty
      ForeColor       =   &H00FFFF00&
      Height          =   210
      Left            =   2917
      TabIndex        =   8
      Top             =   6960
      Width           =   3345
   End
   Begin VB.Label Label2 
      AutoSize        =   -1  'True
      BackColor       =   &H00000000&
      Caption         =   "Socket States:"
      BeginProperty Font 
         Name            =   "Verdana"
         Size            =   9
         Charset         =   0
         Weight          =   400
         Underline       =   0   'False
         Italic          =   0   'False
         Strikethrough   =   0   'False
      EndProperty
      ForeColor       =   &H00C0C0C0&
      Height          =   210
      Left            =   5880
      TabIndex        =   6
      Top             =   120
      Width           =   1380
   End
   Begin VB.Label Label1 
      AutoSize        =   -1  'True
      BackColor       =   &H00000000&
      Caption         =   "Written by Veritas"
      BeginProperty Font 
         Name            =   "Verdana"
         Size            =   9
         Charset         =   0
         Weight          =   400
         Underline       =   0   'False
         Italic          =   0   'False
         Strikethrough   =   0   'False
      EndProperty
      ForeColor       =   &H00FFFF00&
      Height          =   210
      Left            =   3622
      TabIndex        =   5
      Top             =   6720
      Width           =   1710
   End
End
Attribute VB_Name = "Form1"
Attribute VB_GlobalNameSpace = False
Attribute VB_Creatable = False
Attribute VB_PredeclaredId = True
Attribute VB_Exposed = False
Public Data, DataLen, OutStr
Dim DataVal(9999)
Public Buff
Public out
Public x, y, num, value, tmp2, tmp3
Public msgType, pad, msgLen, fso, subCmd
Public DataStr As String
Public DataPrev As String
Public moreCmd As Boolean
Public clientALTS, clientNAME, clientVERS, clientMAC, clientPERS, clientPERSONAS, clientBORN, clientMAIL, clientSKU
Public clientPLAST, clientMADDR, clientUSER, clientMINSIZE, clientMAXSIZE, clientPARAMS, clientCUSTFLAGS, clientPRIV
Public clientSESS, clientSLUS, clientPID, clientDEFPER, clientLAST, clientSEED, clientSYSFLAGS, clientSKEY
Public NEWS_PAYLOAD, clientLKEY, clientPROD, pingREF, pingTIME, roomNAME, ParseTmp, skeyStr
'Option Explicit
Private Declare Sub Sleep Lib "kernel32" (ByVal dwMilliseconds As Long)
Public Function HexToString(ByVal HexToStr As String) As String
Dim strTemp   As String
Dim strReturn As String
Dim i         As Long
    For i = 1 To Len(HexToStr) Step 3
        strTemp = Chr$(Val("&H" & Mid$(HexToStr, i, 2)))
        strReturn = strReturn & strTemp
    Next i
    HexToString = strReturn
End Function
Public Function StringToHex(ByVal StrToHex As String) As String
Dim strTemp   As String
Dim strReturn As String
Dim i         As Long
    For i = 1 To Len(StrToHex)
        strTemp = Hex$(Asc(Mid$(StrToHex, i, 1)))
        If Len(strTemp) = 1 Then strTemp = "0" & strTemp
        strReturn = strReturn & Space$(1) & strTemp
    Next i
    StringToHex = strReturn
    StringToHex = LTrim(StringToHex)
End Function
Public Function HexToBin(HexNum As String) As String
Dim strTemp   As String
Dim strReturn As String
Dim i         As Long
    For i = 1 To Len(HexNum) Step 3
        strTemp = Chr(Val("&H" & (Mid$(HexNum, i, 2))))
        'MsgBox Mid$(HexNum, i, 2)
        strReturn = strReturn & strTemp
    Next i
    HexToBin = strReturn
End Function
Public Function StrToBin(strTemp As String) As String
    binReturn = HexToBin(StringToHex(strTemp))
    StrToBin = binReturn
End Function
Public Function GetParams(msgType, params)
For x = 0 To UBound(params)
    If x = 0 Then
        y = 13
    Else
        y = 1
    End If
    If Mid(HexToString(Trim(params(x))), y, 4) = "MID=" Then
        clientMID = Mid(HexToString(Trim(params(x))), y + 4, Len(HexToString(Trim(params(x)))))
    ElseIf Mid(HexToString(Trim(params(x))), y, 4) = "PID=" Then
        clientPID = Mid(HexToString(Trim(params(x))), y + 4, Len(HexToString(Trim(params(x)))))
    ElseIf Mid(HexToString(Trim(params(x))), y, 4) = "SKU=" Then
        clientSKU = Mid(HexToString(Trim(params(x))), y + 4, Len(HexToString(Trim(params(x)))))
    ElseIf Mid(HexToString(Trim(params(x))), y, 5) = "ALTS=" Then
      clientALTS = Mid(HexToString(Trim(params(x))), y + 4, Len(HexToString(Trim(params(x)))))
    ElseIf Mid(HexToString(Trim(params(x))), y, 5) = "VERS=" Then
        clientVERS = Mid(HexToString(Trim(params(x))), y + 5, Len(HexToString(Trim(params(x)))))
    ElseIf Mid(HexToString(Trim(params(x))), y, 5) = "BORN=" Then
      clientBORN = Mid(HexToString(Trim(params(x))), y + 5, Len(HexToString(Trim(params(x)))))
    ElseIf Mid(HexToString(Trim(params(x))), y, 5) = "SLUS=" Then
      clientSLUS = Mid(HexToString(Trim(params(x))), y + 5, Len(HexToString(Trim(params(x)))))
    ElseIf Mid(HexToString(Trim(params(x))), y, 5) = "VERS=" Then
      clientVERS = Mid(HexToString(Trim(params(x))), y + 5, Len(HexToString(Trim(params(x)))))
    ElseIf Mid(HexToString(Trim(params(x))), y, 5) = "NAME=" Then
        If msgType = "news" Then
            subCmd = "new" & Mid(HexToString(Trim(params(x))), y + 5, 1)
        Else
            clientNAME = Mid(HexToString(Trim(params(x))), y + 5, Len(HexToString(Trim(params(x)))))
        End If
    ElseIf Mid(HexToString(Trim(params(x))), y, 5) = "USER=" Then
      clientUSER = Mid(HexToString(Trim(params(x))), y + 5, Len(HexToString(Trim(params(x)))))
    ElseIf Mid(HexToString(Trim(params(x))), y, 5) = "PASS=" Then
      clientPASS = Mid(HexToString(Trim(params(x))), y + 5, Len(HexToString(Trim(params(x)))))
    ElseIf Mid(HexToString(Trim(params(x))), y, 5) = "PERS=" Then
      clientPERS = Mid(HexToString(Trim(params(x))), y + 5, Len(HexToString(Trim(params(x)))))
    ElseIf Mid(HexToString(Trim(params(x))), y, 5) = "PROD=" Then
      clientPROD = Mid(HexToString(Trim(params(x))), y + 5, Len(HexToString(Trim(params(x)))))
    ElseIf Mid(HexToString(Trim(params(x))), y, 5) = "SKEY=" Then
      clientSKEY = Mid(HexToString(Trim(params(x))), y + 5, Len(HexToString(Trim(params(x)))))
    ElseIf Mid(HexToString(Trim(params(x))), y, 5) = "SEED=" Then
      clientSEED = Mid(HexToString(Trim(params(x))), y + 5, Len(HexToString(Trim(params(x)))))
    ElseIf Mid(HexToString(Trim(params(x))), y, 5) = "MAIL=" Then
      clientMAIL = Mid(HexToString(Trim(params(x))), y + 5, Len(HexToString(Trim(params(x)))))
    ElseIf Mid(HexToString(Trim(params(x))), y, 5) = "LAST=" Then
      clientLAST = Mid(HexToString(Trim(params(x))), y + 5, Len(HexToString(Trim(params(x)))))
    ElseIf Mid(HexToString(Trim(params(x))), y, 5) = "LKEY=" Then
      clientLKEY = Mid(HexToString(Trim(params(x))), y + 5, Len(HexToString(Trim(params(x)))))
    ElseIf Mid(HexToString(Trim(params(x))), y, 5) = "PRIV=" Then
      clientPRIV = Mid(HexToString(Trim(params(x))), y + 5, Len(HexToString(Trim(params(x)))))
    ElseIf Mid(HexToString(Trim(params(x))), y, 6) = "PLAST=" Then
      clientPLAST = Mid(HexToString(Trim(params(x))), y + 6, Len(HexToString(Trim(params(x)))))
    ElseIf Mid(HexToString(Trim(params(x))), y, 6) = "MADDR=" Then
      clientMADDR = Mid(HexToString(Trim(params(x))), y + 6, Len(HexToString(Trim(params(x)))))
    ElseIf Mid(HexToString(Trim(params(x))), y, 7) = "HWFLAG=" Then
      clientHWFLAG = Mid(HexToString(Trim(params(x))), y + 7, Len(HexToString(Trim(params(x)))))
    ElseIf Mid(HexToString(Trim(params(x))), y, 7) = "HWMASK=" Then
      clientHWMASK = Mid(HexToString(Trim(params(x))), y + 7, Len(HexToString(Trim(params(x)))))
    ElseIf Mid(HexToString(Trim(params(x))), y, 7) = "DEFPER=" Then
      clientDEFPER = Mid(HexToString(Trim(params(x))), y + 7, Len(HexToString(Trim(params(x)))))
    ElseIf Mid(HexToString(Trim(params(x))), y, 7) = "PARAMS=" Then
      clientPARAMS = Mid(HexToString(Trim(params(x))), y + 7, Len(HexToString(Trim(params(x)))))
    ElseIf Mid(HexToString(Trim(params(x))), y, 7) = "SDKVER=" Then
      clientSDKVER = Mid(HexToString(Trim(params(x))), y + 7, Len(HexToString(Trim(params(x)))))
    ElseIf Mid(HexToString(Trim(params(x))), y, 8) = "MINSIZE=" Then
      clientMINSIZE = Mid(HexToString(Trim(params(x))), y + 8, Len(HexToString(Trim(params(x)))))
    ElseIf Mid(HexToString(Trim(params(x))), y, 8) = "MAXSIZE=" Then
      clientMAXSIZE = Mid(HexToString(Trim(params(x))), y + 8, Len(HexToString(Trim(params(x)))))
    ElseIf Mid(HexToString(Trim(params(x))), y, 9) = "PERSONAS=" Then
      clientPERSONAS = Mid(HexToString(Trim(params(x))), y + 9, Len(HexToString(Trim(params(x)))))
    ElseIf Mid(HexToString(Trim(params(x))), y, 9) = "SYSFLAGS=" Then
      clientSYSFLAGS = Mid(HexToString(Trim(params(x))), y + 9, Len(HexToString(Trim(params(x)))))
    ElseIf Mid(HexToString(Trim(params(x))), y, 10) = "CUSTFLAGS=" Then
      clientCUSTFLAGS = Mid(HexToString(Trim(params(x))), y + 10, Len(HexToString(Trim(params(x)))))
    End If
Next x
End Function
Public Function ParseData(DataStr As String)
moar:
Buff = Text2.Text
pad = HexToBin("00 00 00 00 00 00 00")
'MsgBox (DataStr)
If DataStr = "moreCmd" Or (msgType = "skey" And Len(clientSKEY) <= 1) Or moreCmd = True Then
    DataStr = DataPrev
    cmds = Split(DataStr, "0A 00")
    DataStr = cmds(1)
    moreCmd = False
End If
cmds = Split(DataStr, "0A 00")
params = Split(cmds(0), "0A")
'MsgBox UBound(params)
If UBound(cmds) >= 1 Then
    If Len(cmds(1)) >= 1 Then
        moreCmd = True
    Else
        moreCmd = False
    End If
End If
DataStr = Trim(DataStr)
msgType = Mid(HexToString(DataStr), 1, 4)
'subCmd = Mid(HexToString(DataStr), 5, 4)
msgSize = Mid(HexToString(DataStr), 12, 1)

Text2.Text = Buff & vbCrLf & "[+] Received: " & msgType & " Size: " & Asc(msgSize) & vbCrLf
Buff = Text2.Text
Text2.Text = Buff & vbCrLf & (Mid(HexToString(DataStr), 13, Len(HexToString(DataStr)) - 3)) & vbCrLf
Buff = Text2.Text

OutStr = ""
a = GetParams(msgType, params)

If msgType = "@dir" Then
    OutStr = "ADDR=192.168.0.228" & Chr(10)
    OutStr = OutStr & "PORT=10901" & Chr(10)
    OutStr = OutStr & "SESS=1337420011" & Chr(10)
    OutStr = OutStr & "MASK=f3f7f3f70ecb1757cd7001b9a7af3f7" & Chr(10)
    msgLen = Len(msgType) + 8 + Len(OutStr) + 1
    ParseData = msgType & pad & Chr(msgLen) & OutStr & Chr(0)
ElseIf msgType = "sele" Then
    OutStr = "USERS=0" & Chr(10)
    OutStr = OutStr & "GAMES=0" & Chr(10)
    OutStr = OutStr & "MYGAME=1" & Chr(10)
    OutStr = OutStr & "ROOMS=0" & Chr(10)
    OutStr = OutStr & "MESGS=0" & Chr(10)
    'OutStr = OutStr & "ASYNC=1" & Chr(10)
    OutStr = OutStr & "USERSETS=0" & Chr(10)
    OutStr = OutStr & "MESGTYPES=100728964" & Chr(10)
    OutStr = OutStr & "STATS=0" & Chr(10)
    msgLen = Len(msgType) + 8 + Len(OutStr) + 1
    ParseData = msgType & pad & Chr(msgLen) & OutStr & Chr(0)
    'Sleep (200)
ElseIf msgType = "skey" Then
    'a = GetParams(msgType, params)
    OutStr = "SKEY=$37940faf2a8d1381a3b7d0d2f570e6a7" & Chr(10)
    msgLen = Len(msgType) + 8 + Len(OutStr) + 1
    skeyStr = msgType & pad & Chr(msgLen) & OutStr & Chr(0)
    ParseData = msgType & pad & Chr(msgLen) & OutStr & Chr(0)
ElseIf msgType = "auth" Then
    OutStr = "TOS=1" & Chr(10)
    OutStr = OutStr & "NAME=" & clientNAME & Chr(10)
    OutStr = OutStr & "MAIL=nospam@no.no" & Chr(10)
    OutStr = OutStr & "PERSONAS=" & clientNAME & ",is,reviving,games" & Chr(10)
    OutStr = OutStr & "BORN=19800325" & Chr(10)
    OutStr = OutStr & "GEND=M" & Chr(10)
    OutStr = OutStr & "FROM=US" & Chr(10)
    OutStr = OutStr & "LANG=en" & Chr(10)
    OutStr = OutStr & "SPAM=NN" & Chr(10)
    OutStr = OutStr & "SINCE=2021.03.05-11:11:11" & Chr(10)
    OutStr = OutStr & "LAST=2021.03.05-11:11:11" & Chr(10)
    'OutStr = OutStr & "SINCE=2021.03.05-11:11:11" & Chr(10)
    msgLen = Len(msgType) + 8 + Len(OutStr) + 1
    ParseData = msgType & pad & Chr(msgLen) & OutStr & Chr(0)
ElseIf msgType = "news" Then
    a = GetParams(msgType, params)
    pad2 = HexToBin("00 00 00")
    OutStr = "BUDDY_SERVER=" & Winsock3.LocalIP & Chr(10)
    OutStr = OutStr & "BUDDY_PORT=" & Winsock3.LocalPort & Chr(10)
    OutStr = OutStr & "NEWS_URL=http://ps3burnout08.ea.com/news.txt" & Chr(10)
    OutStr = OutStr & "TOSAC_URL=http://ps3burnout08.ea.com/TOSAC.txt" & Chr(10)
    'OutStr = OutStr & "TOSA_URL=http://ps3burnout08.ea.com/TOSA.txt" & Chr(10)
    OutStr = OutStr & "TOS_URL=http://ps3burnout08.ea.com/TOS.txt" & Chr(10)
    'OutStr = OutStr & "LIVE_NEWS_URL=http://ps3burnout08.ea.com/LIVE.txt" & Chr(10)
    'OutStr = OutStr & "LIVE_NEWS2_URL=http://ps3burnout08.ea.com/LIVE2.txt" & Chr(10)
    'OutStr = OutStr & "PRODUCT_SEARCH_URL=http://ps3burnout08.ea.com/PROD.txt" & Chr(10)
    'OutStr = OutStr & "AVATAR_URL=http://ps3burnout08.ea.com/AV.txt" & Chr(10)
    'OutStr = OutStr & "STORE_URL=http://ps3burnout08.ea.com/STORE.txt" & Chr(10)
    'OutStr = OutStr & "LIVE_NEWS_URL_IMAGE_PATH=." & Chr(10)
    msgLen = Len(msgType) + 8 + Len(OutStr) + 1
    If msgLen >= 256 Then
        pad2 = HexToBin("00 00 02 01")
        'ParseTmp = ""
        ParseTmp = msgType & subCmd & pad2 & OutStr & Chr(0)
    Else
        'ParseTmp = ""
        ParseTmp = msgType & subCmd & pad2 & Chr(msgLen) & OutStr & Chr(0)
    End If
    'If moreCmd = False Then
    '    Sleep (200)
    '    Winsock2.SendData ParseTmp
    'End If
    ParseData = msgType & subCmd & pad2 & Chr(msgLen) & OutStr & Chr(0)
ElseIf msgType = "onln" Then
    OutStr = "PERS=VTSTech" & Chr(10)
    msgLen = Len(msgType) + 8 + Len(OutStr) + 1
    ParseData = msgType & pad & Chr(msgLen) & OutStr & Chr(0)
ElseIf msgType = "pers" Then
    'PERS=VTSTech
    'MID=$00041f828759
    'PID=SSX-PS2-2004
    OutStr = "LOC=en" & Chr(10)
    OutStr = OutStr & "MA=$00041f828759" & Chr(10)
    OutStr = OutStr & "PERS=" & clientNAME & Chr(10)
    OutStr = OutStr & "NAME=" & clientNAME & Chr(10)
    OutStr = OutStr & "LAST=2021.03.05-11:11:11" & Chr(10)
    'OutStr = OutStr & "PLAST=2021.03.05-11:11:11" & Chr(10)
    'OutStr = OutStr & "PSINCE=2021.03.05-11:11:11" & Chr(10)
    OutStr = OutStr & "LKEY=3fcf27540c92935b0a66fd3b0000283c" & Chr(10)
    msgLen = Len(msgType) + 8 + Len(OutStr) + 1
    ParseData = msgType & pad & Chr(msgLen) & OutStr & Chr(0)
ElseIf msgType = "sviw" Then
    OutStr = "N=5" & Chr(10)
    OutStr = OutStr & "DESC=1,1,1,1,1" & Chr(10)
    OutStr = OutStr & "NAMES=0,3,4,5,6" & Chr(10)
    OutStr = OutStr & "PARAMS=2,2,2,2,2" & Chr(10)
    'OutStr = OutStr & "SYMS=TOTCOM,a,0,TAKEDNS,RIVALS,ACHIEV,FBCHAL,RANK,WINS,SNTTEAM,SNTFFA" & Chr(10)
    'OutStr = OutStr & "TYPES=~num,~num,~num,~num,~rnk,~num,~pts,~pts" & Chr(10)
    'OutStr = OutStr & "SS=65" & Chr(10)
    msgLen = Len(msgType) + 8 + Len(OutStr) + 1
    ParseData = msgType & pad & Chr(msgLen) & OutStr & Chr(0)
End If
DataPrev = DataStr
'ParseData = ParseData
End Function

Private Sub Combo1_Click()
Winsock1.Close
Winsock2.Close
Winsock3.Close
'Burnout 3 Takedown, 0
'Burnout 3 Takedown (Review), 1
'Burnout Paradise (PS3), 2
'Need for Speed: Underground, 3
'Madden NFL 05, 4
'NASCAR Thunder 2004, 5
'SSX3, 6
If Combo1.ListIndex = 0 Then
    Winsock1.LocalPort = 21800
ElseIf Combo1.ListIndex = 1 Then
    Winsock1.LocalPort = 21840
ElseIf Combo1.ListIndex = 2 Then
    Winsock1.LocalPort = 21870
ElseIf Combo1.ListIndex = 3 Then
    Winsock1.LocalPort = 10900
ElseIf Combo1.ListIndex = 4 Then
    Winsock1.LocalPort = 20000
ElseIf Combo1.ListIndex = 5 Then
    Winsock1.LocalPort = 10600
ElseIf Combo1.ListIndex = 6 Then
    Winsock1.LocalPort = 11000
End If
Text1.Text = Winsock1.LocalPort
End Sub

Private Sub Command1_Click()
clientSKEY = ""
moreCmd = False
ParseTmp = ""
tmp2 = ""
tmp3 = ""
If Command1.Caption = "Stop" Then
Winsock1.Close
Winsock2.Close
Winsock3.Close
Command1.Caption = "Listen"
GoTo fin
End If

If Check1.Enabled = True Then
    Winsock1.Protocol = sckTCPProtocol
    Winsock2.Protocol = sckTCPProtocol
    Winsock3.Protocol = sckTCPProtocol
ElseIf Check2.Enabled = True Then
    Winsock1.Protocol = sckUDPProtocol
    Winsock2.Protocol = sckUDPProtocol
    Winsock3.Protocol = sckUDPProtocol
End If

If Text1.Text = "Port" Then
    MsgBox "Error. Select a port"
GoTo fin
Else
    Winsock1.LocalPort = Val(Text1.Text) 'Game
    Winsock2.LocalPort = 10901 'Listener
    Winsock3.LocalPort = 10899 'Buddy
End If

Winsock1.Listen
Winsock2.Listen
Winsock3.Listen
Text2.Text = "[+] Now listening on " & Winsock1.LocalIP & ":" & Winsock1.LocalPort & "..." & vbCrLf
Text2.Text = Text2.Text & "[+] Now listening on " & Winsock2.LocalIP & ":" & Winsock2.LocalPort & "..." & vbCrLf
Text2.Text = Text2.Text & "[+] Now listening on " & Winsock3.LocalIP & ":" & Winsock3.LocalPort & "..." & vbCrLf
Command1.Caption = "Stop"
Buff = Text2.Text
fin:
End Sub

Private Sub Command2_Click()
If Winsock1.State = 0 Then
MsgBox "Error. Cannot send thru a closed socket"
GoTo fin
ElseIf Winsock1.State = 2 Then
MsgBox "Error. Wait for something to send to"
GoTo fin
ElseIf Winsock1.State = 9 Then
MsgBox "Error. Connection has been lost"
GoTo fin
End If
out = Text3.Text
out = HexToString(out)
Winsock1.SendData (out)
Buff = Text2.Text
Text2.Text = Buff & vbCrLf & "[-] Sent: " & StringToHex(out) & vbCrLf
fin:
End Sub

Private Sub Command3_Click()
Winsock1.Close
Winsock1.RemotePort = 80
Text2.Text = ""
Text1.Text = 80
Command1.Caption = "Listen"
End Sub

Private Sub Command4_Click()
If Check3.value = False Then
    If Mid(Text4.Text, 3, 1) = " " And Mid(Text4.Text, 6, 1) = " " Then
        Text4.Text = HexToString(Text4.Text)
    Else
        Text4.Text = StringToHex(Text4.Text)
    End If
Else
    If Mid(Text4.Text, 3, 1) = " " And Mid(Text4.Text, 6, 1) = " " Then
        Open VB.App.Path & "\out.bin" For Binary Access Write As #1
        Put #1, 1, HexToBin(Text4.Text)
        Close #1
    End If
    MsgBox "out.bin written"
End If
End Sub

Private Sub Form_Load()
On Error Resume Next
'Game Socket Port
Set fso = CreateObject("Scripting.FileSystemObject")

Build = "0.1-R2"
Form1.Caption = "VTSTech-SRVEmu v" & Build
Text1.Text = 21800
Check1.value = 1

Combo1.Text = "Burnout 3 Takedown"
Combo1.AddItem "Burnout 3 Takedown", 0
Combo1.AddItem "Burnout 3 Takedown (Review)", 1
Combo1.AddItem "Burnout Paradise (PS3)", 2
Combo1.AddItem "Need for Speed: Underground", 3
Combo1.AddItem "Madden NFL 05", 4
Combo1.AddItem "NASCAR Thunder 2004", 5
Combo1.AddItem "SSX3", 6

Text2.Text = ""
Text3.Text = "Enter data to send in hex (ex: 08 32 DB 32 B7 FF 96)"
Text4.Text = ""
Text5.Text = "192.168.0.228"

'* Game Socket
Winsock1.Bind 0, Text5.Text
Winsock1.Close
'* Listener Socket
Winsock2.Bind 0, Text5.Text
Winsock2.Close
'* Buddy Socket
Winsock3.Bind 0, Text5.Text
Winsock3.Close

Timer1.Interval = 100
Timer1.Enabled = True
End Sub

Private Sub Label3_Click()
Shell ("cmd.exe /c start http://www.VTS-Tech.org"), vbNormalFocus
End Sub

Private Sub Label4_Click()
Shell ("cmd.exe /c start bitcoin:1ByfBujg9bnmk1XXY2rxY6obhqHMUNiDuP?amount=0.02&message=donation"), vbNormalFocus
End Sub

Private Sub Timer1_Timer()
Label2.Caption = "Socket States: " & Winsock1.State & Winsock2.State & Winsock3.State
DoEvents
End Sub

Private Sub Winsock1_Close()
Buff = Text2.Text
Text2.Text = Buff & vbCrLf & "[-] Connection lost..."
End Sub

Private Sub Winsock1_ConnectionRequest(ByVal requestID As Long)
'* Game Socket
clientSKEY = ""
moreCmd = False
ParseTmp = ""
tmp2 = ""
tmp3 = ""
Winsock1.Close
Winsock1.Accept (requestID)
Buff = Text2.Text
Text2.Text = Buff & vbCrLf & "[+] Connection request (" & requestID & ") " & Winsock1.RemoteHostIP & ":" & Winsock1.RemotePort & vbCrLf
End Sub
Private Sub Winsock2_ConnectionRequest(ByVal requestID As Long)
'* Listener Socket 10901
Winsock2.Close
Winsock2.Accept (requestID)
Buff = Text2.Text
Text2.Text = Buff & vbCrLf & "[+] Connection request (" & requestID & ") " & Winsock2.RemoteHostIP & ":" & Winsock2.RemotePort & vbCrLf
End Sub
Private Sub Winsock3_ConnectionRequest(ByVal requestID As Long)
'* Buddy Socket 10899
Winsock3.Close
Winsock3.Accept (requestID)
Buff = Text2.Text
Text2.Text = Buff & vbCrLf & "[+] Connection request (" & requestID & ") " & Winsock3.RemoteHostIP & ":" & Winsock3.RemotePort & vbCrLf
End Sub
Private Sub Winsock1_DataArrival(ByVal bytesTotal As Long)
'* Game Socket
On Error Resume Next
Randomize Timer
Winsock1.GetData Data, vbString
Buff = Text2.Text
DataStr = StringToHex(Data)
DataLen = Len(Data)
tmp2 = ParseData(DataStr)
Text2.Text = Buff & Mid(tmp2, 12, Len(tmp2))
If Len(tmp2) > 1 Then
    'Sleep (250)
    Winsock1.SendData (HexToBin(StringToHex(tmp2)))
End If
If moreCmd = True Then
    Winsock1.SendData (HexToBin(StringToHex(ParseData("moreCmd"))))
End If
End Sub
Private Sub Winsock2_DataArrival(ByVal bytesTotal As Long)
'* Listener Socket 10901
On Error Resume Next
Randomize Timer
Winsock2.GetData Data, vbString
Buff = Text2.Text
DataStr = StringToHex(Data)
DataLen = Len(Data)
tmp2 = ParseData(DataStr)
Text2.Text = Buff & Mid(tmp2, 12, Len(tmp2))
If Len(ParseTmp) >= 1 Then
    'tmp3 = HexToBin(StringToHex(ParseData("moreCmd")))
    Winsock2.SendData (HexToBin(StringToHex(ParseTmp)))
Else
    If msgType = "skey" Then
        If moreCmd = True Or Len(clientSKEY) >= 1 Then
            tmp3 = ParseData(DataStr)
            Sleep (250)
            If Len(ParseTmp) >= 1 Then
                Winsock2.SendData (HexToBin(StringToHex(ParseTmp)))
            End If
            If Len(tmp2) >= 1 Then
                Winsock2.SendData (HexToBin(StringToHex(tmp2)))
            End If
        End If
        ParseTmp = ""
    End If
    If Len(tmp2) > 1 And Len(clientSKEY) >= 1 And Not msgType = "skey" Then
        Winsock2.SendData (HexToBin(StringToHex(tmp2)))
    End If
End If

If msgType = "sviw" Then
    Winsock2.SendData (HexToBin("7e 70 6e 67 00 00 00 2f 00 00 00 14 54 49 4d 45 3d 31 0a 00")) '~png
End If
End Sub

Private Sub Winsock3_DataArrival(ByVal bytesTotal As Long)
'* Buddy Socket 10899
On Error Resume Next
Randomize Timer
Winsock2.GetData Data, vbString
Buff = Text2.Text
DataStr = StringToHex(Data)
DataLen = Len(Data)
tmp2 = ParseData(DataStr)
Text2.Text = Buff & Mid(tmp2, 12, Len(tmp2))
If Len(ParseTmp) >= 1 Then
    'tmp3 = HexToBin(StringToHex(ParseData("moreCmd")))
    Winsock3.SendData (HexToBin(StringToHex(ParseTmp)))
Else
    If msgType = "skey" Then
        Winsock3.SendData (HexToBin(StringToHex(tmp2)))
        If moreCmd = True Then
            tmp3 = ParseData(DataStr)
            Sleep (250)
            Winsock3.SendData (HexToBin(StringToHex(ParseTmp)))
        End If
        ParseTmp = ""
    ElseIf Len(tmp2) > 1 Then
        Winsock3.SendData (HexToBin(StringToHex(tmp2)))
    End If
End If
End Sub
