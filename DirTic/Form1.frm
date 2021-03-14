VERSION 5.00
Object = "{248DD890-BB45-11CF-9ABC-0080C7E7B78D}#1.0#0"; "MSWINSCK.OCX"
Begin VB.Form Form1 
   BackColor       =   &H00000000&
   Caption         =   "SRVEmu GUI v0.1"
   ClientHeight    =   7440
   ClientLeft      =   60
   ClientTop       =   645
   ClientWidth     =   9900
   LinkTopic       =   "Form1"
   ScaleHeight     =   7440
   ScaleWidth      =   9900
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
      Left            =   8880
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
      Height          =   855
      Left            =   6480
      MultiLine       =   -1  'True
      ScrollBars      =   2  'Vertical
      TabIndex        =   11
      Text            =   "Form1.frx":0000
      Top             =   960
      Width           =   3375
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
      Left            =   9360
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
      Height          =   4935
      Left            =   120
      MultiLine       =   -1  'True
      ScrollBars      =   2  'Vertical
      TabIndex        =   4
      Text            =   "Form1.frx":000C
      Top             =   1800
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
      Left            =   8400
      Top             =   6960
      _ExtentX        =   741
      _ExtentY        =   741
      _Version        =   393216
   End
   Begin MSWinsockLib.Winsock Winsock3 
      Left            =   7920
      Top             =   6960
      _ExtentX        =   741
      _ExtentY        =   741
      _Version        =   393216
   End
   Begin MSWinsockLib.Winsock Winsock4 
      Index           =   0
      Left            =   9360
      Top             =   6480
      _ExtentX        =   741
      _ExtentY        =   741
      _Version        =   393216
   End
   Begin MSWinsockLib.Winsock Winsock4 
      Index           =   1
      Left            =   8880
      Top             =   6480
      _ExtentX        =   741
      _ExtentY        =   741
      _Version        =   393216
   End
   Begin MSWinsockLib.Winsock Winsock4 
      Index           =   2
      Left            =   8400
      Top             =   6480
      _ExtentX        =   741
      _ExtentY        =   741
      _Version        =   393216
   End
   Begin MSWinsockLib.Winsock Winsock4 
      Index           =   3
      Left            =   7920
      Top             =   6480
      _ExtentX        =   741
      _ExtentY        =   741
      _Version        =   393216
   End
   Begin MSWinsockLib.Winsock Winsock4 
      Index           =   4
      Left            =   9360
      Top             =   6000
      _ExtentX        =   741
      _ExtentY        =   741
      _Version        =   393216
   End
   Begin MSWinsockLib.Winsock Winsock4 
      Index           =   5
      Left            =   8880
      Top             =   6000
      _ExtentX        =   741
      _ExtentY        =   741
      _Version        =   393216
   End
   Begin MSWinsockLib.Winsock Winsock4 
      Index           =   6
      Left            =   8400
      Top             =   6000
      _ExtentX        =   741
      _ExtentY        =   741
      _Version        =   393216
   End
   Begin MSWinsockLib.Winsock Winsock4 
      Index           =   7
      Left            =   7920
      Top             =   6000
      _ExtentX        =   741
      _ExtentY        =   741
      _Version        =   393216
   End
   Begin MSWinsockLib.Winsock Winsock4 
      Index           =   8
      Left            =   9360
      Top             =   5520
      _ExtentX        =   741
      _ExtentY        =   741
      _Version        =   393216
   End
   Begin MSWinsockLib.Winsock Winsock4 
      Index           =   9
      Left            =   8880
      Top             =   5520
      _ExtentX        =   741
      _ExtentY        =   741
      _Version        =   393216
   End
   Begin MSWinsockLib.Winsock Winsock4 
      Index           =   10
      Left            =   8400
      Top             =   5520
      _ExtentX        =   741
      _ExtentY        =   741
      _Version        =   393216
   End
   Begin MSWinsockLib.Winsock Winsock4 
      Index           =   11
      Left            =   7920
      Top             =   5520
      _ExtentX        =   741
      _ExtentY        =   741
      _Version        =   393216
   End
   Begin MSWinsockLib.Winsock Winsock4 
      Index           =   12
      Left            =   9360
      Top             =   5040
      _ExtentX        =   741
      _ExtentY        =   741
      _Version        =   393216
   End
   Begin MSWinsockLib.Winsock Winsock4 
      Index           =   13
      Left            =   8880
      Top             =   5040
      _ExtentX        =   741
      _ExtentY        =   741
      _Version        =   393216
   End
   Begin MSWinsockLib.Winsock Winsock4 
      Index           =   14
      Left            =   8400
      Top             =   5040
      _ExtentX        =   741
      _ExtentY        =   741
      _Version        =   393216
   End
   Begin MSWinsockLib.Winsock Winsock4 
      Index           =   15
      Left            =   7920
      Top             =   5040
      _ExtentX        =   741
      _ExtentY        =   741
      _Version        =   393216
   End
   Begin MSWinsockLib.Winsock Winsock4 
      Index           =   16
      Left            =   9360
      Top             =   4560
      _ExtentX        =   741
      _ExtentY        =   741
      _Version        =   393216
   End
   Begin MSWinsockLib.Winsock Winsock4 
      Index           =   17
      Left            =   8880
      Top             =   4560
      _ExtentX        =   741
      _ExtentY        =   741
      _Version        =   393216
   End
   Begin MSWinsockLib.Winsock Winsock4 
      Index           =   18
      Left            =   8400
      Top             =   4560
      _ExtentX        =   741
      _ExtentY        =   741
      _Version        =   393216
   End
   Begin MSWinsockLib.Winsock Winsock4 
      Index           =   19
      Left            =   7920
      Top             =   4560
      _ExtentX        =   741
      _ExtentY        =   741
      _Version        =   393216
   End
   Begin MSWinsockLib.Winsock Winsock4 
      Index           =   20
      Left            =   9360
      Top             =   4080
      _ExtentX        =   741
      _ExtentY        =   741
      _Version        =   393216
   End
   Begin MSWinsockLib.Winsock Winsock4 
      Index           =   21
      Left            =   8880
      Top             =   4080
      _ExtentX        =   741
      _ExtentY        =   741
      _Version        =   393216
   End
   Begin MSWinsockLib.Winsock Winsock4 
      Index           =   22
      Left            =   8400
      Top             =   4080
      _ExtentX        =   741
      _ExtentY        =   741
      _Version        =   393216
   End
   Begin MSWinsockLib.Winsock Winsock4 
      Index           =   23
      Left            =   7920
      Top             =   4080
      _ExtentX        =   741
      _ExtentY        =   741
      _Version        =   393216
   End
   Begin MSWinsockLib.Winsock Winsock4 
      Index           =   24
      Left            =   9360
      Top             =   3600
      _ExtentX        =   741
      _ExtentY        =   741
      _Version        =   393216
   End
   Begin MSWinsockLib.Winsock Winsock4 
      Index           =   25
      Left            =   8880
      Top             =   3600
      _ExtentX        =   741
      _ExtentY        =   741
      _Version        =   393216
   End
   Begin MSWinsockLib.Winsock Winsock4 
      Index           =   26
      Left            =   8400
      Top             =   3600
      _ExtentX        =   741
      _ExtentY        =   741
      _Version        =   393216
   End
   Begin MSWinsockLib.Winsock Winsock4 
      Index           =   27
      Left            =   7920
      Top             =   3600
      _ExtentX        =   741
      _ExtentY        =   741
      _Version        =   393216
   End
   Begin MSWinsockLib.Winsock Winsock4 
      Index           =   28
      Left            =   9360
      Top             =   3120
      _ExtentX        =   741
      _ExtentY        =   741
      _Version        =   393216
   End
   Begin MSWinsockLib.Winsock Winsock4 
      Index           =   29
      Left            =   8880
      Top             =   3120
      _ExtentX        =   741
      _ExtentY        =   741
      _Version        =   393216
   End
   Begin MSWinsockLib.Winsock Winsock4 
      Index           =   30
      Left            =   8400
      Top             =   3120
      _ExtentX        =   741
      _ExtentY        =   741
      _Version        =   393216
   End
   Begin MSWinsockLib.Winsock Winsock4 
      Index           =   31
      Left            =   7920
      Top             =   3120
      _ExtentX        =   741
      _ExtentY        =   741
      _Version        =   393216
   End
   Begin VB.Label Label13 
      AutoSize        =   -1  'True
      BackColor       =   &H00000000&
      Caption         =   "clientPROD = "
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
      Left            =   6555
      TabIndex        =   25
      Top             =   3600
      Visible         =   0   'False
      Width           =   1275
   End
   Begin VB.Label Label12 
      AutoSize        =   -1  'True
      BackColor       =   &H00000000&
      Caption         =   "clientPROD = "
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
      Left            =   6555
      TabIndex        =   24
      Top             =   3360
      Visible         =   0   'False
      Width           =   1275
   End
   Begin VB.Label Label11 
      AutoSize        =   -1  'True
      BackColor       =   &H00000000&
      Caption         =   "clientPROD = "
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
      Left            =   6555
      TabIndex        =   23
      Top             =   3120
      Visible         =   0   'False
      Width           =   1275
   End
   Begin VB.Label Label10 
      AutoSize        =   -1  'True
      BackColor       =   &H00000000&
      Caption         =   "clientPROD = "
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
      Left            =   6555
      TabIndex        =   22
      Top             =   2880
      Visible         =   0   'False
      Width           =   1275
   End
   Begin VB.Label Label9 
      AutoSize        =   -1  'True
      BackColor       =   &H00000000&
      Caption         =   "clientPROD = "
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
      Left            =   6560
      TabIndex        =   21
      Top             =   2640
      Visible         =   0   'False
      Width           =   1275
   End
   Begin VB.Label Label8 
      AutoSize        =   -1  'True
      BackColor       =   &H00000000&
      Caption         =   "clientPROD = "
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
      Left            =   6560
      TabIndex        =   20
      Top             =   2400
      Visible         =   0   'False
      Width           =   1275
   End
   Begin VB.Label Label7 
      AutoSize        =   -1  'True
      BackColor       =   &H00000000&
      Caption         =   "clientPROD = "
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
      Left            =   6560
      TabIndex        =   19
      Top             =   2160
      Visible         =   0   'False
      Width           =   1275
   End
   Begin VB.Label Label6 
      AutoSize        =   -1  'True
      BackColor       =   &H00000000&
      Caption         =   "clientPROD = "
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
      Left            =   6560
      TabIndex        =   18
      Top             =   1920
      Visible         =   0   'False
      Width           =   1275
   End
   Begin VB.Label Label5 
      AutoSize        =   -1  'True
      BackColor       =   &H00000000&
      Caption         =   "Connected Players:"
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
      Left            =   5400
      TabIndex        =   17
      Top             =   360
      Width           =   1845
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
   Begin VB.Menu file 
      Caption         =   "File"
      Index           =   0
      Begin VB.Menu save 
         Caption         =   "Save"
         Index           =   3
      End
      Begin VB.Menu exit 
         Caption         =   "Exit"
         Index           =   4
      End
   End
   Begin VB.Menu about 
      Caption         =   "About"
      Index           =   1
   End
End
Attribute VB_Name = "Form1"
Attribute VB_GlobalNameSpace = False
Attribute VB_Creatable = False
Attribute VB_PredeclaredId = True
Attribute VB_Exposed = False
Public Data, DataLen, OutStr
Public Buff
Public out
Public x, y, num, value, tmp2, tmp3, Build
Public msgType, pad, msgLen, fso, subCmd
Public DataStr As String
Public DataPrev As String
Public moreCmd As Boolean
Public userExist As Boolean
Public clientALTS, clientNAME, clientVERS, clientMAC, clientPERS, clientPERSONAS, clientBORN, clientMAIL, clientSKU
Public clientPLAST, clientMADDR, clientUSER, clientMINSIZE, clientMAXSIZE, clientPARAMS, clientCUSTFLAGS, clientPRIV
Public clientSESS, clientSLUS, clientPID, clientDEFPER, clientLAST, clientSEED, clientSYSFLAGS, clientSKEY, userNAME
Public NEWS_PAYLOAD, clientLKEY, clientPROD, pingREF, pingTIME, ParseTmp, skeyStr, acctDB, clientPASS
Public PlayerCnt, playerNUM, secCNT, pingSEC, protoVER, roomTOTAL, roomINDEX, roomMAXSIZE, roomPLAYERS, roomHOST, roomNAME
Public clientTID, playerNAME, playerROOM, playerIP, playerPORT, playerID
Private Type room
    roomINDEX As Integer
    roomNAME As String
    roomMAXSIZE As Integer
    roomPLAYERS As Integer
    roomHOST As String
End Type
Private Type player
    playerNUM As Integer
    playerID As Integer
    playerNAME As String
    playerROOM As Integer
    playerIP As String
    playerPORT As Long
End Type
Dim rooms(9999) As room
Dim players(9999) As player
'Option Explicit
Dim DataVal(9999)
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
    If protoVER = 1 Then
        If Mid(HexToString(Trim(params(x))), y, 4) = "MID=" Then
            clientMID = Mid(HexToString(Trim(params(x))), y + 4, Len(HexToString(Trim(params(x)))))
            clientMAC = clientMID
        ElseIf Mid(HexToString(Trim(params(x))), y, 4) = "MAC=" Then
            clientMAC = Mid(HexToString(Trim(params(x))), y + 4, Len(HexToString(Trim(params(x)))))
        ElseIf Mid(HexToString(Trim(params(x))), y, 4) = "PID=" Then
            clientPID = Mid(HexToString(Trim(params(x))), y + 4, Len(HexToString(Trim(params(x)))))
        ElseIf Mid(HexToString(Trim(params(x))), y, 4) = "SKU=" Then
            clientSKU = Mid(HexToString(Trim(params(x))), y + 4, Len(HexToString(Trim(params(x)))))
        ElseIf Mid(HexToString(Trim(params(x))), y, 5) = "ALTS=" Then
            clientALTS = Mid(HexToString(Trim(params(x))), y + 5, Len(HexToString(Trim(params(x)))))
        ElseIf Mid(HexToString(Trim(params(x))), y, 5) = "VERS=" Then
            clientVERS = Mid(HexToString(Trim(params(x))), y + 5, Len(HexToString(Trim(params(x)))))
            Label8.Caption = "VERS " & clientVERS
            Label8.Visible = True
        ElseIf Mid(HexToString(Trim(params(x))), y, 5) = "BORN=" Then
            clientBORN = Mid(HexToString(Trim(params(x))), y + 5, Len(HexToString(Trim(params(x)))))
        ElseIf Mid(HexToString(Trim(params(x))), y, 5) = "SLUS=" Then
            clientSLUS = Mid(HexToString(Trim(params(x))), y + 5, Len(HexToString(Trim(params(x)))))
        ElseIf Mid(HexToString(Trim(params(x))), y, 5) = "NAME=" Then
            If msgType = "news" Then
                subCmd = "new" & Mid(HexToString(Trim(params(x))), y + 5, 1)
            ElseIf msgType = "room" Then
                roomNAME = Mid(HexToString(Trim(params(x))), y + 5, Len(HexToString(Trim(params(x)))))
            ElseIf msgType = "peek" Then
                roomNAME = Mid(HexToString(Trim(params(x))), y + 5, Len(HexToString(Trim(params(x)))))
            Else
                clientNAME = Mid(HexToString(Trim(params(x))), y + 5, Len(HexToString(Trim(params(x)))))
                Label9.Caption = "USER " & clientNAME
                Label9.Visible = True
            End If
        ElseIf Mid(HexToString(Trim(params(x))), y, 5) = "USER=" Then
            If msgType = "USCH" Then
                userNAME = Mid(HexToString(Trim(params(x))), y + 5, Len(HexToString(Trim(params(x)))))
            End If
            clientUSER = Mid(HexToString(Trim(params(x))), y + 5, Len(HexToString(Trim(params(x)))))
            Label9.Caption = "USER " & clientUSER
            Label9.Visible = True
        ElseIf Mid(HexToString(Trim(params(x))), y, 5) = "PASS=" Then
            clientPASS = Mid(HexToString(Trim(params(x))), y + 5, Len(HexToString(Trim(params(x)))))
        ElseIf Mid(HexToString(Trim(params(x))), y, 5) = "PERS=" Then
            If msgType = "user" Then
                userNAME = Mid(HexToString(Trim(params(x))), y + 5, Len(HexToString(Trim(params(x)))))
            Else
                clientPERS = Mid(HexToString(Trim(params(x))), y + 5, Len(HexToString(Trim(params(x)))))
            End If
        ElseIf Mid(HexToString(Trim(params(x))), y, 5) = "PROD=" Then
            clientPROD = Mid(HexToString(Trim(params(x))), y + 5, Len(HexToString(Trim(params(x)))))
            Label7.Caption = "PROD " & clientPROD
            Label7.Visible = True
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
        ElseIf Mid(HexToString(Trim(params(x))), y, 5) = "TIME=" Then
            pingTIME = Mid(HexToString(Trim(params(x))), y + 5, Len(HexToString(Trim(params(x)))))
        ElseIf Mid(HexToString(Trim(params(x))), y, 6) = "PLAST=" Then
          clientPLAST = Mid(HexToString(Trim(params(x))), y + 6, Len(HexToString(Trim(params(x)))))
        ElseIf Mid(HexToString(Trim(params(x))), y, 6) = "MADDR=" Then
          clientMADDR = Mid(HexToString(Trim(params(x))), y + 6, Len(HexToString(Trim(params(x)))))
          tmp = Split(clientMADDR, "$")
          clientNAME = tmp(0)
          Label9.Caption = "USER " & clientNAME
          Label9.Visible = True
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
    ElseIf protoVER = 2 Then
        If Mid(HexToString(Trim(params(x))), y, 4) = "TID=" Then
            clientTID = Mid(HexToString(Trim(params(x))), y + 4, Len(HexToString(Trim(params(x)))) - y - 4)
            If Len(clientTID) > 1 Then
                clientTID = Mid(HexToString(Trim(params(x))), y + 4, Len(HexToString(Trim(params(x)))) - (y * 2) - 2)
            End If
        ElseIf Mid(HexToString(Trim(params(x))), y, 5) = "PROD=" Then
            clientPROD = Mid(HexToString(Trim(params(x))), y + 5, Len(HexToString(Trim(params(x)))) - y - 5)
            Label7.Caption = "PROD " & clientPROD
            Label7.Visible = True
        ElseIf Mid(HexToString(Trim(params(x))), y, 5) = "VERS=" Then
            clientVERS = Mid(HexToString(Trim(params(x))), y + 5, Len(HexToString(Trim(params(x)))) - y - 5)
            Label8.Caption = "VERS " & clientVERS
            Label8.Visible = True
        End If
    End If
Next x
End Function
Public Function CreateRoom(host)
roomTOTAL = roomTOTAL + 1
roomINDEX = 1000 + Int(roomTOTAL)
rooms(roomTOTAL).roomINDEX = roomINDEX
rooms(roomTOTAL).roomHOST = players(host - 1000).playerIP
rooms(roomTOTAL).roomMAXSIZE = 8
rooms(roomTOTAL).roomNAME = "TestRoom"
rooms(roomTOTAL).roomPLAYERS = 1
players(host - 1000).playerROOM = rooms(roomTOTAL).roomINDEX
players(host - 1000).playerPORT = 28500
If protoVER = 1 Then
ElseIf protoVER = 2 Then
    msgType = "CGAM"
    OutStr = "LOBBY-ID=1" & Chr(34) & "1" & Chr(34) & " "
    OutStr = OutStr & "GAME-ID=" & Chr(34) & rooms(roomTOTAL).roomINDEX & Chr(34)
    msgLen = Len(msgType) + 8 + Len(OutStr) + 1
    cgamData = msgType & pad & Chr(msgLen) & OutStr & Chr(0)
    Winsock4(host - 1000).SendData cgamData
    Sleep (500)
    DoEvents
End If
End Function
Public Function ParseData(DataStr As String)
moar:
Set fso = CreateObject("Scripting.FileSystemObject")
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
subCmd = Mid(HexToString(DataStr), 5, 4)
msgSize = Mid(HexToString(DataStr), 12, 1)
'sizeHex = Hex(msgSize)
If Asc(msgSize) >= 256 Or Asc(msgSize) = 0 Then
    msgSize = Mid(HexToString(DataStr), 11, 2)
    If Asc(msgSize) = 1 Then
        msgSize = 256
    End If
End If
Text2.Text = Buff & vbCrLf & vbCrLf & "[+] Received: " & msgType & " Size: " & Asc(msgSize) & vbCrLf & vbCrLf
Buff = Text2.Text
'Text2.Text = Buff & vbCrLf & (Mid(HexToString(DataStr), 13, Len(HexToString(DataStr)) - 3)) & vbCrLf
'Buff = Text2.Text

OutStr = ""
a = GetParams(msgType, params)
ParseTmp = ""

If msgType = "@tic" Or msgType = "@dir" Then
    protoVER = 1
    Label6.Caption = "protoVER 1"
    Label6.Visible = True
ElseIf msgType = "CONN" Then
    protoVER = 2
    Label6.Caption = "protoVER 2"
    Label6.Visible = True
ElseIf msgType = HexToString("80 1C 01 00") Then
    protoVER = 0
    Label6.Caption = "protoVER 0"
    Label6.Visible = True
    Text2.Text = Text2.Text & vbCrLf & vbCrLf & "!! Encryption Detected !!" & vbCrLf
    Buff = Text2.Text
End If

If protoVER = 1 Then
    Label6.Caption = "protoVER 1 " & msgType
    If msgType = "@dir" Then
        OutStr = "ADDR=" & Winsock1.LocalIP & Chr(10)
        OutStr = OutStr & "PORT=10901" & Chr(10)
        OutStr = OutStr & "SESS=1337420011" & Chr(10)
        OutStr = OutStr & "MASK=f3f7f3f70ecb1757cd7001b9a7af3f7" & Chr(10)
        msgLen = Len(msgType) + 8 + Len(OutStr) + 1
        ParseData = msgType & pad & Chr(msgLen) & OutStr & Chr(0)
        'Winsock1.SendData dirData
    ElseIf msgType = "~png" Then
        pingSEC = secCNT
    ElseIf msgType = "acct" Then
        If fso.FileExists(acctDB) = False Then
            Close #1
            clientLAST = Format(Date, "YYYY.DD.MM") & "-" & Format(Time, "HH:MM:SS")
            Open acctDB For Append As #1
                Print #1, clientNAME & "#" & clientBORN & "#" & clientMAIL & "#" & clientPASS & "#" & clientNAME & "#" & clientLAST
            Close #1
            'MsgBox clientNAME & "#" & clientBORN & "#" & clientMAIL & "#" & clientPASS & "#" & clientNAME & "#" & clientLAST
        Else
            Open acctDB For Input As #2
                While Not EOF(2)
                    Line Input #2, acctUSER
                    tmp = Split(acctUSER, "#")
                    If tmp(0) = clientNAME Then
                        pad2 = HexToBin("00 00 00")
                        ParseData = "acctimst" & pad2 & Chr(14) & Chr(10) & Chr(0)
                        userExist = True
                        Close #2
                        Winsock4(PlayerCnt).SendData ParseData
                    End If
                Wend
            Close #2
            Close #1
            clientLAST = Format(Date, "YYYY.DD.MM") & "-" & Format(Time, "HH:MM:SS")
            Open acctDB For Append As #1
                Print #1, clientNAME & "#" & clientBORN & "#" & clientMAIL & "#" & clientPASS & "#" & clientNAME & "#" & clientLAST
            Close #1
            userExist = True
            OutStr = "TOS=1" & Chr(10)
            OutStr = OutStr & "NAME=" & clientNAME & Chr(10)
            OutStr = OutStr & "AGE=21" & Chr(10)
            OutStr = OutStr & "PERSONAS=" & clientNAME & ",is,reviving,games" & Chr(10)
            OutStr = OutStr & "CPAT=1" & Chr(10)
            OutStr = OutStr & "SINCE=" & Format(Date, "YYYY.DD.MM") & "-" & Format(Time, "HH:MM:SS") & Chr(10)
            OutStr = OutStr & "LAST=" & Format(Date, "YYYY.DD.MM") & "-" & Format(Time, "HH:MM:SS") & Chr(10)
            msgLen = Len(msgType) + 8 + Len(OutStr) + 1
            ParseData = msgType & pad & Chr(msgLen) & OutStr & Chr(0)
        End If
    'ElseIf msgType = "addr" Then 'msgType = "skey"
        'a = GetParams(msgType, params)
        'msgType = "skey"
        'OutStr = "SKEY=$37940faf2a8d1381a3b7d0d2f570e6a7" & Chr(10)
        'OutStr = OutStr & "PLATFORM=PS2" & Chr(10)
        'msgLen = Len(msgType) + 8 + Len(OutStr) + 1
        'skeyStr = msgType & pad & Chr(msgLen) & OutStr & Chr(0)
        'Winsock4(PlayerCnt + 1).SendData skeyStr
        'ParseData = msgType & pad & Chr(msgLen) & OutStr & Chr(0)
    ElseIf msgType = "auth" Then
        userExist = False
        pad2 = HexToBin("00 00 00")
        If fso.FileExists(acctDB) = False Then
            ParseData = "authimst" & pad2 & Chr(14) & Chr(10) & Chr(0)
        Else
            Close #3
            Open acctDB For Input As #3
                While Not EOF(3)
                    Line Input #3, acctUSER
                    tmp = Split(acctUSER, "#")
                    If tmp(0) = clientNAME Then 'And tmp(3) = clientPASS Then
                        userExist = True
                        clientNAME = tmp(0)
                        clientBORN = tmp(1)
                        clientMAIL = tmp(2)
                        clientPASS = tmp(3)
                        clientPERS = tmp(4)
                        clientSINCE = tmp(5)
                        'OutStr = "VERS=" & clientVERS & Chr(10)
                        OutStr = "TOS=1" & Chr(10)
                        OutStr = OutStr & "NAME=" & clientNAME & Chr(10)
                        OutStr = OutStr & "MAIL=" & clientMAIL & Chr(10)
                        OutStr = OutStr & "BORN=" & clientBORN & Chr(10)
                        OutStr = OutStr & "GEND=M" & Chr(10)
                        OutStr = OutStr & "FROM=US" & Chr(10)
                        OutStr = OutStr & "LANG=en" & Chr(10)
                        OutStr = OutStr & "SPAM=NN" & Chr(10)
                        OutStr = OutStr & "PERSONAS=" & clientNAME & ",is,reviving,games" & Chr(10)
                        'OutStr = OutStr & "SINCE=" & clientSINCE & Chr(10)
                        OutStr = OutStr & "LAST=" & Format(Date, "YYYY.DD.MM") & "-" & Format(Time, "HH:MM:SS") & Chr(10)
                        OutStr = OutStr & "ADDR=24.141.39.62" & Chr(10)
                        OutStr = OutStr & "_LUID=$000000000b32588d" & Chr(10)
                        msgLen = Len(msgType) + 8 + Len(OutStr) + 1
                        ParseData = msgType & pad & Chr(msgLen) & OutStr & Chr(0)
                        'Winsock4(PlayerCnt).SendData authStr
                        Close #2
                    End If
                Wend
            Close #2
            If userExist = False Then
                ParseData = "authimst" & pad2 & Chr(14) & Chr(10) & Chr(0)
            'ElseIf userExist = True Then
                'ParseData = "passimst" & pad2 & Chr(14) & Chr(10) & Chr(0)
            End If
        End If
    ElseIf msgType = "AUTH" Then
        OutStr = "NAME=" & clientNAME & Chr(10)
        OutStr = OutStr & "USER=" & clientNAME & Chr(10)
        OutStr = OutStr & "PROD=" & clientVERS & Chr(10)
        OutStr = OutStr & "LKEY=" & clientLKEY & Chr(10)
        msgLen = Len(msgType) + 8 + Len(OutStr) + 1
        authData = msgType & pad & Chr(msgLen) & OutStr & Chr(0)
        Winsock3.SendData authData
        'Winsock3.SendData (HexToBin("7e 70 6e 67 00 00 00 2f 00 00 00 14 54 49 4d 45 3d 31 0a 00"))
    ElseIf msgType = "cper" Then
        OutStr = "PERS=" & clientPERS & Chr(10)
        OutStr = OutStr & "ALTS=" & clientALTS & Chr(10)
        msgLen = Len(msgType) + 8 + Len(OutStr) + 1
        ParseData = msgType & pad & Chr(msgLen) & OutStr & Chr(0)
    ElseIf msgType = "edit" Then
        OutStr = "NAME=" & clientNAME & Chr(10)
        OutStr = OutStr & "MAIL=" & clientMAIL & Chr(10)
        msgLen = Len(msgType) + 8 + Len(OutStr) + 1
        ParseData = msgType & pad & Chr(msgLen) & OutStr & Chr(0)
    ElseIf msgType = "fget" Then
        a = Send_Who()
        OutStr = "FLUP=0" & Chr(10)
        OutStr = OutStr & "PRES=" & Chr(10)
        msgLen = Len(msgType) + 8 + Len(OutStr) + 1
        'TEXT=05GkkkkiWxYUsUWOrK1liy3/8s4WdLT1qK2Jbqt6XAP6lhDsb/9/+XDriFxK4pcWuNXHrkVya5UDKpc//f/v/3/7/9/+//f/v/3/4D0B+BAgeP/3/7/9/+//f/v/3/7/9/+//f/v/3/7/9/+//f/v/3/7/9/+//f/v/3/7/9/+//f/v/3/7/9/+//f/v/3/7/9/+//f/v/3/7/9/+//f/v/3/7/9/+//f/v/3/7/83nJuf/v/y5cA%3d
        ParseData = "+fup" & pad & Chr(msgLen) & OutStr & Chr(0)
    ElseIf msgType = "gget" Then
        a = Send_Rom()
        OutStr = "IDENT=1" & clientNAME & Chr(10)
        OutStr = OutStr & "WHEN=" & Format(Date, "YYYY.DD.MM") & "-" & Format(Time, "HH:MM:SS") & Chr(10)
        OutStr = OutStr & "NAME=" & clientNAME & Chr(10)
        OutStr = OutStr & "PARAMS=" & Chr(10)
        OutStr = OutStr & "ROOM=" & clientNAME & Chr(10)
        OutStr = "TEXT=05GkkkkiWxYUsUWOrK1liy3/8s4WdLT1qK2Jbqt6XAP6lhDsb/9/+XDriFxK4pcWuNXHrkVya5UDKpc//f/v/3/7/9/+//f/v/3/4D0B+BAgeP/3/7/9/+//f/v/3/7/9/+//f/v/3/7/9/+//f/v/3/7/9/+//f/v/3/7/9/+//f/v/3/7/9/+//f/v/3/7/9/+//f/v/3/7/9/+//f/v/3/7/9/+//f/v/3/7/83nJuf/v/y5cA%3d"
        msgLen = Len(msgType) + 8 + Len(OutStr) + 1
        'TEXT=05GkkkkiWxYUsUWOrK1liy3/8s4WdLT1qK2Jbqt6XAP6lhDsb/9/+XDriFxK4pcWuNXHrkVya5UDKpc//f/v/3/7/9/+//f/v/3/4D0B+BAgeP/3/7/9/+//f/v/3/7/9/+//f/v/3/7/9/+//f/v/3/7/9/+//f/v/3/7/9/+//f/v/3/7/9/+//f/v/3/7/9/+//f/v/3/7/9/+//f/v/3/7/9/+//f/v/3/7/83nJuf/v/y5cA%3d
        ParseData = "auxi" & pad & Chr(msgLen) & OutStr & Chr(0)
    ElseIf msgType = "move" Then
        a = Send_Rom()
        Sleep (200)
        a = Send_Who()
        Sleep (200)
        a = Send_usr()
        Sleep (200)
        OutStr = "IDENT=0" & Chr(10)
        OutStr = OutStr & "NAME=" & roomNAME & Chr(10)
        OutStr = OutStr & "COUNT=1" & Chr(10)
        msgLen = Len(msgType) + 8 + Len(OutStr) + 1
        ParseData = "move" & pad & Chr(msgLen) & OutStr & Chr(0)
    ElseIf msgType = "news" Then
        a = GetParams(msgType, params)
        pad2 = HexToBin("00 00 00")
        'MsgBox subCmd
        If subCmd = "new0" Or subCmd = "new1" Or subCmd = "new2" Or subCmd = "new3" Then
            OutStr = "VTSTech.is.reviving.games" & Chr(10)
        Else
            OutStr = "BUDDY_SERVER=" & Winsock3.LocalIP & Chr(10)
            OutStr = OutStr & "BUDDY_URL=http://ps3burnout08.ea.com/BUDDY.txt" & Chr(10)
            OutStr = OutStr & "BUDDY_PORT=" & Winsock3.LocalPort & Chr(10)
            OutStr = OutStr & "EACONNECT_WEBOFFER_URL=http://ps3burnout08.ea.com/EACONNECT.txt" & Chr(10)
            OutStr = OutStr & "ETOKEN_URL=http://ps3burnout08.ea.com/ETOKEN.txt" & Chr(10)
            OutStr = OutStr & "NEWS_URL=http://ps3burnout08.ea.com/NEWS.txt" & Chr(10)
            OutStr = OutStr & "TOSAC_URL=http://ps3burnout08.ea.com/TOSAC.txt" & Chr(10)
            OutStr = OutStr & "TOSA_URL=http://ps3burnout08.ea.com/TOSA.txt" & Chr(10)
            OutStr = OutStr & "TOS_URL=http://ps3burnout08.ea.com/TOS.txt" & Chr(10)
            OutStr = OutStr & "NEWS_URL=http://ps3burnout08.ea.com/NEWS.txt" & Chr(10)
            OutStr = OutStr & "NEWS_DATE=" & Format(Date, "YYYY.DD.MM") & "-" & Format(Time, "HH:MM:SS") & Chr(10)
            OutStr = OutStr & "LIVE_NEWS_URL=http://ps3burnout08.ea.com/LIVE.txt" & Chr(10)
            OutStr = OutStr & "LIVE_NEWS2_URL=http://ps3burnout08.ea.com/LIVE2.txt" & Chr(10)
            OutStr = OutStr & "PRODUCT_SEARCH_URL=http://ps3burnout08.ea.com/PROD.txt" & Chr(10)
            OutStr = OutStr & "AVATAR_URL=http://ps3burnout08.ea.com/AV.txt" & Chr(10)
            OutStr = OutStr & "STORE_URL=http://ps3burnout08.ea.com/STORE.txt" & Chr(10)
            OutStr = OutStr & "TOS_TEXT=VTSTech.is.reviving.games_TOS" & Chr(10)
            OutStr = OutStr & "NEWS_TEXT=VTSTech.is.reviving.games_NEWS" & Chr(10)
            OutStr = OutStr & "LIVE_NEWS_URL_IMAGE_PATH=." & Chr(10)
            OutStr = OutStr & "USE_ETOKEN=0" & Chr(10)
        End If
        msgLen = Len(msgType) + 8 + Len(OutStr) + 1
        sizeHex = Hex(msgLen)
        If msgLen >= 256 Then
            If Len(sizeHex) <= 3 Then
                sizeHex = "0" + sizeHex
            End If
            s1 = Mid(sizeHex, 1, 2)
            s2 = Mid(sizeHex, 3, 2)
            pad2 = HexToBin("00 00 " & s1 & " " & s2)
            'ParseTmp = ""
            If subCmd = "newc" Then
                subCmd = "new7"
            End If
            ParseTmp = msgType & subCmd & pad2 & OutStr & Chr(0)
        Else
            'ParseTmp = ""
            ParseTmp = msgType & subCmd & pad2 & Chr(msgLen) & OutStr & Chr(0)
        End If
        'If moreCmd = False Then
        '    Sleep (200)
        '    Winsock4(PlayerCnt + 1).SendData ParseTmp
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
        OutStr = OutStr & "MA=" & clientMAC & Chr(10)
        OutStr = OutStr & "NAME=" & clientNAME & Chr(10)
        OutStr = OutStr & "PERS=" & clientNAME & Chr(10)
        OutStr = OutStr & "LAST=" & Format(Date, "YYYY.DD.MM") & "-" & Format(Time, "HH:MM:SS") & Chr(10)
        OutStr = OutStr & "PLAST=" & Format(Date, "YYYY.DD.MM") & "-" & Format(Time, "HH:MM:SS") & Chr(10)
        OutStr = OutStr & "SINCE=" & Format(Date, "YYYY.DD.MM") & "-" & Format(Time, "HH:MM:SS") & Chr(10)
        OutStr = OutStr & "PSINCE=" & Format(Date, "YYYY.DD.MM") & "-" & Format(Time, "HH:MM:SS") & Chr(10)
        OutStr = OutStr & "LKEY=3fcf27540c92935b0a66fd3b0000283c" & Chr(10)
        msgLen = Len(msgType) + 8 + Len(OutStr) + 1
        ParseData = msgType & pad & Chr(msgLen) & OutStr & Chr(0)
    ElseIf msgType = "room" Or msgType = "RGET" Then
        If players(PlayerCnt).playerROOM = 0 Then
            a = CreateRoom(players(PlayerCnt).playerID)
        End If
        OutStr = "LIDENT=1" & Chr(10)
        OutStr = OutStr & "LCOUNT=1" & Chr(10)
        OutStr = OutStr & "NAME=" & roomNAME & Chr(10)
        OutStr = OutStr & "HOST=" & clientNAME & Chr(10)
        OutStr = OutStr & "COUNT=1" & Chr(10)
        OutStr = OutStr & "LIMIT=50" & Chr(10)
        msgLen = Len(msgType) + 8 + Len(OutStr) + 1
        ParseData = "room" & pad & Chr(msgLen) & OutStr & Chr(0)
        'Sleep (200)
    ElseIf msgType = "sele" Then
        'OutStr = "VERS=" & clientVERS & Chr(10)
        'OutStr = OutStr & "SKU=" & clientSKU & Chr(10)
        'OutStr = "GAMES=0" & Chr(10)
        'OutStr = OutStr & "CTRL=0" & Chr(10)
        'OutStr = OutStr & "ROOMS=0" & Chr(10)
        'OutStr = OutStr & "INGAME=0" & Chr(10)
        'OutStr = "MYGAME=1" & Chr(10)
        OutStr = OutStr & "MORE=0" & Chr(10)
        'OutStr = OutStr & "PLATFORM=PS2" & Chr(10)
        OutStr = OutStr & "SLOTS=4" & Chr(10)
        'OutStr = OutStr & "ASYNC=0" & Chr(10)
        OutStr = OutStr & "STATS=0" & Chr(10)
        'OutStr = OutStr & "MORE=1" & Chr(10)
        'OutStr = OutStr & "SLOTS=8" & Chr(10)
        'OutStr = OutStr & "USERSETS=0" & Chr(10)
        'OutStr = OutStr & "MESGTYPES=100728964" & Chr(10)
        'OutStr = OutStr & "STATS=0" & Chr(10)
        msgLen = Len(msgType) + 8 + Len(OutStr) + 1
        ParseData = msgType & pad & Chr(msgLen) & OutStr & Chr(0)
        'Sleep (200)
    ElseIf msgType = "skey" Then
        'a = GetParams(msgType, params)
        'msgType = "skey"
        OutStr = "SKEY=$37940faf2a8d1381a3b7d0d2f570e6a7" & Chr(10)
        'OutStr = OutStr & "PLATFORM=PS2" & Chr(10)
        msgLen = Len(msgType) + 8 + Len(OutStr) + 1
        skeyStr = msgType & pad & Chr(msgLen) & OutStr & Chr(0)
        Winsock4(PlayerCnt + 1).SendData skeyStr
        Sleep (1000)
        'ParseData = msgType & pad & Chr(msgLen) & OutStr & Chr(0)
    ElseIf msgType = "sviw" Then
        OutStr = "N=9" & Chr(10)
        OutStr = OutStr & "NAMES=0,3,4,5,6,7,8,9" & Chr(10)
        OutStr = OutStr & "DESC=1,1,1,1,1,1,1,1,1" & Chr(10)
        OutStr = OutStr & "PARAMS=2,2,2,2,2,2,2,2" & Chr(10)
        OutStr = OutStr & "WIDTHS=1,1,1,1,1,1,1,1" & Chr(10)
        OutStr = OutStr & "SYMS=TOTCOM,a,0,TAKEDNS,RIVALS,ACHIEV,FBCHAL,RANK,WINS,SNTTEAM,SNTFFA" & Chr(10)
        OutStr = OutStr & "TYPES=~num,~num,~num,~num,~rnk,~num,~pts,~pts" & Chr(10)
        OutStr = OutStr & "SS=65" & Chr(10)
        msgLen = Len(msgType) + 8 + Len(OutStr) + 1
        ParseData = msgType & pad & Chr(msgLen) & OutStr & Chr(0)
    ElseIf msgType = "user" Then
        'a = GetParams(msgType, params)
        If Len(userNAME) > 1 Then
            OutStr = "PERS=" & userNAME & Chr(10)
        Else
            OutStr = "PERS=" & clientNAME & Chr(10)
        End If
        'OutStr = OutStr & "CRC=0" & Chr(10)
        'OutStr = OutStr & "PID=0" & Chr(10)
        msgLen = Len(msgType) + 8 + Len(OutStr) + 1
        ParseData = msgType & pad & Chr(msgLen) & OutStr & Chr(0)
    ElseIf msgType = "USCH" Then
        'a = GetParams(msgType, params)
        OutStr = "COUNT=1" & Chr(10)
        OutStr = OutStr & "NAME=" & userNAME & Chr(10)
        OutStr = OutStr & "CRC=0" & Chr(10)
        OutStr = OutStr & "PID=0" & Chr(10)
        msgLen = Len(msgType) + 8 + Len(OutStr) + 1
        uschStr = "USER" & pad & Chr(msgLen) & OutStr & Chr(0)
        If Winsock1.State = 7 Then
            Winsock1.SendData uschStr
        Else
            Winsock4(PlayerCnt).SendData uschStr
        End If
    ElseIf msgType = "usld" Then
        'a = GetParams(msgType, params)
        OutStr = "SKEY=$37940faf2a8d1381a3b7d0d2f570e6a7" & Chr(10)
        OutStr = "IMGATE=0" & Chr(10)
        OutStr = OutStr & "QMSG0=TEST0" & Chr(10)
        OutStr = OutStr & "QMSG1=TEST1" & Chr(10)
        OutStr = OutStr & "QMSG2=TEST2" & Chr(10)
        OutStr = OutStr & "QMSG3=TEST3" & Chr(10)
        OutStr = OutStr & "QMSG4=TEST4" & Chr(10)
        OutStr = OutStr & "QMSG5=TEST5" & Chr(10)
        OutStr = OutStr & "SPM_EA=0" & Chr(10)
        OutStr = OutStr & "SPM_PART=0" & Chr(10)
        OutStr = OutStr & "UID=$000000000b32588d" & Chr(10)
        msgLen = Len(msgType) + 8 + Len(OutStr) + 1
        ParseData = msgType & pad & Chr(msgLen) & OutStr & Chr(0)
    End If
ElseIf protoVER = 2 Then
    Label6.Caption = "protoVER 2 " & msgType
    If msgType = "CONN" Then
        OutStr = "NUM-CHALLENGES=0" & Chr(0)
        'OutStr = OutStr & "PROD=" & clientPROD & Chr(0)
        'OutStr = OutStr & "VERS=" & clientVERS & Chr(0)
        'OutStr = OutStr & "LKEY=" & clientLKEY & Chr(0)
        'msgLen = Len(msgType) + 8 + Len(OutStr) + 1
        msgLen = Len(msgType) + 8 + 1
        ParseData = msgType & pad & Chr(msgLen) & Chr(0) ' empty response
    ElseIf msgType = "CGAM" Then
        If players(PlayerCnt).playerROOM = 0 Then
            a = CreateRoom(players(PlayerCnt).playerID)
        End If
        msgType = "UGAM"
        OutStr = "QUENCH=" & Chr(34) & "20" & Chr(34)
        msgLen = Len(msgType) + 8 + Len(OutStr) + 1
        ParseData = msgType & pad & Chr(msgLen) & OutStr & Chr(0)
    ElseIf msgType = "GLST" Then
        OutStr = "TID=" & clientTID & " "
        OutStr = OutStr & "NUM-GAMES=" & roomTOTAL & " "
        OutStr = OutStr & "LOBBY-ID=1"
        msgLen = Len(msgType) + 8 + Len(OutStr) + 1
        ParseData = HexToBin(StringToHex(msgType & pad & Chr(msgLen) & OutStr & Chr(0)))
    ElseIf msgType = "USER" Then
        'YD[&YE@@eÀ¨äÀ¨Þ7Ü9!Ct"seúMPúhHUSERTICKET=YOLO
        OutStr = Trim("TICKET=") & Chr(34) & players(PlayerCnt).playerID & Chr(34)
        'OutStr = OutStr & "PROD=" & clientPROD & Chr(0)
        'OutStr = OutStr & "VERS=" & clientVERS & Chr(0)
        'OutStr = OutStr & "LKEY=" & clientLKEY & Chr(0)
        msgLen = Len(msgType) + 8 + Len(OutStr) + 1
        ParseData = msgType & pad & Chr(msgLen) & OutStr & Chr(0)
    ElseIf msgType = "LLST" Then
        OutStr = "TID=" & clientTID & " "
        'OutStr = OutStr & "NUM-REGIONS=1" & " "
        OutStr = OutStr & "NUM-LOBBIES=1"
        msgLen = Len(msgType) + 8 + Len(OutStr) + 1
        ParseData = msgType & pad & Chr(msgLen) & OutStr & Chr(0)
    ElseIf msgType = "FILE" Then
        'OutStr = "CLEAN-TEXT=" & Chr(34) & "VTSTech.is.reviving.games" & Chr(34) & Chr(0)
        'OutStr = OutStr & "PROD=" & clientPROD & Chr(0)
        'OutStr = OutStr & "VERS=" & clientVERS & Chr(0)
        'OutStr = OutStr & "LKEY=" & clientLKEY & Chr(0)
        msgLen = Len(msgType) + 8 + 1
        ParseData = msgType & pad & Chr(msgLen) & Chr(0) ' empty response
    ElseIf msgType = "PROF" Then
        'YD[&YEF @eÀ¨äÀ¨Þ7Ü9!Ct:seú©PúsøPROFCLEAN-TEXT="YOLO"
        OutStr = "CLEAN-TEXT=" & Chr(34) & "VTSTech" & Chr(34)
        'OutStr = OutStr & "PROD=" & clientPROD & Chr(0)
        'OutStr = OutStr & "VERS=" & clientVERS & Chr(0)
        'OutStr = OutStr & "LKEY=" & clientLKEY & Chr(0)
        msgLen = Len(msgType) + 8 + Len(OutStr) + 1
        ParseData = msgType & pad & Chr(msgLen) & OutStr & Chr(0)
    ElseIf msgType = "RLST" Then
        'YD[&YEH!@e|À¨äÀ¨Þ7Ü9!CtXseú»Pùú# RLST TID=1 NUM-REGIONS=1
        OutStr = "TID=" & clientTID & " "
        OutStr = OutStr & "NUM-REGIONS=1"
        msgLen = Len(msgType) + 8 + Len(OutStr) + 1
        ParseData = msgType & pad & Chr(msgLen) & OutStr & Chr(0)
    End If

End If
DataPrev = DataStr
'ParseData = ParseData
End Function
Public Function Send_LDAT(Index)
    msgType = "LDAT"
    x = 0
    For x = 0 To roomTOTAL
        OutStr = "TID=" & clientTID & " "
        OutStr = OutStr & "LOBBY-ID=1" & " "
        'OutStr = OutStr & "NAME=" & Chr(34) & rooms(x).roomNAME & Chr(34) & " "
        OutStr = OutStr & "NAME=" & Chr(34) & "Global" & Chr(34) & " "
        OutStr = OutStr & "LOCALE=0" & " "
        OutStr = OutStr & "NUM-GAMES=" & roomTOTAL & " "
        OutStr = OutStr & "FAVORITE-GAMES=0" & " "
        OutStr = OutStr & "FAVORITE-PLAYERS=0"
        msgLen = Len(msgType) + 8 + Len(OutStr) + 1
        ldatData = msgType & pad & Chr(msgLen) & OutStr & Chr(0)
        Winsock4(Index).SendData ldatData 'protoVER = 2
        x = x + 1
        Sleep (200)
        DoEvents
    Next x
End Function
Public Function Send_RDAT(Index)
    'YD[&YEx"@eKÀ¨äÀ¨Þ7Ü9!Ctxseú»PùúmRDATPTID=1 REGION-ID=1 NAME="IamLupo" LOCALE=0 NUM-GAMES=1 NUM-PLAYERS=1
    msgType = "RDAT"
    OutStr = "TID=" & clientTID & " "
    OutStr = OutStr & "REGION-ID=1" & " "
    OutStr = OutStr & "NAME=" & Chr(34) & "Global" & Chr(34) & " "
    OutStr = OutStr & "LOCALE=0" & " "
    OutStr = OutStr & "NUM-GAMES=" & roomTOTAL & " "
    OutStr = OutStr & "NUM-PLAYERS=" & playerNUM
    msgLen = Len(msgType) + 8 + Len(OutStr) + 1
    rdatData = msgType & pad & Chr(msgLen) & OutStr & Chr(0)
    Winsock4(Index).SendData rdatData 'protoVER = 2
End Function
Public Function Send_GDAT(Index)
    'TID IP PORT GAME-ID FAVORITE NUM-FAV-PLAYERS NUM-PLAYERS MAX-PLAYERS NAME
    msgType = "GDAT"
    x = 1
    For x = 1 To Int(roomTOTAL)
        OutStr = "TID=" & clientTID & " "
        OutStr = OutStr & "IP=" & Chr(34) & rooms(x).roomHOST & Chr(34) & " "
        'OutStr = OutStr & "NAME=" & Chr(34) & rooms(x).roomNAME & Chr(34) & " "
        OutStr = OutStr & "PORT=28500" & " "
        'OutStr = OutStr & "GAME-ID=" & rooms(x).roomINDEX & " "
        OutStr = OutStr & "GAME-ID=1" & " "
        OutStr = OutStr & "FAVORITE=0" & " "
        OutStr = OutStr & "NUM-FAV-PLAYERS=0" & " "
        OutStr = OutStr & "NUM-PLAYERS=" & rooms(x).roomPLAYERS & " "
        OutStr = OutStr & "MAX-PLAYERS=" & rooms(x).roomMAXSIZE & " "
        OutStr = OutStr & "NAME=" & Chr(34) & rooms(x).roomNAME & Chr(34)
        msgLen = Len(msgType) + 8 + Len(OutStr) + 1
        gdatData = msgType & pad & Chr(msgLen) & OutStr & Chr(0)
        Winsock4(Index).SendData gdatData 'protoVER = 2
        x = x + 1
        Sleep (200)
        DoEvents
    Next x
End Function
Public Function Send_usr()
    msgType = "+usr"
    OutStr = "I=1" & clientTID & Chr(10)
    OutStr = OutStr & "N=" & clientNAME & Chr(10)
    msgLen = Len(msgType) + 8 + Len(OutStr) + 1
    usrData = msgType & pad & Chr(msgLen) & OutStr & Chr(0)
    Winsock2.SendData usrData
End Function
Public Function Send_Who()
    msgType = "+who"
    OutStr = "M=" & clientNAME & Chr(10)
    OutStr = OutStr & "N=" & clientNAME & Chr(10)
    OutStr = OutStr & "MA=" & clientMAC & Chr(10)
    OutStr = OutStr & "A=" & Winsock2.RemoteHostIP & Chr(10)
    OutStr = OutStr & "LA=" & Winsock2.RemoteHostIP & Chr(10)
    OutStr = OutStr & "P=1" & Chr(10)
    OutStr = OutStr & "CL=511" & Chr(10)
    OutStr = OutStr & "F=U" & Chr(10)
    OutStr = OutStr & "G=1" & Chr(10)
    OutStr = OutStr & "HW=0" & Chr(10)
    OutStr = OutStr & "I=71615" & Chr(10)
    OutStr = OutStr & "LO=enUS" & Chr(10)
    OutStr = OutStr & "LV=1049601" & Chr(10)
    OutStr = OutStr & "MD=0" & Chr(10)
    OutStr = OutStr & "PRES=" & Chr(10)
    OutStr = OutStr & "SESS=" & clientSESS & Chr(10)
    OutStr = OutStr & "RP=0" & Chr(10)
    OutStr = OutStr & "S=" & Chr(10)
    OutStr = OutStr & "US=0" & Chr(10)
    OutStr = OutStr & "VER=5" & Chr(10)
    OutStr = OutStr & "X=" & Chr(10)
    msgLen = Len(msgType) + 8 + Len(OutStr) + 1
    whoStr = msgType & pad & Chr(msgLen) & OutStr & Chr(0)
    Winsock2.SendData whoStr
End Function
Public Function Send_Rom()
    msgType = "+rom"
    'OutStr = "IDENT=1001" & Chr(10)
    'OutStr = OutStr & "NAME=" & roomNAME & Chr(10)
    'OutStr = OutStr & "HOST=" & clientPERS & Chr(10)
    'OutStr = OutStr & "DESC=" & Chr(10)
    'OutStr = OutStr & "COUNT=1" & Chr(10)
    'OutStr = OutStr & "LIMIT=50" & Chr(10)
    'OutStr = OutStr & "FLAGS=C" & Chr(10)
    OutStr = "I=420" & Chr(10)
    OutStr = OutStr & "N=" & clientPERS & Chr(10)
    'OutStr = OutStr & "M=" & clientPERS & Chr(10)
    'OutStr = OutStr & "R=" & roomNAME & Chr(10)
    'OutStr = OutStr & "RI=1001" & Chr(10)
    'OutStr = OutStr & "F=" & Chr(10)
    'OutStr = OutStr & "A=" & Winsock2.RemoteHostIP & Chr(10)
    'OutStr = OutStr & "S=" & Chr(10)
    OutStr = OutStr & "T=1" & Chr(10)
    OutStr = OutStr & "L=4" & Chr(10)
    msgLen = Len(msgType) + 8 + Len(OutStr) + 1
    romStr = msgType & pad & Chr(msgLen) & OutStr & Chr(0)
    Winsock2.SendData romStr
End Function
Public Function Send_Png()
    msgType = "~png"
    OutStr = "REF=" & Format(Date, "YYYY.DD.MM") & "-" & Format(Time, "HH:MM:SS") & Chr(10)
    OutStr = OutStr & "TIME=" & pingTIME & Chr(10)
    msgLen = Len(msgType) + 8 + Len(OutStr) + 1
    pingStr = msgType & pad & Chr(msgLen) & OutStr & Chr(0)
    If Winsock2.State = 7 And Not clientVERS = "KOKPS22004/M1" Then
        Winsock2.SendData pingStr
    End If
    If Winsock3.State = 7 Then
        Winsock3.SendData pingStr
    End If
    For x = 0 To PlayerCnt
    If Winsock4(x).State = 7 Then
        Winsock4(x).SendData pingStr
    End If
    Next x
End Function

    
Private Sub about_Click(Index As Integer)
msgStr = "Written by Veritas/VTSTech (Nigel Todman)" & vbCr & "Veritas Technical Solutions (www.VTS-Tech.org)" & vbCr
msgStr = msgStr & "GitHub: https://github.com/Veritas83/VTSTech-SRVEmu" & vbCr & vbCr
msgStr = msgStr & "Not affiliated with or endorsed by EA, Electronic Arts Inc" & vbCr
msgStr = msgStr & "All copyrights and trademarks property of their respective owners" & vbCr & vbCr
msgStr = msgStr & "This project would not be possible without the previous work by the following:" & vbCr & vbCr
msgStr = msgStr & "TeknoGods/eaEmu & HarpyWar/nfsuserver & riperiperi/Breakin-In" & vbCr & vbCr
msgStr = msgStr & "With contributions from: No23, IamLupo" & vbCr
MsgBox msgStr
End Sub

Private Sub Combo1_Click()
Winsock1.Close
Winsock2.Close
Winsock3.Close
'Burnout 3 Takedown", 0
'Burnout 3 Takedown (Review)", 1
'Burnout Paradise (PS3)", 2
'Fight Night 2004", 3
'Madden NFL 05", 4
'Medal of Honor: Rising Sun", 5
'NASCAR Thunder 2004", 6
'Need for Speed: Underground", 7
'SSX3", 8
If Combo1.ListIndex = 0 Then
    Winsock1.LocalPort = 21800
ElseIf Combo1.ListIndex = 1 Then
    Winsock1.LocalPort = 21840
ElseIf Combo1.ListIndex = 2 Then
    Winsock1.LocalPort = 21870
ElseIf Combo1.ListIndex = 3 Then
    Winsock1.LocalPort = 11500
ElseIf Combo1.ListIndex = 4 Then
    Winsock1.LocalPort = 20000
ElseIf Combo1.ListIndex = 5 Then
    Winsock1.LocalPort = 14300
    protoVER = 2
ElseIf Combo1.ListIndex = 6 Then
    Winsock1.LocalPort = 10600
ElseIf Combo1.ListIndex = 7 Then
    Winsock1.LocalPort = 10900
ElseIf Combo1.ListIndex = 8 Then
    Winsock1.LocalPort = 20900
ElseIf Combo1.ListIndex = 9 Then
    Winsock1.LocalPort = 11000
End If
Text1.Text = Winsock1.LocalPort
End Sub

Private Sub Command1_Click()
Dim rooms(9999) As room
Dim players(9999) As player
clientSKEY = ""
moreCmd = False
ParseTmp = ""
tmp2 = ""
tmp3 = ""
PlayerCnt = 0
Label6.Visible = False
Label7.Visible = False
Label8.Visible = False
Label9.Visible = False
Label10.Visible = False
Label11.Visible = False
Label12.Visible = False
Label13.Visible = False
'Label14.Visible = False
'Label15.Visible = False

'* Game Socket
Winsock1.Close
Winsock1.Bind 0, Text5.Text

'* Listener Socket
Winsock2.Close
Winsock2.Bind 0, Text5.Text

'* Buddy Socket
Winsock3.Close
Winsock3.Bind 0, Text5.Text



If Command1.Caption = "Stop" Then
Winsock1.Close
Winsock2.Close
Winsock3.Close
Command1.Caption = "Listen"
GoTo fin
End If

If Check1.Enabled = True Then
    Winsock1.Close
    Winsock2.Close
    Winsock3.Close
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
    'Winsock3.LocalPort = 28500 'Buddy
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
If Winsock2.State = 0 Then
MsgBox "Error. Cannot send thru a closed socket"
GoTo fin
ElseIf Winsock2.State = 2 Then
MsgBox "Error. Wait for something to send to"
GoTo fin
ElseIf Winsock2.State = 9 Then
MsgBox "Error. Connection has been lost"
GoTo fin
End If
out = Text3.Text
out = HexToString(out)
Winsock2.SendData (out)
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


Private Sub exit_Click(Index As Integer)
Unload Form1
End
End Sub

Private Sub Form_Load()
On Error Resume Next
Set fso = CreateObject("Scripting.FileSystemObject")
acctDB = VB.App.Path & "\acct.db"
Build = "0.1-R15"
Form1.Caption = "VTSTech-SRVEmu v" & Build
Text1.Text = 21800
Check1.value = 1
PlayerCnt = 0
playerNUM = PlayerCnt
pingTIME = 2
secCNT = 0
pingSEC = 30
protoVER = 1
Combo1.Text = "Burnout 3 Takedown"
Combo1.AddItem "Burnout 3 Takedown", 0
Combo1.AddItem "Burnout 3 Takedown (Review)", 1
Combo1.AddItem "Burnout Paradise (PS3)", 2
Combo1.AddItem "Fight Night 2004", 3
Combo1.AddItem "Madden NFL 05", 4
Combo1.AddItem "Medal of Honor: Rising Sun", 5
Combo1.AddItem "NASCAR Thunder 2004", 6
Combo1.AddItem "Need for Speed: Underground", 7
Combo1.AddItem "Need for Speed: Underground 2", 8
Combo1.AddItem "SSX3", 9

Text2.Text = ""
Text3.Text = "Enter data to send in hex (ex: 7e 70 6e 67 00 00 00 2f 00 00 00 14 54 49 4d 45 3d 31 0a 00)"
Text4.Text = ""
Text5.Text = "192.168.0.228"

Timer1.Interval = 999
Timer1.Enabled = True
End Sub

Private Sub Label3_Click()
Shell ("cmd.exe /c start http://www.VTS-Tech.org"), vbNormalFocus
End Sub

Private Sub Label4_Click()
Shell ("cmd.exe /c start bitcoin:1ByfBujg9bnmk1XXY2rxY6obhqHMUNiDuP?amount=0.02&message=donation"), vbNormalFocus
End Sub

Private Sub save_Click(Index As Integer)
Open VB.App.Path & "\log.txt" For Output As #4
Print #4, "VTSTech-SRVEmu v" & Build & vbCrLf & Text2.Text
Close #4
MsgBox "log.txt written", vbInformation
End Sub

Private Sub Timer1_Timer()
secCNT = secCNT + 1
Label2.Caption = "Socket States: " & Winsock1.State & Winsock2.State & Winsock3.State
Label5.Caption = "Connected Players: " & PlayerCnt
DoEvents
If Winsock1.State = 0 Then
    Winsock1.Listen
End If
If Winsock2.State = 0 Then
    Winsock2.Listen
End If
If Winsock3.State = 0 Then
    Winsock3.Listen
End If
If (secCNT - pingSEC) > Int(pingTIME) * 10 And (Winsock2.State = 7 Or Winsock3.State = 7) Then
    a = Send_Png()
End If
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
playerExists = False
For x = 0 To PlayerCnt
    If players(x).playerIP = Winsock1.RemoteHostIP Then
        PlayerCnt = PlayerCnt
        playerExists = True
        Winsock1.Close
        Winsock4(PlayerCnt).Close
        Winsock4(PlayerCnt).Accept (requestID)
        players(PlayerCnt).playerNUM = PlayerCnt
        players(PlayerCnt).playerID = Int(1000 + PlayerCnt)
        players(PlayerCnt).playerIP = Winsock1.RemoteHostIP
        players(PlayerCnt).playerROOM = 0
        players(PlayerCnt).playerPORT = Winsock1.RemotePort
        players(PlayerCnt).playerNAME = ""
    End If
Next x
If playerExists = False Then
        Winsock1.Close
        Winsock4(PlayerCnt).Close
        Winsock4(PlayerCnt).Accept (requestID)
        PlayerCnt = PlayerCnt + 1
        x = PlayerCnt
        players(PlayerCnt).playerNUM = PlayerCnt
        players(PlayerCnt).playerID = Int(1000 + PlayerCnt)
        players(PlayerCnt).playerIP = Winsock1.RemoteHostIP
        players(PlayerCnt).playerROOM = 0
        players(PlayerCnt).playerPORT = Winsock1.RemotePort
        players(PlayerCnt).playerNAME = ""
End If
Buff = Text2.Text
Text2.Text = Buff & vbCrLf & "[+] Connection request (" & requestID & ") " & Winsock1.RemoteHostIP & ":" & Winsock1.RemotePort & vbCrLf
End Sub

Private Sub Winsock1_Error(ByVal Number As Integer, Description As String, ByVal Scode As Long, ByVal Source As String, ByVal HelpFile As String, ByVal HelpContext As Long, CancelDisplay As Boolean)
Winsock1.Close
Winsock1.Listen
PlayerCnt = PlayerCnt - 1
End Sub
Private Sub Winsock2_Error(ByVal Number As Integer, Description As String, ByVal Scode As Long, ByVal Source As String, ByVal HelpFile As String, ByVal HelpContext As Long, CancelDisplay As Boolean)
Winsock2.Close
Winsock2.Listen
clientSKEY = ""
moreCmd = False
ParseTmp = ""
tmp2 = ""
tmp3 = ""
PlayerCnt = PlayerCnt - 1
End Sub
Private Sub Winsock3_Error(ByVal Number As Integer, Description As String, ByVal Scode As Long, ByVal Source As String, ByVal HelpFile As String, ByVal HelpContext As Long, CancelDisplay As Boolean)
Winsock3.Close
Winsock3.Listen
End Sub
Private Sub Winsock2_ConnectionRequest(ByVal requestID As Long)
'* Listener Socket 10901
Winsock2.Close
Winsock4(PlayerCnt + 1).Close
Winsock4(PlayerCnt + 1).Accept (requestID)
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

'If msgType = "auth" Then
    'a = Send_Who()
    'a = Send_Rom()
'End If

If msgType = "pers" Then
    DoEvents
    'a = Send_Rom()
    'Sleep (500)
    DoEvents
    'a = Send_Who()
    'Sleep (500)
    DoEvents
    'a = Send_usr()
End If

If msgType = "sviw" Then
    a = Send_Who()
    'a = Send_Rom()
End If

End Sub

Private Sub Winsock3_DataArrival(ByVal bytesTotal As Long)
'* Buddy Socket 10899
On Error Resume Next
Randomize Timer
Winsock3.GetData Data, vbString
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
 
Private Sub Winsock4_ConnectionRequest(Index As Integer, ByVal requestID As Long)
'* Listener Socket
clientSKEY = ""
moreCmd = False
'ParseTmp = ""
tmp2 = ""
tmp3 = ""
'ReDim players(PlayerCnt)
players(PlayerCnt).playerNUM = PlayerCnt
players(PlayerCnt).playerIP = Winsock1.RemoteHostIP
players(PlayerCnt).playerROOM = 0
players(PlayerCnt).playerPORT = Winsock1.RemotePort
players(PlayerCnt).playerNAME = ""
Winsock4(Index).Close
Winsock4(Index).Accept (requestID)
Buff = Text2.Text
Text2.Text = Buff & vbCrLf & "[+] Connection request (" & requestID & ") " & Winsock4(Index).RemoteHostIP & ":" & Winsock4(Index).RemotePort & vbCrLf
End Sub

Private Sub Winsock4_DataArrival(Index As Integer, ByVal bytesTotal As Long)
'*Listener Socket
On Error Resume Next
Randomize Timer
Winsock4(Index).GetData Data, vbString
Buff = Text2.Text
DataStr = StringToHex(Data)
DataLen = Len(Data)
tmp2 = ParseData(DataStr)
Text2.Text = Buff & Mid(tmp2, 12, Len(tmp2))
If Len(ParseTmp) >= 1 Then
    'tmp3 = HexToBin(StringToHex(ParseData("moreCmd")))
    Winsock4(Index).SendData (HexToBin(StringToHex(ParseTmp)))
Else
    If msgType = "skey" Then
        If moreCmd = True Or Len(clientSKEY) >= 1 Then
            DataStr = StringToHex(Data)
            tmp3 = ParseData(DataStr)
            Sleep (250)
            If Len(ParseTmp) >= 1 Then
                Winsock4(Index).SendData (HexToBin(StringToHex(ParseTmp)))
            End If
            If Len(tmp2) >= 1 Then
                Winsock4(Index).SendData (HexToBin(StringToHex(tmp2)))
            End If
        End If
        ParseTmp = ""
    End If
    If Len(tmp2) > 1 And Len(clientSKEY) >= 1 And Not msgType = "skey" Then
        Winsock4(Index).SendData (HexToBin(StringToHex(tmp2)))
        tmp2 = ""
    End If
End If
If Len(tmp2) > 1 Then
    'Sleep (250)
    Winsock4(Index).SendData (HexToBin(StringToHex(tmp2)))
End If
If msgType = "RLST" Then
    DoEvents
    Sleep (1000)
    DoEvents
    a = Send_RDAT(Index)
End If
If msgType = "GLST" Then
    DoEvents
    Sleep (500)
    DoEvents
    a = Send_GDAT(Index)
End If
If msgType = "LLST" Then
    DoEvents
    Sleep (500)
    DoEvents
    a = Send_LDAT(Index)
End If
If moreCmd = True Then
    Winsock4(Index).SendData (HexToBin(StringToHex(ParseData("moreCmd"))))
End If
End Sub

Private Sub Winsock4_Error(Index As Integer, ByVal Number As Integer, Description As String, ByVal Scode As Long, ByVal Source As String, ByVal HelpFile As String, ByVal HelpContext As Long, CancelDisplay As Boolean)
'Winsock4(Index).Close
'Winsock4(Index).Listen
clientSKEY = ""
moreCmd = False
ParseTmp = ""
tmp2 = ""
tmp3 = ""
'PlayerCnt = PlayerCnt - 1
End Sub
