**================================================================================**

**NASCAR THUNDER 2004 - COMPREHENSIVE PROTOCOL REFERENCE (v0.12)**

**================================================================================**



**\[I. CORE NETWORK \& HANDSHAKE]**

CMD     DIRECTION   PARAMS (REQ)                PARAMS (RESP)

---     ---------   ------------                -------------

@dir    C -> S      ADDR, PORT, SESS            ADDR, PORT, SESS, MASK

addr    C -> S      ADDR, PORT                  IP, PORT, STATUS=1

skey    C -> S      SKEY (16-byte hex)          SKEY, STATUS=1

~png    C -> S      REF, TIME, SESS             REF, TIME, STATUS=1



Note: skey generates the RC4 state at DAT\_0050a8d0.

--------------------------------------------------------------------------------



**\[II. AUTHENTICATION \& IDENTITY]**

CMD     DIRECTION   PARAMS (REQ)                PARAMS (RESP)

---     ---------   ------------                -------------

auth    C -> S      NAME, PASS$, PERS, VERS     NAME, PID, LKEY, STATUS=1

acct    C -> S      NAME, PASS$, MAIL, BORN     NAME, PID, STATUS=1

user    C -> S      PERS (Target Name)          PERS, TITLE=1, STATUS=1

pers    C -> S      PERS (Desired Persona)      PERS, STATUS=1, LAST

cper    C -> S      PERS, ALTS                  PERS, STATUS=1



Note: TITLE=1 in 'user' response is MANDATORY to enable the UI challenge button.

--------------------------------------------------------------------------------



**\[III. LOBBY \& NAVIGATION]**

CMD     DIRECTION   PARAMS (REQ)                PARAMS (RESP)

---     ---------   ------------                -------------

sele    C -> S      ROOMS=1, USERS=1            S=0 (Triggers +rom/+usr bursts)

room    C -> S      NAME, PASS, DESC, MAX       I, L, T, F, H, A

move    C -> S      NAME, PASS                  I, N, T, F

peek    C -> S      NAME                        S=0 (Sent on hover/highlight)



Note: Room Response Keys: I=ID, L=Max, T=Count, H=Host, A=Addr.

--------------------------------------------------------------------------------



**\[IV. THE CHALLENGE HANDSHAKE ("THE DANCE")]**

Sequence is strict. Deviation results in UI soft-lock.



1\.  C -> S  auxi    TEXT=token (e.g., w893m\_a016o\_g)

&nbsp;   S -> C  auxi    S=0

2\.  C -> S  mesg    N=TargetPersona, T=CHAL, F=3

&nbsp;   S -> C  mesg    S=0

3\.  S -> C  +msg    FROM=HostPersona, TEXT=CHAL, F=3  (To Target)

4\.  C -> S  mesg    N=HostPersona, T=ACPT, F=3        (From Target)

&nbsp;   S -> C  mesg    S=0

5\.  S -> C  +msg    FROM=TargetPersona, TEXT=ACPT, F=3 (To Host)





--------------------------------------------------------------------------------



**\[V. RACE EXECUTION]**

CMD     DIRECTION   PARAMS (REQ)                PARAMS (RESP)

---     ---------   ------------                -------------

play    C -> S      SELF, HOST, FROM, SEED      SELF, HOST, STATUS=0

+ses    S -> C      (Broadcast/Push)            272-byte Binary Blob

rank    C -> S      SET\_TRACKID, SET\_NUMAI      S=0



Note: +ses must arrive after ACPT but before the 'play' command resolves.

--------------------------------------------------------------------------------



**\[VI. SERVER ASYNC BROADCASTS]**

CMD     PURPOSE             PAYLOAD FIELDS

---     -------             --------------

+who    Global Presence     F (Flags), N (Name), RI (RoomID), RT (Total)

+usr    Room Presence       I (UserID), N (Persona), F (Flags), A (IP)

+rom    Room List           I (ID), N (Name), H (Host), T (Current), L (Max)

+pop    Population          Z=RoomID:Count (e.g., Z=0:5 1:2)

+msg    Message/CHAL        FROM, TEXT, F (0x3=Challenge, 0x10000=Private)

--------------------------------------------------------------------------------



**\[VII. ERROR \& STATUS CODES]**

CODE    LABEL       MEANING

----    -----       -------

1       SUCCESS     Standard success (auth, skey, news)

0       OK/IDLE     Standard success (auxi, mesg, play, snap)

100     AUTH\_FAIL   Invalid credentials

103     ROOM\_FULL   Capacity reached

105     BUSY        Player currently in another transaction

106     INV\_TOKEN   Malformed auxi token

--------------------------------------------------------------------------------



**\[VIII. MEMORY, OFFSETS \& CRYPTO]**

\- Session Key:   16-bytes (from skey)

\- Re-key String: "ru paranoid?" (used for UDP/Play transition)

\- Binary Base:   DAT\_004e31a8 (Location of the 272-byte session data)

\- Valid Flag:    Base + 0x2d8 (Set to 1 when session data is parsed)

\- Track ID:      Offset 0x18 within the +ses blob

\- AI Count:      Offset 0x46 within the +ses blob

\- Host IP:       Offset 0x30 within the +ses blob (Big Endian)

================================================================================

