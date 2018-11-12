#define REGISTER_METHOD "REGISTER sip:%s SIP/2.0\r\n\
Via: SIP/2.0/UDP %s:%d;branch=z9hG4bKus19\r\n\
Max-Forwards: 70\r\n\
From: <sip:%s@%s>;tag=1234\r\n\
To: <sip:%s@%s>\r\n\
Call-ID: 12345678\r\n\
CSeq: 1 REGISTER\r\n\
Contact: <sip:%s@%s>\r\n\
Content-Length: 0\r\n"

#define REGISTER_AUTH_METHOD "REGISTER sip:%s SIP/2.0\r\n\
Via: SIP/2.0/UDP %s:%d;branch=z9hG4bKus19\r\n\
Max-Forwards: 70\r\n\
From: <sip:%s@%s>;tag=1234\r\n\
To: <sip:%s@%s>\r\n\
Call-ID: 12345678\r\n\
CSeq: 2 REGISTER\r\n\
Contact: <sip:%s@%s>\r\n\
Authorization: Digest username=\"%s\", realm=\"%s\", nonce=\"%s\",\
uri=\"sip:%s\", response=\"%s\", algorithm=MD5\r\n\
Content-Length: 0\r\n"
	
	
