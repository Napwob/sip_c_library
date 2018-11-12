#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/evp.h>
#include <malloc.h>
#include "md5_count.h"
#include "my_sip.h"

#define BUFF_SIZE 1400
#define SERV_PORT 5060
#define CLI_PORT 7777
#define SERV_IP "192.168.5.185"
#define CLI_IP "192.168.5.185"
#define USERNAME "1001"
#define PASSWORD "1234"

int main(void)
{
	int fd = 0;
	int length;
	struct sockaddr_in sip_serv;
	struct sockaddr_in sip_cli;
	char send_buff[BUFF_SIZE];
	char recv_buff[BUFF_SIZE];
	char *start_of_auth = NULL;
	char *start_of_realm = NULL;
	char *start_of_nonce = NULL;
	char *sptr = NULL;
	char *realm = NULL;
	char *nonce = NULL;
	char *uri = NULL;
	char *token = NULL;
	char *tag = NULL;
	unsigned char response_str[EVP_MAX_MD_SIZE*2];

	fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (fd < 0) {
		perror("Socket create error:");
		exit(-1);
	}
	
	memset(&sip_cli, 0, sizeof(sip_cli));
	sip_cli.sin_family = AF_INET;
	sip_cli.sin_port  = htons(CLI_PORT);
	sip_cli.sin_addr.s_addr = inet_addr(CLI_IP);
	if (bind(fd, (struct sockaddr*)&sip_cli, sizeof(sip_cli)) == -1) {
		perror("Socket binding error:");
		exit(-1);
	}	

	memset(&sip_serv, 0, sizeof(sip_serv));
	sip_serv.sin_family = AF_INET;
	sip_serv.sin_port  = htons(SERV_PORT);
	sip_serv.sin_addr.s_addr = inet_addr(SERV_IP);

	memset(send_buff, 0, BUFF_SIZE);
	memset(recv_buff, 0, BUFF_SIZE);
	sprintf(send_buff, REGISTER_METHOD, SERV_IP, CLI_IP, CLI_PORT, USERNAME, 
			SERV_IP, USERNAME, SERV_IP, USERNAME, CLI_IP);
	printf("%s\n", send_buff);
	sendto(fd, send_buff, BUFF_SIZE, 0, (struct sockaddr *)&sip_serv, sizeof(sip_serv));

	length = sizeof(sip_cli);
	recvfrom(fd, recv_buff, BUFF_SIZE, 0, (struct sockaddr *)&sip_serv, &length);
	printf("%s\n", recv_buff);

	start_of_auth = strstr(recv_buff, "WWW-Authenticate");
	printf("%s\n", start_of_auth);
	
	start_of_realm = strstr(start_of_auth, "realm=");
	token = strtok_r(start_of_realm, "\"", &sptr);
	token = strtok_r(NULL, "\"", &sptr);
	realm = malloc(strlen(token) + 1);
	strncpy(realm, token, strlen(token) + 1);

	start_of_nonce = strstr(start_of_auth, "nonce=");
	token = strtok_r(start_of_nonce, "\"", &sptr);
	token = strtok_r(NULL, "\"", &sptr);
	nonce = malloc(strlen(token) + 1);
	strncpy(nonce, token, strlen(token) + 1);

	uri = malloc(255);
	sprintf(uri, "sip:%s", SERV_IP);
	//printf("realm=%s %ld nonce=%s %ld\n", realm, strlen(realm), nonce, strlen(nonce));
	calculate_response("REGISTER", USERNAME, realm, PASSWORD, uri, nonce, response_str);

	memset(send_buff, 0, BUFF_SIZE);
	memset(recv_buff, 0, BUFF_SIZE);	
	//printf("realm=%s nonce=%s\n", realm, nonce);
	sprintf(send_buff, REGISTER_AUTH_METHOD, SERV_IP, CLI_IP, CLI_PORT, USERNAME,
			SERV_IP, USERNAME, SERV_IP, USERNAME, CLI_IP, USERNAME,
			realm, nonce, SERV_IP, response_str);
	printf("%s\n", send_buff);
	sendto(fd, send_buff,BUFF_SIZE, 0, (struct sockaddr *)&sip_serv, sizeof(sip_serv));
	free(realm);
	free(nonce);
	free(uri);	

	length = sizeof(sip_cli);
	recvfrom(fd, recv_buff, BUFF_SIZE, 0, (struct sockaddr *)&sip_serv, &length);
	printf("%s\n", recv_buff);
	
	memset(send_buff, 0, BUFF_SIZE);
	memset(recv_buff, 0, BUFF_SIZE);
	sprintf(send_buff, "INVITE sip:1002@192.168.5.185 SIP/2.0\r\nVia: SIP/2.0/UDP 192.168.5.185:7777;rport;branch=z9hG4bKPsfsdfds\r\nMax-Forwards: 70\r\nFrom: <sip:1001@192.168.5.185>;tag=123456\r\nTo: <sip:1002@192.168.5.185>\r\nContact: <sip:1001@192.168.5.185:7777>\r\nCall-ID: 1234567890\r\nCSeq: 1 INVITE\r\nAllow: PRACK, INVITE, ACK, BYE, CANCEL, UPDATE, INFO, SUBSCRIBE, NOTIFY, REFER, MESSAGE, OPTIONS\r\nContent-Type: application/sdp\r\nContent-Length: 136\r\n\r\nv=0\r\no=- 3749511925 3749511925 IN IP4 192.168.5.185\r\ns=Test phone\r\nt=0 0\r\nm=audio 4010 RTP/AVP 0\r\nc=IN IP4 192.168.5.185\r\na=rtpmap:0 PCMU/8000\r\n");
	printf("%s\n", send_buff);
	sendto(fd, send_buff,BUFF_SIZE, 0, (struct sockaddr *)&sip_serv, sizeof(sip_serv));
	
	length = sizeof(sip_cli);
	recvfrom(fd, recv_buff, BUFF_SIZE, 0, (struct sockaddr *)&sip_serv, &length);
	printf("%s\n", recv_buff);
	
	token = strstr(recv_buff, "To:");
	token = strstr(token, "tag=");
	token = strtok_r(token + 4, "=", &sptr);
	tag = malloc(strlen(token) + 1);
	strncpy(tag, token, strlen(token) + 1);

	start_of_auth = strstr(recv_buff, "WWW-Authenticate");
	printf("%s\n", start_of_auth);
	
	start_of_realm = strstr(start_of_auth, "realm=");
	token = strtok_r(start_of_realm, "\"", &sptr);
	token = strtok_r(NULL, "\"", &sptr);
	realm = malloc(strlen(token) + 1);
	strncpy(realm, token, strlen(token) + 1);

	start_of_nonce = strstr(start_of_auth, "nonce=");
	token = strtok_r(start_of_nonce, "\"", &sptr);
	token = strtok_r(NULL, "\"", &sptr);
	nonce = malloc(strlen(token) + 1);
	strncpy(nonce, token, strlen(token) + 1);

	uri = malloc(255);
	sprintf(uri, "sip:1002@%s", SERV_IP);
	printf("uri: %s\n", uri);
	//printf("realm=%s %ld nonce=%s %ld\n", realm, strlen(realm), nonce, strlen(nonce));
	calculate_response("INVITE", USERNAME, realm, PASSWORD, uri, nonce, response_str);
	
	memset(send_buff, 0, BUFF_SIZE);
	sprintf(send_buff, "ACK sip:1002@192.168.5.185 SIP/2.0\r\nVia: SIP/2.0/UDP 192.168.5.185:7777;rport;branch=z9hG4bKPsfsdfds\r\nMax-Forwards: 70\r\nFrom: <sip:1001@192.168.5.185>;tag=123456\r\nTo: <sip:1002@192.168.5.185>;tag=%s\r\nCall-ID: 1234567890\r\nCseq: 1 ACK\r\nContent-Length: 0\r\n", tag);
	printf("%s\n", send_buff);
	sendto(fd, send_buff, BUFF_SIZE, 0, (struct sockaddr *)&sip_serv, sizeof(sip_serv));
	//sleep(1);
	memset(send_buff, 0, BUFF_SIZE);
	memset(recv_buff, 0, BUFF_SIZE);	
	sprintf(send_buff, "INVITE sip:1002@192.168.5.185 SIP/2.0\r\nVia: SIP/2.0/UDP 192.168.5.185:7777;rport;branch=z9hG4bKPsfwqeqwesdfds\r\nMax-Forwards: 70\r\nFrom: <sip:1001@192.168.5.185>;tag=123456\r\nTo: <sip:1002@192.168.5.185>\r\nContact: <sip:1001@192.168.5.185:7777>\r\nCall-ID: 1234567890\r\nCSeq: 2 INVITE\r\nAllow: PRACK, INVITE, ACK, BYE, CANCEL, UPDATE, INFO, SUBSCRIBE, NOTIFY, REFER, MESSAGE, OPTIONS\r\nAuthorization: Digest username=\"%s\", realm=\"%s\", nonce=\"%s\", uri=\"%s\", response=\"%s\", algorithm=MD5\r\nContent-Type: application/sdp\r\nContent-Length: 136\r\n\r\nv=0\r\no=- 3749511925 3749511925 IN IP4 192.168.5.185\r\ns=Test phone\r\nt=0 0\r\nm=audio 4010 RTP/AVP 0\r\nc=IN IP4 192.168.5.185\r\na=rtpmap:0 PCMU/8000\r\n", USERNAME, realm, nonce, uri, response_str);
	printf("%s\n", send_buff);
	sendto(fd, send_buff,BUFF_SIZE, 0, (struct sockaddr *)&sip_serv, sizeof(sip_serv));
	
	length = sizeof(sip_cli);
	recvfrom(fd, recv_buff, BUFF_SIZE, 0, (struct sockaddr *)&sip_serv, &length);
	printf("%s\n", recv_buff);
	
	//length = sizeof(sip_cli);
	//recvfrom(fd, recv_buff, BUFF_SIZE, 0, (struct sockaddr *)&sip_serv, &length);
	//printf("%s\n", recv_buff);
	
	close(fd);


	return 0;
}
