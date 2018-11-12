#include <openssl/evp.h>
#include <string.h>

int md5_to_str(unsigned char *md5_hash, unsigned int md5_len,unsigned char *md5_string)
{
	int idx;

	memset(md5_string, 0, EVP_MAX_MD_SIZE * 2);
	for(idx = 0; idx < md5_len; idx++){
		sprintf(&md5_string[idx*2], "%02x", md5_hash[idx]);
	}
	
	//printf("result of convert: %s\n", md5_string);
	return 0;
}

int calculate_response(unsigned char *method, unsigned char *username, 
		unsigned char *realm, unsigned char *password, 
		unsigned char *uri, unsigned char *nonce, 
		unsigned char *response_str)
{
	EVP_MD_CTX *md5ctx;
	const EVP_MD *md5;
	unsigned char data[1024];
	unsigned char tmp[EVP_MAX_MD_SIZE];
	unsigned char hash_v1[EVP_MAX_MD_SIZE];
	unsigned char hash_v1_str[EVP_MAX_MD_SIZE*2];
	unsigned char hash_v2[EVP_MAX_MD_SIZE];
	unsigned char hash_v2_str[EVP_MAX_MD_SIZE*2];
	unsigned char response[EVP_MAX_MD_SIZE];

	int v1_len, v2_len, res_len;
	
	int slen = 0;
	int idx;

	md5 = EVP_get_digestbyname("md5");
	md5ctx = EVP_MD_CTX_new();
	EVP_DigestInit_ex(md5ctx, md5, NULL);
	
	memset(data, 0, 1024);
	slen = sprintf(data, "%s:%s:%s", username, realm, password);
	EVP_DigestUpdate(md5ctx, data, (unsigned long ) slen);
	EVP_DigestFinal_ex(md5ctx, hash_v1, &v1_len);
	EVP_MD_CTX_free(md5ctx);

	md5ctx = EVP_MD_CTX_new();
	EVP_DigestInit_ex(md5ctx, md5, NULL);
	
	memset(data, 0, 1024);
	slen = sprintf(data, "%s:%s", method, uri);
	EVP_DigestUpdate(md5ctx, data, (unsigned long ) slen);
	EVP_DigestFinal_ex(md5ctx, hash_v2, &v2_len);
	EVP_MD_CTX_free(md5ctx);

	md5ctx = EVP_MD_CTX_new();
	EVP_DigestInit_ex(md5ctx, md5, NULL);
	
	md5_to_str(hash_v1, v1_len, hash_v1_str);
	md5_to_str(hash_v2, v2_len, hash_v2_str);
	memset(data, 0, 1024);
	slen = sprintf(data, "%s:%s:%s", hash_v1_str, nonce, hash_v2_str);
	EVP_DigestUpdate(md5ctx, data, (unsigned long ) slen);
	EVP_DigestFinal_ex(md5ctx, response, &res_len);
	EVP_MD_CTX_free(md5ctx);


	/*printf("hash_v1: ");
	for(idx = 0;idx < v1_len; idx++)
		printf("%02x", hash_v1[idx]);
	printf("\n");
	
	printf("hash_v2: ");
	for(idx = 0;idx < v2_len; idx++)
		printf("%02x", hash_v2[idx]);
	printf("\n");

	printf("response: ");
	for(idx = 0;idx < res_len; idx++)
		printf("%02x", response[idx]);
	printf("\n");*/
	md5_to_str(response, res_len, response_str);

	return 0;
}

