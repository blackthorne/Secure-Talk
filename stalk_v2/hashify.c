#include <openssl/sha.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define SHA_DIGEST_LEN 20
#define DEBUG_MODE 1

int main(int argc,char *argv[]){
	size_t buf_len = strlen(argv[1]);
	unsigned char digest[SHA_DIGEST_LEN];
	SHA_CTX sha_ctx = { 0 };
	
	int rc;	

	rc = SHA1_Init(&sha_ctx);
	rc = SHA1_Update(&sha_ctx, argv[1], buf_len);
	rc = SHA1_Final(digest, &sha_ctx);
	
	//SHA1((unsigned char *)argv[1], buf_len, digest);
	int i;
	for(i=0;i< SHA_DIGEST_LEN;printf("%x",digest[i]),i++);
	puts("");
	return 0;
}
