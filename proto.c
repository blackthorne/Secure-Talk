#include "rc4.h"
#include "proto.h"
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/rand.h>

#define NONCE_SIZE 24/8
#define NONCE_FIELD_SIZE sizeof(int)
#define SK_SIZE 40/8
#define MAXBUFLEN 1500 
#define USERNAME_MAXSIZE sizeof (unsigned char) * 8

#define DEBUG_MODE 0

#define SOCKET_CREATION_ERROR -10
#define SOCK_BIND_ERROR -11
#define KEY_INIT_ERROR -12
#define SEND_MSG_ERROR -13
#define RECV_ERROR -14
#define INVALID_IP_ADDR_ERROR -15
#define PROTO_MALLOC_ERROR -16

// auxiliary method to generate random bytes
void gen_random_bytes(unsigned char *rand, int nbytes){
	RAND_seed(rand,nbytes);
	RAND_bytes(rand,nbytes);
}

int proto_init(unsigned char *key, unsigned char key_size, struct proto_ctx *context){

	//	int rand = random() % 0x00ffffff; // generates a 3 bytes long pseudo-random number but...

	context->smsg.msg = NULL; // else realloc won't work for the first time
	
	if((context->rc4_data = malloc(sizeof(struct RC4_ctx))) == NULL){ // NOT PYTHON indeed
		printf("error allocating memory for (struct)proto_ctx->rc4_date in proto_init\n");
		exit(PROTO_MALLOC_ERROR);
	}
		
	if(DEBUG_MODE)
		printf("------- sizeof(struct RC4_ctx) ----> %d\n",sizeof(struct RC4_ctx));

	if(RC4_init(key, key_size , context->rc4_data) != 0) 
	{
		perror("error while initializing RC4 key.");
		exit(KEY_INIT_ERROR);
	}

	context->sk_size = key_size;
	
	if((context->sk = calloc(sizeof(unsigned char), key_size + NONCE_SIZE)) == NULL){
		printf("error allocating memory for key in proto_init\n");
		exit(PROTO_MALLOC_ERROR);
	}
	
	memcpy(context->sk, key, key_size);	

	if(DEBUG_MODE)
		printf("--> %s\n", context->sk);

	// error checking
	if ((context->sockfd_recv = socket(AF_INET, SOCK_DGRAM, 0)) == -1 ||
			(context->sockfd_send = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
		perror("socket error");
		exit(SOCKET_CREATION_ERROR);
	}

	context->my_addr.sin_family = AF_INET;		 // host byte order
	context->their_addr.sin_family = AF_INET;

	if(DEBUG_MODE){
		printf("------sin_port: %d\n", ntohs(context->my_addr.sin_port));
		printf("------nsin_address: %s\n", inet_ntoa(context->my_addr.sin_addr));
	}
	memset(context->my_addr.sin_zero, '\0', sizeof context->my_addr.sin_zero);

	if (bind(context->sockfd_recv, (struct sockaddr *)&context->my_addr, sizeof context->my_addr) == -1) {
		perror("socket bind failed");
		exit(SOCK_BIND_ERROR);
	}

	return 0;
}

/* 
 * Fun�‹o que envia uma mensagem para um determinado IP/porto. 
 */ 
int proto_send_msg(struct proto_ctx *context, unsigned char *dest_ip,  
		unsigned short dest_port, unsigned char *msg,  
		unsigned int size_bytes)
{
	unsigned char rand[NONCE_SIZE];
	unsigned char key[context->sk_size + NONCE_SIZE];
	int msg_to_crypt_size = size_bytes + sizeof(int) + USERNAME_MAXSIZE;	
	int full_msg_size = sizeof(int) + NONCE_FIELD_SIZE + msg_to_crypt_size;
	char send_data[full_msg_size];
	unsigned char msg_crypted[msg_to_crypt_size];
	unsigned char msg_to_crypt[msg_to_crypt_size];
	struct in_addr target_addr;

	gen_random_bytes(rand,NONCE_SIZE); // poker time

	context->their_addr.sin_port = htons(dest_port);
	if (!inet_aton((char *)dest_ip, &target_addr)){
		printf("can't parse IP address %s", dest_ip);
		exit(INVALID_IP_ADDR_ERROR);
	}
	context->their_addr.sin_addr = target_addr;
	memset(context->their_addr.sin_zero, '\0', sizeof context->their_addr.sin_zero);

	if(DEBUG_MODE){
		printf("NONCE: %x\n",*rand);
		printf("sizeof(context->sk) = %d\t\t SK_SIZE=%d\n",sizeof(unsigned char)*SK_SIZE,SK_SIZE);
	}

	memset(key, '\0', context->sk_size+NONCE_SIZE);
	memcpy(key,context->sk,context->sk_size);
	memcpy(key + context->sk_size,rand,NONCE_SIZE);
	memcpy(msg_to_crypt,context->smsg.username,USERNAME_MAXSIZE);
	memcpy(msg_to_crypt + USERNAME_MAXSIZE, &context->smsg.size, sizeof (int));
	memcpy(msg_to_crypt + USERNAME_MAXSIZE + sizeof(int),msg, size_bytes);
	
	RC4_renew(context->rc4_data, key,context->sk_size);
	RC4_stream(context->rc4_data, msg_to_crypt, msg_crypted,(unsigned char) msg_to_crypt_size);	// things go dark..

	if(DEBUG_MODE)
		printf("MESSAGE DECRYPTED: %s\nMESSAGE CRYPTED: %s\n",msg, msg_crypted);

	//int nonce = (int)*rand;
	memset(send_data,'\0',full_msg_size);
	memcpy(send_data,rand,NONCE_SIZE);
	memcpy(send_data + NONCE_FIELD_SIZE,&msg_to_crypt_size,NONCE_FIELD_SIZE);
	memcpy(send_data + NONCE_FIELD_SIZE + sizeof(int),msg_crypted,msg_to_crypt_size);
	
	if(DEBUG_MODE){
		int t;
		puts("data sent (decrypted): ");
		for(t=0; t < msg_to_crypt_size; printf("[%x]",msg_to_crypt[t]), t++);
		puts("");
	}

	int numbytes;

	if ((numbytes = sendto(context->sockfd_send, (char *) send_data, full_msg_size, 0,
			(struct sockaddr *)&context->their_addr, sizeof context->their_addr)) == -1) { // sends UPS dgrams
		perror("sendto problem.");
		exit(SEND_MSG_ERROR);
	}

	if(DEBUG_MODE)
		printf("sent %d bytes to %s\n", numbytes, inet_ntoa(context->their_addr.sin_addr));

	return 0;
}

int proto_recv_msg(struct proto_ctx *context, unsigned char *source_ip, 
		unsigned short *source_port, unsigned char *msg, 
		unsigned int *size_bytes)
{
	socklen_t addr_len;
	int numbytes;	   
	char buf[MAXBUFLEN];

	unsigned char key[context->sk_size + NONCE_SIZE];
	unsigned char *msg_decrypted;
	
	addr_len = sizeof context->their_addr;
	if ((numbytes = recvfrom(context->sockfd_recv, buf, MAXBUFLEN , 0,
			(struct sockaddr *)&context->their_addr, &addr_len)) == -1) { // receives UDP dgrams
		perror("recvfrom problem");
		exit(RECV_ERROR);
	}

	if(DEBUG_MODE)
		printf("package size: %d\n",numbytes);
	
	//	| nonce(unsigned int) | size(unsigned int) | msg(unsigned char *) |
	// get key from nonce
	memcpy(key,context->sk,context->sk_size);
	memcpy(key + context->sk_size,buf,NONCE_SIZE);
	
	if(DEBUG_MODE)
		printf("KEY: %s\n",key);
	// get size
	size_bytes = (unsigned int *)(buf + NONCE_FIELD_SIZE); // out variable :P
	source_ip = (unsigned char *) inet_ntoa(context->their_addr.sin_addr);
	*source_port = (unsigned short) ntohs(context->their_addr.sin_port);
	
	if(DEBUG_MODE)
		printf("size of message: %d\n",*size_bytes);

	if((msg_decrypted = calloc(sizeof(unsigned char),numbytes - NONCE_FIELD_SIZE - sizeof(int))) == NULL){
				printf("error allocating memory for msg_decrypted in proto_recv_msg\n");
				exit(PROTO_MALLOC_ERROR);
			}
	
	RC4_renew(context->rc4_data, key,context->sk_size);
	RC4_stream(context->rc4_data,(unsigned char *) buf + NONCE_FIELD_SIZE + sizeof(int),msg_decrypted,*size_bytes);	// things come to light..

	if(DEBUG_MODE){
		int t;
		printf("got packet from %s\n",inet_ntoa(context->their_addr.sin_addr));
		printf("packet is %d bytes long\n",numbytes);
		printf("MESSAGE CRYPTED: %s\nMESSAGE DECRYPTED: %s\n",buf+NONCE_FIELD_SIZE + sizeof(int), msg_decrypted);
		printf("Received %d bytes from IP: %s using PORT: %d\n", numbytes,source_ip,*source_port);
		puts("data sent: ");
		for(t=0; t < numbytes+1; printf("[%x]",buf[t]),++t);
		puts("");
	}	    
	
	memset(context->smsg.username,'\0',USERNAME_MAXSIZE);
	memcpy(context->smsg.username,msg_decrypted,USERNAME_MAXSIZE);
	memcpy(&context->smsg.size,msg_decrypted + USERNAME_MAXSIZE, sizeof (int));
	
	if(context->smsg.msg != NULL) { // C
		if((context->smsg.msg = malloc(*size_bytes + 1)) == NULL){
			printf("error allocating memory for (struct)proto_ctx->smsg.msg in proto_recv_msg\n");
			exit(PROTO_MALLOC_ERROR);
		}
	} else if((context->smsg.msg = realloc(context->smsg.msg,*size_bytes + 1)) == NULL){			
		printf("error reallocating memory for (struct)proto_ctx->smsg.msg in proto_recv_msg\n");
		exit(PROTO_MALLOC_ERROR);
	}
		
	memset(context->smsg.msg,'\0',*size_bytes + 1);	// calloc ? naa...
	memcpy(context->smsg.msg,msg_decrypted + USERNAME_MAXSIZE + sizeof (int),*size_bytes);

	if(DEBUG_MODE){
		int t;
		puts("data decrypted: ");
		for(t=0; t < numbytes + 2; ++t)
			printf("[%x]",msg_decrypted[t]);
		puts("");
	}

	free(msg_decrypted);
	
	return 1;
}

/*  
 * Funï¿½â€¹o que altera a chave SK usada pelo protocolo.  
 */  
int proto_renew_key(struct proto_ctx *context, unsigned char *key,  
		unsigned char key_size)
{
	RC4_renew(context->rc4_data, key,context->sk_size);
	memcpy(context->sk, key, key_size);
	return 0;
}

int proto_terminate(struct proto_ctx *context){
	close(context->sockfd_send);
	close(context->sockfd_recv);
	free(context); // so much for freedom...
	return 0;
}
/*// ### BEGIN TEST CODE ### 
// teste1 
int main(int argc,char *argv[]){
	unsigned char k[6] = "Wiki";
	unsigned char m[6] = "pedia";
	unsigned char s_ip,msg;
	unsigned short s_port;
	unsigned char g = (unsigned char)4;
	unsigned int g2 = 5;
	unsigned int size;
	struct proto_ctx a;

	char *ip = argv[1];
	short port = atoi(argv[2]);

	if(DEBUG_MODE)
		printf("DEBG: IP: %s\t\tPORT: %d\n",ip,port);
	a.my_addr.sin_port = htons(atoi(argv[2]));
	inet_aton(argv[1], &(a.my_addr.sin_addr));

	proto_init(k,g,&a);

	int ds,dr;

	a.their_addr.sin_port = htons(atoi(argv[2]));
	inet_aton(argv[1], &(a.their_addr.sin_addr));
	ds= proto_send_msg(&a,(unsigned char *)argv[1],port, m, g2);	

	// anybody out there?
	//while(1)
	//	dr= proto_recv_msg(&a, &s_ip,&s_port, &msg, &size);

	proto_terminate(&a);
}
// ### END TEST CODE ### */
