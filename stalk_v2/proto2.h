#ifndef PROTO_H_
#define PROTO_H_

#include <netinet/in.h>

#define NONCE_SIZE 64/8 // upgrade
#define NONCE_FIELD_SIZE NONCE_SIZE
#define ID_SIZE sizeof(int)
#define SK_SIZE 64/8
#define MAXBUFLEN 1500 
#define USERNAME_MAXSIZE sizeof (unsigned char) * 8
#define SHA_DIGEST_LEN 20
#define MAX_HOSTS_ALLOWED 2
#define MAX_DELAYED_ITEMS 20

#define SOCKET_CREATION_ERROR -10
#define SOCK_BIND_ERROR -11
#define KEY_INIT_ERROR -12
#define SEND_MSG_ERROR -13
#define RECV_ERROR -14
#define INVALID_IP_ADDR_ERROR -15
#define PROTO_MALLOC_ERROR -16

//unsigned int slide_window[MAX_DELAYED_ITEMS];
//unsigned int current_id, oldest_id_index, round; troubles :(

struct proto_ctx {
/*
* Informa��o de contexto que considerarem necess�ria
* para a execu��o do protocolo.
*/
	int sockfd_recv;
	int sockfd_send;
	
	struct RC4_ctx *rc4_data;
	unsigned char *sk;
	int sk_size;
	struct sockaddr_in my_addr; // my address information
	struct sockaddr_in their_addr; // connector's address information
	
	struct stalk_msg {
		unsigned int id;
	    unsigned char username[8]; /* nome do utilizador terminado com o caracter ‘\0’ */ 
	    unsigned int size;         /* tamanho da mensagem */ 
	    unsigned char *msg;        /* conteúdo da mensagem */ 
	} smsg; 
};
 
/* 
 * Fun��o de inicializa��o do protocolo onde: 
 *       � especificada a chave SK a utilizar; 
 *       � inicializada a estrutura proto_ctx (incluindo por exemplo o descritor    
 *       do socket que dever� ser criado tamb�m nesta fun��o) 
 */ 
int proto_init(unsigned char *key, unsigned char key_size, struct proto_ctx *context);  
 
/*  
 * Fun��o que termina a execu��o do protocolo, libertando a mem�ria associada ao mesmo.  
 */ 
int proto_terminate(struct proto_ctx *context);  
 
/*  
 * Fun��o que altera a chave SK usada pelo protocolo.  
 */  
int proto_renew_key(struct proto_ctx *context, unsigned char *key,  
                    unsigned char key_size);  
 
/* 
 * Fun��o que envia uma mensagem para um determinado IP/porto. 
 */ 
int proto_send_msg(struct proto_ctx *context, unsigned char *dest_ip,  
                   unsigned short dest_port, unsigned char *msg,  
                   unsigned int size_bytes); 
 
/* 
 * Fun��o que recebe uma mensagem de um IP/porto remoto. 
 * A fun��o deve bloquear-se at� que seja recebida alguma mensagem.  
 * O par�metro size_bytes indica, � entrada, o n�mero m�ximo de bytes que devem ser   
 * lidos e dever� ser preenchido, no retorno, com o n�mero de bytes efectivamente   
 * lidos. 
  */ 
int proto_recv_msg(struct proto_ctx *context, unsigned char *source_ip, 
                   unsigned short *source_port, unsigned char *msg, 
                   unsigned int *size_bytes);


#endif /*PROTO_H_*/
