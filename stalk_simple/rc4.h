#ifndef RC4_H_
#define RC4_H_
#define MAX_S_SIZE 256

struct RC4_ctx { 
    unsigned char i,j;
    unsigned char s[MAX_S_SIZE];
}; 
 
 
/* 
 * Fun��o de inicializa��o da estrutura RC4_ctx. 
 */ 
int RC4_init(unsigned char *key, unsigned char key_size, struct RC4_ctx *context);  
 
/*  
 * Fun��o que destr�i a estrutura RC4_ctx libertando a mem�ria associada.  
 */ 
int RC4_destroy(struct RC4_ctx *context);

/*  
 * Fun��o que pega numa estrutura RC4_ctx previamente inicializada  
 * e actualiza o seu contexto com uma nova chave.  
 */  
int RC4_renew(struct RC4_ctx *context, unsigned char *key, unsigned char key_size);  

/* 
 * Fun��o que cifra e decifra os dados. 
 * Se o texto cifrado for passado como input, o output � o texto em claro e vice-versa. 
 * O par�metro size_bytes indica a dimens�o do input. O output tem que ter  
 * obrigatoriamente a mesma dimens�o. 
 */ 
int RC4_stream(struct RC4_ctx *context, unsigned char *input, unsigned char *output,  
               unsigned int size_bytes); 

#endif /*RC4_H_*/
