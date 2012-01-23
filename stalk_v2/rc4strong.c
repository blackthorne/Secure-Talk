#include "rc4strong.h"
#include <string.h>
#include <stdio.h>
#include <openssl/sha.h>

#define DEBUG_MODE 0

// ### TEST CODE BEGIN ###
/* variaveis de teste
unsigned char atr[] = "Wiki";
unsigned char i[] = "pedia";
unsigned char b[30],y[30];
unsigned char g;
unsigned int g2 = 5;
struct RC4_ctx a;

// teste
int testrc4(){
	g = (unsigned char)strlen((char *)atr);
	printf("--> %d\n", RC4_init(atr, g,&a));
}

// teste 2
int testrc4_2(){
	int t;
	g = (unsigned char)strlen((char *)i);
//	memset(&a, '\0', sizeof a);
	RC4_stream(&a,i,b,g2);
	RC4_stream(&a,b,y,g2);
	printf("--y: %s ----------\n\n",y);
	for(t=0; b[t] != '\0'; ++t)
		printf("%x",b[t]);
	puts("");
	puts("RC4( Wiki, pedia ) == 1021BF0420");
}

// teste 3
int main(){
	testrc4();
	testrc4_2();
}
 /* ### TEST CODE END ### */

void swap_bytes(unsigned char *a, unsigned char *b){
	unsigned char temp;
	temp = *a;
	*a = *b;
	*b = temp;
}

int RC4_init(unsigned char *key, unsigned char key_size, struct RC4_ctx *context){

	if(DEBUG_MODE)
		printf("key: %s key_size: %d context: %d\n",key,key_size,context);
	
	// these two are needed for KSA
	unsigned char y;
	int x;
    
    context->i = 0;
    context->j = 0;
    
    
    // KSA: key-scheduling algorithm
    // Initialization
	for (x = 0; x < 256; x++)
        context->s[x] = (unsigned char) x;

	// Scrambling	
	for (x = y = 0; x < 256; x++){
		y += context->s[x] + key[x % key_size];
		swap_bytes(&context->s[x],&context->s[y]);
	}
	
	return 0;	
}

int RC4_destroy(struct RC4_ctx *context){
    context->i = 0;
    context->j = 0;
    memset((void*) &context->s, 0, sizeof(unsigned char) * MAX_S_SIZE);
    return 0;
}

int RC4_renew(struct RC4_ctx *context, unsigned char *key, unsigned char key_size){
	RC4_init(key, key_size, context);
	return 0;
}

int RC4_stream(struct RC4_ctx *context, unsigned char *input, unsigned char *output,  
               unsigned int size_bytes){ 
	    
	// PRGA: pseudo-random generation algorithm
	int x;
	unsigned char y;

 //   memset(context, '\0', sizeof(struct RC4_ctx)); // no comment
	for (x = 0; x < 256; x++) { // upgrade

			context->i++;
			context->j += context->s[context->i];

			swap_bytes(&context->s[context->i],
					&context->s[context->j]);
		}

	for (x = 0; x < size_bytes; x++) {

			context->i++;
			context->j += context->s[context->i];

			swap_bytes(&context->s[context->i],
					&context->s[context->j]);

			/* Encrypt/decrypt next byte */
			y = context->s[context->i] + context->s[context->j];
			output[x] = input[x] ^ context->s[y];
		}
}
