#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "stalk.h"
#include "proto.h"

int num_channels; // number of contacted hosts
struct proto_ctx pctx;

unsigned char key[KEY_SIZE+1];
unsigned char my_name[8];
int my_name_size;

void * send_others(void *ptr){
	char input[MAX_INPUT_BUF];
	char newkey_cmd[] = "newkey ";
	int newkey_cmd_size = strlen(newkey_cmd);
	
	// main cicle
	while(fgets(input, MAX_INPUT_BUF + 1, stdin) != NULL){
		int i; // indexer
		int input_size = strlen(input) - 1; // who needs /n's ? 
		if(DEBUG_MODE){
			printf("string size: %d\n",input_size);
			if(input_size == (newkey_cmd_size + KEY_SIZE))
				puts("input_size == (newkey_cmd_size + KEY_SIZE) - valid");
			if(strncmp(newkey_cmd,input,newkey_cmd_size) == 0)
				puts("strncmp(newkey_cmd,input,newkey_cmd_size) == 0 - valid");
		}
		// validating allowed commands, not just italian food
		if(	input_size > newkey_cmd_size &&  // just for performance
			(	input_size < (newkey_cmd_size + KEY_SIZE) ||
				input_size > (newkey_cmd_size + KEY_SIZE) )&& 
				strncmp(newkey_cmd,input,newkey_cmd_size) == 0 ) // newkey has invalid size?
			printf("Given key has incorrect size.\nKey size should be %d bytes\n",KEY_SIZE);

		else if(input_size == (newkey_cmd_size + KEY_SIZE) &&
				strncmp(newkey_cmd,input,newkey_cmd_size) == 0 ){ // newkey valid?

			memcpy((char *) key, input + newkey_cmd_size, KEY_SIZE);			
			if(proto_renew_key(&pctx, key, KEY_SIZE) == 0)
				puts("New key defined.");
		} else{ // spread the word

			pctx.smsg.size = input_size;
			memcpy(&pctx.smsg.msg,&input,input_size);
			
			if(DEBUG_MODE){
				printf("num_channels=%d/n", num_channels);
			}
			
			for(i = 1; i < num_channels + 1; i++){
				memset(pctx.smsg.username,'\0', sizeof (unsigned char)*8);
				memcpy(pctx.smsg.username,my_name,my_name_size);
				proto_send_msg(&pctx, hosts[i].ip, hosts[i].port, (unsigned char *) input, (unsigned int) input_size);
			}
		}
	}
}

void * listen_others(){
	unsigned char s_ip[16];
	unsigned short s_port;
	unsigned int size = MAX_RECV_BUF;
	unsigned char msg[MAX_RECV_BUF];
	unsigned char username[9];
	
	while(1)
		if(proto_recv_msg(&pctx, s_ip, &s_port, msg, &size)){
			if(pctx.smsg.size < MAX_RECV_BUF - sizeof(int) * 2 + 1){
				memset(username, '\0', sizeof(unsigned char) * 9);
				memcpy(username,pctx.smsg.username,sizeof(unsigned char) * 8);
				printf("%s sent: %s\n",username,pctx.smsg.msg);
			}
			else
				printf("\n=================================================\n"
						"\tinvalid or corrupted message.\n"
						"   Probably someone is using the wrong key... \n"
						"\t  else you are being owned!\n"
						"      last received message was ignored\n"
						"=================================================\n\n");

		}
}


int main(int argc,char *argv[]){
	unsigned char key_size;
	num_channels = (argc - 5) / 2;

	pthread_t thread1; // we are
	pthread_t thread2; // one planet

	int iret1, iret2; // thread ret values
	my_name_size=strlen(argv[2]);
	
	// validates input
	if (argc > 6) {
		key_size = strlen((char *) argv[1]);

		if(key_size != KEY_SIZE){
			printf("Invalid key size given.\n Expecting: %d\tgiven: %d\n", KEY_SIZE, key_size);
			printf("\nusage:\nstalk key my_name my_ip my_port (ip_X port_X)+\n");
			exit(WRONG_SIZE_KEY_ERROR);
		}
		else if(num_channels > MAX_HOSTS_ALLOWED){
			printf("Too many hosts given.\n Maximum hosts allowed: %d\tgiven: %d\n", MAX_HOSTS_ALLOWED, num_channels);
			printf("\nusage:\nstalk key my_name my_ip my_port (ip_X port_X)+\n");
			exit(TOO_MANY_HOSTS_ERROR);
		}
		else if(my_name_size > sizeof(unsigned char) * 8){ // king's names are not allowed
			printf("Name too big.\n");
			printf("\nusage:\nstalk key my_name my_ip my_port (ip_X port_X)+\n");
			exit(INVALID_NAME_SIZE_ERROR);
		}
		else{
			int i,z; // indexer

			if(DEBUG_MODE)
				puts("input valid");
			memcpy((char *) key, argv[1], key_size + 1);
			memcpy(my_name,argv[2],my_name_size);
			if(DEBUG_MODE){
				printf("my_name: %s my_name_size: %d\n",my_name,my_name_size);
			}
			memcpy(pctx.smsg.username,my_name,my_name_size);
			if(my_name_size < sizeof (unsigned char)*8)
				pctx.smsg.username[my_name_size] = '\0';
			if(DEBUG_MODE){
				printf("key: %s\n key_size: %d\n",key,key_size);
				printf("username: [%s]\n",pctx.smsg.username);
			}
			// fill communication values
			inet_aton(argv[3], &(pctx.my_addr.sin_addr));
			pctx.my_addr.sin_port = htons(atoi(argv[4])); 
			proto_init(key,key_size,&pctx); // protocol iniciated
			for(i = 0, z = 3; i < num_channels + 1; i++, z+=2){
				memcpy(hosts[i].ip, argv[z], strlen(argv[z]) + 1);
				hosts[i].port = (unsigned short) atoi(argv[z+1]);
			}
		}
	}
	else{ 
		printf("usage:\nstalk key my_name my_ip my_port (ip_X port_X)+\n");
		exit(WRONG_USAGE_ERROR);
	}

	iret1 = pthread_create( &thread1, NULL, listen_others, NULL);
	iret2 = pthread_create( &thread2, NULL, send_others,NULL);

	pthread_join( thread1, NULL);
	pthread_join( thread2, NULL); 

	if(DEBUG_MODE)
		puts("fora da thread");

	// Smooth termination	
	return proto_terminate(&pctx);
}
