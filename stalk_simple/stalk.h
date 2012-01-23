#ifndef STALK_H_
#define STALK_H_

#define MAX_INPUT_BUF 1000
#define MAX_RECV_BUF MAX_INPUT_BUF
#define KEY_SIZE 40/8 
#define MAX_HOSTS_ALLOWED 10

#define INVALID_NAME_SIZE_ERROR -4
#define TOO_MANY_HOSTS_ERROR -3
#define WRONG_SIZE_KEY_ERROR -2
#define WRONG_USAGE_ERROR -1

#define DEBUG_MODE 0

struct host {
	unsigned char ip[16]; // i know it fits in sizeof(int)
	short port;
};

struct host hosts[MAX_HOSTS_ALLOWED];

#endif /*STALK_H_*/
