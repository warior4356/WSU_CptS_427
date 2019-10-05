#include <crypt.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <time.h> 

#define SHDW_LINE_LEN 256
#define WORD_LEN 80
#define ACCOUNT_LIMIT 4096
#define FIELD_LENGTH 256

typedef struct account { 
	char userId[FIELD_LENGTH];
	char salt[FIELD_LENGTH];
	char hash[FIELD_LENGTH];
} ACCOUNT;

int main(){

	FILE *shadow;
	FILE *dict;
	ACCOUNT Accounts[ACCOUNT_LIMIT];

	shadow = fopen("shadowHard", "r");
	if(shadow == NULL){
		fprintf(stderr, "Cannot open shadow file \n");
		exit(1);
	}

	dict = fopen("wordsBig.txt", "r");
	if(dict == NULL){
		fprintf(stderr, "Cannot open dict file\n");
		exit(1);
	}

	char shdw_line[SHDW_LINE_LEN];
	int num_accounts = 0;
	while(fgets(shdw_line, SHDW_LINE_LEN, shadow)!=NULL){
		char *token = strtok(shdw_line, ":");
		printf("ID: %s\n", token);
		char* user = token;
		char *shdw_hash = strtok(NULL, ":");
		if(strcmp(shdw_hash, "*")!=0 && strcmp(shdw_hash, "!")!=0){
			strcpy(Accounts[num_accounts].userId, user);
			token = strtok(shdw_hash, "$");
			token = strtok(NULL, "$");
			strcpy(Accounts[num_accounts].salt, token);
			printf("  salt: %s\n", Accounts[num_accounts].salt);
			token = strtok(NULL, "$");
			strcpy(Accounts[num_accounts].hash, token);
			printf("  hash: %s\n", Accounts[num_accounts].hash);
			num_accounts++;
			//////////////////////
			// Part A: 
			//  These values need to 
			//  be stored in an array
			//////////////////////
		}
	}

	char word[WORD_LEN];
	int wordCount = 0;
	clock_t t; 
	t = clock(); 
	while(fgets(word, WORD_LEN, dict)!=NULL){
		word[strlen(word)-1] = '\0';
		//printf("word = %s\n", word);
		if(wordCount % 10000 == 0) printf("Word Count = %d Elapsed = %ld Seconds\n", wordCount, (clock()-t)/CLOCKS_PER_SEC);
		wordCount++;
		for(int i=0; i<num_accounts; i++){
			//////////////////////
			// Part B: 
			//  For each account, compute
			//  the hash for that dictionary
			//  word and the users known salt
			//  as shown below:
			//     hash = crypt("password", "$6$_____");
			//  then check if the password is 
			//  the same as that users entry 
			//  from  /etc/shadow, if so
			//  you've successfully cracked it,
			//  print the password and userid
			//////////////////////
			char hash[FIELD_LENGTH], salt[FIELD_LENGTH], fileHash[FIELD_LENGTH];
			strcpy(salt, "$6$");
			strcat(salt, Accounts[i].salt);
			strcpy(fileHash, salt);
			strcat(fileHash, "$");
			strcat(fileHash, Accounts[i].hash);
			//printf("accSalt = %s new salt length = %ld\n", Accounts[i].salt, strlen(salt));
			strcpy(hash, crypt(word, salt));
			//printf("File Hash = %s\n Hash = %s\n", fileHash, hash);
			//getchar();
			if(strcmp(fileHash, hash) == 0)
			{
				printf("UserID = %s Password = %s\n", Accounts[i].userId, word);
				//getchar();
			}
			
		}
	}
}
