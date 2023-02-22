
/*This program creates a simple control flow graph to 
 * identify the call sequence for authentication based
 * partitioning
 * 
 * 
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct RtnInfo
{
	//string _name;
	//string _image;
        //ADDRINT _address;
        struct RtnInfo * _next;
} RTN_INFO;


int search(char *str, char * pattern)
{
	int ret=0;
	char *input;
	char * pch;
	
	input=strdup(str);
	
	pch = strtok (input,">");
	while(pch!=NULL){
    
   	 
	    if(strcmp(pch,pattern)==0){
		ret=1;
	    }
		
	    pch = strtok (NULL, ">");
	  
	}

	free(input);
	return ret;
}


int 
main(int argc, char *argv[])
{

	int res;
	int first_part_1;
	int first_part_2;

	int size_line;
	int count;
	
	char *line1;
	char *line2;

	char *caller2;
	char *callee2;
	char *previous_callee=NULL;
	char *tmp;

	char *caller1;
	char *callee1;
	char *sequence;

	FILE *input1;
	FILE *input2;

	FILE *output;
	int i;
	if(argc!=2){
		printf("usage: relation file-name\n");
		exit(-1);
	}

	input1=fopen(argv[1],"r");
	if(input1==NULL){
		exit(-1);
	}

	input2=fopen(argv[1],"r");
	if(input2==NULL){
		exit(-1);
	}


	count =0;

	line1 = (char *)malloc(sizeof(char)*300);
	line2 = (char *)malloc(sizeof(char)*300);
	
	memset(line1,300,sizeof(char)*300);
	memset(line2,300,sizeof(char)*300);



	size_line=300;

	sequence=(char*)malloc(sizeof(char)*10000000);

	memset(sequence,0,sizeof(char)*10000000);



	while(fgets(line1,size_line,input1)!=NULL){
		i=0;
		previous_callee=strdup("test");
		first_part_1=strstr(line1,",")-line1; 
		caller1=strndup(line1,first_part_1);
		
		callee1=strndup(strstr(line1,",")+1,strlen(strstr(line1,","))-2);

		//we can add here the pair and just concatenate after that... 
		//we can put this in a list
		strcat(sequence,caller1);
		strcat(sequence,">");
		strcat(sequence,callee1);
			
inner_loop:
		input2=fopen(argv[1],"r");
		
		if(input2==NULL){
			exit(-1);
		}

		memset(line2,300,sizeof(char)*300);


		while(fgets(line2,size_line,input2)!=NULL){
			
			first_part_2=strstr(line2,",")-line2; 
			caller2=strndup(line2,first_part_2);
			callee2=strndup(strstr(line2,",")+1,strlen(strstr(line2,","))-2);


			if(strcmp(previous_callee,callee2)==0){
				
				memset(previous_callee,0,strlen(previous_callee));
				i++;
				
				res=search(sequence,callee2);
				if(res==1){
					break;
				}
				free(caller2);
				free(callee2);
				//break;
				continue;	
				//goto finish_inner;
			}



			if(strcmp(callee1,caller2)==0){

				
				memset(previous_callee,0,strlen(previous_callee));
				previous_callee=strdup(callee1);
				
				strcat(sequence,">");
				

				strncat(sequence,callee2,strlen(callee2));
			

		 		callee1=strndup(callee2,strlen(callee2));
				fclose(input2);

				goto inner_loop;
				

			}

			memset(line2,300,sizeof(char)*100);

		}
		fclose(input2);


		
		printf("call sequence: %s \n",sequence);
		memset(sequence,0,sizeof(char)*1000000);
		memset(line1,300,sizeof(char)*300);

	}

	fclose(input1);
}
