#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <crypt.h>
#include <string.h>
#include <pthread.h> 

#define magic 30092 
#define allbooks 2433289  
#define arxiki 509044
#define dates_count 601840
#define big_words 660381
#define add_2digits 601840
#define firsthalf  allbooks/2
#define secondhalf allbooks/2
#define usernum 8196

FILE *fp;
//pthread_mutex_t mutex1 = PTHREAD_MUTEX_INITIALIZER;
/*struct arg_struct {
    int start;
    int end;
    char * salt;
};*/



int readfile(char* file){
    fp = fopen(file,"r");
    if (fp == NULL){
    printf("FAIL TO OPEN dictionary\n");
    return 0;
    }
    return 1; 
}



/*void *thr(void* s){
    struct arg_struct *args = s;
    int gnr;
    pthread_mutex_lock( &mutex1 );
    for(gnr=args->start;gnr<args->end;gnr++){
        strcpy(hashedtable[gnr],crypt(books[gnr],args->salt)+6);
    }
    pthread_mutex_unlock( &mutex1 );
    return NULL;
}*/

/*
void *thr1(void* s){
    for(gnr=0; gnr<firsthalf ;gnr++){
        printf("%d\n",gnr);
        fflush(stdout);
        strcpy(hashedtable[gnr],crypt(books[gnr],s)+6);

    }
    return 0;
}

void *thr2(void* s){
    for(gnr=firsthalf; gnr<allbooks ;gnr++){
         //printf("%d\n",gnr);
        fflush(stdout);
        strcpy(hashedtable[gnr],crypt(books[gnr],s)+6);
    }
    return 0;
}
*/

int main(int argc, char *argv[]){

    if(argc<3){
        printf("wrong arguments \n");
        return 0;
    }



    char *name1 = "allbooks1.txt";
    char *name3 = argv[2];
    char *line = NULL;
    char tmp[10],tmp2[5];
    char *token;
    char *salt;
    char help[100];
    char help2[100];
    char str[5];
    char xor[10];
    char zorz[10];
    char date1900[10];
    size_t len = 0;
    ssize_t read;
    int i = 0;
    int j = 0;
    int count = 0;
    char **first_words = malloc(magic * sizeof(char*));
    char **userpassword = malloc(usernum * sizeof(char*));
    char **username = malloc(usernum * sizeof(char*));
    char **hashedtable = malloc(allbooks * sizeof(char*));
    char **books = malloc(allbooks * sizeof(char*));

    memset(help,'\0',sizeof(help));

    for(i=0;i<usernum;i++){
       userpassword[i] = malloc(50 * sizeof(char)); 
       username[i] = malloc(20 * sizeof(char)); 
    }

    for(i=0;i<magic;i++){
       first_words[i] = malloc(20 * sizeof(char)); 
    }


    for(i=0;i<allbooks;i++){
        books[i] = malloc(40 * sizeof(char));
    }

    for(i=0;i<allbooks;i++){
        hashedtable[i] = malloc(50 * sizeof(char)); 
    }

   i=0;


    /*Open Dictionary*/
    if(readfile(name1) == 0 ) return 0;

    /*Read First words*/
    while((read = getline(&line,&len,fp))!=-1){
        if(count == magic) break;
        
        first_words[count++] = strdup(strtok(line,"\n"));
    }
    fclose(fp);


       /*OPEN DICTIONARY ALLBOOKS*/
    if(readfile(name1) == 0 ) return 0;
    
    /* READ allbooks AND SAVE WORDS TO A TABLE*/
    while ((read = getline(&line, &len, fp)) != -1) {
        books[i++] = strdup(strtok(line,"\n"));     
    }
    
    fclose(fp);


    /*ADD XOR/Zorz*/
    strcpy(xor,  "xor");
    strcpy(zorz, "zorz");

    for(i=0;i<magic;i++){
        strcpy(help,first_words[i]);
        strcat(help,xor);
        books[arxiki+i] = strdup(help);
    }

    for(i=0;i<magic;i++){
        strcpy(help,first_words[i]);
        strcat(help,zorz);
        books[arxiki+magic+i] = strdup(help);
    }

    /*Add 19xx at the end*/
    count = 0;
    strcpy(date1900, "19");
        for(i=0;i<magic;i++){
            for(j=70;j<90;j++){
                strcpy(help,first_words[i]);
                strcat(help,date1900);
                count++;
                sprintf(str, "%d", j);
                strcat(help,str);
                books[arxiki+magic*2+count] = strdup(help);

        }
    }

/*add xx at the end*/
    count = 0;
    for(i=0;i<magic;i++){
        for(j=70;j<90;j++){
            strcpy(help,first_words[i]);
            sprintf(str, "%d", j);
            strcat(help,str);
            count++;
            books[arxiki+magic*2+count+dates_count] = strdup(help);
        }
    }


    /*concat 2 words*/
    count = 0;
    for(i=0;i<magic;i++){
        strcpy(help,first_words[i]);
        if(strlen(help)==10){
            for(j=0;j<magic;j++){
                strcpy(help2,first_words[j]);
                if(strlen(help2)==14){
                   strcat(help,help2);
                   count++;
                   books[arxiki+magic*2+dates_count+add_2digits+count] = strdup(help);
                    strcpy(help,first_words[i]);
               } 
            }
        }
    }
        
     

    //  for(i=0;i<allbooks;i++){
    //      printf("%s\n",books[i]);
    //      fflush(stdout);
    // }
    // return 0;

    /*READ SHADOW FILE*/
    if(readfile(name3) == 0 ) return 0;


    i=0;
    while ((read = getline(&line, &len, fp)) != -1) {
        token = strtok(line,":");
        username[i] = strdup(token);
        token = strtok(NULL,"$");
        token = strtok(NULL,"$");
        if(i==0) salt = strdup(token);
        token = strtok(NULL,":");
        userpassword[i++] = strdup(token);

       
    }
    i=0;
    fclose(fp);

    /*CONCAT M5+SALT*/
    strcpy(tmp,  "$1$");
    strcpy(tmp2, "$");
    strcat(salt,tmp2);
    strcat(tmp,salt);
    

    /*struct arg_struct args;
    args.start = 0;
    args.end = firsthalf;
    args.salt = tmp;

    struct arg_struct args1;
    args1.start = secondhalf;
    args1.end = allbooks;
    args1.salt = tmp;

    pthread_t thread_id;
    pthread_t thread_id2;
    printf("Before Thread 1\n");
    if(pthread_create(&thread_id, NULL, thr, (void*) &args)!=0){
        printf("Uh-oh!\n");
    } 
    
    printf("Before Thread 2\n");
    if(pthread_create(&thread_id2, NULL, thr,(void*) &args1)!=0){
        printf("Uh-oh!2\n");
    }
   
     pthread_join(thread_id, NULL);
     printf("After Thread 1\n");
   
     pthread_join(thread_id2, NULL);
     printf("After Thread 2\n");
   */
    
   /*HASH dictionary*///
  // printf("HASH BEGIN \n");
    for(i=0;i<allbooks;i++){
        strcpy(hashedtable[i],crypt(books[i],tmp)+6);
    }
    //   printf("HASH END \n");
    
    /*Break passwords */
    for(i=0;i<usernum;i++){
       for(j=0;j<allbooks;j++){
           if(strcmp(userpassword[i],hashedtable[j])==0){
               printf("%s:%s\n",username[i],books[j]);
               fflush(stdout);
               break;
           }
       } 
    }



    /*  for(i=0;i<top250_dic;i++){
            printf("%s\n",hashedtop250[i]);
    }
    */


    return 0;
}


