#include <stdio.h> 
#include <sys/socket.h> 
#include <arpa/inet.h> 
#include <stdlib.h> 
#include <string.h> 
#include <unistd.h> 
#include <sys/types.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdint.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <errno.h>

#include "dns.h"

#define ECHOMAX 10000
#define PORT 25 
#define FILE_MODE 0644

    void base64enc(const char *,char *);
    char username[200], password[200];
    char used[200], paed[200];

    extern int res_query();
    extern int res_search();
    extern int errno;
    extern int h_errno;
     
    static unsigned short getshort(unsigned char *c) { unsigned short u; u = c[0]; return (u << 8) + c[1]; }
     
    static union { HEADER hdr; unsigned char buf[PACKETSZ]; } response;
    static int responselen;
    static unsigned char *responseend;
    static unsigned char *responsepos;
    static int numanswers;
    static char name[MAXDNAME];
    unsigned short pref_value;

//The function of MX
    //dns_resolve函数发起一个指定查询名(domain)和查询类型(type)的DNS查询
    int dns_resolve(char *domain,int type)
    {
        int n;
        int i;
        errno=0;
        if(NULL == domain)
            return -1;
        responselen = res_search(domain,C_IN,type,response.buf,sizeof(response));//res_search函数发起一条指定类型的DNS查询. 其中的参数C_IN表示Internet地址
        if(responselen <= 0)
            return -1;
        if(responselen >= sizeof(response))
            responselen = sizeof(response);
        responseend = response.buf + responselen;
        responsepos = response.buf + sizeof(HEADER);
        n = ntohs(response.hdr.qdcount);
        while(n-->0)
        {
            i = dn_expand(response.buf,responseend,responsepos,name,MAXDNAME);
            responsepos += i;
            i = responseend - responsepos;
            if(i < QFIXEDSZ) return -1;
            responsepos += QFIXEDSZ;//responsepos指向了下一个查询问题字段
        }
        numanswers = ntohs(response.hdr.ancount);
        return numanswers;
    }
     
    //分析DNS响应报文中的回答字段
    int dns_findmx(int wanttype)
    {
        unsigned short rrtype;
        unsigned short rrdlen;
        int i;
     
        if(numanswers <=0) return DNS_MSG_END;
        numanswers--;
        if(responsepos == responseend) return -1;
        i = dn_expand(response.buf,responseend,responsepos,name,MAXDNAME);
        if(i < 0) return -1;
        responsepos += i;
        i = responseend - responsepos;
        if(i < 10) return -1;
        rrtype = getshort(responsepos);
        rrdlen = getshort(responsepos + 8);
        responsepos += 10;
        if(rrtype == wanttype)
        {
            if(rrdlen < 3)
                return -1;
            pref_value = (responsepos[0] << 8) + responsepos[1];
            memset(name,0,MAXDNAME);
            if(dn_expand(response.buf,responseend,responsepos + 2,name,MAXDNAME) < 0)
                return -1;
            responsepos += rrdlen;
            return strlen(name);
        }
        responsepos += rrdlen;
        return 0;
    }
    //res_init函数执行相关初始化操作. 并对name数组清零. 
    void dns_init()
    {
        res_init();
        memset(name,0,MAXDNAME);
    }
    //dns_get_mxrr函数将pref的值(优先值)存储到p指向的地址中, 并将name中存储的主机名复制到dn指向的地址中
    int dns_get_mxrr(unsigned short *p,unsigned char *dn,unsigned int len)
    {
        *p = pref_value;
        strncpy(dn,name,len);
        if(len < (strlen(name)+1))
            return -1;
        return 0;
    } 

int main(int argc, char *argv[])
{
   int sock,newsock; 
   int sock2;
   struct sockaddr_in MailServAddr;
   struct sockaddr_in ServAddr; 
   struct sockaddr_in ClntAddr; 
   unsigned int cliAddrLen;
   char msg[6][ECHOMAX];//store message received from thunderbird
   char tosend[4][ECHOMAX];//store message to send
   char store[1][ECHOMAX];//store message that read from the file
   char msg2[7][ECHOMAX]; //store message received from the mail agender
   char auth[3][ECHOMAX];//store auth message to send
   char authmsg[3][ECHOMAX];//store received auth message
   char compare[3][ECHOMAX];   

   char domain_name[MAXDNAME];//used for MX
   int i;
   unsigned short p; 
   struct hostent *ht=NULL;
   struct in_addr dstaddr;

//work as server
 //socket 
 if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
 {
    printf("socket() failed.\n");
    exit(1); 
  }
 else
    printf("Server : got a connection\n");

 //address information
 bzero(&ServAddr,sizeof(ServAddr));
 ServAddr.sin_family = AF_INET;
 ServAddr.sin_addr.s_addr = htonl(INADDR_ANY);
 ServAddr.sin_port =htons(PORT);


 //bind
 if ((bind(sock, (struct sockaddr *) &ServAddr, sizeof(ServAddr))) < 0)
     { perror("bind");
       printf("bind() failed.\n");}

 //listen
 if ((listen(sock, 5)) < 0)
      {perror("listen");
       printf("listen() failed.\n");}

 //accept
	cliAddrLen=sizeof(ClntAddr);
   if ((newsock=accept(sock,(struct sockaddr *)&ClntAddr,&cliAddrLen))< 0)
     {perror("accept");
     printf("accept failed.\n");}
  

   //start to send and recieve
    //s-220
	bzero(tosend[0], ECHOMAX);
	strcpy(tosend[0], "220 beta OK");
	strcat(tosend[0], "\n");
    if ((send(newsock, tosend[0], strlen(tosend[0]), 0)) ==-1)
       {printf("send() error1.\n");
        exit(1);}

    //r-helo
    int a;
    if ((a=(recv(newsock,msg[0], ECHOMAX, 0))) ==-1)
        {printf("recv() failed1.\n");
         exit(1);}
           printf("%s \n",msg[0]);
    //s-auth login
        bzero(tosend[1], ECHOMAX);
	strcpy(tosend[1], "250 AUTH LOGIN");
	strcat(tosend[1], "\n");
    if ((send(newsock,tosend[1], strlen(tosend[1]), 0)) ==-1)
        {printf("send() error2.\n");
        exit(1);}

//auth test
    //r-auth
    if ((recv(newsock,authmsg[0], ECHOMAX, 0)) ==-1)
        {printf("recv() failed2.\n");
        exit(1);}
        printf("%s \n",authmsg[0]);
    if(strncmp(authmsg[0],"AUTH",4)==0)
       { //s-334
        bzero(auth[0], ECHOMAX);
	strcpy(auth[0], "334 username");
	strcat(auth[0], "\n");
         if ((send(newsock,auth[0], strlen(auth[0]), 0)) ==-1)
         {printf("send() error3.\n");
         exit(1);}
       }
     else
        {printf("auth login() error3.\n");
         exit(1);}
    //r-name
    if ((recv(newsock,authmsg[1], ECHOMAX, 0)) ==-1)
        {printf("recv() failed2.\n");
        exit(1);}
        printf("Recieved username: %s \n",authmsg[1]);
    //s-334
        bzero(auth[1], ECHOMAX);
	strcpy(auth[1], "334 password");
	strcat(auth[1], "\n");
      if ((send(newsock,auth[1], strlen(auth[1]), 0)) ==-1)
         {printf("send() error3.\n");
         exit(1);} 
    //r-passwd
     if ((recv(newsock,authmsg[2], ECHOMAX, 0)) ==-1)
        {printf("recv() failed2.\n");
        exit(1);}
        printf("Recieved password: %s \n",authmsg[2]);

    //auth test!!
     strcpy(username, "cc"); //copy   
     strcpy(password, "891020");
     printf("The user name is: %s \n",username);
     printf("The password is: %s \n\n",password);
     //use the function
     base64enc(username, used);
     base64enc(password, paed);
     printf("Your user encoded is:%s\nYour password encoded is:%s\n\n",used, paed);

   //complement the encode name and password
    strcat(used, "\r\n");   
    strcat(paed, "\r\n");
   
   //compare the authentication
    int na,pa;
    if(((pa=strcmp(authmsg[2],paed))!=0)&&((na=strcmp(authmsg[1],used))!=0))
    {
     printf("The name or password failed!\n");
     exit(1);
    }
   else
      printf("Login success!!!\n\n");
      //s-235
        bzero(auth[2], ECHOMAX);
	strcpy(auth[2], "235");
	strcat(auth[2], "\n");
      if ((send(newsock,auth[2], strlen(auth[2]), 0)) ==-1)
         {printf("send() error3.\n");
         exit(1);}
//end of auth login



    //r-mail from
    if ((recv(newsock,msg[1], ECHOMAX, 0)) ==-1)
        {printf("recv() failed2.\n");
        exit(1);}
   printf("%s \n",msg[1]);
   if(strncmp(msg[1],"MAIL",4)==0)
   { 
      //MAIL250
      if ((send(newsock,tosend[1], strlen(tosend[1]), 0)) ==-1)
         {printf("send() error3.\n");
         exit(1);}
   }
   else
      {printf("mail from() error3.\n");
         exit(1);}

    //rcpt
    if ((recv(newsock,msg[2], ECHOMAX, 0))==-1)
        {printf("recv() failed3.\n");
        exit(1);}
   printf("%s \n",msg[2]);
   if(strncmp(msg[2],"RCPT",4)==0)
   { 
     //cut the rcpt to get xx.com
     int x,y;
     x=strlen(msg[2]);
     bzero(compare[0], ECHOMAX);
     strcpy(compare[0], "@");
     
     int j=0;
     int k=0;
     int h=0;
     while((msg[2][j])!=(compare[0][0]))
     {
        j++;
      }

     bzero(compare[1], ECHOMAX);
     for(k=j+1;k<x-3;k++)
     {              
       compare[1][h]=msg[2][k]; 
       h++;       
     }
      //RCPT250
      if ((send(newsock,tosend[1], strlen(tosend[1]), 0)) ==-1)
       {printf("send() error4.\n");
        exit(1);}
   }
   else
    {printf("rcpt to() error3.\n");
         exit(1);}

    //data
    if ((recv(newsock,msg[3], ECHOMAX, 0)) ==-1)
        {printf("recv() failed4.\n");
        exit(1);}
    printf("%s \n",msg[3]);

    if(strncmp(msg[3],"DATA",4)==0)
    {//data354
        bzero(tosend[2], ECHOMAX);
	strcpy(tosend[2], "354 OK");
	strcat(tosend[2], "\n");
    if ((send(newsock,tosend[2], strlen(tosend[2]), 0)) ==-1)
        {printf("send() error5.\n");
        exit(1);}     
    }
   else
    {printf("rcpt to() error3.\n");
         exit(1);}
    
    //message
    if ((recv(newsock,msg[4], ECHOMAX, 0)) ==-1)
        {printf("recv() failed4.\n");
        exit(1);}

    //store in file
    int fd;
    if((fd=creat("file.hole",FILE_MODE))<0)
    {printf("creat error.\n");
        exit(1);}
    if(write(fd,msg[4],strlen(msg[4]))!=strlen(msg[4]))
    {printf("msg write error.\n");
        exit(1);}
    //end250
    if ((send(newsock,tosend[1], strlen(tosend[1]), 0)) ==-1)
        {printf("send() error6.\n");
        exit(1);}
    //quit
    if ((recv(newsock,msg[5], ECHOMAX, 0)) ==-1)
        {printf("recv() failed5.\n");
        exit(1);}
    printf("%s \n",msg[5]);
    //close221
        bzero(tosend[3], ECHOMAX);
	strcpy(tosend[3], "221 beta OK");
	strcat(tosend[3], "\n");
    if ((send(newsock,tosend[3], strlen(tosend[3]), 0)) ==-1)
        {printf("send() error7.\n");
        exit(1);}  
   //close
    if (close(newsock) < 0)
      printf("close() failed.\n"); 

//MX-resolve
        //利用dns.h中定义的宏, 发起MX查询
        dns_init();
        i = dns_mx_query(compare[1]);//compare[1] is xx.com
        if(i<0)
        {
            fprintf(stderr,"err\n");
            return 0;
        }
        printf("pref_value\tdomain name\n");
        foreach_mxrr(p,domain_name)
        {
            printf("%d\t%s\n",p,domain_name);
        }
//end of MX

//turn DNS to IP
ht = gethostbyname(domain_name);
memcpy(&dstaddr,ht->h_addr_list[0],4);
printf("Host addresses:%s\n",inet_ntoa(dstaddr));

                                            
//work as client
 if ((sock2 = socket(AF_INET, SOCK_STREAM, 0)) < 0)
 {
    printf("socket() failed.\n");
    exit(1); 
  }
 else
  printf("Begin to send email.\n");
  
 bzero(&ServAddr,sizeof(MailServAddr));
 MailServAddr.sin_family = AF_INET;
 MailServAddr.sin_addr.s_addr = inet_addr(inet_ntoa(dstaddr));
 MailServAddr.sin_port =htons(PORT);

 //build connect
 if(connect(sock2,(struct sockaddr *) &MailServAddr, sizeof(MailServAddr))<0)
 {     perror("connect");
       printf("connect() failed.\n");}

   //r-220
    if ((recv(sock2,msg2[0], ECHOMAX, 0)) ==-1)
        {printf("recv() failed1.\n");
         exit(1);}
           printf("%s \n",msg2[0]);
//judge mas2[0]
    if(strncmp(msg2[0],"220",3)==0)
     {
       printf("\n");
      
       //s-Helo
       if ((send(sock2, msg[0], strlen(msg[0]), 0)) ==-1)
       {perror("send"); 
        printf("send() error1.\n");
        exit(1);}

        //r-helo250 
        if ((recv(sock2,msg2[1], ECHOMAX, 0)) ==-1)
        {
          printf("recv() failed2.\n");
          exit(1);}
          printf("%s \n",msg2[1]);

//judge mas2[1]
          if(strncmp(msg2[1],"250",3)==0)
          {
            printf("\n");
         
            //s-mail from
            if ((send(sock2, msg[1], strlen(msg[1]), 0)) ==-1)
            {perror("send"); 
            printf("send() error2.\n");
            exit(1);}

            //r-mail250
            if ((recv(sock2,msg2[2], ECHOMAX, 0)) ==-1)
            {printf("recv() failed3.\n");
            exit(1);}
            printf("%s \n",msg2[2]);

//judge mas2[2]
            if(strncmp(msg2[2],"250",3)==0)
            {
              printf("\n");      

              //s-rcpt to
              if ((send(sock2, msg[2], strlen(msg[2]), 0)) ==-1)
              {perror("send"); 
               printf("send() error3.\n");
               exit(1);}

               //r-rcpt250
               if ((recv(sock2,msg2[3], ECHOMAX, 0)) ==-1)
               {printf("recv() failed3.\n");
                exit(1);}
                printf("%s \n",msg2[3]);

//judge mas2[3]
              if(strncmp(msg2[3],"250",3)==0)
              {printf("\n");
      
               //s-data
              if ((send(sock2, msg[3], strlen(msg[3]), 0)) ==-1)
             {perror("send"); 
              printf("send() error3.\n");
              exit(1);}

             //r-354
             if ((recv(sock2,msg2[4], ECHOMAX, 0)) ==-1)
             {printf("recv() failed4.\n");
             exit(1);}
             printf("%s \n",msg2[4]);

//judge mas2[4]
             if(strncmp(msg2[4],"354",3)==0)
             {
               printf("\n");
        
//open and read a file into the buff
              int ms;
              if((ms=open("file.hole",O_RDWR|O_CREAT,0))==-1)
              {printf("read error.\n");
               exit(1);}
              int gs;
              if((gs=read(ms,store[0],strlen(msg[4])))<0)
              {printf("read error.\n");
               exit(1);}
           //   printf("%s \n",store[0]);
               //s-message
               if ((send(sock2,store[0], strlen(store[0]), 0)) ==-1)
               {perror("send"); 
               printf("send() error4.\n");
               exit(1);}

               //r-message250
               if ((recv(sock2,msg2[5], ECHOMAX, 0)) ==-1)
               {printf("recv() failed5.\n");
               exit(1);}
               printf("%s \n",msg2[5]);

//judge mas2[5]
              if(strncmp(msg2[5],"250",3)==0)
              {
                printf("\n");
      
                //s-quit
                if ((send(sock2, msg[5], strlen(msg[5]), 0)) ==-1)
                {perror("send"); 
                 printf("send() error5.\n");
                 exit(1);}

                 //r-quit250
                if ((recv(sock2,msg2[6], ECHOMAX, 0)) ==-1)
                 {printf("recv() failed6.\n");
                  exit(1);}
                  printf("%s \n",msg2[6]);

//judge mas2[6]
                 if(strncmp(msg2[6],"221",3)==0)
                 {
                   printf("\n");
                 }
                 else
                   {printf("r-quit250 fail\n");
                    exit(1);}//end of judge mas2[6]

                }
                else
                   {printf("r-message250 fail\n");
                     exit(1);}//end of judge mas2[5]

              }
              else
                {printf("r-354 fail\n");
                exit(1);}//end of judge mas2[4]

            }
             else
                {printf("r-rcpt250 fail\n");
                exit(1);}//end of judge mas2[3]

         }
          else
            {printf("r-mail250 fail\n");
            exit(1);}//end of judge mas2[2]

      }
       else
         {printf("r-helo250 fail\n");
          exit(1);}//end of judge mas2[1]

    }
     else
        {printf("r-220 fail\n");
        exit(1);}//end of judge mas2[0]

 //close
    if (close(sock2) < 0)
      printf("close() failed.\n"); 
    else
     printf("End of sending mail.\n"); 

}

//base64 encoder
void base64enc(const char *instr,char *outstr)
{ 
     char * table="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
     int instr_len=0;
     instr_len=strlen(instr);
     while(instr_len>0){
       *outstr++=table[(instr[0]>>2) & 0x3f];
      if(instr_len>2){
     *outstr++= table[((instr[0] & 0x03)<<4) | (instr[1] >>4)];
     *outstr++= table[((instr[1] & 0x0f)<<2) | (instr[2] >>6)];
     *outstr++= table[(instr[2] & 0x3f)];
        }
    else{
       switch(instr_len){
       case 1:
        *outstr++= table[((instr[0] & 0x03)<<4)];
        *outstr ++ = '=';
        *outstr ++ = '=';
        break;
        case 2:
        *outstr++= table[((instr[0] & 0x03)<<4) | (instr[1] >>4)];
        *outstr++= table[((instr[1] & 0x0f)<<2) | (instr[2] >>6)];
        *outstr++ = '=';
        break;
         }
        }
      instr += 3;
      instr_len -= 3;
      }
   *outstr = 0;
}



