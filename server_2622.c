#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <signal.h>
#include <sys/wait.h>
#include <time.h>
#include <openssl/sha.h>
#include <ctype.h>

#define PORT 50622
#define BUFFER_SIZE 4096
#define SID "1026"
#define DATA_DIR "./data"
#define DB_PATH "./data/users.db"
#define LOG_PATH "./data/server_IT24102622.log"

typedef struct {
    char username[50];
    char token[65];
    time_t token_expiry;
    int failed_attempts;
    time_t lock_time;
} Session;

Session session = {"", "", 0, 0, 0};

/* ---------------- HASH ---------------- */
void sha256_hash(char *input, char output[65]) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)input, strlen(input), hash);

    for(int i=0;i<SHA256_DIGEST_LENGTH;i++)
        sprintf(output + (i*2), "%02x", hash[i]);

    output[64] = 0;
}

/* ---------------- SALT ---------------- */
void generate_salt(char *salt) {
    sprintf(salt,"%ld%d",time(NULL),rand());
}

/* ---------------- SESSION CHECK ---------------- */
int session_valid() {
    time_t now = time(NULL);

    if(strlen(session.username)==0)
        return 0;

    if(now > session.token_expiry)
        return 0;

    return 1;
}

/* ---------------- USERNAME VALIDATION ---------------- */
int valid_username(char *u) {
    int len = strlen(u);

    if(len < 3 || len > 20)
        return 0;

    for(int i=0;i<len;i++)
        if(!isalnum(u[i]))
            return 0;

    return 1;
}

/* ---------------- LOGGING ---------------- */
void log_event(char *ip,int port,char *user,char *cmd,char *result) {
    FILE *log=fopen(LOG_PATH,"a");

    time_t now=time(NULL);
    char *t=ctime(&now);
    t[strlen(t)-1]=0;

    fprintf(log,"%s | %s:%d | PID:%d | USER:%s | CMD:%s | RESULT:%s\n",
            t,ip,port,getpid(),user,cmd,result);

    fclose(log);
}

/* ---------------- USER EXISTS ---------------- */
int user_exists(char *user) {
    FILE *fp=fopen(DB_PATH,"r");
    if(!fp) return 0;

    char line[200],u[50];

    while(fgets(line,sizeof(line),fp)) {
        sscanf(line,"%[^:]",u);
        if(strcmp(u,user)==0) {
            fclose(fp);
            return 1;
        }
    }

    fclose(fp);
    return 0;
}

/* ---------------- REGISTER ---------------- */
void register_user(char *user,char *pass,char *response) {

    if(!valid_username(user)) {
        sprintf(response,"ERR 400 SID:%s Invalid Username\n",SID);
        return;
    }

    if(user_exists(user)) {
        sprintf(response,"ERR 409 SID:%s User Exists\n",SID);
        return;
    }

    FILE *fp=fopen(DB_PATH,"a");

    char salt[32];
    char salted[128];
    char hash[65];

    generate_salt(salt);
    sprintf(salted,"%s%s",salt,pass);
    sha256_hash(salted,hash);

    fprintf(fp,"%s:%s:%s\n",user,salt,hash);
    fclose(fp);

    sprintf(response,"OK 200 SID:%s Registered\n",SID);
}

/* ---------------- LOGIN ---------------- */
int login_user(char *user,char *pass) {
    FILE *fp=fopen(DB_PATH,"r");
    if(!fp) return 0;

    char line[200];
    char u[50],salt[50],h[100];
    char salted[128],hash[65];

    while(fgets(line,sizeof(line),fp)) {
        sscanf(line,"%[^:]:%[^:]:%s",u,salt,h);

        if(strcmp(u,user)==0) {
            sprintf(salted,"%s%s",salt,pass);
            sha256_hash(salted,hash);

            fclose(fp);

            if(strcmp(hash,h)==0)
                return 1;
            else
                return -1;
        }
    }

    fclose(fp);
    return 0;
}

/* ---------------- TOKEN ---------------- */
void generate_token(char *token) {
    sprintf(token,"%ld%d",time(NULL),rand());
}

/* ---------------- SIGNAL ---------------- */
void sigchld_handler(int s) {
    while(waitpid(-1,NULL,WNOHANG)>0);
}

/* ---------------- CLIENT HANDLER ---------------- */
void handle_client(int client_fd, struct sockaddr_in addr) {

    char buffer[BUFFER_SIZE];
    char payload[BUFFER_SIZE];
    char ip[INET_ADDRSTRLEN];

    inet_ntop(AF_INET,&addr.sin_addr,ip,sizeof(ip));
    int port=ntohs(addr.sin_port);

    char help_menu[] =
"┌──────────────────────────────────────────────┐\n"
"│         Available Commands                   │\n"
"├──────────────────────────────────────────────┤\n"
"│  REGISTER <user> <pass>                      │\n"
"│  LOGIN <user> <pass>                         │\n"
"│  LOGOUT                                      │\n"
"│  WHOAMI                                      │\n"
"│  HELP                                        │\n"
"│  EXIT                                        │\n"
"└──────────────────────────────────────────────┘\n";

    send(client_fd,help_menu,strlen(help_menu),0);

    while(1) {

        memset(buffer,0,sizeof(buffer));
        int bytes=recv(client_fd,buffer,sizeof(buffer),0);
        if(bytes<=0) break;

        sscanf(buffer,"LEN:%*d\n%[^\n]",payload);

        char cmd[20],user[50],pass[50];
        memset(cmd,0,sizeof(cmd));
        sscanf(payload,"%s %s %s",cmd,user,pass);

        char response[BUFFER_SIZE];
        memset(response,0,sizeof(response));

        /* SESSION CHECK */
        if(strcmp(cmd,"LOGIN")!=0 &&
           strcmp(cmd,"REGISTER")!=0 &&
           strcmp(cmd,"HELP")!=0 &&
           strcmp(cmd,"EXIT")!=0) {

            if(!session_valid()) {
                sprintf(response,"Session Expired, Please Login Again\n");
                log_event(ip,port,user,"SESSION","EXPIRED");
                send(client_fd,response,strlen(response),0);
                continue;
            }
        }

        /* REGISTER */
        if(strcmp(cmd,"REGISTER")==0) {

            register_user(user,pass,response);

            if(strncmp(response,"OK",2)==0)
                log_event(ip,port,user,"REGISTER","SUCCESS");
            else
                log_event(ip,port,user,"REGISTER","FAIL");
        }

        /* LOGIN */
        else if(strcmp(cmd,"LOGIN")==0) {

            time_t now=time(NULL);

            if(session.lock_time > now) {
                int rem=session.lock_time-now;
                sprintf(response,"ERR 403 SID:%s Locked %d sec\n",SID,rem);
                log_event(ip,port,user,"LOGIN","LOCKED");
            }

            else {

                int result=login_user(user,pass);

                if(result==1) {
                    strcpy(session.username,user);
                    generate_token(session.token);
                    session.token_expiry=time(NULL)+300;
                    session.failed_attempts=0;

                    sprintf(response,"OK 200 SID:%s TOKEN:%s\n",SID,session.token);
                    log_event(ip,port,user,"LOGIN","SUCCESS");
                }

                else if(result==-1) {
                    session.failed_attempts++;

                    if(session.failed_attempts>=3) {
                        session.lock_time=time(NULL)+60;
                        session.failed_attempts=0;

                        sprintf(response,"ERR 403 SID:%s Account Locked for 60 sec\n",SID);
                        log_event(ip,port,user,"LOGIN","LOCKED");
                    }
                    else {
                        sprintf(response,"ERR 401 SID:%s Login Failed\n",SID);
                        log_event(ip,port,user,"LOGIN","FAIL");
                    }
                }

                else {
                    sprintf(response,"ERR 404 SID:%s User Not Found\n",SID);
                    log_event(ip,port,user,"LOGIN","NOT_FOUND");
                }
            }
        }

        /* LOGOUT */
        else if(strcmp(cmd,"LOGOUT")==0) {
            log_event(ip,port,session.username,"LOGOUT","SUCCESS");

            strcpy(session.username,"");
            session.token_expiry=0;

            sprintf(response,"OK 200 SID:%s Logout\n",SID);
        }

        /* WHOAMI */
        else if(strcmp(cmd,"WHOAMI")==0) {
            log_event(ip,port,session.username,"WHOAMI","SUCCESS");

            sprintf(response,"Logged in as %s\n",session.username);
        }

        /* HELP */
        else if(strcmp(cmd,"HELP")==0) {
            strcpy(response,help_menu);
        }

        /* EXIT */
        else if(strcmp(cmd,"EXIT")==0) {
            send(client_fd,"Goodbye\n",8,0);
            break;
        }

        else {
            sprintf(response,"ERR 400 SID:%s Unknown Command\n",SID);
            log_event(ip,port,user,"UNKNOWN","FAIL");
        }

        send(client_fd,response,strlen(response),0);
    }

    close(client_fd);
}

/* ---------------- MAIN ---------------- */
int main() {

    signal(SIGCHLD,sigchld_handler);

    system("mkdir -p ./data");

    int server_fd=socket(AF_INET,SOCK_STREAM,0);

    struct sockaddr_in server_addr,client_addr;
    socklen_t addr_len=sizeof(client_addr);

    server_addr.sin_family=AF_INET;
    server_addr.sin_port=htons(PORT);
    server_addr.sin_addr.s_addr=INADDR_ANY;

    bind(server_fd,(struct sockaddr*)&server_addr,sizeof(server_addr));
    listen(server_fd,10);

    printf("Server running on port %d\n",PORT);

    while(1) {

        int client_fd=accept(server_fd,(struct sockaddr*)&client_addr,&addr_len);

        pid_t pid=fork();

        if(pid==0) {
            close(server_fd);
            handle_client(client_fd,client_addr);
            exit(0);
        }
        else {
            close(client_fd);
        }
    }

    return 0;
}
