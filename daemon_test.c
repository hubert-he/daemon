#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <syslog.h>
#include <signal.h>
#include <string.h>
#include <signal.h>
#include<sys/wait.h>
#define PCRE_STATIC // 静态库编译选项 
#include "pcre.h"

#define DEBUG_OPEN 0
#define DEBUG_MEMCHK 0
struct lstring
{
	char *line;
	unsigned int length;
};

#define LOCKFILE "/var/run/rotated.pid"
#define LOCKMODE (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)

int     lockfile;                  /* 锁文件的描述字 */
void    flock_reg ();              /* 注册文件锁 */
int     program_running_check();   /* 锁控制函数 */
int daemon_init(void);
int trim(char *buf, long int *start, long int *end);
static void sig_child(int signo);

void sig_term(int signo) 
{ 
	if(signo == SIGTERM) 
	/* catched signal sent by kill(1) command */ 
	{ 
		syslog(LOG_INFO, "program terminated."); 
		closelog(); 
		exit(0); 
	} 
}

void skip_space(char *htm, int *index)
{
    while(isspace(htm[*index]))
        (*index)++;
}
size_t getLine(char *buf, long int *start, long int *end)
{
	int i = *end + 1;
#if DEBUG_OPEN		
	fprintf(stderr, "%s:%d: %d %d \n", __FUNCTION__, __LINE__, i, *start);
#endif	
	for(; buf[i] != '\n' && buf[i] != 0; i++)
		;
	*start = *end + 1;
	*end = i;
	if(buf[i] == '\0')
	{
#if DEBUG_OPEN	
		fprintf(stderr, "%s:%d: %d %d %d\n", __FUNCTION__, __LINE__, i, *start, *end);
		//40:41: 0 -111 -5 0
		fprintf(stderr, "%d:%d: %d %d %d %d\n", \
		buf[*start -3], buf[*start-2], buf[*start-1], buf[*start], buf[*start+1], buf[*end]);
#endif
		return (*end - *start);
	}else
		return (*end - *start + 1);

}
// 2M 
#define MAX_FILE_SIZE 0x200000 
#define DEFAULT_POINTER_SIZE 1024
struct lstring* readingFile(char *filePath, int flags)
{
	struct lstring *bbf = (struct lstring*)malloc(1024*sizeof(struct lstring));
	memset(bbf, 0, 1024*sizeof(struct lstring));
#if DEBUG_MEMCHK
	fprintf(stderr, "+%s:%d  %p \n", __FUNCTION__, __LINE__, bbf);
#endif		
	int FD = open(filePath, flags, S_IREAD);
	if(FD < 0)
	{
		syslog(LOG_INFO, "Err: file %s open!\n", filePath);
		goto ERROR;
	}
	off_t fileSize = lseek(FD, 0L, SEEK_END);
	lseek(FD, 0L, SEEK_SET);
	if(fileSize > MAX_FILE_SIZE)
	{
		syslog(LOG_INFO, "Err: file %s too larger!\n", filePath);
		goto ERROR;
	}
	char *buf = (char *)malloc(fileSize+1);// left \0 in the bottom of buffer
	memset(buf, 0, fileSize+1);
#if DEBUG_MEMCHK
	fprintf(stderr, "+%s:%d  %p \n", __FUNCTION__, __LINE__, buf);
#endif	
	if(!buf)
	{
		syslog(LOG_INFO, "Err: Can NOT get more memory!\n");
		goto ERROR;
	}
	int stat = read(FD, buf, fileSize);
	if(stat <= 0)
	{
		syslog(LOG_INFO, "Err: file %s can NOT read!\n", filePath);
		goto ERROR;
	}
#if DEBUG_OPEN
	fprintf(stderr, "%s: %d %d\n", filePath, fileSize, stat);
#endif	
	long int s = 0, e = -1, s0 = 0, e0 = 0;
	long int ix = 0;
	int tmp = 0, status = 0;
	while(tmp = getLine(buf, &s, &e))
	{
		s0 = s;
		e0 = e;
#if DEBUG_OPEN		
		fprintf(stderr, "%d: %d + %d %d + %d %d\n", s, e,buf[s], buf[s+1], buf[e-1], buf[e]);
#endif		
		status = trim(buf, &s0, &e0);
#if DEBUG_OPEN		
		fprintf(stderr, "=====%d: %d======\n", tmp, status);
#endif		
		if( status < 0)
		{
			fprintf(stderr, "Err: reading error! start more than end\n");
			return NULL;
		}
		else if( status == 0) continue;
		else 
		{
			bbf[ix].line = buf + s0;
			bbf[ix].length = e0 - s0 + 1;
#if DEBUG_OPEN			
			fprintf(stderr, "=> %d %d %d: %d: %d %d %d\n", \
				bbf[ix].line[bbf[ix].length-2], bbf[ix].line[bbf[ix].length-1], bbf[ix].line[bbf[ix].length], \
				s0, e0, bbf[ix].length, strlen(bbf[ix].line));
#endif				
		}
#if DEBUG_OPEN
		fprintf(stderr, "%d=> %s [%d:%d]\n", __LINE__, bbf[ix].line, s, e);
		fprintf(stderr, "===========\n");
#endif		
		ix++;
	}
	close(FD);
	return bbf;
ERROR:
#if DEBUG_MEMCHK
	fprintf(stderr, "-%s:%d  %p %p\n", __FUNCTION__, __LINE__, buf, bbf);
#endif
	if(buf) free(buf);
	if(bbf) free(bbf);
	if(FD > 0) close(FD);
	return NULL;
} 

int trim(char *buf, long int *s, long int *e)
{
	long int start = *s, end = *e;
	if(start > end) return -1;
	for(; start < end; start++)
	{
		if(isspace(buf[start])) continue;
		break;
	}
	for(; end > start; end--)
	{
		if(buf[end] == '\0' || isspace(buf[end])) 
			continue;
		break;
	}
#if DEBUG_OPEN	
	fprintf(stderr, "++++++ %d: %d= %x %x=====\n", start, end, buf[end], buf[end+1]);
#endif	
	if(start == end && isspace(buf[start]))
		return 0;
	buf[end+1] = '\0';
	*s = start;
	*e = end;
	return 1;
}

#define OVECCOUNT 6
char* check_ext_rdnis(struct lstring line, char *repStr)
{
	int i = 0, rc;
	static char xString[4096] = {0};
	memset(xString, 0, 4096);
	const char *error; 
    int  erroffset; 
    int  ovector[OVECCOUNT]; 
	pcre  *re; 
	char  pattern [] = "^[[:space:]]*exten[[:space:]]+=>[[:space:]]+.+CALLERID\\(rdnis\\)=([^\\)]+)";
	re = pcre_compile(pattern, 0, &error, &erroffset, NULL);
	if (re == NULL)
    {
        printf("PCRE compilation failed at offset %d: %s\n", erroffset, error); 
        return 0; 
    } 
	rc = pcre_exec(re, NULL, line.line, line.length, 0, 0, ovector, OVECCOUNT);
	
    if (rc < 0)
    {//如果没有匹配，返回错误信息 
#if DEBUG_OPEN		
            if (rc == PCRE_ERROR_NOMATCH) printf("Sorry, no match ...\n"); 
            else printf("Matching error %d\n", rc); 
#endif				
            pcre_free(re); 
            return NULL; 
    } 
#if DEBUG_OPEN		
	fprintf(stderr, "$%2d: %.*s\n", 10, ovector[1], line.line);
	fprintf(stderr, "$%2d: %.*s\n", 11, ovector[2], line.line);
	fprintf(stderr, "$%2d: %.*s\n", 12, ovector[1], line.line + ovector[1]);
	for (i = 0; i < rc; i++)
    {//分别取出捕获分组 $0整个正则公式 $1第一个() 
        char *substring_start = line + ovector[2*i]; 
        int substring_length = ovector[2*i+1] - ovector[2*i]; 
        fprintf(stderr, "$%2d: %.*s\n", i, substring_length, substring_start);
    } 
#endif	
	int repStr_size = strlen(repStr);
	if(repStr_size > 512) repStr_size = 512;
	memcpy(xString, line.line, ovector[2]);
	memcpy(xString+ovector[2], repStr, repStr_size);
	memcpy(xString+ovector[2]+repStr_size, line.line + ovector[1], line.length - ovector[1]);
	memcpy(xString+ovector[2]+repStr_size + line.length - ovector[1], "\n", 1);
	pcre_free(re);
	return xString;
}
void do_edit_extensions(char *extPath, struct lstring *buff)
{
	static unsigned int count = 0;
	unsigned int buff_size = 0;
	int i;
	for(i = 0; buff[i].line; i++)
		buff_size++;
#if DEBUG_OPEN
		fprintf(stderr, "buff size :%d\n", buff_size);
#endif		
	// loading extension.conf
	struct lstring *extFileBuf = readingFile(extPath, O_RDWR);
#if DEBUG_OPEN	
	fprintf(stderr, "%d => %s %s\n", __LINE__, extFileBuf[0].line, extFileBuf[1].line);
	fprintf(stderr, "\n--------------------------------------\n");
#endif	
	int wfd = open(extPath, O_TRUNC|O_WRONLY|O_CREAT);
	for(i = 0; extFileBuf[i].line; i++)
	{
		char *stat = NULL;
#if DEBUG_OPEN		
		fprintf(stderr, "%d => %s\n", __LINE__, extFileBuf[i].line);
#endif		
		stat = check_ext_rdnis(extFileBuf[i], buff[count].line);
		if(stat)
		{	// replace call id
#if DEBUG_OPEN			
			fprintf(stderr, "ready to replace!\n");
#endif			
			write(wfd, stat, strlen(stat));
			count = (count + 1) % buff_size;// line number
		}
		else
		{
#if DEBUG_OPEN			
			fprintf(stderr, "+%s  [%d:%d] %d %d\n", \
				extFileBuf[i].line, strlen(extFileBuf[i].line), extFileBuf[i].length, \
				extFileBuf[i].line[strlen(extFileBuf[i].line)], extFileBuf[i].line[extFileBuf[i].length]);
#endif				
			write(wfd, extFileBuf[i].line, strlen(extFileBuf[i].line));
			write(wfd, "\n", 1);
		}
	}
	// clean all buffer
#if DEBUG_MEMCHK
	fprintf(stderr, "-%s:%d  %p %p %p\n", __FUNCTION__, __LINE__, &(buff->line[0]), &(extFileBuf->line[0]), extFileBuf);
#endif
	free(&(buff->line[0]));
	free(&(extFileBuf->line[0]));
	free(extFileBuf);
//	free(buff);
	close(wfd);
}

int main(int argc, char *argv[]) 
{
	//打开锁文件
    lockfile = open (LOCKFILE, O_RDWR | O_CREAT , LOCKMODE);
    if (lockfile < 0){
        fprintf(stderr,"Lockfile Open Failed");
        exit(1);
    }
    // 检测可否获得锁 
    int mun;
    if ( (mun = program_running_check())){
        printf("Instance with pid %d running, just exit\n", mun);
        exit(1);
    }
#if 1
	if(daemon_init() == -1) 
	{ 
		fprintf(stderr, "can't fork self/n"); 
		exit(0); 
	} 
#endif	
	signal(SIGCHLD,sig_child);
  //  grep daemontest /var/log/messages
	openlog("daemontest", LOG_PID, LOG_USER); 
	syslog(LOG_INFO, "program started."); 
	signal(SIGTERM, sig_term); /* arrange to catch the signal */
	struct lstring *phoneBook = NULL;
	if(argc != 3) 
	{
		syslog(LOG_INFO, "Argument %d.\n", argc);
		exit(0);
	}
	int left;
	pid_t pid; 
	while(1) 
	{ 
		left = 300;
		phoneBook = readingFile(argv[1], O_RDONLY);
		if(phoneBook)
			do_edit_extensions(argv[2], phoneBook);
		else return 0;
		// clean malloc-buffer
#if DEBUG_MEMCHK
		fprintf(stderr, "-%s:%d  %p \n", __FUNCTION__, __LINE__, phoneBook);
#endif			
		free(phoneBook);
		if((pid = fork()) < 0) 
			return(-1); 
		else if(pid == 0) 
		{// asterisk -rx "dialplan reload"
			char * argv[ ] ={"asterisk", "-rx", "\"dialplan reload\"",0};
			execvp("asterisk",argv);
			syslog(LOG_INFO, "asterisk exec Failed.\n"); 
		}
		while(left > 0)
		{
			left = sleep(left);
			fprintf(stderr, "left = %d\n", left);
		}
	} 
	return(0); 
}

void flock_reg ()
{
    char buf[16];
    struct flock fl;
    fl.l_start = 0;
    fl.l_whence = SEEK_SET;
    fl.l_len = 0;
    fl.l_type = F_WRLCK;
    fl.l_pid = getpid();
    //阻塞式的加锁
    if (fcntl (lockfile, F_SETLKW, &fl) < 0){
        perror ("fcntl_reg");
        exit(1);
    }
    //把pid写入锁文件
    ftruncate (lockfile, 0);    
    sprintf (buf, "%ld", (long)getpid());
    write (lockfile, buf, strlen(buf) + 1);
}
int program_running_check()
{
    struct flock fl;
    fl.l_start = 0;
    fl.l_whence = SEEK_SET;
    fl.l_len = 0;
    fl.l_type = F_WRLCK;
 
    //尝试获得文件锁
    if (fcntl (lockfile, F_GETLK, &fl) < 0){
        perror ("fcntl_get");
        exit(1);
    }
 
    //没有锁，则给文件加锁，否则返回锁着文件的进程pid
    if (fl.l_type == F_UNLCK) {
        flock_reg ();
        return 0;
    }
    return fl.l_pid;
}
int daemon_init(void) 
{ 
	pid_t pid; 
	if((pid = fork()) < 0) 
		return(-1); 
	else if(pid != 0) 
  	{
		fprintf(stdout, "&&Info: Forked background with PID: [%d]\n", pid);
		exit(0); /* parent exit */ 
	}
	/* child continues */ 
	setsid(); 
	chdir("/opt/"); 
	umask(0); 
	//子进程重新加锁
	flock_reg ();
	close(0); /* close stdin */ 
	close(1); /* close stdout */ 
	close(2); /* close stderr */ 
	return(0); 
}
static void sig_child(int signo)
{
     pid_t        pid;
     int        stat;
     //处理僵尸进程
     while ((pid = waitpid(-1, &stat, WNOHANG)) >0)
		fprintf(stderr, "child %d terminated.\n", pid);
}