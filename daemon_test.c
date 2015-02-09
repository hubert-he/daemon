#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <syslog.h>
#include <signal.h>
#include <string.h>
#define PCRE_STATIC // 静态库编译选项 
#include "pcre.h"
#define DEBUG_OPEN 0

struct qstring
{
	char *s;
	unsigned int len;
};

int trim(char *buf, int start, int end);



void skip_space(char *htm, int *index)
{
    while(isspace(htm[*index]))
        (*index)++;
}
size_t getLine(char *buf, long int *start, long int *end)
{
	int i = *end + 1;
	//getLine:23: 612 588 
	//getLine:30: 612 612 612
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
char** readingFile(char *filePath, int flags)
{
	char **bbf = (char **)malloc(1024*sizeof(char *));
	memset(bbf, 0, 1024);
	int phonebookFD = open(filePath, flags, S_IREAD);
	if(phonebookFD < 0)
	{
		syslog(LOG_INFO, "Err: file %s open!\n", filePath);
		goto ERROR;
	}
	off_t fileSize = lseek(phonebookFD, 0L, SEEK_END);
	lseek(phonebookFD, 0L, SEEK_SET);
	if(fileSize > MAX_FILE_SIZE)
	{
		syslog(LOG_INFO, "Err: file %s too larger!\n", filePath);
		goto ERROR;
	}
	char *buf = (char *)malloc(fileSize);
	if(!buf)
	{
		syslog(LOG_INFO, "Err: Can NOT get more memory!\n");
		goto ERROR;
	}
	int stat = read(phonebookFD, buf, fileSize);
	if(stat <= 0)
	{
		syslog(LOG_INFO, "Err: file %s can NOT read!\n", filePath);
		goto ERROR;
	}
	fprintf(stderr, "%s: %d %d\n", filePath, fileSize, stat);
	long int s = 0, e = -1;
	long int ix = 0;
	int tmp = 0, status = 0;
	while(tmp = getLine(buf, &s, &e))
	{
		status = trim(buf, s, e);
#if DEBUG_OPEN		
		fprintf(stderr, "=====%d: %d======\n", tmp, status);
#endif		
		if( status == -2)
		{
			fprintf(stderr, "Err: reading error! start more than end\n");
			return NULL;
		}
		else if( status == -1) continue;
		else 
			bbf[ix] = buf + status;
#if DEBUG_OPEN			
		fprintf(stderr, "%d=> %s [%d:%d]\n", __LINE__, bbf[ix], s, e);
		fprintf(stderr, "===========\n");
#endif		
		ix++;
	}
	return bbf;
ERROR:
	if(buf) free(buf);
	if(bbf) free(bbf);
	if(phonebookFD > 0) close(phonebookFD);
	return NULL;
} 

int trim(char *buf, int start, int end)
{
	if(start > end) return -1;
	for(; start < end; start++)
	{
		if(isspace(buf[start])) continue;
		break;
	}
	for(; end > start; end--)
	{
		if(isspace(buf[end])) continue;
		break;
	}
#if DEBUG_OPEN	
	fprintf(stderr, "++++++ %d: %d======\n", start, end);
#endif	
	if(start == end && isspace(buf[start]))
		return -1;
	buf[end+1] = '\0';
	return start;
}

#define OVECCOUNT 6
char* check_ext_rdnis(char *line, char *repStr)
{
	int i = 0, rc;
	static char xString[4096] = {0};
	memset(xString, 0, 4096);
	const char *error; 
    int  erroffset; 
    int  ovector[OVECCOUNT]; 
	pcre  *re; 
	char  pattern [] = "[[:space:]]*exten[[:space:]]+=>[[:space:]]+.+CALLERID\\(rdnis\\)=([^\\)]+)";
	re = pcre_compile(pattern, 0, &error, &erroffset, NULL);
	if (re == NULL)
    {
        printf("PCRE compilation failed at offset %d: %s\n", erroffset, error); 
        return 0; 
    } 
	rc = pcre_exec(re, NULL, line, strlen(line), 0, 0, ovector, OVECCOUNT);
	
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
	fprintf(stderr, "$%2d: %.*s\n", 10, ovector[1], line);
	fprintf(stderr, "$%2d: %.*s\n", 11, ovector[2], line);
	fprintf(stderr, "$%2d: %.*s\n", 12, ovector[1], line + ovector[1]);
	for (i = 0; i < rc; i++)
    {//分别取出捕获分组 $0整个正则公式 $1第一个() 
        char *substring_start = line + ovector[2*i]; 
        int substring_length = ovector[2*i+1] - ovector[2*i]; 
        fprintf(stderr, "$%2d: %.*s\n", i, substring_length, substring_start);
    } 
#endif	
	int repStr_size = strlen(repStr), line_size = strlen(line);
	if(repStr_size > 512) repStr_size = 512;
	if(line_size > 1024) line_size = 1024;
	memcpy(xString, line, ovector[2]);
	memcpy(xString+ovector[2], repStr, repStr_size);
	memcpy(xString+ovector[2]+repStr_size, line + ovector[1], line_size - ovector[1]);
	memcpy(xString+ovector[2]+repStr_size + line_size - ovector[1], "\n", 1);
	return xString;
}
void do_edit_extensions(char *extPath, char **buff)
{
	static unsigned int count = 0;
	// loading extension.conf
	int ext_size = 0;
	char **extFileBuf = readingFile(extPath, O_RDWR);
	int i;
	fprintf(stderr, "%d => %s %s\n", __LINE__, extFileBuf[0], extFileBuf[1]);
	fprintf(stderr, "\n--------------------------------------\n");
	int wfd = open("result.conf", O_TRUNC|O_WRONLY|O_CREAT);
	for(i = 0; extFileBuf[i]; i++)
	{
		char *stat = NULL;
		fprintf(stderr, "%d => %s\n", __LINE__, extFileBuf[i]);
		stat = check_ext_rdnis(extFileBuf[i], buff[count]);
		if(stat)
		{	// replace call id
			fprintf(stderr, "ready to replace!\n");
			write(wfd, stat, strlen(stat));
			count++;
		}
		else
		{
			fprintf(stderr, "+%s\n", extFileBuf[i]);
			//fprintf(wfd, "%s\n", extFileBuf[i]);
			write(wfd, extFileBuf[i], strlen(extFileBuf[i]));
			write(wfd, "\n", 1);
		}
	}
}
int main(int argc, char *argv[]) 
{ 
  char **phoneBook = NULL;
	phoneBook = readingFile(argv[1], O_RDONLY);
	if(phoneBook)
		do_edit_extensions(argv[2], phoneBook);
  return(0); 
}