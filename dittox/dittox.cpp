/***************************************************************************************************
 * Antoine Calando - 2012/2013
 * wacawlawndow@free.fr (remove the w)
 *
 * This file is public domain. Do whatever you want with it.
 * However, please note that the whole project is based on Parcellite (GPL v3) and Ditto (GPL v2/v3),
 * and some other files from the same package are NOT public domain.
 */

/* If not compiled in GNU mode, uncomment: #define _GNU_SOURCE */
#include <new>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/netdevice.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdarg.h>
#include <netdb.h>
#include <fcntl.h>
#include <time.h>
#include <signal.h>

#include "ServerDefines.h"
#include "EncryptDecrypt/Encryption.h"

extern "C" {
#include "dittox.h"
}


/**************************************************************************************************/
/* Required constants from Ditto */
#define ENCRYPTED_SIZE_CSENDINFO	508

/* Password to use if user does not provide any */
#define DITTOX_PWD_DEFAULT		"default"
/* All small clips are extended to a min size to speed up encryption */
#define CLIP_ENC_SIZE_MIN		508
/* Number of immediate retries after the first error */
#define HOST_RETRY_CNT			3

/* DEBUG can be 0, 1, 2 */
#define DEBUG				0

/**************************************************************************************************/
/* Enums and structs */


typedef struct clip {
	int		ref_cnt;
	int		desc_len;
	char		*desc;
	int		enc_utf16_len;
	uint8_t		*enc_utf16;
} clip_t;

typedef struct ll {
	struct ll 	*next;
	clip_t		*data;
} ll_t;

typedef enum host_state {
	HOST_INIT = 0,
	HOST_ADDR_INFO_WAIT = 1,
	HOST_ADDR_CONNECT_WAIT = 2,
	HOST_SEND_READY = 3,
	HOST_SEND_CONNECT_WAIT = 4,
	HOST_SEND_START = 5,
	HOST_SEND_DATASTART = 6,
	HOST_SEND_DATA = 7,
	HOST_SEND_DATAEND_END_EXIT = 8,

	HOST_USER_ERROR = 100,
	HOST_INTERNAL_ERROR = 101,
	HOST_WAIT_RETRY = 102,
	HOST_DISCARDED = 103,
	HOST_MAX

} host_state_t;

typedef struct host {
	struct host 	*next;
	host_state_t	state;
	int		success_cnt;
	int		error_cnt;
	time_t		error_time;
	char		*name;
	struct gaicb	*ga_req;
	int		family;
	size_t		addr_len;
	struct sockaddr *addr;
	char		*local;
	int		socket;
	ll_t		*clip_head;		/* next clip to send */

	uint8_t		*send_buffer;		/* buffer to free after the send */
	uint8_t		*send_addr;		/* remaining buffer to send */
	int		send_remaining;		/* remaining bytes to send */

} host_t;

typedef struct CSendInfo CSendInfo;

typedef struct dittox_settings {
	char		*pwd;
	uint8_t		*cache_fixed_datastart;
	uint8_t		*cache_dataend_end_exit;
	int		retry;
	char		*hostname_buffer;
	host_t		*host_head;
	char		local_host[256];	/* Max hostname size on Unix, much smaller on Windows */
	int		listen_socket;
	int		filter_cr;
	struct CEncryption *crypt;
} dittox_settings_t;


/**************************************************************************************************/
/* Error management: DEBUG can be 0, 1, 2 */
#undef ASSERT

#if DEBUG > 0
	// ANSI colors
	#define ESC	"\x1B["
	#define OFF	ESC "0m"
	#define RED	ESC "0;31m"
	#define YELLOW	ESC "0;33m"
	#define BLUE	ESC "0;34m"
	#define MAGENTA	ESC "0;35m"
	#define CYAN	ESC "0;36m"
	#define WHITE	ESC "0;37m"

	// Fast debug macros
	#define MMM fprintf(stderr, "__%s__%d__\n", __FUNCTION__, __LINE__);
	#define DDD(x) fprintf(stderr, "__%s__%d__ %d\n", __FUNCTION__, __LINE__, (x)) ;
	#define HHH(x) fprintf(stderr, "__%s__%d__ %x\n", __FUNCTION__, __LINE__, (unsigned long) (x)) ;

	#if DEBUG > 1
		// Log macro for dev
		#define LOG(f, a...) fprintf(stderr, WHITE "%s:%d: " OFF f, __FUNCTION__, __LINE__, ## a)
	#else
		// Log macro for dev disabled
		#define LOG(f, a...)do { } while (0)
	#endif

	// Error macro for dev (errors which should never occurs)
	#define ERR(f, a...) fprintf(stderr, RED "%s:%d: " OFF f, __FUNCTION__, __LINE__, ## a)

	#undef ASSERT
	#define ASSERT(x)                                                   \
		do { if (! (x)) {                                           \
			fprintf(stderr, RED "ASSERTION FAILED (%s) at %s:%d\n" OFF, \
			(#x), __FILE__, __LINE__);                          \
		} } while(0);
#else // DEBUG
	// Error macro for dev disabled
	#define ERR(fmt, a...) do { } while (0)
	#define ASSERT(x) do { } while (0)
	#define timediff(x) NULL
	#define LOG(f, a...)do { } while (0)
#endif // !DEBUG



#if DEBUG > 1
/* Needs "-lrt" library! */
static const char *timediff(int precision)
{
	static char str[256];
#if 0
	static uint32_t prev_us;
	struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
	uint32_t now_us = ts.tv_sec * 1000000 + ts.tv_nsec / 1000;

	sprintf(str, "%9u us", now_us - prev_us);
	prev_us = now_us;
#else
	int sec = 0, nsec = 0;
	static struct timespec ref = { 0 };
	struct timespec last;

	clock_gettime(CLOCK_MONOTONIC, &last);
	if (ref.tv_sec || ref.tv_nsec) {
		if (ref.tv_nsec <= last.tv_nsec) {
			nsec = last.tv_nsec - ref.tv_nsec;
		} else {
			nsec = 1000000000 + last.tv_nsec - ref.tv_nsec;
			ref.tv_sec += 1;
		}
		sec = last.tv_sec - ref.tv_sec;
	}

	if (0 < precision && precision <= 9) {
		for (int i = precision; i < 9; i++)
			nsec = (nsec + 5) / 10;

		snprintf(str, 256, "%d.%0*ds", sec, precision, nsec);
	} else {
		snprintf(str, 256, "%ds", sec);
	}

	ref.tv_sec = last.tv_sec;
	ref.tv_nsec = last.tv_nsec;
#endif
	return str;
}
#endif

#define ERR_BUFFER_LEN	1024
char err_buffer[ERR_BUFFER_LEN];
int err_buffer_len = 0;

// Reinit dittox_error() function
static void err_init(void)
{
	err_buffer_len = 0;
}

// Error macro for dev and end user (errors due to external factors).
// va_copy() is C99, you can try __va_copy() if not found.
#define err_add(f, a...) _err_add(__FUNCTION__, __LINE__, f, ##a)
static void _err_add(const char *func, int line, const char *fmt, ...)
{
	va_list args1, args2;
	va_start(args1, fmt);
	#if DEBUG
		va_copy(args2, args1);
		fprintf(stderr, RED "%s:%d: " OFF , func, line);
		vfprintf(stderr, fmt, args2);
		va_end(args2);
	#endif
	err_buffer_len += vsnprintf(err_buffer + err_buffer_len, ERR_BUFFER_LEN - err_buffer_len, fmt, args1);
	va_end(args1);
}

extern "C" {
// Get latest Dittox error for end users
const char *dittox_error(void)
{
	if (!err_buffer_len)
		return NULL;

	return err_buffer;
}
} // extern C

/**************************************************************************************************/
/* Useful macros */
#define max(a,b)			\
	({ __typeof__ (a) _a = (a);	\
	   __typeof__ (b) _b = (b);	\
	   _a > _b ? _a : _b; })

#define min(a,b)			\
	({ __typeof__ (a) _a = (a);	\
	   __typeof__ (b) _b = (b);	\
	   _a < _b ? _a : _b; })

#define STR(x) _STR(x)
#define _STR(x) # x

#define member_sizeof(type, member) sizeof(((type *)0)->member)

/**************************************************************************************************/
/* Pretty Hex printing */
#define BYTE_PER_FIELD	4U
#define BYTE_PER_LINE	16U

/* pretty hex print a contiguous buffer */
void prhex(const char *msg, void *buf, uint n)
{
	uint8_t *p = (uint8_t*) buf;
	uint i;

	if (msg && (msg[0] != '\0'))
		fprintf(stderr,"%s[%d / 0x%x]:", msg, n, n);

	for (i = 0; i < n; i++) {
		if (i % BYTE_PER_LINE == 0)
			fprintf(stderr,"\n %3x:", i);
		else if (i % BYTE_PER_FIELD == 0)
			fprintf(stderr, " ");
		fprintf(stderr," %02x", p[i]);
	}

	fprintf(stderr,"\n");
}

void prhexasc(const char *msg, void *buf, uint n)
{
	uint8_t *p = (uint8_t*) buf;
	uint i, j;

	if (msg && (msg[0] != '\0'))
		fprintf(stderr,"%s [%d / 0x%x]:", msg, n, n);


	for (i = 0; i < n; i += BYTE_PER_LINE) {
		fprintf(stderr,"\n%3x:", i);

		uint j_max = min(n - i, BYTE_PER_LINE);

		for (j = 0; j < j_max; j++) {
			if (j % BYTE_PER_FIELD == 0)
				fprintf(stderr, " ");
			fprintf(stderr," %02x", p[i+j]);
		}

		for (; j < BYTE_PER_LINE + 1; j++) {
			if (j % BYTE_PER_FIELD == 0)
				fprintf(stderr, " ");
			fprintf(stderr,"   ");
		}

		for (j = 0; j < j_max; j++) {
			if (j % BYTE_PER_FIELD == 0)
				fprintf(stderr, " ");

			if (0x20 <= p[i+j] && p[i+j] < 0x80)
				fprintf(stderr, "%c", p[i+j]);
			else
				fprintf(stderr, ".");
		}
	}

	fprintf(stderr,"\n");
}

/* Static buffer: CANNOT be called several time as an argument: printf(..., ip2str(...), ip2str(...)); */
static char *ip2str(void *sockaddr, int prefix)
{
	struct sockaddr *sa = (struct sockaddr*)sockaddr;

	static char ip[8 + INET_ADDRSTRLEN + INET6_ADDRSTRLEN];
	char *p = ip;

	if (sa->sa_family == AF_INET) {
		if (prefix)
			p += sprintf(p, "IPv4:");
		inet_ntop(AF_INET, &((struct sockaddr_in*) sa)->sin_addr, p, sizeof(ip) + ip - p);

	} else if (sa->sa_family == AF_INET6) {
		if (prefix)
			p += sprintf(p, "IPv6:");
		inet_ntop(AF_INET6, &((struct sockaddr_in6*) sa)->sin6_addr, p, sizeof(ip) + ip - p);
	} else {
		/* str len ok compared to buffer */
		sprintf(ip, "<Unkown address family %d>", sa->sa_family);
	}
	return ip;
}

/**************************************************************************************************/
/* UTF Conversion */
#define CHAR_INVALID_ASC	'?'
#define CHAR_INVALID_UCS	0xFFFD
#define CHAR_UNMATCHED_ASC	'?'

/* This function translatse the UTF-16, NUL terminated, input to UTF-8 in the
 * buffer provided in dest. len is the size of this buffer and MUST be >= 1
 * as dest must contain at least NUL.
 * This function will also translate any ilegal combination to CHAR_INVALID_UCS.
 * Return code is the size of the translated buffer in bytes without the trailing NUL.
 */
static int conv_utf16_to_8(char *dest, const uint16_t *src, int len, int filter_cr)
{
	char *dest_org = dest;
	while (--len && *src) {
		if (*src <= 0x7F) {
			/* ASCII char - remove CR from Windows if option set and CRLF */
			if (*src != 0x0D || filter_cr == 0 || len == 1 || src[1] != 0x0A)
				*dest++ = *src++;
			else
				src++;

		} else if (*src <= 0x7FF) {
			/* 2 bytes UTF-8 */
			if ((len -= 1) < 0)
				break;
			*dest++ = 0xC0 | (*src >> 6);
			*dest++ = 0x80 | (*src++ & 0x3F);

		} else if (*src < 0xD800 || 0xDFFF < *src) {
			/* Non surrogate */
			if ((*src & 0xFFFE) == 0xFFFE ||
				(0xFDD0 <= *src && *src <= 0xFDEF))
				/* Noncharacters */
				goto illegal;
			/* 3 bytes UTF-8 */
			if ((len -= 2) < 0)
				break;
			*dest++ = 0xE0 | (*src >> 12);
			*dest++ = 0x80 | ((*src >> 6) & 0x3F);
			*dest++ = 0x80 | (*src++ & 0x3F);

		} else if (*src < 0xDC00) {
			/* Lead surrogate: 0xD800-0xDBFF */
			uint32_t val = (*src++ & 0x3FF) << 10;
			if (*src < 0xDC00 || 0xDFFF < *src)
				/* Unpaired surrogate */
				goto illegal;
			val += (*src++ & 0x3FF) + 0x10000;

			if ((val & 0xFFFE) == 0xFFFE)
				/* Noncharacters */
				goto illegal;
			/* 4 bytes UTF-8 */
			if ((len -= 3) < 0)
				break;
			*dest++ = 0xF0 | (val >> 18);
			*dest++ = 0x80 | ((val >> 12) & 0x3F);
			*dest++ = 0x80 | ((val >> 6) & 0x3F);
			*dest++ = 0x80 | (val & 0x3F);
		} else {
			/* Trail surrogate: 0xDC00-0xDFFF: unpaired or bad endianness */
		illegal:
			if ((len -= 2) < 0)
				break;
			*dest++ = 0xE0 | (CHAR_INVALID_UCS >> 12);
			*dest++ = 0x80 | ((CHAR_INVALID_UCS >> 6) & 0x3F);
			*dest++ = 0x80 | (CHAR_INVALID_UCS & 0x3F);
			src++;
		}
	}

	*dest = 0;

	return dest - dest_org;
}

/* This function translates the UTF-8, NUL terminated, input to UTF-8 in the
 * buffer provided in dest. len is the size of this buffer in !!16-bits words!!
 * and MUST be >= 1 as dest must contain at least NUL.
 * This function will also translate any ilegal combination to CHAR_INVALID_UCS
 * Return code is the size of the translated buffer in !!16-bits words!! without
 * the trailing NUL.
 */
static int conv_utf8_to_16(uint16_t *dest, const char *src, int len)
{
	uint16_t *dest_org = dest;
	while (--len && *src) {
		if (*src & 0x80) {
			/* Non-ASCII char */
			int skip = 0;
			/* Detect size and check format */
			while (*src & (0x40 >> skip))
				skip++;
			if (skip == 0 || skip > 3) {
				/* Illegal UTF-8: Skip current byte and all following 10xx xxxx */
				while ((*++src & 0xC0) == 0x80);
			illegal:
				*dest++ = CHAR_INVALID_UCS;
				continue;
			}
			/* Get Unicode value */
			uint32_t val = *src++ & (0x3F >> skip);
			for (int i = 0; i < skip; i++) {
				if ((*src & 0xC0) != 0x80)
					goto illegal;
				val = (val << 6) | (*src++ & 0x3F);
			}

			/* Encode Unicode if valid */
			uint32_t min_val[] = { 0x80, 0x800, 0x10000, 0x110000 };
			if (val < min_val[skip - 1] || min_val[skip] < val) {
				/* Invalid range */
				goto illegal;

			} else if ((val & 0xFFFE) == 0xFFFE) {
				/* Noncharacters for BOM detection */
				goto illegal;

			} else if (val >= 0x10000) {
				/* Planes 1 - 16 */
				val -= 0x10000;
				*dest++ = 0xD800 | (val >> 10);
				*dest++ = 0xDC00 | (val & 0x3FF);

			} else if (0xFDD0 <= val && val <= 0xFDEF) {
				/* Noncharacters reserved for internal purpose */
				goto illegal;

			} else if (0xD800 <= val && val <= 0xDFFF) {
				/* Plane 0 reserved for UTF-16 surrogates */
				goto illegal;

			} else {
				/* Plane 0 */
				*dest++ = val;
			}
		} else
			/* ASCII char */
			*dest++ = *src++;
	}

	*dest = 0;

	return dest - dest_org;
}


/* This function takes translate UTF-8, NUL terminated, src to the buffer provided by dest,
 * converting non-ASCII chars to ISO-8859-1 (aka Latin1) when possible, which are also
 * compatible with CP1252 used, AFAIK, by Ditto (if this last assumption is wrong, it seems
 * that we have no way to guess the right encoding used by Ditto).
 * Non convertible chars are translated to '.' and illegal bytes to '?'.
 * Return code is the size of the translated buffer in bytes without the trailing NUL.
 */
static int conv_utf8_to_latin1(char *dest, const char *src, int len)
{
	char *dest_org = dest;
	/* len MUST be >= 1 as dest must contain at least NUL */
	while (--len && *src) {
		if (*src & 0x80) {
			/* Non-ASCII char */
			int skip;
			if (!(*src & 0x40))
				/* illegal UTF-8: 10xx xxxx */
				goto illegal;

			else if (!(*src & 0x20)) {
				/* 110x xxxx */
				if ((src[1] & 0xC0) != 0x80)
					goto illegal;

				/* 110x xxxx  10xx xxxx */
				if (!(src[0] & 0x3C) && ( (src[0] & 1) || (src[1] & 0x20))) {
					/* 1100 00x0  101x xxxx - (UTF-8 chars easily convertible */
					/* 1100 00x1  100x xxxx - to Latin1; first x should be 1 */
					/* 1100 00x1  101x xxxx - but 0 (i.e. overlong) is OK) */
					*dest++ = (src[0] << 6) | (src[1] & 0x3F);
					src += 2;
					continue;
				}
				skip = 1;

			} else if (!(*src & 0x10)) {
				/* 1110 xxxx */
				skip = 2;
			} else if (!(*src & 0x08)) {
				/* 1111 0xxx */
				skip = 3;
			} else {
				/* illegal UTF-8: 1111 1xxx */
			illegal:
				*dest++ = CHAR_INVALID_ASC;
				src++;
				continue;
			}

			while (++src, skip--) {
				if ((*src & 0xC0) != 0x80)
					goto illegal;
			}

			if (CHAR_UNMATCHED_ASC) {
				*dest++ = CHAR_UNMATCHED_ASC;
			} else {
				len++;
			}
		} else
			/* ASCII char */
			*dest++ = *src++;
	}

	*dest = '\0';

	return dest - dest_org;
}


/**************************************************************************************************/
/* dittox specific code; common functions */

static int pwd_register(dittox_settings_t *sett, const char *password)
{
	/* Use default password if empty one provided */
	if (!password || strnlen(password, 1) == 0)
		password = DITTOX_PWD_DEFAULT;
	/* Check if the same password is already registered */
	if (sett->pwd && !strcmp(password, sett->pwd))
		return 0;
	free(sett->pwd);
	sett->pwd = strdup(password);
	if (!sett->pwd) {
		ERR("Pwd: Cannot allocate memory\n");
		return -1;
	}

	/* This stupid Ditto protocol is encrypting a lot of data just to send one clip.
	 * We cache here the constant blocks to save time and CPU */
	delete[] sett->cache_fixed_datastart;
	delete[] sett->cache_dataend_end_exit;

 	CSendInfo info;
 	int ret, len;

	uint8_t *buf_out = NULL;
	sett->cache_dataend_end_exit = new uint8_t[ENCRYPTED_SIZE_CSENDINFO * 3];

	/* We put 2 encrypted CSendInfo in this cache */
	info.m_Type = MyEnums::DATA_END;
	ret = sett->crypt->Encrypt((uint8_t*) &info, sizeof(info), sett->pwd, buf_out, len);
	ASSERT(len == ENCRYPTED_SIZE_CSENDINFO);
	memcpy(sett->cache_dataend_end_exit + ENCRYPTED_SIZE_CSENDINFO * 0, buf_out, ENCRYPTED_SIZE_CSENDINFO);
	delete[] buf_out;

	info.m_Type = MyEnums::END;
	ret = sett->crypt->Encrypt((uint8_t*) &info, sizeof(info), sett->pwd, buf_out, len);
	ASSERT(len == ENCRYPTED_SIZE_CSENDINFO);
	memcpy(sett->cache_dataend_end_exit + ENCRYPTED_SIZE_CSENDINFO * 1, buf_out, ENCRYPTED_SIZE_CSENDINFO);
	delete[] buf_out;

	info.m_Type = MyEnums::EXIT;
	ret = sett->crypt->Encrypt((uint8_t*) &info, sizeof(info), sett->pwd, buf_out, len);
	ASSERT(len == ENCRYPTED_SIZE_CSENDINFO);
	memcpy(sett->cache_dataend_end_exit + ENCRYPTED_SIZE_CSENDINFO * 2, buf_out, ENCRYPTED_SIZE_CSENDINFO);
	delete[] buf_out;

	/* This one is only used for UTF-16 clip smaller or equal to CLIP_ENC_SIZE_MIN */
	info.m_Type = MyEnums::DATA_START;
	strcpy(info.m_cDesc, "CF_UNICODETEXT");
	info.m_lParameter1 = CLIP_ENC_SIZE_MIN;
	ret = sett->crypt->Encrypt((uint8_t*) &info, sizeof(info), sett->pwd, sett->cache_fixed_datastart, len);
	ASSERT(len == ENCRYPTED_SIZE_CSENDINFO);

	return 0;
}


/**************************************************************************************************/
/* Rx functions */

static int recv_decrypt(dittox_settings_t *sett, int sock_cnx, int size_exp, uint8_t **buf_clear, int *buf_clear_len)
{
	int ret;
	uint8_t *buf_crypt = new uint8_t[size_exp];
	int size_cumul = 0;

	while (size_exp - size_cumul) {
		ret = recv(sock_cnx, buf_crypt + size_cumul, size_exp - size_cumul, 0);
		if (ret <= 0) {
			*buf_clear_len = 0;
			goto get_out;
		}
		size_cumul += ret;
	}

	ret = !sett->crypt->Decrypt(buf_crypt, size_exp, sett->pwd, *buf_clear, *buf_clear_len);
get_out:
	delete[] buf_crypt;
	return ret;
}

extern "C" {
int dittox_server_create(dittox_settings_t *sett, const char *password, const int filter_cr)
{
	/* Init and check arguments */
	err_init();
	if (!sett) {
		ERR("Incorrect arguments\n");
		return -1;
	}

	dittox_server_kill(sett);

	if (pwd_register(sett, password))
		return -2;
	sett->filter_cr = filter_cr;

	struct sockaddr_in server_addr;

	sett->listen_socket = socket(AF_INET, SOCK_STREAM, 0);
	if (sett->listen_socket == -1) {
		err_add("Cannot open socket:\n      %s\n", strerror(errno));
		return -3;
	}

	int ret = fcntl(sett->listen_socket, F_GETFL, 0);
	if (ret != -1)
		ret = fcntl(sett->listen_socket, F_SETFL, ret | O_NONBLOCK);
	if (ret == -1) {
		err_add("Cannot set socket as non-blocking:\n      %s\n", strerror(errno));
		goto error_socket;
	}

	int param; param = 1;
	ret = setsockopt(sett->listen_socket, SOL_SOCKET, SO_REUSEADDR, &param, sizeof(int));
	if (ret == -1) {
		err_add("Cannot allow socket to reuse address:\n      %s\n", strerror(errno));
		goto error_socket;
	}

	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(DITTOX_LISTEN_PORT);
	server_addr.sin_addr.s_addr = INADDR_ANY;

	bzero(&(server_addr.sin_zero), 8);

	ret = bind(sett->listen_socket, (struct sockaddr *)&server_addr, sizeof(struct sockaddr));
	if (ret == -1) {
		err_add("Cannot bind socket to port %d:\n      %s\n", DITTOX_LISTEN_PORT, strerror(errno));
		goto error_socket;
	}

	ret = listen(sett->listen_socket, 5);
	if (ret == -1) {
		err_add("Cannot listen with socket:\n      %s\n", strerror(errno));
		goto error_socket;
	}

	LOG("TCPServer Waiting for client on port " STR(DITTOX_LISTEN_PORT) "\n");
	return 0;

error_socket:
	if (close(sett->listen_socket) == -1) {
		ERR("Cannot close socket: %s\n", strerror(errno));
		return -4;
	}
	sett->listen_socket = -1;

	return -5;
}

int dittox_server_kill(dittox_settings_t *sett)
{
	/* Init and check arguments */
	err_init();
	if (!sett) {
		ERR("Incorrect arguments\n");
		return -1;
	}

	if (sett->listen_socket != -1) {
		if (close(sett->listen_socket) == -1) {
			ERR("Cannot close socket: %s\n", strerror(errno));
			return -2;
		}
		sett->listen_socket = -1;
	}
	return 0;
}

int dittox_server_check(dittox_settings_t *sett, char **utf8)
{
	int ret = 0;
	/* Init and check arguments */
	err_init();
	if (!sett || !utf8) {
		ERR("Incorrect arguments\n");
		return -1;
	}

	struct sockaddr_storage client_addr;
	socklen_t sin_size = sizeof(client_addr);
	*utf8 = NULL;

	if (sett->listen_socket == -1) {
		ERR("Socket not initialized. Retrying...\n");
		ret = dittox_server_create(sett, sett->pwd, 1);
		if (ret < 0)
			return ret;
	}

	int sock_cnx = accept(sett->listen_socket, (struct sockaddr*) &client_addr, &sin_size);
	if (sock_cnx == -1) {
		if (errno == EAGAIN)
			return 0;
		ERR("Error accept: %d: %s\n", sock_cnx, strerror(errno));
		return -3;
	}

	/* Format debug info - these tricks should be ok for IPv6 */
	char addr_str[max(INET_ADDRSTRLEN,INET6_ADDRSTRLEN)];
	inet_ntop(client_addr.ss_family, &((struct sockaddr_in*)&client_addr)->sin_addr, addr_str, sizeof(addr_str));
	int port = ntohs(((struct sockaddr_in*)&client_addr)->sin_port);
	(void) port;

	/* Set timeout after connection has been opened */
	struct timeval timeout;
	timeout.tv_sec = 3;
	timeout.tv_usec = 0;
	int r = setsockopt(sock_cnx, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
	if (r == -1) {
		err_add("Cannot set timeout on receiving socket:\n      %s\n", strerror(errno));
		close(sock_cnx);
		return -4;
	}

	LOG(" - I got a connection from (%s, %d):\n\n", addr_str, port);

	int cont = true;
	while (cont) {
		CSendInfo *info = NULL;
		int info_len = 0;
		r = recv_decrypt(sett, sock_cnx, ENCRYPTED_SIZE_CSENDINFO, (uint8_t **)&info, &info_len);
		if (r == -1) {
			err_add("Error while receiving data from <%s>:\n      %s\n", addr_str, strerror(errno));
			ret++;
			break;
		} else if (r == 1) {
			err_add("Error while decrypting data from <%s>:\n      bad password?\n", addr_str);
			ret++;
			break;
		} else if (info_len == 0)
			/* Probably remote checking */
			break;

		if (info_len != sizeof(*info))
			ERR("SIZE MISMATCH %d != %zu\n", info_len, sizeof(*info));

		if (0) LOG("\n  sz:%x   t:%x   v:%x\n  IP:%s   n:%s   d:%s\n  p1:%d   p2:%d   x:%s\n",
			info->m_nSize, info->m_Type, info->m_nVersion,
			info->m_cIP, info->m_cComputerName, info->m_cDesc,
			info->m_lParameter1, info->m_lParameter2, info->m_cExtra);

		switch(info->m_Type) {
		case MyEnums::START:
			LOG("SEQ: start\n", info->m_Type);
			break;

		case MyEnums::DATA_START: {
			LOG("SEQ: new data\n", info->m_Type);
			uint8_t *data = NULL;
			int data_len = 0;
			if (recv_decrypt(sett, sock_cnx, info->m_lParameter1, &data, &data_len)) {
				ERR("ERROR recv DECR 2\n");
				cont = false;
				break;
			}
			if (!strcmp("CF_UNICODETEXT", info->m_cDesc) && !*utf8) {
				*utf8 = (char*) malloc(data_len+1);
				/* data is 0 terminated by Decrypt() function */
				int len_out = conv_utf16_to_8(*utf8, (uint16_t *)data, data_len+1, sett->filter_cr);
				if (DEBUG > 2) {
					prhexasc("DataStart", data, data_len);
					prhexasc("Conv", *utf8, len_out);
				}
			}
			delete[] data;
			break;
		}

		case MyEnums::DATA_END:
			LOG("SEQ: end data\n", info->m_Type);
			break;

		case MyEnums::END:
			LOG("SEQ: end\n", info->m_Type);
			break;

		case MyEnums::EXIT:
			LOG("SEQ: exit\n", info->m_Type);
			cont = false;
			break;

		default:
			ERR("\n ##### ERROR unknown action type exiting: %d\n", info->m_Type);
		}

		delete[] info;
	}
	LOG(" - closed!\n\n");
	close(sock_cnx);

	return ret;
}
} // extern C

/**************************************************************************************************/
/* Tx functions */

static clip_t *clip_prepare(dittox_settings_t *sett, const char *utf8)
{
	/* We compute here the min size of clear data from the min of encrypted one */
	int clip_clear_size_min = ((CLIP_ENC_SIZE_MIN - 140)/16 - 1) * 16 + 14;
	LOG("clip_clear_size_min: %d->%d\n", CLIP_ENC_SIZE_MIN, clip_clear_size_min);

	int len_in = strlen(utf8);
	if (len_in == 0)
		return NULL;

	char *tmp = NULL;
	int ret, tmp_len;

	clip_t *clip = (clip_t *) malloc(sizeof(clip_t));
	if (clip == NULL)
		goto mem_err;

	clip->ref_cnt = 0;

	/* Prepare description in UTF-8 */
	clip->desc = strndup(utf8, member_sizeof(CSendInfo,m_cDesc)-1);
	clip->desc_len = min(len_in, (int) member_sizeof(CSendInfo,m_cDesc)-1);
	if (clip->desc == NULL)
		goto mem_err;

	tmp = (char*) calloc(1, max(len_in * 2 + 2, clip_clear_size_min));
	if (tmp == NULL)
		goto enc_err;

	/* Prepare text in UTF-16 */
	tmp_len = max(conv_utf8_to_16((uint16_t*)tmp, utf8, len_in * 2 + 2) * 2, clip_clear_size_min);
	ret = sett->crypt->Encrypt((uint8_t*)tmp, tmp_len, sett->pwd, clip->enc_utf16, clip->enc_utf16_len);
	if (ret == FALSE)
		goto enc_err;
	ASSERT(clip->enc_utf16_len >= CLIP_ENC_SIZE_MIN);

	//LOG("--------------------> SIZE %d/%d %d - %d\n", len_in, tmp_len, clip->enc_utf16_len, clip->enc_utf16_len - 140);

	free(tmp);
	return clip;

enc_err:
	free(clip->desc);
mem_err:
	free(tmp);
	free(clip);
	ERR("Clip: Encrypt or memory error\n");
	return NULL;
}


static void ll_delete(ll_t **ptr)
{
	ll_t *link = *ptr;
	clip_t *clip = link->data;
	if (--clip->ref_cnt == 0) {
		free(clip->desc);
		delete[] clip->enc_utf16;
		free(clip);
	}
	*ptr = link->next;
	free(link);
}


static void dittox_hosts_cleanup(dittox_settings_t *sett)
{
	err_init();

	/* Cancel all ongoing request, if any */
	gai_cancel(NULL);

	free(sett->pwd);
	sett->pwd = NULL;
	delete[] sett->cache_fixed_datastart;
	sett->cache_fixed_datastart = NULL;
	delete[] sett->cache_dataend_end_exit;
	sett->cache_dataend_end_exit = NULL;

	free(sett->hostname_buffer);
	sett->hostname_buffer = NULL;

	host_t *host = sett->host_head;
	while (host) {
		host_t *prev = host;
		if (host->ga_req && host->ga_req->ar_result)
			freeaddrinfo(host->ga_req->ar_result);
		free(host->ga_req);
		free(host->addr);
		free(host->local);
		while (host->clip_head)
			ll_delete(&host->clip_head);

		host = host->next;
		free(prev);
	}

	sett->host_head = NULL;
}


static int host_send_connect(dittox_settings_t *sett, host_t *host)
{
	/* Open socket to remote host */
	host->socket = socket(host->family, SOCK_STREAM, 0);
	if (host->socket == -1) {
		ERR("Cannot open socket:\n      %s\n", strerror(errno));
		return -1;
	}

	int ret = fcntl(host->socket, F_GETFL, 0);
	if (ret != -1)
		ret = fcntl(host->socket, F_SETFL, ret | O_NONBLOCK);
	if (ret == -1) {
		ERR("Cannot set socket as non-blocking:\n      %s\n", strerror(errno));
		return ret;
	}

	LOG("Trying to connect to %s\n", ip2str(host->addr, TRUE));

	ret = connect(host->socket, host->addr, host->addr_len);
	if (ret == -1 && errno != EINPROGRESS) {
		ERR("Cannot connect: %d\n      %s\n", errno, strerror(errno));
		return ret;
	}

	host->state = HOST_SEND_CONNECT_WAIT;

	return 1;
}


static int host_send_new_state(dittox_settings_t *sett, host_t *host)
{
	switch (host->state) {
	case HOST_SEND_CONNECT_WAIT: {
		ASSERT(!host->send_buffer && !host->send_addr && !host->send_remaining);

		/* Prepare to send CSendInfo START  */
		host->state = HOST_SEND_START;
		CSendInfo info;
		info.m_Type = MyEnums::START;
		/* These strings are already truncated to right size */
		strcpy(info.m_cIP, host->local);
		strcpy(info.m_cComputerName, sett->local_host);
		/* desc must be UTF-8 and NUL terminated within the m_cDesc size */
		strncpy(info.m_cDesc, host->clip_head->data->desc, sizeof(info.m_cDesc));

		int len = 0;
		int ret = sett->crypt->Encrypt((uint8_t*) &info, sizeof(info), sett->pwd, host->send_buffer, len);
		ASSERT(ret && len == ENCRYPTED_SIZE_CSENDINFO);
		host->send_addr = host->send_buffer;
		host->send_remaining = len;
		break;
	}
	case HOST_SEND_START:
		delete [] host->send_buffer;
		/* Prepare to send CSendInfo DATASTART, cached or custom one */
		host->state = HOST_SEND_DATASTART;
		if (host->clip_head->data->enc_utf16_len > CLIP_ENC_SIZE_MIN) {
			CSendInfo info;
			info.m_Type = MyEnums::DATA_START;
			strcpy(info.m_cDesc, "CF_UNICODETEXT");
			info.m_lParameter1 = host->clip_head->data->enc_utf16_len;

			int len = 0;
			int ret = sett->crypt->Encrypt((uint8_t*) &info, sizeof(info), sett->pwd, host->send_buffer, len);
			ASSERT(ret && len == ENCRYPTED_SIZE_CSENDINFO);
			host->send_addr = host->send_buffer;
			host->send_remaining = len;
		} else {
			host->send_buffer = NULL;
			host->send_addr = sett->cache_fixed_datastart;
			host->send_remaining = ENCRYPTED_SIZE_CSENDINFO;
		}
		break;

	case HOST_SEND_DATASTART:
		delete [] host->send_buffer;
		host->send_buffer = NULL;
		/* Prepare to send data */
		host->state = HOST_SEND_DATA;
		host->send_addr = host->clip_head->data->enc_utf16;
		host->send_remaining = host->clip_head->data->enc_utf16_len;
		break;

	case HOST_SEND_DATA:
		ll_delete(&host->clip_head);
		/* Prepare to send CSendInfo's DATAEND + END + EXIT */
		host->state = HOST_SEND_DATAEND_END_EXIT;
		host->send_addr = (uint8_t*) sett->cache_dataend_end_exit;
		host->send_remaining = ENCRYPTED_SIZE_CSENDINFO * 3;
		break;

	case HOST_SEND_DATAEND_END_EXIT:
		host->success_cnt++;
		/* Clean up */
		host->send_addr = NULL;
		host->state = HOST_SEND_READY;
		close(host->socket);
		host->socket = -1;
		break;
	default:
		ASSERT(FALSE);
	}

	return host->send_remaining;
}


static int host_send_data(dittox_settings_t *sett, host_t *host)
{
	ASSERT(host->send_remaining);

	for (;;) {
		int ret = send(host->socket, host->send_addr, host->send_remaining, MSG_NOSIGNAL);
		if (ret == -1) {
			if (host->success_cnt)
				err_add("Connexion to '%s' broken:\n      %s\n", host->name, strerror(errno));
			else if (errno == EPIPE && host->success_cnt)
				err_add("Cannot send data to '%s', probably because of password mismatch:\n      %s\n", host->name, strerror(errno));
			else
				err_add("Cannot send data to '%s':\n      %s\n", host->name, strerror(errno));

			close(host->socket);
			host->socket = -1;
			host->state = HOST_USER_ERROR;

			delete [] host->send_buffer;
			host->send_buffer = NULL;
			host->send_addr = NULL;
			host->send_remaining = 0;

			ERR("SEND RETURNED -1, -> %d: %s\n", errno, strerror(errno));
			return 1;
		}

		host->send_addr += ret;
		host->send_remaining -= ret;
		ASSERT(ret >= 0 && host->send_remaining >= 0);

		/* Remaining data to send? Tx buffer full, we will retry later */
		if (host->send_remaining)
			break;

		/* New data to send? If yes, send it now */
		if (host_send_new_state(sett, host) == 0)
			break;
	}

	return host->clip_head != NULL;
}


static int host_send_connect_check(dittox_settings_t *sett, host_t *host)
{
	fd_set fdset;
	FD_ZERO(&fdset);
	FD_SET(host->socket, &fdset);
	struct timeval tv = { 0 };

	ASSERT(host->clip_head);

	int ret = select(host->socket + 1, NULL, &fdset, NULL, &tv);
	if (ret == 0) {
		// Still in progress
		return 1;
	} else if (ret < 0) {
		ERR("select error %d %d!?\n", ret, errno);
		return -1;
	}

	socklen_t slen = sizeof(ret);
	ret = getsockopt(host->socket, SOL_SOCKET, SO_ERROR, &ret, &slen);
	if (ret != 0) {
		/* This addr fails */
		err_add("Cannot connect to '%s' anymore:\n      %s\n", host->name, strerror(errno));
		close(host->socket);
		host->socket = -1;
		host->state = HOST_USER_ERROR;
	} else {
		host_send_new_state(sett, host);
	}

	return 1;
}


static int host_addr_getinfo_start(dittox_settings_t *sett, host_t *host)
{
	/* Do one malloc for the 3 structs */
	struct ga_tmp {
		struct gaicb	req;
		struct addrinfo	hint;
		struct sigevent	sevp;
	} *ga = (struct ga_tmp*) calloc(1, sizeof(struct ga_tmp));
 	ASSERT(ga);
 	ASSERT(host->ga_req == NULL);

	host->ga_req = &ga->req;

	/* Other fields are already 0 / NULL */
	ga->req.ar_name = host->name;
	ga->req.ar_request = &ga->hint;
	ga->req.ar_result = NULL;
	ga->hint.ai_family = AF_UNSPEC;
	ga->hint.ai_socktype = SOCK_STREAM;
	ga->sevp.sigev_notify = SIGEV_NONE;

	/* Get IP corresponding to hostname */
	int ret = getaddrinfo_a(GAI_NOWAIT, &host->ga_req, 1, &ga->sevp);
	if (ret) {
		/* error to process */
		ERR("getaddrinfo_a() for '%s' returned immediate error:\n      %s\n", host->name, (char*) gai_strerror(ret));
		return -1;
	}
	host->state = HOST_ADDR_INFO_WAIT;
	return 1;
}

static int host_addr_connect_continue(dittox_settings_t *sett, host_t *host, int discard)
{
	/* Try to connect to all address provided */
	for (;;) {
		struct addrinfo *addr = host->ga_req->ar_result;
		if (addr && discard) {
			/* Remove the processed addr from the list */
			host->ga_req->ar_result = addr->ai_next;
			addr->ai_next = NULL;
			freeaddrinfo(addr);
			addr = host->ga_req->ar_result;
		} else
			discard = TRUE;

		if (addr == NULL) {
			//err_add("Cannot connect to hostname '%s' (Dittox not launched?).\n", host->name);
			free(host->ga_req);
			host->ga_req = NULL;
			host->state = HOST_USER_ERROR;
			return 1;
		}

		if (addr->ai_family == AF_INET)
			((struct sockaddr_in*)addr->ai_addr)->sin_port = htons(DITTOX_LISTEN_PORT);
		else if (addr->ai_family == AF_INET6)
			((struct sockaddr_in6*)addr->ai_addr)->sin6_port = htons(DITTOX_LISTEN_PORT);
		else
			continue;

		if (addr->ai_socktype != SOCK_STREAM)
			continue;

		host->socket = socket(addr->ai_family, SOCK_STREAM, 0);
		if (host->socket != -1) {
			int ret = fcntl(host->socket, F_GETFL, 0);
			if (ret != -1)
				ret = fcntl(host->socket, F_SETFL, ret | O_NONBLOCK);
			if (ret == -1) {
				ERR("Cannot set socket as non-blocking:\n      %s\n", strerror(errno));
			} else {
				LOG("Trying to connect to %x %x %x - %s (%d)\n",
					addr->ai_flags, addr->ai_family, addr->ai_protocol,
					ip2str(addr->ai_addr, TRUE), addr->ai_addrlen);

				ret = connect(host->socket, addr->ai_addr, addr->ai_addrlen);
				if (ret == -1 && errno != EINPROGRESS)
					ERR("Cannot connect: %d\n      %s\n", errno, strerror(errno));
				else {
					/* Connection start is OK, return and check later */
					break;
				}
			}

			close(host->socket);
			host->socket = -1;
		}
	}

	host->state = HOST_ADDR_CONNECT_WAIT;
	return 1;
}

static int host_addr_getinfo_check(dittox_settings_t *sett, host_t *host)
{
	int ret = gai_error(host->ga_req);
	if (ret == EAI_INPROGRESS)
		return 1;
	else if (ret) {
		/* error to process */
		err_add("Cannot get hostname '%s' address:\n      %s\n", host->name, (char*) gai_strerror(ret));
		free(host->ga_req);
		host->ga_req = NULL;
		host->state = HOST_USER_ERROR;
		return 1;
	}

	ASSERT(host->ga_req->ar_result);
	return host_addr_connect_continue(sett, host, FALSE);
}

static int host_addr_connect_check(dittox_settings_t *sett, host_t *host)
{
	fd_set fdset;
	FD_ZERO(&fdset);
	FD_SET(host->socket, &fdset);
	struct timeval tv = { 0 };

	int ret = select(host->socket + 1, NULL, &fdset, NULL, &tv);
	if (ret == 0) {
		// Still in progress
		return 1;
	} else if (ret < 0) {
		ERR("select error %d %d!?\n", ret, errno);
		return -1;
	}

	/* Address currently checked */
	struct addrinfo *addr = host->ga_req->ar_result;

	int cnct_err;
	socklen_t len = sizeof(cnct_err);
	ret = getsockopt(host->socket, SOL_SOCKET, SO_ERROR, &cnct_err, &len);
	if (ret) {
		ERR("getsockopt error %d %d!?\n", ret, errno);
		return -1;
	}
	if (cnct_err) {
		/* This addr fails */
		close(host->socket);
		host->socket = -1;

		int cnt = 0;
		while ((addr = addr->ai_next))
			cnt++;
		err_add("Connection check failed for %s (%s, %d other IPs):\n      %s\n",
			host->name, ip2str(host->ga_req->ar_result->ai_addr, TRUE), cnt, strerror(cnct_err));

		/* Remove the processed addr from the list and try next addr */
		return host_addr_connect_continue(sett, host, TRUE);
	}

	/* Copy the first address working */
	host->family = addr->ai_family;
	host->addr = (struct sockaddr*) malloc(addr->ai_addrlen);
	ASSERT(host->addr);
	memcpy(host->addr, addr->ai_addr, addr->ai_addrlen);
	host->addr_len = addr->ai_addrlen;

	/* Retrieve corresponding local IP - it can change depending on the remote host
	 * so we must retrieve and save it for each one */
	struct sockaddr_storage sock_addr;
	len = sizeof(sock_addr);
	ret = getsockname(host->socket, (struct sockaddr *) &sock_addr, &len);
	if (ret == -1) {
		/* Truncate the name if bigger than its destination (CSendInfo::m_cIP) */
		host->local = strndup("<Unknown address>", member_sizeof(CSendInfo, m_cIP) - 1);
		ERR("Error getsockname:%d \n", ret);

	} else {
		/* Truncate the name if bigger than its destination (CSendInfo::m_cIP) */
		host->local = strndup(ip2str(&sock_addr, FALSE), member_sizeof(CSendInfo, m_cIP) - 1);
		LOG("Host OK:%s  (remote %s   local:%s)\n", host->name, ip2str(host->addr, TRUE), host->local);
	}
	close (host->socket);
	host->socket = -1;

	/* Now that we finally have our host address, free all the getaddr stuff */
	freeaddrinfo(addr);
	free(host->ga_req); /* 3 contigous structs freed */
	host->ga_req = NULL;

	host->state = HOST_SEND_READY;
	host->error_time = 0;

	return 0;
}


static int host_process(dittox_settings_t *sett, host_t *host)
{
	int ret = 0;
	//DDD(host->state)
	switch (host->state) {
	case HOST_INIT:
		/* Start to retrieve IPv4 or IPv6 from hostname */
		ret = host_addr_getinfo_start(sett, host);
		break;

	case HOST_ADDR_INFO_WAIT:
		/* Check if address is available and start a connect */
		ret = host_addr_getinfo_check(sett, host);
		break;
		/* thr */
	case HOST_ADDR_CONNECT_WAIT:
		/* Check if the connect() has succeeded */
		ret = host_addr_connect_check(sett, host);
		break;

	case HOST_SEND_READY:
		/* Host ready to send, start connect() when clip ready */
		if (host->clip_head)
			ret = host_send_connect(sett, host);
		break;

	case HOST_SEND_CONNECT_WAIT:
		/* connect() succeeded, send the clip */
		ret = host_send_connect_check(sett, host);
		if (host->state != HOST_SEND_START)
			break;

	case HOST_SEND_START:
	case HOST_SEND_DATASTART:
	case HOST_SEND_DATA:
	case HOST_SEND_DATAEND_END_EXIT:
		ret = host_send_data(sett, host);
		break;

	case HOST_USER_ERROR:
	case HOST_INTERNAL_ERROR:
		host->success_cnt = 0;
		while (host->clip_head)
			ll_delete(&host->clip_head);

		/* Error processing: we try to re-register the host from the beginning
		 * 3 times just after the first error. After, we discard the host or we
		 * retry once every 'retry' seconds */
		if (host->error_cnt++ < HOST_RETRY_CNT) {
			host->state = HOST_INIT;
			host->error_time = time(NULL);
			ret = 1;
		} else if (sett->retry) {
			host->state = HOST_WAIT_RETRY;
	case HOST_WAIT_RETRY:
			if (host->error_time + sett->retry < time(NULL)) {
				host->state = HOST_INIT;
				host->error_time = time(NULL);
			}
			ret = 1;
		} else {
			host->state = HOST_DISCARDED;
			while (host->clip_head)
				ll_delete(&host->clip_head);
		}
	case HOST_DISCARDED:
		break;

	default:
		ERR("Invalid state %d\n", host->state);
	}

	if (ret < 0) {
		if (host->ga_req && host->ga_req->ar_result)
			freeaddrinfo(host->ga_req->ar_result);
		free(host->ga_req);
		host->ga_req = NULL;
		if (host->socket != -1) {
			close(host->socket);
			host->socket = -1;
		}
		host->state = HOST_INTERNAL_ERROR;
	}

	return ret;
}

extern "C" {
int dittox_send_iteration(dittox_settings_t *sett)
{
	int retsum = 0, ret;
	/* Init and check arguments */
	err_init();
	if (!sett) {
		ERR("Incorrect arguments\n");
		return -1;
	}

	host_t *host = (host_t *) &sett->host_head;
	while ((host = host->next)) {
		if (host->state != 3 && host->state < 102)
			LOG(CYAN "Processing host '%s', state %d\n" OFF, host->name, host->state);
		ret = host_process(sett, host);
		if (ret < 0)
			return ret;
		else
			retsum += ret;
	}

	return retsum;
}


int dittox_send_add(dittox_settings_t *sett, const char *utf8)
{
	/* Init and check arguments */
	err_init();
	if (!sett || !utf8) {
		ERR("Incorrect arguments\n");
		return -1;
	}

	/* If no host resgitered, just return */
	if (sett->host_head == NULL)
		return 0;

	clip_t *clip = clip_prepare(sett, utf8);
	if (clip == NULL)
		return -2;

	host_t *host = (host_t *) &sett->host_head;
	while ((host = host->next)) {
		if (host->state == HOST_DISCARDED)
			continue;
		/* Append new clip to end of host clips */
		ll_t *newlink = (ll_t *) malloc(sizeof(ll_t));
		newlink->data = clip;
		clip->ref_cnt++;
		ll_t *link = (ll_t *) &host->clip_head;
		while (link->next)
			link = link->next;
		link->next = newlink;
		newlink->next = NULL;

		LOG("Adding <%s> to <%s>\n", utf8, host->name);
	}

	return dittox_send_iteration(sett);
}


int dittox_hosts_set(dittox_settings_t *sett, const char *hostnames, const char *password, int retry)
{
	/* Init and check arguments */
	err_init();
	if (!sett || !hostnames) {
		ERR("Incorrect arguments\n");
		return -1;
	}

	/* Clean up old values if any */
	dittox_hosts_cleanup(sett);

	/* Process easy arguments */
	sett->retry = retry;

	if (pwd_register(sett, password))
		return -2;

	sett->hostname_buffer = (char *) malloc(strlen(hostnames) + 2);
	if (!sett->hostname_buffer) {
		/* Don't care now if pwd is not freed */
		ERR("Cannot allocate memory\n");
		return -3;
	}

	/* Parse host names and store them in hostname_buffer with NUL after each name */
	const char *in = hostnames;
	char *out = sett->hostname_buffer;
	bool name_done = TRUE;

	for (;;) {
		if (*in == '\0' || *in == ',' || *in == ';' || *in == ' ' || *in == '\t' || *in == '\n') {
			if (name_done == FALSE) {
				*out++ = '\0';
				name_done = TRUE;
			}
			if (*in++ == '\0') {
				/* Double NUL to terminate the buffer */
				*out++ = '\0';
				break;
			}
		} else {
			name_done = FALSE;
			*out++ = *in++;
		}
	}

	char *buf = sett->hostname_buffer;
	while (*buf) {
		host_t *host = (host_t*) calloc(1, sizeof(host_t));
		if (!host) {
			ERR("Cannot allocate memory\n");
			return -5;
		}
		host->next = sett->host_head;
		sett->host_head = host;
		host->name = buf;
		host->socket = -1;

		while (*buf++);
	}

	return dittox_send_iteration(sett);
}
} // extern C

/**************************************************************************************************/
/* Base API */
extern "C" {
dittox_settings_t * dittox_init(void)
{
	err_init();
	dittox_settings_t *sett = (dittox_settings_t *) calloc(1, sizeof(dittox_settings_t));
	if (!sett) {
		ERR("Cannot allocate memory\n");
		return NULL;
	}

	sett->listen_socket = -1;

	/* Retrieve local hostname */
	int ret = gethostname(sett->local_host, sizeof(sett->local_host));
	if (ret == -1)
		ERR("Cannot retrieve local hostname with gethostname: %d: %s\n", ret, strerror(errno));

	/* Truncate the name if bigger than its destination (CSendInfo::m_cComputerName) */
	sett->local_host[MAX_COMPUTERNAME_LENGTH] = '\0';

	sett->crypt = new (std::nothrow) CEncryption();
	if (!sett->crypt) {
		ERR("Cannot allocate memory\n");
		free(sett);
		sett = NULL;
	}

	return sett;
}

void dittox_cleanup(dittox_settings_t *sett)
{
	err_init();

	dittox_server_kill(sett);

	if (sett) {
		dittox_hosts_cleanup(sett);
		delete sett->crypt;
		free(sett);
	}
}
// extern C

/**************************************************************************************************/
/* Debug code. Allow to build stand alone executable for testing */
#ifdef DBGEXEC
void usage(void) {
	fprintf(stderr, "dittox: can be used in transmit or receive modes:\n"
		"\tdittox -t [-h host1,host2...] [-p passwd] [--] <text to send...>\n"
		"\tdittox -r [-p passwd]\n");
	exit(-1);
}

int main(int argc, char **argv)
{
	dittox_settings_t *sett = dittox_init();
	int mode = -1;

	const char *hosts = "ac2";
	const char *pwd = DITTOX_PWD_DEFAULT;

	int text_start = 0;
	int text_len = 0;

	for (int i = 1; i < argc; i++) {
		if (argv[i][0] == '-' && !text_start) {
			if (argv[i][2])
				usage();

			if (argv[i][1] == 'r')
				mode = 0;
			else if (argv[i][1] == 't')
				mode = 1;
			else if (argv[i][1] == 'h' && ++i < argc)
				hosts = argv[i];
			else if (argv[i][1] == 'p' && ++i < argc)
				pwd = argv[i];
			else if (argv[i][1] == '-')
				text_start = i + 1;
			else
				usage();
			continue;
		}
		if (mode == -1)
			usage();
		if (!text_start)
			text_start = i;
		text_len += strlen(argv[i]) + 2;
	}

	if (mode) {
		/* transmit */
		if (!text_len)
			usage();

		char *text = (char *) malloc(text_len);
		char *dst = text;

		for (;;) {
			char *src = argv[text_start];
			while ((*dst++ = *src++));
			if (++text_start == argc)
				break;
			dst[-1] = ' ';
		}

		LOG("Dittox: mode:%d hosts:%s pwd:%s, text:%s\n", mode, hosts, pwd, text);


		dittox_hosts_set(sett, hosts, pwd, 10);

		while (dittox_send_iteration(sett))
			sleep(1);

		dittox_send_add(sett, text);

		while (dittox_send_iteration(sett))
			sleep(1);

		free(text);

	} else  {
		/* receive */
		if (text_len)
			usage();

		if (dittox_server_create(sett, "dittoditto", 1))
			ERR("ERROR server_create\n");

		for (;;) {
			char *text = NULL;

			if (dittox_server_check(sett, &text))
				ERR("ERROR server_check\n");

			if (text)
				ERR("text: <%s>\n", text);
			else
				ERR("keud...\n");

			free(text);
			sleep(1);
		}

	}
cassos:
 	dittox_cleanup(sett);

	return 0;
}
#endif

} /* extern "C" */
