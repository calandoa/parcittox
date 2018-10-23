/***************************************************************************************************
 * Compatibility layer include file to avoid errors due to windows specific declarations */

#ifndef _WIN_ABS_H_
#define _WIN_ABS_H_

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <time.h>
#include <stdio.h>

typedef int64_t __int64;
typedef uint8_t BYTE;
typedef uint16_t WORD;
typedef uint32_t DWORD;
typedef uint64_t QWORD;

typedef uint8_t * PBYTE;
typedef uint16_t * PWORD;
typedef uint32_t * PDWORD;
typedef uint64_t * PQWORD;

typedef uint8_t ** PPBYTE;
typedef uint16_t ** PPWORD;
typedef uint32_t ** PPDWORD;
typedef uint64_t ** PPQWORD;

typedef long LONG;
typedef unsigned long ULONG;
typedef int INT;
typedef unsigned int UINT;
typedef short SHORT;
typedef unsigned short USHORT;
typedef char CHAR;
typedef unsigned char UCHAR;

typedef BYTE TCHAR;
typedef int BOOL;

typedef void *LPVOID;

typedef int SOCKET;

#define ui64 LLU

#define MAX_COMPUTERNAME_LENGTH		15

#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif

#define ASSERT(x)                                                   \
	do { if (! (x)) {                                           \
		fprintf(stderr, "ASSERTION FAILED (%s) at %s:%d\n", \
		(#x), __FILE__, __LINE__);                          \
	} } while(0);

#endif // _WIN_ABS_H_
