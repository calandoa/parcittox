/***************************************************************************************************
 * Antoine Calando - 2012/2013
 * wacawlawndow@free.fr (remove the w)
 *
 * This file is public domain. Do whatever you want with it.
 * However, please note that the whole project is based on Parcellite (GPL v3) and Ditto (GPL v2/v3),
 * and some other files from the same package are NOT public domain.
 */

#ifndef _DITTOX_DEF_H_
#define _DITTOX_DEF_H_


/**************************************************************************************************/
/* Versionning */
#define DITTOX_VER_MAJ    	0
#define DITTOX_VER_MIN    	2
#define DITTOX_CHECK_VER(maj,min) \
	(DITTOX_VER_MAJ > (maj) || (DITTOX_VER_MAJ == (maj) && DITTOX_VER_MIN > (min))

/* Macro stringification */
#define STR(x) _STR(x)
#define _STR(x) # x

/* VERSION workaround if config.h not included */
#ifndef VERSION
#define VERSION 		"$Revision: 31 $"
#endif

#define DITTOX_VER_STR    	(STR(DITTOX_VER_MAJ) "." STR(DITTOX_VER_MIN) "." VERSION)


/**************************************************************************************************/
/* Required constants from Ditto */

#define DITTOX_LISTEN_PORT	23443


/**************************************************************************************************/
/* Private struct */
typedef struct dittox_settings dittox_settings_t;


/**************************************************************************************************/
/* Init and clean up */

/* Allocate private struct and intialize partially the library. Return NULL in case of error */
dittox_settings_t * dittox_init(void);

/* Terminate and disallocate all Dittox related stuff */
void dittox_cleanup(dittox_settings_t *sett);


/**************************************************************************************************/
/* Rx functions */

/* Set the TCP server which will listen for clipboard entries.
 * - 'password' is the password common for all hosts. If NULL, DITTOX_PWD_DEFAULT is used.
 *   It is usually the same than for dittox_hosts_set().
 * - 'filter_cr' set to 1 means that CR+LF (win) in received clips will be converted to LF (unix)
 */
int dittox_server_create(dittox_settings_t *sett, const char *password, const int filter_cr);

/* Accept and process potential connection on the listen server. Must be called frequently.
 * - 'utf8' is a pointer set to NULL or to an allocated buffer containgin the received text.
 * This buffer must be freed by free() after usage.
 */
int dittox_server_check(dittox_settings_t *sett, char **utf8);

/* Terminate the TCP listen server */
int dittox_server_kill(dittox_settings_t *sett);


/**************************************************************************************************/
/* Tx functions */

/* Set the list of host to which send clipboard entries.
 * - 'hosts' is a list of host, IPv4, IPV6 separated by NUL, comma, semicolon, space, tab, EOL and
 *   terminated by double NUL.
 * - 'password' is the passwod common for all hosts. If NULL, DITTOX_PWD_DEFAULT is used
 * - 'retry' is a boolean to force Dittox to keep sending data to an host even after errors
 */
int dittox_hosts_set(dittox_settings_t *sett, const char *hosts, const char *password, int retry);

/* Add an UTF-8 string to send to all hosts previously registered.
 * This function use non-blocking socket calls so will not block, but the encryption process
 * may require some time, around hundreds of milliseconds.
 */
int dittox_send_add(dittox_settings_t *sett, const char *utf8);

/* Continue the processing and sending of added strings.
 * This function use non-blocking socket calls so will not block, but the encryption process
 * may require some time, around hundreds of milliseconds.
 * This function will also return a positive code if there is more procesing to do, but
 * (to the difference of non critical errors which also returns positive code) will not
 * add any error message. If all processing has been done, the function will just return 0.
 */
int dittox_send_iteration(dittox_settings_t *sett);


/**************************************************************************************************/
/* Error checking
 *
 * Functions above returns:
 * - 0 for OK
 * - negative code for critical errors (with errors printed on stderr)
 * - postive code for non critical errors (e.g. the user provided a host which is down). The string
 * describing the error can be retrieved with dittox_error().
 *
 * Note that dittox_send_iteration() also returns a postive code if there is no errors but
 * more processing left to finish.
 */

/* This function retrieves an error string from a static buffer describing the latest non critical
 * error, or NULL.
 */
const char *dittox_error(void);


/**************************************************************************************************/
/* Usefull debug */

void prhex(const char *msg, void *buf, unsigned int n);
void prhexasc(const char *msg, void *buf, unsigned int n);
#define MMM fprintf(stderr, "__%s__%d__\n", __FUNCTION__, __LINE__);
#define DDD(x) fprintf(stderr, "__%s__%d__ %d\n", __FUNCTION__, __LINE__, (x)) ;
#define HHH(x) fprintf(stderr, "__%s__%d__ %x\n", __FUNCTION__, __LINE__, (unsigned long) (x)) ;
/*

static inline void TTT(void)
{
	static uint32_t prev_us;
	struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
	uint32_t now_us = ts.tv_sec * 1000000 + ts.tv_nsec / 1000;

	fprintf(stderr, "__%s__%d__ %d\n", __FUNCTION__, __LINE__, now_us - prev_us) ;
	prev_us = now_us;
}
*/
#endif // _DITTOX_DEF_H_
