/*
 *   Unreal Internet Relay Chat Daemon, src/s_conf.c
 *   (C) 1998-2000 Chris Behrens & Fred Jacobs (comstud, moogle)
 *   (C) 2000-2002 Carsten V. Munk and the UnrealIRCd Team
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 1, or (at your option)
 *   any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */
#include "struct.h"
#include "url.h"
#include "common.h"
#include "sys.h"
#include "numeric.h"
#include "channel.h"
#include <fcntl.h>
#ifndef _WIN32
#include <sys/socket.h>
#include <sys/wait.h>
#else
#include <io.h>
#endif
#include <sys/stat.h>
#ifdef __hpux
#include "inet.h"
#endif
#if defined(PCS) || defined(AIX) || defined(SVR3)
#include <time.h>
#endif
#include <string.h>
#ifdef GLOBH
#include <glob.h>
#endif
#ifdef STRIPBADWORDS
#include "badwords.h"
#endif
#include "h.h"
#include "inet.h"
#include "proto.h"
#ifdef _WIN32
#undef GLOBH
#endif
#include "badwords.h"
#ifdef UDB
#include "s_bdd.h"
#endif

#define ircstrdup(x,y) do { if (x) MyFree(x); if (!y) x = NULL; else x = strdup(y); } while(0)
#define ircfree(x) do { if (x) MyFree(x); x = NULL; } while(0)
#define ircabs(x) (x < 0) ? -x : x

/* 
 * Some typedefs..
*/
typedef struct _confcommand ConfigCommand;
struct	_confcommand
{
	char	*name;
	int	(*conffunc)(ConfigFile *conf, ConfigEntry *ce);
	int 	(*testfunc)(ConfigFile *conf, ConfigEntry *ce);
};

typedef struct _conf_operflag OperFlag;
struct _conf_operflag
{
	long	flag;
	char	*name;
};


/* Config commands */

static int	_conf_admin		(ConfigFile *conf, ConfigEntry *ce);
static int	_conf_me		(ConfigFile *conf, ConfigEntry *ce);
static int	_conf_oper		(ConfigFile *conf, ConfigEntry *ce);
static int	_conf_class		(ConfigFile *conf, ConfigEntry *ce);
static int	_conf_drpass		(ConfigFile *conf, ConfigEntry *ce);
static int	_conf_ulines		(ConfigFile *conf, ConfigEntry *ce);
static int	_conf_include		(ConfigFile *conf, ConfigEntry *ce);
static int	_conf_tld		(ConfigFile *conf, ConfigEntry *ce);
static int	_conf_listen		(ConfigFile *conf, ConfigEntry *ce);
static int	_conf_allow		(ConfigFile *conf, ConfigEntry *ce);
static int	_conf_except		(ConfigFile *conf, ConfigEntry *ce);
static int	_conf_vhost		(ConfigFile *conf, ConfigEntry *ce);
static int	_conf_link		(ConfigFile *conf, ConfigEntry *ce);
static int	_conf_ban		(ConfigFile *conf, ConfigEntry *ce);
static int	_conf_set		(ConfigFile *conf, ConfigEntry *ce);
#ifdef STRIPBADWORDS
static int	_conf_badword		(ConfigFile *conf, ConfigEntry *ce);
#endif
static int	_conf_deny		(ConfigFile *conf, ConfigEntry *ce);
static int	_conf_deny_dcc		(ConfigFile *conf, ConfigEntry *ce);
static int	_conf_deny_link		(ConfigFile *conf, ConfigEntry *ce);
static int	_conf_deny_channel	(ConfigFile *conf, ConfigEntry *ce);
static int	_conf_deny_version	(ConfigFile *conf, ConfigEntry *ce);
static int	_conf_allow_channel	(ConfigFile *conf, ConfigEntry *ce);
static int	_conf_allow_dcc		(ConfigFile *conf, ConfigEntry *ce);
static int	_conf_loadmodule	(ConfigFile *conf, ConfigEntry *ce);
static int	_conf_log		(ConfigFile *conf, ConfigEntry *ce);
static int	_conf_alias		(ConfigFile *conf, ConfigEntry *ce);
static int	_conf_help		(ConfigFile *conf, ConfigEntry *ce);
static int	_conf_offchans		(ConfigFile *conf, ConfigEntry *ce);
static int	_conf_spamfilter	(ConfigFile *conf, ConfigEntry *ce);

/* 
 * Validation commands 
*/

static int	_test_admin		(ConfigFile *conf, ConfigEntry *ce);
static int	_test_me		(ConfigFile *conf, ConfigEntry *ce);
static int	_test_oper		(ConfigFile *conf, ConfigEntry *ce);
static int	_test_class		(ConfigFile *conf, ConfigEntry *ce);
static int	_test_drpass		(ConfigFile *conf, ConfigEntry *ce);
static int	_test_ulines		(ConfigFile *conf, ConfigEntry *ce);
static int	_test_include		(ConfigFile *conf, ConfigEntry *ce);
static int	_test_tld		(ConfigFile *conf, ConfigEntry *ce);
static int	_test_listen		(ConfigFile *conf, ConfigEntry *ce);
static int	_test_allow		(ConfigFile *conf, ConfigEntry *ce);
static int	_test_except		(ConfigFile *conf, ConfigEntry *ce);
static int	_test_vhost		(ConfigFile *conf, ConfigEntry *ce);
static int	_test_link		(ConfigFile *conf, ConfigEntry *ce);
static int	_test_ban		(ConfigFile *conf, ConfigEntry *ce);
static int	_test_set		(ConfigFile *conf, ConfigEntry *ce);
#ifdef STRIPBADWORDS
static int	_test_badword		(ConfigFile *conf, ConfigEntry *ce);
#endif
static int	_test_deny		(ConfigFile *conf, ConfigEntry *ce);
/* static int	_test_deny_dcc		(ConfigFile *conf, ConfigEntry *ce); ** TODO? */
/* static int	_test_deny_link		(ConfigFile *conf, ConfigEntry *ce); ** TODO? */
/* static int	_test_deny_channel	(ConfigFile *conf, ConfigEntry *ce); ** TODO? */
/* static int	_test_deny_version	(ConfigFile *conf, ConfigEntry *ce); ** TODO? */
static int	_test_allow_channel	(ConfigFile *conf, ConfigEntry *ce);
static int	_test_allow_dcc		(ConfigFile *conf, ConfigEntry *ce);
static int	_test_loadmodule	(ConfigFile *conf, ConfigEntry *ce);
static int	_test_log		(ConfigFile *conf, ConfigEntry *ce);
static int	_test_alias		(ConfigFile *conf, ConfigEntry *ce);
static int	_test_help		(ConfigFile *conf, ConfigEntry *ce);
static int	_test_offchans		(ConfigFile *conf, ConfigEntry *ce);
static int	_test_spamfilter	(ConfigFile *conf, ConfigEntry *ce);
 
/* This MUST be alphabetized */
static ConfigCommand _ConfigCommands[] = {
	{ "admin", 		_conf_admin,		_test_admin 	},
	{ "alias",		_conf_alias,		_test_alias	},
	{ "allow",		_conf_allow,		_test_allow	},
#ifdef STRIPBADWORDS
	{ "badword",		_conf_badword,		_test_badword	},
#endif
	{ "ban", 		_conf_ban,		_test_ban	},
	{ "class", 		_conf_class,		_test_class	},
	{ "deny",		_conf_deny,		_test_deny	},
	{ "drpass",		_conf_drpass,		_test_drpass	},
	{ "except",		_conf_except,		_test_except	},
	{ "help",		_conf_help,		_test_help	},
	{ "include",		NULL,	  		_test_include	},
	{ "link", 		_conf_link,		_test_link	},
	{ "listen", 		_conf_listen,		_test_listen	},
	{ "loadmodule",		NULL,		 	_test_loadmodule},
	{ "log",		_conf_log,		_test_log	},
	{ "me", 		_conf_me,		_test_me	},
	{ "official-channels", 		_conf_offchans,		_test_offchans	},
	{ "oper", 		_conf_oper,		_test_oper	},
	{ "set",		_conf_set,		_test_set	},
	{ "spamfilter",	_conf_spamfilter,	_test_spamfilter	},
	{ "tld",		_conf_tld,		_test_tld	},
	{ "ulines",		_conf_ulines,		_test_ulines	},
	{ "vhost", 		_conf_vhost,		_test_vhost	},
};

static int _OldOperFlags[] = {
	OFLAG_LOCAL, 'o',
	OFLAG_GLOBAL, 'O',
	OFLAG_REHASH, 'r',
	OFLAG_DIE, 'D',
	OFLAG_RESTART, 'R',
	OFLAG_HELPOP, 'h',
	OFLAG_GLOBOP, 'g',
	OFLAG_WALLOP, 'w',
	OFLAG_LOCOP, 'l',
	OFLAG_LROUTE, 'c',
	OFLAG_GROUTE, 'L',
	OFLAG_LKILL, 'k',
	OFLAG_GKILL, 'K',
	OFLAG_KLINE, 'b',
	OFLAG_UNKLINE, 'B',
	OFLAG_LNOTICE, 'n',
	OFLAG_GNOTICE, 'G',
	OFLAG_ADMIN_, 'A',
	OFLAG_SADMIN_, 'a',
	OFLAG_NADMIN, 'N',
	OFLAG_COADMIN, 'C',
	OFLAG_ZLINE, 'z',
	OFLAG_WHOIS, 'W',
	OFLAG_HIDE, 'H',
	OFLAG_TKL, 't',
	OFLAG_GZL, 'Z',
	OFLAG_OVERRIDE, 'v',
	OFLAG_UMODEQ, 'q',
	OFLAG_DCCDENY, 'd',
	OFLAG_ADDLINE, 'X',
	0, 0
};

/* This MUST be alphabetized */
static OperFlag _OperFlags[] = {
	{ OFLAG_ADMIN_,		"admin"},
	{ OFLAG_ADDLINE,	"can_addline"},
	{ OFLAG_DCCDENY,	"can_dccdeny"},
	{ OFLAG_DIE,		"can_die" },
	{ OFLAG_TKL,		"can_gkline"},
	{ OFLAG_GKILL,		"can_globalkill" },
	{ OFLAG_GNOTICE,	"can_globalnotice" },
	{ OFLAG_GROUTE,		"can_globalroute" },
	{ OFLAG_GLOBOP,         "can_globops" },
	{ OFLAG_GZL,		"can_gzline"},
	{ OFLAG_KLINE,		"can_kline" },
	{ OFLAG_LKILL,		"can_localkill" },
	{ OFLAG_LNOTICE,	"can_localnotice" },
	{ OFLAG_LROUTE,		"can_localroute" },
	{ OFLAG_OVERRIDE,	"can_override" },
	{ OFLAG_REHASH,		"can_rehash" },
	{ OFLAG_RESTART,        "can_restart" },
	{ OFLAG_UMODEQ,		"can_setq" },
	{ OFLAG_UNKLINE,	"can_unkline" },
	{ OFLAG_WALLOP,         "can_wallops" },
	{ OFLAG_ZLINE,		"can_zline"},
	{ OFLAG_COADMIN_,	"coadmin"},
	{ OFLAG_HIDE,		"get_host"},
	{ OFLAG_WHOIS,		"get_umodew"},
	{ OFLAG_GLOBAL,		"global" },
	{ OFLAG_HELPOP,         "helpop" },
	{ OFLAG_LOCAL,		"local" },
	{ OFLAG_LOCOP,		"locop"},
	{ OFLAG_NADMIN,		"netadmin"},
	{ OFLAG_SADMIN_,	"services-admin"},
};

/* This MUST be alphabetized */
static OperFlag _ListenerFlags[] = {
	{ LISTENER_CLIENTSONLY, "clientsonly"},
	{ LISTENER_JAVACLIENT, 	"java"},
	{ LISTENER_MASK, 	"mask"},
	{ LISTENER_REMOTEADMIN, "remoteadmin"},
	{ LISTENER_SERVERSONLY, "serversonly"},
	{ LISTENER_SSL, 	"ssl"},
	{ LISTENER_NORMAL, 	"standard"},
};

/* This MUST be alphabetized */
static OperFlag _LinkFlags[] = {
	{ CONNECT_AUTO,	"autoconnect" },
	{ CONNECT_NODNSCACHE, "nodnscache" },
	{ CONNECT_NOHOSTCHECK, "nohostcheck" },
	{ CONNECT_QUARANTINE, "quarantine"},
	{ CONNECT_SSL,	"ssl"		  },
	{ CONNECT_ZIP,	"zip"		  },
};

/* This MUST be alphabetized */
static OperFlag _LogFlags[] = {
	{ LOG_CHGCMDS, "chg-commands" },
	{ LOG_CLIENT, "connects" },
	{ LOG_ERROR, "errors" },
	{ LOG_KILL, "kills" },
	{ LOG_KLINE, "kline" },
	{ LOG_OPER, "oper" },
	{ LOG_OVERRIDE, "oper-override" },
	{ LOG_SACMDS, "sadmin-commands" },
	{ LOG_SERVER, "server-connects" },
	{ LOG_SPAMFILTER, "spamfilter" },
	{ LOG_TKL, "tkl" },
};

#ifdef USE_SSL
/* This MUST be alphabetized */
static OperFlag _SSLFlags[] = {
	{ SSLFLAG_FAILIFNOCERT, "fail-if-no-clientcert" },
	{ SSLFLAG_DONOTACCEPTSELFSIGNED, "no-self-signed" },
	{ SSLFLAG_VERIFYCERT, "verify-certificate" },
};
#endif

struct {
	unsigned conf_me : 1;
	unsigned conf_admin : 1;
	unsigned conf_listen : 1;
	struct 
	{
		unsigned kline_address : 1;
		unsigned maxchannelsperuser : 1;
		unsigned name_server : 1;
		unsigned host_timeout : 1;
		unsigned host_retries : 1;
		unsigned servicesserv : 1;
		unsigned defaultserv : 1;
		unsigned irc_network : 1;
		unsigned operhost : 1;
		unsigned adminhost : 1;
		unsigned locophost : 1;
		unsigned sadminhost : 1;
		unsigned netadminhost : 1;
		unsigned coadminhost : 1;
		unsigned hlpchan : 1;
		unsigned hidhost : 1;
	} settings;
} requiredstuff;

/*
 * Utilities
*/

void	ipport_seperate(char *string, char **ip, char **port);
void	port_range(char *string, int *start, int *end);
long	config_checkval(char *value, unsigned short flags);

/*
 * Parser
*/

ConfigFile		*config_load(char *filename);
void			config_free(ConfigFile *cfptr);
static ConfigFile 	*config_parse(char *filename, char *confdata);
static void 		config_entry_free(ConfigEntry *ceptr);
ConfigEntry		*config_find_entry(ConfigEntry *ce, char *name);
/*
 * Error handling
*/

void 			config_error(char *format, ...);
void 			config_status(char *format, ...);
void 			config_progress(char *format, ...);

#ifdef _WIN32
extern void 	win_log(char *format, ...);
extern void		win_error();
#endif
extern void add_entropy_configfile(struct stat st, char *buf);
extern void unload_all_unused_snomasks();
extern void unload_all_unused_umodes();

/* Stuff we only need here for spamfilter, so not in h.h... */
extern aTKline *tklines[TKLISTLEN];
extern inline int tkl_hash(char c);
extern aTKline *tkl_del_line(aTKline *tkl);

/*
 * Config parser (IRCd)
*/
int			init_conf(char *rootconf, int rehash);
int			load_conf(char *filename);
void			config_rehash();
int			config_run();
/*
 * Configuration linked lists
*/
ConfigItem_me		*conf_me = NULL;
ConfigItem_class 	*conf_class = NULL;
ConfigItem_class	*default_class = NULL;
ConfigItem_admin 	*conf_admin = NULL;
ConfigItem_admin	*conf_admin_tail = NULL;
ConfigItem_drpass	*conf_drpass = NULL;
ConfigItem_ulines	*conf_ulines = NULL;
ConfigItem_tld		*conf_tld = NULL;
ConfigItem_oper		*conf_oper = NULL;
ConfigItem_listen	*conf_listen = NULL;
ConfigItem_allow	*conf_allow = NULL;
ConfigItem_except	*conf_except = NULL;
ConfigItem_vhost	*conf_vhost = NULL;
ConfigItem_link		*conf_link = NULL;
ConfigItem_ban		*conf_ban = NULL;
ConfigItem_deny_dcc     *conf_deny_dcc = NULL;
ConfigItem_deny_channel *conf_deny_channel = NULL;
ConfigItem_allow_channel *conf_allow_channel = NULL;
ConfigItem_allow_dcc    *conf_allow_dcc = NULL;
ConfigItem_deny_link	*conf_deny_link = NULL;
ConfigItem_deny_version *conf_deny_version = NULL;
ConfigItem_log		*conf_log = NULL;
ConfigItem_alias	*conf_alias = NULL;
ConfigItem_include	*conf_include = NULL;
ConfigItem_help		*conf_help = NULL;
#ifdef STRIPBADWORDS
ConfigItem_badword	*conf_badword_channel = NULL;
ConfigItem_badword      *conf_badword_message = NULL;
ConfigItem_badword	*conf_badword_quit = NULL;
#endif
ConfigItem_offchans	*conf_offchans = NULL;

aConfiguration		iConf;
MODVAR aConfiguration		tempiConf;
MODVAR ConfigFile		*conf = NULL;

MODVAR int			config_error_flag = 0;
int			config_verbose = 0;

void add_include(char *);
#ifdef USE_LIBCURL
void add_remote_include(char *, char *, int, char *);
int remote_include(ConfigEntry *ce);
#endif
void unload_notloaded_includes(void);
void load_includes(void);
void unload_loaded_includes(void);
int rehash_internal(aClient *cptr, aClient *sptr, int sig);


/* Pick out the ip address and the port number from a string.
 * The string syntax is:  ip:port.  ip must be enclosed in brackets ([]) if its an ipv6
 * address because they contain colon (:) separators.  The ip part is optional.  If the string
 * contains a single number its assumed to be a port number.
 *
 * Returns with ip pointing to the ip address (if one was specified), a "*" (if only a port 
 * was specified), or an empty string if there was an error.  port is returned pointing to the 
 * port number if one was specified, otherwise it points to a empty string.
 */
void ipport_seperate(char *string, char **ip, char **port)
{
	char *f;
	
	/* assume failure */
	*ip = *port = "";

	/* sanity check */
	if (string && strlen(string) > 0)
	{
		/* handle ipv6 type of ip address */
		if (*string == '[')
		{
			if ((f = strrchr(string, ']')))
			{
				*ip = string + 1;	/* skip [ */
				*f = '\0';			/* terminate the ip string */
				/* next char must be a : if a port was specified */
				if (*++f == ':')
				{
					*port = ++f;
				}
			}
		}
		/* handle ipv4 and port */
		else if ((f = strchr(string, ':')))
		{
			/* we found a colon... we may have ip:port or just :port */
			if (f == string)
			{
				/* we have just :port */
				*ip = "*";
			}
			else
			{
				/* we have ip:port */
				*ip = string;
				*f = '\0';
			}
			*port = ++f;
		}
		/* no ip was specified, just a port number */
		else if (!strcmp(string, my_itoa(atoi(string))))
		{
			*ip = "*";
			*port = string;
		}
	}
}

void port_range(char *string, int *start, int *end)
{
	char *c = strchr(string, '-');
	if (!c)
	{
		int tmp = atoi(string);
		*start = tmp;
		*end = tmp;
		return;
	}
	*c = '\0';
	*start = atoi(string);
	*end = atoi((c+1));
}

/** Parses '5:60s' config values.
 * orig: original string
 * times: pointer to int, first value (before the :)
 * period: pointer to int, second value (after the :) in seconds
 * RETURNS: 0 for parse error, 1 if ok.
 * REMARK: times&period should be ints!
 */
int config_parse_flood(char *orig, int *times, int *period)
{
char *x;

	*times = *period = 0;
	x = strchr(orig, ':');
	/* 'blah', ':blah', '1:' */
	if (!x || (x == orig) || (*(x+1) == '\0'))
		return 0;

	*x = '\0';
	*times = atoi(orig);
	*period = config_checkval(x+1, CFG_TIME);
	*x = ':'; /* restore */
	return 1;
}

long config_checkval(char *orig, unsigned short flags) {
	char *value;
	char *text;
	long ret = 0;

	value = strdup(orig);

	if (flags == CFG_YESNO) {
		for (text = value; *text; text++) {
			if (!isalnum(*text))
				continue;
			if (tolower(*text) == 'y' || (tolower(*text) == 'o' &&
			    tolower(*(text+1)) == 'n') || *text == '1' || tolower(*text) == 't') {
				ret = 1;
				break;
			}
		}
	}
	else if (flags == CFG_SIZE) {
		int mfactor = 1;
		char *sz;
		for (text = value; *text; text++) {
			if (isalpha(*text)) {
				if (tolower(*text) == 'k') 
					mfactor = 1024;
				else if (tolower(*text) == 'm') 
					mfactor = 1048576;
				else if (tolower(*text) == 'g') 
					mfactor = 1073741824;
				else 
					mfactor = 1;
				sz = text;
				while (isalpha(*text))
					text++;

				*sz-- = 0;
				while (sz-- > value && *sz) {
					if (isspace(*sz)) 
						*sz = 0;
					if (!isdigit(*sz)) 
						break;
				}
				ret += atoi(sz+1)*mfactor;
				if (*text == '\0') {
					text++;
					break;
				}
			}
		}
		mfactor = 1;
		sz = text;
		sz--;
		while (sz-- > value) {
			if (isspace(*sz)) 
				*sz = 0;
			if (!isdigit(*sz)) 
				break;
		}
		ret += atoi(sz+1)*mfactor;
	}
	else if (flags == CFG_TIME) {
		int mfactor = 1;
		char *sz;
		for (text = value; *text; text++) {
			if (isalpha(*text)) {
				if (tolower(*text) == 'w')
					mfactor = 604800;	
				else if (tolower(*text) == 'd') 
					mfactor = 86400;
				else if (tolower(*text) == 'h') 
					mfactor = 3600;
				else if (tolower(*text) == 'm') 
					mfactor = 60;
				else 
					mfactor = 1;
				sz = text;
				while (isalpha(*text))
					text++;

				*sz-- = 0;
				while (sz-- > value && *sz) {
					if (isspace(*sz)) 
						*sz = 0;
					if (!isdigit(*sz)) 
						break;
				}
				ret += atoi(sz+1)*mfactor;
				if (*text == '\0') {
					text++;
					break;
				}
			}
		}
		mfactor = 1;
		sz = text;
		sz--;
		while (sz-- > value) {
			if (isspace(*sz)) 
				*sz = 0;
			if (!isdigit(*sz)) 
				break;
		}
		ret += atoi(sz+1)*mfactor;
	}
	free(value);
	return ret;
}

void set_channelmodes(char *modes, struct ChMode *store, int warn)
{
	aCtab *tab;
	char *params = strchr(modes, ' ');
	char *parambuf = NULL;
	char *param = NULL;
	if (params)
	{
		params++;
		parambuf = MyMalloc(strlen(params)+1);
		strcpy(parambuf, params);
		param = strtok(parambuf, " ");
	}		

	for (; *modes && *modes != ' '; modes++)
	{
		if (*modes == '+')
			continue;
		if (*modes == '-')
		/* When a channel is created it has no modes, so just ignore if the
		 * user asks us to unset anything -- codemastr 
		 */
		{
			while (*modes && *modes != '+')
				modes++;
			continue;
		}
		switch (*modes)
		{
			case 'f':
			{
#ifdef NEWCHFLOODPROT
				char *myparam = param;

				/* TODO */
				ChanFloodProt newf;
				
				memset(&newf, 0, sizeof(newf));
				if (!myparam)
					break;
				/* Go to next parameter */
				param = strtok(NULL, " ");

				if (myparam[0] != '[')
				{
					if (warn)
						config_status("set::modes-on-join: usa el nuevo formato +f: '10:5' es '[10t]:5' "
					                  "y '*10:5' es '[10t#b]:5'.");
				} else
				{
					char xbuf[256], c, a, *p, *p2, *x = xbuf+1;
					int v;
					unsigned short breakit;
					unsigned char r;
					
					/* '['<number><1 letter>[optional: '#'+1 letter],[next..]']'':'<number> */
					strlcpy(xbuf, myparam, sizeof(xbuf));
					p2 = strchr(xbuf+1, ']');
					if (!p2)
						break;
					*p2 = '\0';
					if (*(p2+1) != ':')
						break;
					breakit = 0;
					for (x = strtok(xbuf+1, ","); x; x = strtok(NULL, ","))
					{
						/* <number><1 letter>[optional: '#'+1 letter] */
						p = x;
						while(isdigit(*p)) { p++; }
						if ((*p == '\0') ||
						    !((*p == 'c') || (*p == 'j') || (*p == 'k') ||
						    (*p == 'm') || (*p == 'n') || (*p == 't')))
							break;
						c = *p;
						*p = '\0';
						v = atoi(x);
						if ((v < 1) || (v > 999)) /* out of range... */
							break;
						p++;
						a = '\0';
						r = 0;
						if (*p != '\0')
						{
							if (*p == '#')
							{
								p++;
								a = *p;
								p++;
								if (*p != '\0')
								{
									int tv;
									tv = atoi(p);
									if (tv <= 0)
										tv = 0; /* (ignored) */
									if (tv > 255)
										tv = 255; /* set to max */
									r = tv;
								}
							}
						}

						switch(c)
						{
							case 'c':
								newf.l[FLD_CTCP] = v;
								if ((a == 'm') || (a == 'M'))
									newf.a[FLD_CTCP] = a;
								else
									newf.a[FLD_CTCP] = 'C';
								newf.r[FLD_CTCP] = r;
								break;
							case 'j':
								newf.l[FLD_JOIN] = v;
								if (a == 'R')
									newf.a[FLD_JOIN] = a;
								else
									newf.a[FLD_JOIN] = 'i';
								newf.r[FLD_JOIN] = r;
								break;
							case 'k':
								newf.l[FLD_KNOCK] = v;
								newf.a[FLD_KNOCK] = 'K';
								newf.r[FLD_KNOCK] = r;
								break;
							case 'm':
								newf.l[FLD_MSG] = v;
								if (a == 'M')
									newf.a[FLD_MSG] = a;
								else
									newf.a[FLD_MSG] = 'm';
								newf.r[FLD_MSG] = r;
								break;
							case 'n':
								newf.l[FLD_NICK] = v;
								newf.a[FLD_NICK] = 'N';
								newf.r[FLD_NICK] = r;
								break;
							case 't':
								newf.l[FLD_TEXT] = v;
								if (a == 'b')
									newf.a[FLD_TEXT] = 'b';
								/** newf.r[FLD_TEXT] ** not supported */
								break;
							default:
								breakit=1;
								break;
						}
						if (breakit)
							break;
					} /* for strtok.. */
					if (breakit)
						break;
					/* parse 'per' */
					p2++;
					if (*p2 != ':')
						break;
					p2++;
					if (!*p2)
						break;
					v = atoi(p2);
					if ((v < 1) || (v > 999)) /* 'per' out of range */
						break;
					newf.per = v;
					/* Is anything turned on? (to stop things like '+f []:15' */
					breakit = 1;
					for (v=0; v < NUMFLD; v++)
						if (newf.l[v])
							breakit=0;
					if (breakit)
						break;
					
					/* w00t, we passed... */
					memcpy(&store->floodprot, &newf, sizeof(newf));
					store->mode |= MODE_FLOODLIMIT;
					break;
				}
#else
				char *myparam = param;
				char kmode = 0;
				char *xp;
				int msgs=0, per=0;
				int hascolon = 0;
				if (!myparam)
					break;
				/* Go to next parameter */
				param = strtok(NULL, " ");

				if (*myparam == '*')
					kmode = 1;
				for (xp = myparam; *xp; xp++)
				{
					if (*xp == ':')
					{
						hascolon++;
						continue;
					}
					if (((*xp < '0') || (*xp > '9')) && *xp != '*')
						break;
					if (*xp == '*' && *myparam != '*')
						break;
				}
				if (hascolon != 1)
					break;
				xp = strchr(myparam, ':');
					*xp = 0;
				msgs = atoi((*myparam == '*') ? (myparam+1) : myparam);
				xp++;
				per = atoi(xp);
				xp--;
				*xp = ':';
				if (msgs == 0 || msgs > 500 || per == 0 || per > 500)
					break;
				store->msgs = msgs;
				store->per = per;
				store->kmode = kmode; 					     
				store->mode |= MODE_FLOODLIMIT;
#endif
				break;
			}
			default:
				for (tab = &cFlagTab[0]; tab->mode; tab++)
				{
					if (tab->flag == *modes)
					{
						store->mode |= tab->mode;
						break;
					}
				}
#ifdef EXTCMODE
				/* Try extcmodes */
				if (!tab->mode)
				{
					int i;
					for (i=0; i <= Channelmode_highest; i++)
					{
						if (!(Channelmode_Table[i].flag))
							continue;
						if (*modes == Channelmode_Table[i].flag)
						{
							if (Channelmode_Table[i].paracount)
							{
								if (!param)
									break;
								store->extparams[i] = strdup(Channelmode_Table[i].conv_param(param));
								/* Get next parameter */
								param = strtok(NULL, " ");
							}
							store->extmodes |= Channelmode_Table[i].mode;
							break;
						}
					}
				}
#endif
		}
	}
	if (parambuf)
		free(parambuf);
}

void chmode_str(struct ChMode modes, char *mbuf, char *pbuf)
{
	aCtab *tab;
	int i;
	*pbuf = 0;
	*mbuf++ = '+';
	for (tab = &cFlagTab[0]; tab->mode; tab++)
	{
		if (modes.mode & tab->mode)
		{
			if (!tab->parameters)
				*mbuf++ = tab->flag;
		}
	}
#ifdef EXTCMODE
	for (i=0; i <= Channelmode_highest; i++)
	{
		if (!(Channelmode_Table[i].flag))
			continue;
	
		if (modes.extmodes & Channelmode_Table[i].mode)
		{
			*mbuf++ = Channelmode_Table[i].flag;
			if (Channelmode_Table[i].paracount)
			{
				strcat(pbuf, modes.extparams[i]);
				strcat(pbuf, " ");
			}
		}
	}
#endif
#ifdef NEWCHFLOODPROT
	if (modes.floodprot.per)
	{
		*mbuf++ = 'f';
		strcat(pbuf, channel_modef_string(&modes.floodprot));
	}
#else
	if (modes.per)
	{
		*mbuf++ = 'f';
		if (modes.kmode)
			strcat(pbuf, "*");
		strcat(pbuf, my_itoa(modes.msgs));
		strcat(pbuf, ":");
		strcat(pbuf, my_itoa(modes.per));
	}
#endif
	*mbuf++=0;
}

ConfigFile *config_load(char *filename)
{
	struct stat sb;
	int			fd;
	int			ret;
	char		*buf = NULL;
	ConfigFile	*cfptr;

#ifndef _WIN32
	fd = open(filename, O_RDONLY);
#else
	fd = open(filename, O_RDONLY|O_BINARY);
#endif
	if (fd == -1)
	{
		config_error("No puede abrir \"%s\": %s\n", filename, strerror(errno));
		return NULL;
	}
	if (fstat(fd, &sb) == -1)
	{
		config_error("No puede hacer fstat \"%s\": %s\n", filename, strerror(errno));
		close(fd);
		return NULL;
	}
	if (!sb.st_size)
	{
		close(fd);
		return NULL;
	}
	buf = MyMalloc(sb.st_size+1);
	if (buf == NULL)
	{
		config_error("Memoria insuficiente \"%s\"\n", filename);
		close(fd);
		return NULL;
	}
	ret = read(fd, buf, sb.st_size);
	if (ret != sb.st_size)
	{
		config_error("Error al leer \"%s\": %s\n", filename,
			ret == -1 ? strerror(errno) : strerror(EFAULT));
		free(buf);
		close(fd);
		return NULL;
	}
	/* Just me or could this cause memory corrupted when ret <0 ? */
	buf[ret] = '\0';
	close(fd);
	add_entropy_configfile(sb, buf);
	cfptr = config_parse(filename, buf);
	free(buf);
	return cfptr;
}

void config_free(ConfigFile *cfptr)
{
	ConfigFile	*nptr;

	for(;cfptr;cfptr=nptr)
	{
		nptr = cfptr->cf_next;
		if (cfptr->cf_entries)
			config_entry_free(cfptr->cf_entries);
		if (cfptr->cf_filename)
			free(cfptr->cf_filename);
		free(cfptr);
	}
}

/* This is the internal parser, made by Chris Behrens & Fred Jacobs */
static ConfigFile *config_parse(char *filename, char *confdata)
{
	char		*ptr;
	char		*start;
	int			linenumber = 1;
	ConfigEntry	*curce;
	ConfigEntry	**lastce;
	ConfigEntry	*cursection;

	ConfigFile	*curcf;
	ConfigFile	*lastcf;

	lastcf = curcf = MyMalloc(sizeof(ConfigFile));
	memset(curcf, 0, sizeof(ConfigFile));
	curcf->cf_filename = strdup(filename);
	lastce = &(curcf->cf_entries);
	curce = NULL;
	cursection = NULL;
	/* Replace \r's with spaces .. ugly ugly -Stskeeps */
	for (ptr=confdata; *ptr; ptr++)
		if (*ptr == '\r')
			*ptr = ' ';

	for(ptr=confdata;*ptr;ptr++)
	{
		switch(*ptr)
		{
			case ';':
				if (!curce)
				{
					config_status("%s:%i Ignorando llave extra\n",
						filename, linenumber);
					break;
				}
				*lastce = curce;
				lastce = &(curce->ce_next);
				curce->ce_fileposend = (ptr - confdata);
				curce = NULL;
				break;
			case '{':
				if (!curce)
				{
					config_status("%s:%i: Secci�n sin nombre\n",
							filename, linenumber);
					continue;
				}
				else if (curce->ce_entries)
				{
					config_status("%s:%i: Ignorando secci�n extra\n",
							filename, linenumber);
					continue;
				}
				curce->ce_sectlinenum = linenumber;
				lastce = &(curce->ce_entries);
				cursection = curce;
				curce = NULL;
				break;
			case '}':
				if (curce)
				{
					config_error("%s:%i: Falta llave antes de cerrar\n",
						filename, linenumber);
					config_entry_free(curce);
					config_free(curcf);

					return NULL;
				}
				else if (!cursection)
				{
					config_status("%s:%i: Ignorando llave extra\n",
						filename, linenumber);
					continue;
				}
				curce = cursection;
				cursection->ce_fileposend = (ptr - confdata);
				cursection = cursection->ce_prevlevel;
				if (!cursection)
					lastce = &(curcf->cf_entries);
				else
					lastce = &(cursection->ce_entries);
				for(;*lastce;lastce = &((*lastce)->ce_next))
					continue;
				break;
			case '#':
				ptr++;
				while(*ptr && (*ptr != '\n'))
					 ptr++;
				if (!*ptr)
					break;
				ptr--;
				continue;
			case '/':
				if (*(ptr+1) == '/')
				{
					ptr += 2;
					while(*ptr && (*ptr != '\n'))
						ptr++;
					if (!*ptr)
						break;
					ptr--; /* grab the \n on next loop thru */
					continue;
				}
				else if (*(ptr+1) == '*')
				{
					int commentstart = linenumber;
					int commentlevel = 1;

					for(ptr+=2;*ptr;ptr++)
					{
						if ((*ptr == '/') && (*(ptr+1) == '*'))
						{
							commentlevel++;
							ptr++;
						}

						else if ((*ptr == '*') && (*(ptr+1) == '/'))
						{
							commentlevel--;
							ptr++;
						}

						else if (*ptr == '\n')
							linenumber++;

						if (!commentlevel)
							break;
					}
					if (!*ptr)
					{
						config_error("%s:%i Comentario sin finalizar\n",
							filename, commentstart);
						config_entry_free(curce);
						config_free(curcf);
						return NULL;
					}
				}
				break;
			case '\"':
				start = ++ptr;
				for(;*ptr;ptr++)
				{
					if ((*ptr == '\\') && (*(ptr+1) == '\"'))
					{
						char *tptr = ptr;
						while((*tptr = *(tptr+1)))
							tptr++;
					}
					else if ((*ptr == '\"') || (*ptr == '\n'))
						break;
				}
				if (!*ptr || (*ptr == '\n'))
				{
					config_error("%s:%i: Comillas sin cerrar\n",
							filename, linenumber);
					config_entry_free(curce);
					config_free(curcf);
					return NULL;
				}
				if (curce)
				{
					if (curce->ce_vardata)
					{
						config_status("%s:%i: Ignorando informaci�n extra\n",
							filename, linenumber);
					}
					else
					{
						curce->ce_vardata = MyMalloc(ptr-start+1);
						strncpy(curce->ce_vardata, start, ptr-start);
						curce->ce_vardata[ptr-start] = '\0';
					}
				}
				else
				{
					curce = MyMalloc(sizeof(ConfigEntry));
					memset(curce, 0, sizeof(ConfigEntry));
					curce->ce_varname = MyMalloc((ptr-start)+1);
					strncpy(curce->ce_varname, start, ptr-start);
					curce->ce_varname[ptr-start] = '\0';
					curce->ce_varlinenum = linenumber;
					curce->ce_fileptr = curcf;
					curce->ce_prevlevel = cursection;
					curce->ce_fileposstart = (start - confdata);
				}
				break;
			case '\n':
				linenumber++;
				/* fall through */
			case '\t':
			case ' ':
			case '=':
			case '\r':
				break;
			default:
				if ((*ptr == '*') && (*(ptr+1) == '/'))
				{
					config_status("%s:%i Ignorando final de comentario extra\n",
						filename, linenumber);
					ptr++;
					break;
				}
				start = ptr;
				for(;*ptr;ptr++)
				{
					if ((*ptr == ' ') || (*ptr == '=') || (*ptr == '\t') || (*ptr == '\n') || (*ptr == ';'))
						break;
				}
				if (!*ptr)
				{
					if (curce)
						config_error("%s: EOF antes de variable empezando en %i\n",
							filename, curce->ce_varlinenum);
					else if (cursection) 
						config_error("%s: EOF antes de secci�n empezando en %i\n",
							filename, cursection->ce_sectlinenum);
					else
						config_error("%s: EOF inesperado.\n", filename);
					config_entry_free(curce);
					config_free(curcf);
					return NULL;
				}
				if (curce)
				{
					if (curce->ce_vardata)
					{
						config_status("%s:%i: Ignorando informaci�n extra\n",
							filename, linenumber);
					}
					else
					{
						curce->ce_vardata = MyMalloc(ptr-start+1);
						strncpy(curce->ce_vardata, start, ptr-start);
						curce->ce_vardata[ptr-start] = '\0';
					}
				}
				else
				{
					curce = MyMalloc(sizeof(ConfigEntry));
					memset(curce, 0, sizeof(ConfigEntry));
					curce->ce_varname = MyMalloc((ptr-start)+1);
					strncpy(curce->ce_varname, start, ptr-start);
					curce->ce_varname[ptr-start] = '\0';
					curce->ce_varlinenum = linenumber;
					curce->ce_fileptr = curcf;
					curce->ce_prevlevel = cursection;
					curce->ce_fileposstart = (start - confdata);
				}
				if ((*ptr == ';') || (*ptr == '\n'))
					ptr--;
				break;
		} /* switch */
		if (!*ptr) /* This IS possible. -- Syzop */
			break;
	} /* for */
	if (curce)
	{
		config_error("%s: EOF inesperado para variable de la l�nea %i\n",
			filename, curce->ce_varlinenum);
		config_entry_free(curce);
		config_free(curcf);
		return NULL;
	}
	else if (cursection)
	{
		config_error("%s: EOF inesperado para secci�n de la l�nea %i\n",
				filename, cursection->ce_sectlinenum);
		config_free(curcf);
		return NULL;
	}
	return curcf;
}

static void config_entry_free(ConfigEntry *ceptr)
{
	ConfigEntry	*nptr;

	for(;ceptr;ceptr=nptr)
	{
		nptr = ceptr->ce_next;
		if (ceptr->ce_entries)
			config_entry_free(ceptr->ce_entries);
		if (ceptr->ce_varname)
			free(ceptr->ce_varname);
		if (ceptr->ce_vardata)
			free(ceptr->ce_vardata);
		free(ceptr);
	}
}

ConfigEntry		*config_find_entry(ConfigEntry *ce, char *name)
{
	ConfigEntry *cep;
	
	for (cep = ce; cep; cep = cep->ce_next)
		if (cep->ce_varname && !strcmp(cep->ce_varname, name))
			break;
	return cep;
}

void config_error(char *format, ...)
{
	va_list		ap;
	char		buffer[1024];
	char		*ptr;

	va_start(ap, format);
	vsprintf(buffer, format, ap);
	va_end(ap);
	if ((ptr = strchr(buffer, '\n')) != NULL)
		*ptr = '\0';
	if (!loop.ircd_booted)
#ifndef _WIN32
		fprintf(stderr, "[error] %s\n", buffer);
#else
		win_log("[error] %s", buffer);
#endif
	else
		ircd_log(LOG_ERROR, "config error: %s", buffer);
	sendto_realops("error: %s", buffer);
	/* We cannot live with this */
	config_error_flag = 1;
}

/* Like above */
void config_status(char *format, ...)
{
	va_list		ap;
	char		buffer[1024];
	char		*ptr;

	va_start(ap, format);
	vsnprintf(buffer, 1023, format, ap);
	va_end(ap);
	if ((ptr = strchr(buffer, '\n')) != NULL)
		*ptr = '\0';
	if (!loop.ircd_booted)
#ifndef _WIN32
		fprintf(stderr, "* %s\n", buffer);
#else
		win_log("* %s", buffer);
#endif
	sendto_realops("%s", buffer);
}

void config_progress(char *format, ...)
{
	va_list		ap;
	char		buffer[1024];
	char		*ptr;

	va_start(ap, format);
	vsnprintf(buffer, 1023, format, ap);
	va_end(ap);
	if ((ptr = strchr(buffer, '\n')) != NULL)
		*ptr = '\0';
	if (!loop.ircd_booted)
#ifndef _WIN32
		fprintf(stderr, "* %s\n", buffer);
#else
		win_log("* %s", buffer);
#endif
	sendto_realops("%s", buffer);
}

ConfigCommand *config_binary_search(char *cmd) {
	int start = 0;
	int stop = sizeof(_ConfigCommands)/sizeof(_ConfigCommands[0])-1;
	int mid;
	while (start <= stop) {
		mid = (start+stop)/2;
		if (smycmp(cmd,_ConfigCommands[mid].name) < 0) {
			stop = mid-1;
		}
		else if (strcmp(cmd,_ConfigCommands[mid].name) == 0) {
			return &_ConfigCommands[mid];
		}
		else
			start = mid+1;
	}
	return NULL;
}

void	free_iConf(aConfiguration *i)
{
	ircfree(i->name_server);
	ircfree(i->kline_address);
	ircfree(i->auto_join_chans);
	ircfree(i->oper_auto_join_chans);
	ircfree(i->oper_only_stats);
	ircfree(i->channel_command_prefix);
	ircfree(i->oper_snomask);
	ircfree(i->user_snomask);
	ircfree(i->egd_path);
	ircfree(i->static_quit);
#ifdef USE_SSL
	ircfree(i->x_server_cert_pem);
	ircfree(i->x_server_key_pem);
	ircfree(i->trusted_ca_file);
#endif	
	ircfree(i->restrict_usermodes);
	ircfree(i->restrict_channelmodes);
	ircfree(i->restrict_extendedbans);
	ircfree(i->network.x_ircnetwork);
	ircfree(i->network.x_ircnet005);	
	ircfree(i->network.x_defserv);
	ircfree(i->network.x_services_name);
	ircfree(i->network.x_oper_host);
	ircfree(i->network.x_admin_host);
	ircfree(i->network.x_locop_host);	
	ircfree(i->network.x_sadmin_host);
	ircfree(i->network.x_netadmin_host);
	ircfree(i->network.x_coadmin_host);
	ircfree(i->network.x_hidden_host);
	ircfree(i->network.x_prefix_quit);
	ircfree(i->network.x_helpchan);
	ircfree(i->network.x_stats_server);
	ircfree(i->spamfilter_ban_reason);
	ircfree(i->spamfilter_virus_help_channel);
	ircfree(i->spamexcept_line);
}

int	config_test();

void config_setdefaultsettings(aConfiguration *i)
{
	i->unknown_flood_amount = 4;
	i->unknown_flood_bantime = 600;
	i->oper_snomask = strdup(SNO_DEFOPER);
	i->ident_read_timeout = 30;
	i->ident_connect_timeout = 10;
	i->nick_count = 3; i->nick_period = 60; /* nickflood protection: max 3 per 60s */
#ifdef NO_FLOOD_AWAY
	i->away_count = 4; i->away_period = 120; /* awayflood protection: max 4 per 120s */
#endif
#ifdef NEWCHFLOODPROT
	i->modef_default_unsettime = 0;
	i->modef_max_unsettime = 60; /* 1 hour seems enough :p */
#endif
	i->ban_version_tkl_time = 86400; /* 1d */
	i->spamfilter_ban_time = 86400; /* 1d */
	i->spamfilter_ban_reason = strdup("Spam/advertising");
	i->spamfilter_virus_help_channel = strdup("#help");
	i->maxdccallow = 10;
}

/* 1: needed for set::options::allow-part-if-shunned,
 * we can't just make it M_SHUN and do a ALLOW_PART_IF_SHUNNED in
 * m_part itself because that will also block internal calls (like sapart). -- Syzop
 * 2: now also used by spamfilter entries added by config...
 * we got a chicken-and-egg problem here.. antries added without reason or ban-time
 * field should use the config default (set::spamfilter::ban-reason/ban-time) but
 * this isn't (or might not) be known yet when parsing spamfilter entries..
 * so we do a VERY UGLY mass replace here.. unless someone else has a better idea.
 */
static void do_weird_shun_stuff()
{
aCommand *cmptr;
aTKline *tk;
char *encoded;

	if ((cmptr = find_Command_simple("PART")))
	{
		if (ALLOW_PART_IF_SHUNNED)
			cmptr->flags |= M_SHUN;
		else
			cmptr->flags &= ~M_SHUN;
	}

	encoded = unreal_encodespace(SPAMFILTER_BAN_REASON);
	for (tk = tklines[tkl_hash('q')]; tk; tk = tk->next)
	{
		if (tk->type != TKL_NICK)
			continue;
		if (!tk->setby)
		{
			if (me.name[0] != '\0')
				tk->setby = strdup(me.name);
			else
				tk->setby = strdup(conf_me->name ? conf_me->name : "~server~");
		}
	}

	for (tk = tklines[tkl_hash('f')]; tk; tk = tk->next)
	{
		if (tk->type != TKL_SPAMF)
			continue; /* global entry or something else.. */
		if (!strcmp(tk->ptr.spamf->tkl_reason, "<internally added by ircd>"))
		{
			MyFree(tk->ptr.spamf->tkl_reason);
			tk->ptr.spamf->tkl_reason = strdup(encoded);
			tk->ptr.spamf->tkl_duration = SPAMFILTER_BAN_TIME;
		}
		/* This one is even more ugly, but our config crap is VERY confusing :[ */
		if (!tk->setby)
		{
			if (me.name[0] != '\0')
				tk->setby = strdup(me.name);
			else
				tk->setby = strdup(conf_me->name ? conf_me->name : "~server~");
		}
	}
}

int	init_conf(char *rootconf, int rehash)
{
	config_status("Cargando configuraci�n del IRCd ...");
	if (conf)
	{
		config_error("%s:%i - Error en", __FILE__, __LINE__);
		return -1;
	}
	bzero(&tempiConf, sizeof(iConf));
	bzero(&requiredstuff, sizeof(requiredstuff));
	config_setdefaultsettings(&tempiConf);
	if (load_conf(rootconf) > 0)
	{
		if ((config_test() < 0) || (callbacks_check() < 0))
		{
			config_error("La configuraci�n no ha pasado el test.");
#ifdef _WIN32
			if (!rehash)
				win_error();
#endif
#ifndef STATIC_LINKING
			Unload_all_testing_modules();
#endif
			unload_notloaded_includes();
			config_free(conf);
			conf = NULL;
			free_iConf(&tempiConf);
			return -1;
		}
		callbacks_switchover();
		if (rehash)
		{
			Hook *h;
			del_async_connects();
			config_rehash();
#ifndef STATIC_LINKING
			Unload_all_loaded_modules();

			/* Notify permanent modules of the rehash */
			for (h = Hooks[HOOKTYPE_REHASH]; h; h = h->next)
		        {
				if (!h->owner)
					continue;
				if (!(h->owner->options & MOD_OPT_PERM))
					continue;
				(*(h->func.intfunc))();
			}
#else
			RunHook0(HOOKTYPE_REHASH);
#endif
			unload_loaded_includes();
		}
		load_includes();
#ifndef STATIC_LINKING
		Init_all_testing_modules();
#else
		if (!rehash) {
			ModuleInfo ModCoreInfo;
			ModCoreInfo.size = sizeof(ModuleInfo);
			ModCoreInfo.module_load = 0;
			ModCoreInfo.handle = NULL;
			l_commands_Init(&ModCoreInfo);
		}
#endif
		if (config_run() < 0)
		{
			config_error("Bad case of config errors. Server will now die. This really shouldn't happen");
#ifdef _WIN32
			if (!rehash)
				win_error();
#endif
			abort();
		}
			
	}
	else	
	{
		config_error("IRCd configuration failed to load");
#ifndef STATIC_LINKING
		Unload_all_testing_modules();
#endif
		unload_notloaded_includes();
		config_free(conf);
		conf = NULL;
		free_iConf(&tempiConf);
#ifdef _WIN32
		if (!rehash)
			win_error();
#endif
		return -1;
	}
	config_free(conf);
	conf = NULL;
	if (rehash)
	{
#ifndef STATIC_LINKING
		module_loadall(0);
#endif
		RunHook0(HOOKTYPE_REHASH_COMPLETE);
	}
	do_weird_shun_stuff();
	nextconnect = TStime() + 1; /* check for autoconnects */
	config_status("Configuraci�n cargada sin problemas ...");
	return 0;
}

int	load_conf(char *filename)
{
	ConfigFile 	*cfptr, *cfptr2, **cfptr3;
	ConfigEntry 	*ce;
	int		ret;

	if (config_verbose > 0)
		config_status("Cargando el archivo de configuraci�n %s ..", filename);
	if ((cfptr = config_load(filename)))
	{
		for (cfptr3 = &conf, cfptr2 = conf; cfptr2; cfptr2 = cfptr2->cf_next)
			cfptr3 = &cfptr2->cf_next;
		*cfptr3 = cfptr;
		if (config_verbose > 1)
			config_status("Cargando los m�dulos en %s", filename);
		for (ce = cfptr->cf_entries; ce; ce = ce->ce_next)
			if (!strcmp(ce->ce_varname, "loadmodule"))
			{
				 ret = _conf_loadmodule(cfptr, ce);
				 if (ret < 0) 
					 	return ret;
			}
		if (config_verbose > 1)
			config_status("Searching through %s for include files..", filename);
		for (ce = cfptr->cf_entries; ce; ce = ce->ce_next)
			if (!strcmp(ce->ce_varname, "include"))
			{
				 ret = _conf_include(cfptr, ce);
				 if (ret < 0) 
					 	return ret;
			}
		return 1;
	}
	else
	{
		config_error("No se pudo cargar la configuraci�n del archivo %s", filename);
		return -1;
	}	
}

void	config_rehash()
{
	ConfigItem_oper			*oper_ptr;
	ConfigItem_class 		*class_ptr;
	ConfigItem_ulines 		*uline_ptr;
	ConfigItem_allow 		*allow_ptr;
	ConfigItem_except 		*except_ptr;
	ConfigItem_ban 			*ban_ptr;
	ConfigItem_link 		*link_ptr;
	ConfigItem_listen	 	*listen_ptr;
	ConfigItem_tld			*tld_ptr;
	ConfigItem_vhost		*vhost_ptr;
	ConfigItem_badword		*badword_ptr;
	ConfigItem_deny_dcc		*deny_dcc_ptr;
	ConfigItem_allow_dcc		*allow_dcc_ptr;
	ConfigItem_deny_link		*deny_link_ptr;
	ConfigItem_deny_channel		*deny_channel_ptr;
	ConfigItem_allow_channel	*allow_channel_ptr;
	ConfigItem_admin		*admin_ptr;
	ConfigItem_deny_version		*deny_version_ptr;
	ConfigItem_log			*log_ptr;
	ConfigItem_alias		*alias_ptr;
	ConfigItem_help			*help_ptr;
	ConfigItem_offchans		*of_ptr;
	OperStat 			*os_ptr;
	ListStruct 	*next, *next2;
	aTKline *tk, *tk_next;
	SpamExcept *spamex_ptr;
	int i;

	USE_BAN_VERSION = 0;
	/* clean out stuff that we don't use */	
	for (admin_ptr = conf_admin; admin_ptr; admin_ptr = (ConfigItem_admin *)next)
	{
		next = (ListStruct *)admin_ptr->next;
		ircfree(admin_ptr->line);
		DelListItem(admin_ptr, conf_admin);
		MyFree(admin_ptr);
	}
	/* wipe the fckers out ..*/
	for (oper_ptr = conf_oper; oper_ptr; oper_ptr = (ConfigItem_oper *)next)
	{
		ConfigItem_oper_from *oper_from;
		next = (ListStruct *)oper_ptr->next;
		ircfree(oper_ptr->name);
		ircfree(oper_ptr->swhois);
		ircfree(oper_ptr->snomask);
		Auth_DeleteAuthStruct(oper_ptr->auth);
		for (oper_from = (ConfigItem_oper_from *) oper_ptr->from; oper_from; oper_from = (ConfigItem_oper_from *) next2)
		{
			next2 = (ListStruct *)oper_from->next;
			ircfree(oper_from->name);
			DelListItem(oper_from, oper_ptr->from);
			MyFree(oper_from);
		}
		DelListItem(oper_ptr, conf_oper);
		MyFree(oper_ptr);
	}
	for (link_ptr = conf_link; link_ptr; link_ptr = (ConfigItem_link *) next)
	{
		next = (ListStruct *)link_ptr->next;
		if (link_ptr->refcount == 0)
		{
			Debug((DEBUG_ERROR, "s_conf: deleting block %s (refcount 0)", link_ptr->servername));
			delete_linkblock(link_ptr);
		}
		else
		{
			Debug((DEBUG_ERROR, "s_conf: marking block %s (refcount %d) as temporary",
				link_ptr->servername, link_ptr->refcount));
			link_ptr->flag.temporary = 1;
		}
	}
	for (class_ptr = conf_class; class_ptr; class_ptr = (ConfigItem_class *) next)
	{
		next = (ListStruct *)class_ptr->next;
		if (class_ptr->flag.permanent == 1)
			continue;
		class_ptr->flag.temporary = 1;
		/* We'll wipe it out when it has no clients */
		if (!class_ptr->clients && !class_ptr->xrefcount)
		{
			delete_classblock(class_ptr);
		}
	}
	for (uline_ptr = conf_ulines; uline_ptr; uline_ptr = (ConfigItem_ulines *) next)
	{
		next = (ListStruct *)uline_ptr->next;
		/* We'll wipe it out when it has no clients */
		ircfree(uline_ptr->servername);
		DelListItem(uline_ptr, conf_ulines);
		MyFree(uline_ptr);
	}
	for (allow_ptr = conf_allow; allow_ptr; allow_ptr = (ConfigItem_allow *) next)
	{
		next = (ListStruct *)allow_ptr->next;
		ircfree(allow_ptr->ip);
		ircfree(allow_ptr->hostname);
		if (allow_ptr->netmask)
			MyFree(allow_ptr->netmask);
		Auth_DeleteAuthStruct(allow_ptr->auth);
		DelListItem(allow_ptr, conf_allow);
		MyFree(allow_ptr);
	}
	for (except_ptr = conf_except; except_ptr; except_ptr = (ConfigItem_except *) next)
	{
		next = (ListStruct *)except_ptr->next;
		ircfree(except_ptr->mask);
		if (except_ptr->netmask)
			MyFree(except_ptr->netmask);
		DelListItem(except_ptr, conf_except);
		MyFree(except_ptr);
	}
	for (ban_ptr = conf_ban; ban_ptr; ban_ptr = (ConfigItem_ban *) next)
	{
		next = (ListStruct *)ban_ptr->next;
		if (ban_ptr->flag.type2 == CONF_BAN_TYPE_CONF || ban_ptr->flag.type2 == CONF_BAN_TYPE_TEMPORARY)
		{
			ircfree(ban_ptr->mask);
			ircfree(ban_ptr->reason);
			if (ban_ptr->netmask)
				MyFree(ban_ptr->netmask);
			DelListItem(ban_ptr, conf_ban);
			MyFree(ban_ptr);
		}
	}
	for (listen_ptr = conf_listen; listen_ptr; listen_ptr = (ConfigItem_listen *)listen_ptr->next)
	{
		listen_ptr->flag.temporary = 1;
	}
	for (tld_ptr = conf_tld; tld_ptr; tld_ptr = (ConfigItem_tld *) next)
	{
		aMotd *motd;
		next = (ListStruct *)tld_ptr->next;
		ircfree(tld_ptr->motd_file);
		ircfree(tld_ptr->rules_file);
		ircfree(tld_ptr->smotd_file);
		if (!tld_ptr->flag.motdptr) {
			while (tld_ptr->motd) {
				motd = tld_ptr->motd->next;
				ircfree(tld_ptr->motd->line);
				ircfree(tld_ptr->motd);
				tld_ptr->motd = motd;
			}
		}
		if (!tld_ptr->flag.rulesptr) {
			while (tld_ptr->rules) {
				motd = tld_ptr->rules->next;
				ircfree(tld_ptr->rules->line);
				ircfree(tld_ptr->rules);
				tld_ptr->rules = motd;
			}
		}
		while (tld_ptr->smotd) {
			motd = tld_ptr->smotd->next;
			ircfree(tld_ptr->smotd->line);
			ircfree(tld_ptr->smotd);
			tld_ptr->smotd = motd;
		}
		DelListItem(tld_ptr, conf_tld);
		MyFree(tld_ptr);
	}
	for (vhost_ptr = conf_vhost; vhost_ptr; vhost_ptr = (ConfigItem_vhost *) next)
	{
		ConfigItem_oper_from *vhost_from;
		
		next = (ListStruct *)vhost_ptr->next;
		
		ircfree(vhost_ptr->login);
		Auth_DeleteAuthStruct(vhost_ptr->auth);
		ircfree(vhost_ptr->virthost);
		ircfree(vhost_ptr->virtuser);
		for (vhost_from = (ConfigItem_oper_from *) vhost_ptr->from; vhost_from;
			vhost_from = (ConfigItem_oper_from *) next2)
		{
			next2 = (ListStruct *)vhost_from->next;
			ircfree(vhost_from->name);
			DelListItem(vhost_from, vhost_ptr->from);
			MyFree(vhost_from);
		}
		DelListItem(vhost_ptr, conf_vhost);
		MyFree(vhost_ptr);
	}

#ifdef STRIPBADWORDS
	for (badword_ptr = conf_badword_channel; badword_ptr;
		badword_ptr = (ConfigItem_badword *) next) {
		next = (ListStruct *)badword_ptr->next;
		ircfree(badword_ptr->word);
		if (badword_ptr->replace)
			ircfree(badword_ptr->replace);
		regfree(&badword_ptr->expr);
		DelListItem(badword_ptr, conf_badword_channel);
		MyFree(badword_ptr);
	}
	for (badword_ptr = conf_badword_message; badword_ptr;
		badword_ptr = (ConfigItem_badword *) next) {
		next = (ListStruct *)badword_ptr->next;
		ircfree(badword_ptr->word);
		if (badword_ptr->replace)
			ircfree(badword_ptr->replace);
		regfree(&badword_ptr->expr);
		DelListItem(badword_ptr, conf_badword_message);
		MyFree(badword_ptr);
	}
	for (badword_ptr = conf_badword_quit; badword_ptr;
		badword_ptr = (ConfigItem_badword *) next) {
		next = (ListStruct *)badword_ptr->next;
		ircfree(badword_ptr->word);
		if (badword_ptr->replace)
			ircfree(badword_ptr->replace);
		regfree(&badword_ptr->expr);
		DelListItem(badword_ptr, conf_badword_quit);
		MyFree(badword_ptr);
	}
#endif
	/* Clean up local spamfilter entries... */
	for (tk = tklines[tkl_hash('f')]; tk; tk = tk_next)
	{
		if (tk->type == TKL_SPAMF)
			tk_next = tkl_del_line(tk);
		else /* global spamfilter.. don't touch! */
			tk_next = tk->next;
	}

	for (tk = tklines[tkl_hash('q')]; tk; tk = tk_next)
	{
		if (tk->type == TKL_NICK)
			tk_next = tkl_del_line(tk);
		else 
			tk_next = tk->next;
	}

	for (deny_dcc_ptr = conf_deny_dcc; deny_dcc_ptr; deny_dcc_ptr = (ConfigItem_deny_dcc *)next)
	{
		next = (ListStruct *)deny_dcc_ptr->next;
		if (deny_dcc_ptr->flag.type2 == CONF_BAN_TYPE_CONF)
		{
			ircfree(deny_dcc_ptr->filename);
			ircfree(deny_dcc_ptr->reason);
			DelListItem(deny_dcc_ptr, conf_deny_dcc);
			MyFree(deny_dcc_ptr);
		}
	}
	for (deny_link_ptr = conf_deny_link; deny_link_ptr; deny_link_ptr = (ConfigItem_deny_link *) next) {
		next = (ListStruct *)deny_link_ptr->next;
		ircfree(deny_link_ptr->prettyrule);
		ircfree(deny_link_ptr->mask);
		crule_free(&deny_link_ptr->rule);
		DelListItem(deny_link_ptr, conf_deny_link);
		MyFree(deny_link_ptr);
	}
	for (deny_version_ptr = conf_deny_version; deny_version_ptr; deny_version_ptr = (ConfigItem_deny_version *) next) {
		next = (ListStruct *)deny_version_ptr->next;
		ircfree(deny_version_ptr->mask);
		ircfree(deny_version_ptr->version);
		ircfree(deny_version_ptr->flags);
		DelListItem(deny_version_ptr, conf_deny_version);
		MyFree(deny_version_ptr);
	}
	for (deny_channel_ptr = conf_deny_channel; deny_channel_ptr; deny_channel_ptr = (ConfigItem_deny_channel *) next)
	{
		next = (ListStruct *)deny_channel_ptr->next;
		ircfree(deny_channel_ptr->redirect);
		ircfree(deny_channel_ptr->channel);
		ircfree(deny_channel_ptr->reason);
		DelListItem(deny_channel_ptr, conf_deny_channel);
		MyFree(deny_channel_ptr);
	}

	for (allow_channel_ptr = conf_allow_channel; allow_channel_ptr; allow_channel_ptr = (ConfigItem_allow_channel *) next)
	{
		next = (ListStruct *)allow_channel_ptr->next;
		ircfree(allow_channel_ptr->channel);
		DelListItem(allow_channel_ptr, conf_allow_channel);
		MyFree(allow_channel_ptr);
	}
	for (allow_dcc_ptr = conf_allow_dcc; allow_dcc_ptr; allow_dcc_ptr = (ConfigItem_allow_dcc *)next)
	{
		next = (ListStruct *)allow_dcc_ptr->next;
		if (allow_dcc_ptr->flag.type2 == CONF_BAN_TYPE_CONF)
		{
			ircfree(allow_dcc_ptr->filename);
			DelListItem(allow_dcc_ptr, conf_allow_dcc);
			MyFree(allow_dcc_ptr);
		}
	}

	if (conf_drpass)
	{
		Auth_DeleteAuthStruct(conf_drpass->restartauth);
		conf_drpass->restartauth = NULL;
		Auth_DeleteAuthStruct(conf_drpass->dieauth);
		conf_drpass->dieauth = NULL;
		ircfree(conf_drpass);
	}
	for (log_ptr = conf_log; log_ptr; log_ptr = (ConfigItem_log *)next) {
		next = (ListStruct *)log_ptr->next;
		ircfree(log_ptr->file);
		DelListItem(log_ptr, conf_log);
		MyFree(log_ptr);
	}
	for (alias_ptr = conf_alias; alias_ptr; alias_ptr = (ConfigItem_alias *)next) {
		aCommand *cmptr = find_Command(alias_ptr->alias, 0, 0);
		ConfigItem_alias_format *fmt;
		next = (ListStruct *)alias_ptr->next;		
		ircfree(alias_ptr->nick);
		del_Command(alias_ptr->alias, NULL, cmptr->func);
		ircfree(alias_ptr->alias);
		if (alias_ptr->format && alias_ptr->type == ALIAS_COMMAND) {
			for (fmt = (ConfigItem_alias_format *) alias_ptr->format; fmt; fmt = (ConfigItem_alias_format *) next2)
			{
				next2 = (ListStruct *)fmt->next;
				ircfree(fmt->format);
				ircfree(fmt->nick);
				ircfree(fmt->parameters);
				regfree(&fmt->expr);
				DelListItem(fmt, alias_ptr->format);
				MyFree(fmt);
			}
		}
		DelListItem(alias_ptr, conf_alias);
		MyFree(alias_ptr);
	}
	for (help_ptr = conf_help; help_ptr; help_ptr = (ConfigItem_help *)next) {
		aMotd *text;
		next = (ListStruct *)help_ptr->next;
		ircfree(help_ptr->command);
		while (help_ptr->text) {
			text = help_ptr->text->next;
			ircfree(help_ptr->text->line);
			ircfree(help_ptr->text);
			help_ptr->text = text;
		}
		DelListItem(help_ptr, conf_help);
		MyFree(help_ptr);
	}
	for (os_ptr = iConf.oper_only_stats_ext; os_ptr; os_ptr = (OperStat *)next)
	{
		next = (ListStruct *)os_ptr->next;
		ircfree(os_ptr->flag);
		MyFree(os_ptr);
	}
	iConf.oper_only_stats_ext = NULL;
	for (spamex_ptr = iConf.spamexcept; spamex_ptr; spamex_ptr = (SpamExcept *)next)
	{
		next = (ListStruct *)spamex_ptr->next;
		MyFree(spamex_ptr);
	}
	iConf.spamexcept = NULL;
	for (of_ptr = conf_offchans; of_ptr; of_ptr = (ConfigItem_offchans *)next)
	{
		next = (ListStruct *)of_ptr->next;
		ircfree(of_ptr->topic);
		MyFree(of_ptr);
	}
#ifdef EXTCMODE
	for (i = 0; i < EXTCMODETABLESZ; i++)
	{
		if (iConf.modes_on_join.extparams[i])
			free(iConf.modes_on_join.extparams[i]);
	}
#endif
	conf_offchans = NULL;
}

int	config_post_test()
{
#define Error(x) { config_error((x)); errors++; }
	int 	errors = 0;
	Hook *h;
	
	if (!requiredstuff.conf_me)
		Error("falta bloque me {}");
	if (!requiredstuff.conf_admin)
		Error("falta bloque admin {}");
	if (!requiredstuff.conf_listen)
		Error("falta bloque listen {}");
	if (!requiredstuff.settings.kline_address)
		Error("falta set::kline-address");
	if (!requiredstuff.settings.maxchannelsperuser)
		Error("falta set::maxchannelsperuser");
	if (!requiredstuff.settings.name_server)
		Error("falta set::dns::nameserver");
	if (!requiredstuff.settings.host_timeout)
		Error("falta set::dns::timeout");
	if (!requiredstuff.settings.host_retries)
		Error("falta set::dns::retries");
	if (!requiredstuff.settings.servicesserv)
		Error("falta set::services-server");
	if (!requiredstuff.settings.defaultserv)
		Error("falta set::default-server");
	if (!requiredstuff.settings.irc_network)
		Error("falta set::network-name");
	if (!requiredstuff.settings.operhost)
		Error("falta set::hosts::global");
	if (!requiredstuff.settings.adminhost)
		Error("falta set::hosts::admin");
	if (!requiredstuff.settings.sadminhost)
		Error("falta set::hosts::servicesadmin");
	if (!requiredstuff.settings.netadminhost)
		Error("falta set::hosts::netadmin");
	if (!requiredstuff.settings.coadminhost)
		Error("falta set::hosts::coadmin");
	if (!requiredstuff.settings.hlpchan)
		Error("falta set::help-channel");
	if (!requiredstuff.settings.hidhost)
		Error("falta set::hiddenhost-prefix");
	for (h = Hooks[HOOKTYPE_CONFIGPOSTTEST]; h; h = h->next) 
	{
		int value, errs = 0;
		if (h->owner && !(h->owner->flags & MODFLAG_TESTING) &&
		                !(h->owner->options & MOD_OPT_PERM))
			continue;
		value = (*(h->func.intfunc))(&errs);
		if (value == -1)
		{
			errors += errs;
			break;
		}
		if (value == -2)
			errors += errs;
	}
	return errors;	
}

int	config_run()
{
	ConfigEntry 	*ce;
	ConfigFile	*cfptr;
	ConfigCommand	*cc;
	int		errors = 0;
	Hook *h;
	for (cfptr = conf; cfptr; cfptr = cfptr->cf_next)
	{
		if (config_verbose > 1)
			config_status("Ejecutando %s", cfptr->cf_filename);
		for (ce = cfptr->cf_entries; ce; ce = ce->ce_next)
		{
			if ((cc = config_binary_search(ce->ce_varname))) {
				if ((cc->conffunc) && (cc->conffunc(cfptr, ce) < 0))
					errors++;
			}
			else
			{
				int value;
				for (h = Hooks[HOOKTYPE_CONFIGRUN]; h; h = h->next)
				{
					value = (*(h->func.intfunc))(cfptr,ce,CONFIG_MAIN);
					if (value == 1)
						break;
				}
			}
		}
	}

	close_listeners();
	listen_cleanup();
	close_listeners();
	loop.do_bancheck = 1;
	free_iConf(&iConf);
	bcopy(&tempiConf, &iConf, sizeof(aConfiguration));
	bzero(&tempiConf, sizeof(aConfiguration));
#ifdef THROTTLING
	{
		EventInfo eInfo;
		eInfo.flags = EMOD_EVERY;
		eInfo.every = THROTTLING_PERIOD ? THROTTLING_PERIOD/2 : 86400;
		EventMod(EventFind("bucketcleaning"), &eInfo);
	}
#endif

	if (errors > 0)
	{
		config_error("%i errores.", errors);
	}
	return (errors > 0 ? -1 : 1);
}


OperFlag *config_binary_flags_search(OperFlag *table, char *cmd, int size) {
	int start = 0;
	int stop = size-1;
	int mid;
	while (start <= stop) {
		mid = (start+stop)/2;

		if (smycmp(cmd,table[mid].name) < 0) {
			stop = mid-1;
		}
		else if (strcmp(cmd,table[mid].name) == 0) {
			return &(table[mid]);
		}
		else
			start = mid+1;
	}
	return NULL;
}


int	config_test()
{
	ConfigEntry 	*ce;
	ConfigFile	*cfptr;
	ConfigCommand	*cc;
	int		errors = 0;
	Hook *h;

	for (cfptr = conf; cfptr; cfptr = cfptr->cf_next)
	{
		if (config_verbose > 1)
			config_status("Probando %s", cfptr->cf_filename);
		for (ce = cfptr->cf_entries; ce; ce = ce->ce_next)
		{
			if (!ce->ce_varname)
			{
				config_error("%s:%i: %s:%i: null ce->ce_varname",
					ce->ce_fileptr->cf_filename, ce->ce_varlinenum,
					__FILE__, __LINE__);
				return -1;
			}
			if ((cc = config_binary_search(ce->ce_varname))) {
				if (cc->testfunc)
					errors += (cc->testfunc(cfptr, ce));
			}
			else 
			{
				int used = 0;
				for (h = Hooks[HOOKTYPE_CONFIGTEST]; h; h = h->next) 
				{
					int value, errs = 0;
					if (h->owner && !(h->owner->flags & MODFLAG_TESTING)
					    && !(h->owner->options & MOD_OPT_PERM))


						continue;
					value = (*(h->func.intfunc))(cfptr,ce,CONFIG_MAIN,&errs);
					if (value == 2)
						used = 1;
					if (value == 1)
					{
						used = 1;
						break;
					}
					if (value == -1)
					{
						used = 1;
						errors += errs;
						break;
					}
					if (value == -2) 
					{
						used = 1;
						errors += errs;
					}
						
				}
				if (!used)
					config_status("%s:%i: directriz desconocida %s", 
						ce->ce_fileptr->cf_filename, ce->ce_varlinenum,
						ce->ce_varname);
			}
		}
	}
	errors += config_post_test();
	if (errors > 0)
	{
		config_error("%i errores", errors);
	}
	return (errors > 0 ? -1 : 1);
}

/*
 * Service functions
*/

ConfigItem_deny_dcc	*Find_deny_dcc(char *name)
{
	ConfigItem_deny_dcc	*p;

	if (!name)
		return NULL;

	for (p = conf_deny_dcc; p; p = (ConfigItem_deny_dcc *) p->next)
	{
		if (!match(name, p->filename))
			return (p);
	}
	return NULL;
}

ConfigItem_alias *Find_alias(char *name) {
	ConfigItem_alias *alias;

	if (!name)
		return NULL;

	for (alias = conf_alias; alias; alias = (ConfigItem_alias *)alias->next) {
		if (!stricmp(alias->alias, name))
			return alias;
	}
	return NULL;
}

ConfigItem_class	*Find_class(char *name)
{
	ConfigItem_class	*p;

	if (!name)
		return NULL;

	for (p = conf_class; p; p = (ConfigItem_class *) p->next)
	{
		if (!strcmp(name, p->name))
			return (p);
	}
	return NULL;
}

ConfigItem_oper	*Find_oper(char *name)
{
	ConfigItem_oper	*p;

	if (!name)
		return NULL;

	for (p = conf_oper; p; p = (ConfigItem_oper *) p->next)
	{
		if (!strcmp(name, p->name))
			return (p);
	}
	return NULL;
}

int count_oper_sessions(char *name)
{
int i, count = 0;
aClient *cptr;

#ifdef NO_FDLIST
	for (i = 0; i <= LastSlot; i++)
#else
int j;
	for (i = oper_fdlist.entry[j = 1]; j <= oper_fdlist.last_entry; i = oper_fdlist.entry[++j])
#endif
		if ((cptr = local[i]) && IsPerson(cptr) && IsAnOper(cptr) &&
		    cptr->user && cptr->user->operlogin && !strcmp(cptr->user->operlogin,name))
			count++;

	return count;
}

ConfigItem_listen	*Find_listen(char *ipmask, int port)
{
	ConfigItem_listen	*p;

	if (!ipmask)
		return NULL;

	for (p = conf_listen; p; p = (ConfigItem_listen *) p->next)
	{
		if (!match(p->ip, ipmask) && (port == p->port))
			return (p);
		if (!match(ipmask, p->ip) && (port == p->port))
			return (p);
	}
	return NULL;
}

ConfigItem_ulines *Find_uline(char *host) {
	ConfigItem_ulines *ulines;

	if (!host)
		return NULL;

	for(ulines = conf_ulines; ulines; ulines =(ConfigItem_ulines *) ulines->next) {
		if (!stricmp(host, ulines->servername))
			return ulines;
	}
	return NULL;
}


ConfigItem_except *Find_except(aClient *sptr, char *host, short type) {
	ConfigItem_except *excepts;

	if (!host)
		return NULL;

	for(excepts = conf_except; excepts; excepts =(ConfigItem_except *) excepts->next) {
		if (excepts->flag.type == type)
		{
			if (match_ip(sptr->ip, host, excepts->mask, excepts->netmask))
				return excepts;
		}
	}
	return NULL;
}

ConfigItem_tld *Find_tld(aClient *cptr, char *uhost) {
	ConfigItem_tld *tld;

	if (!uhost || !cptr)
		return NULL;

	for(tld = conf_tld; tld; tld = (ConfigItem_tld *) tld->next)
	{
		if (!match(tld->mask, uhost))
		{
			if ((tld->options & TLD_SSL) && !IsSecure(cptr))
				continue;
			if ((tld->options & TLD_REMOTE) && MyClient(cptr))
				continue;
			return tld;
		}
	}
	return NULL;
}


ConfigItem_link *Find_link(char *username,
			   char *hostname,
			   char *ip,
			   char *servername)
{
	ConfigItem_link	*link;

	if (!username || !hostname || !servername || !ip)
		return NULL;

	for(link = conf_link; link; link = (ConfigItem_link *) link->next)
	{
		if (!match(link->servername, servername) &&
		    !match(link->username, username) &&
		    (!match(link->hostname, hostname) || !match(link->hostname, ip)))
			return link;
	}
	return NULL;

}

ConfigItem_ban 	*Find_ban(aClient *sptr, char *host, short type)
{
	ConfigItem_ban *ban;

	/* Check for an except ONLY if we find a ban, makes it
	 * faster since most users will not have a ban so excepts
	 * don't need to be searched -- codemastr
	 */

	for (ban = conf_ban; ban; ban = (ConfigItem_ban *) ban->next)
	{
		if (ban->flag.type == type)
		{
			if (sptr)
			{
				if (match_ip(sptr->ip, host, ban->mask, ban->netmask))
				{
					/* Person got a exception */
					if ((type == CONF_BAN_USER || type == CONF_BAN_IP)
					    && Find_except(sptr, host, CONF_EXCEPT_BAN))
						return NULL;
					return ban;
				}
			}
			else if (!match(ban->mask, host)) /* We don't worry about exceptions */
				return ban;
		}
	}
	return NULL;
}

ConfigItem_ban 	*Find_banEx(aClient *sptr, char *host, short type, short type2)
{
	ConfigItem_ban *ban;

	/* Check for an except ONLY if we find a ban, makes it
	 * faster since most users will not have a ban so excepts
	 * don't need to be searched -- codemastr
	 */

	for (ban = conf_ban; ban; ban = (ConfigItem_ban *) ban->next)
	{
		if ((ban->flag.type == type) && (ban->flag.type2 == type2))
		{
			if (sptr)
			{
				if (match_ip(sptr->ip, host, ban->mask, ban->netmask)) {
					/* Person got a exception */
					if (Find_except(sptr, host, type))
						return NULL;
					return ban;
				}
			}
			else if (!match(ban->mask, host)) /* We don't worry about exceptions */
				return ban;
		}
	}
	return NULL;
}

int	AllowClient(aClient *cptr, struct hostent *hp, char *sockhost, char *username)
{
	ConfigItem_allow *aconf;
#ifdef UDB
	udb *reg, *ireg;
	int defmaxclons;
	aClient *aux;
#endif		
	char *hname;
	int  i, ii = 0;
	static char uhost[HOSTLEN + USERLEN + 3];
	static char fullname[HOSTLEN + 1];

	for (aconf = conf_allow; aconf; aconf = (ConfigItem_allow *) aconf->next)
	{
		if (!aconf->hostname || !aconf->ip)
			goto attach;
		if (aconf->auth && !cptr->passwd && aconf->flags.nopasscont)
			continue;
		if (aconf->flags.ssl && !IsSecure(cptr))
			continue;
		if (hp)
			for (i = 0, hname = hp->h_name; hname;
			    hname = hp->h_aliases[i++])
			{
				strncpyzt(fullname, hname,
				    sizeof(fullname));
				add_local_domain(fullname,
				    HOSTLEN - strlen(fullname));
				Debug((DEBUG_DNS, "a_il: %s->%s",
				    sockhost, fullname));
				if (index(aconf->hostname, '@'))
				{
					/*
					 * Doing strlcpy / strlcat here
					 * would simply be a waste. We are
					 * ALREADY sure that it is proper 
					 * lengths
					*/
					if (aconf->flags.noident)
						strcpy(uhost, username);
					else
						(void)strcpy(uhost, cptr->username);
					(void)strcat(uhost, "@");
				}
				else
					*uhost = '\0';
				/* 
				 * Same here as above
				 * -Stskeeps 
				*/
				(void)strncat(uhost, fullname,
				    sizeof(uhost) - strlen(uhost));
				if (!match(aconf->hostname, uhost))
					goto attach;
			}

		if (index(aconf->ip, '@'))
		{
			if (aconf->flags.noident)
				strncpyzt(uhost, username, sizeof(uhost));
			else
				strncpyzt(uhost, cptr->username, sizeof(uhost));
			(void)strcat(uhost, "@");
		}
		else
			*uhost = '\0';
		(void)strncat(uhost, sockhost, sizeof(uhost) - strlen(uhost));
		/* Check the IP */
		if (match_ip(cptr->ip, uhost, aconf->ip, aconf->netmask))
			goto attach;

		/* Hmm, localhost is a special case, hp == NULL and sockhost contains
		 * 'localhost' instead of an ip... -- Syzop. */
		if (!strcmp(sockhost, "localhost"))
		{
			if (index(aconf->hostname, '@'))
			{
				if (aconf->flags.noident)
					strcpy(uhost, username);
				else
					strcpy(uhost, cptr->username);
				strcat(uhost, "@localhost");
			}
			else
				strcpy(uhost, "localhost");

			if (!match(aconf->hostname, uhost))
				goto attach;
		}
		
		continue;
	      attach:
/*		if (index(uhost, '@'))  now flag based -- codemastr */
		if (!aconf->flags.noident)
			cptr->flags |= FLAGS_DOID;
		if (!aconf->flags.useip && hp) 
			strncpyzt(uhost, fullname, sizeof(uhost));
		else
			strncpyzt(uhost, sockhost, sizeof(uhost));
		get_sockhost(cptr, uhost);
		/* FIXME */
#ifndef UDB
		if (aconf->maxperip)
		{
#endif
#ifdef UDB
			if (!(ireg = busca_registro(BDD_ILINES, ".")))
				defmaxclons = aconf->maxperip;
			else
				defmaxclons = atoi(ireg->value);
			if (!(reg = busca_registro(BDD_ILINES, cptr->sockhost))) { }
			else
				defmaxclons = atoi(reg->value);
#endif		
			ii = 1;
#ifdef UDB
			for (aux = client; aux; aux = aux->next)
				if (IsClient(aux) &&
#ifndef INET6
				    !strcmp(aux->user->realhost, cptr->sockhost))
#else
				    !bcmp(aux->ip.S_ADDR, cptr->ip.S_ADDR, sizeof(cptr->ip.S_ADDR)))
#endif
#else
			for (i = LastSlot; i >= 0; i--)
				if (local[i] && MyClient(local[i]) &&
#ifndef INET6
				    local[i]->ip.S_ADDR == cptr->ip.S_ADDR)
#else
				    !bcmp(local[i]->ip.S_ADDR, cptr->ip.S_ADDR, sizeof(cptr->ip.S_ADDR)))
#endif
#endif /* UDB */
				{
					ii++;
#ifdef UDB
					if (ii > defmaxclons)
					{
						if (!(ireg = busca_registro(BDD_ILINES, reg && reg->value[0] ? "..." : "..")))
							exit_client(cptr, cptr, &me, "Demasiadas conexiones para tu IP");
						else
							exit_client(cptr, cptr, &me, ireg->value);
						return -5;
					}	
#else										
					if (ii > aconf->maxperip)		
					{
						exit_client(cptr, cptr, &me,
							"Demasiadas conexiones desde tu ip.");
						return -5;	/* Already got one with that ip# */
					}
#endif					
				}
#ifndef UDB
		}
#endif		
		if ((i = Auth_Check(cptr, aconf->auth, cptr->passwd)) == -1)
		{
			exit_client(cptr, cptr, &me,
				"Contrase�a incorrecta");
			return -5;
		}
		if ((i == 2) && (cptr->passwd))
		{
			MyFree(cptr->passwd);
			cptr->passwd = NULL;
		}
		if (!((aconf->class->clients + 1) > aconf->class->maxclients))
		{
			cptr->class = aconf->class;
			cptr->class->clients++;
		}
		else
		{
			sendto_one(cptr, rpl_str(RPL_REDIR), me.name, cptr->name, aconf->server ? aconf->server : defserv, aconf->port ? aconf->port : 6667);
			return -3;
		}
		return 0;
	}
	return -1;
}

ConfigItem_vhost *Find_vhost(char *name) {
	ConfigItem_vhost *vhost;

	for (vhost = conf_vhost; vhost; vhost = (ConfigItem_vhost *)vhost->next) {
		if (!strcmp(name, vhost->login))
			return vhost;
	}
	return NULL;
}


/** returns NULL if allowed and struct if denied */
ConfigItem_deny_channel *Find_channel_allowed(char *name)
{
	ConfigItem_deny_channel *dchannel;
	ConfigItem_allow_channel *achannel;

	for (dchannel = conf_deny_channel; dchannel; dchannel = (ConfigItem_deny_channel *)dchannel->next)
	{
		if (!match(dchannel->channel, name))
			break;
	}
	if (dchannel)
	{
		for (achannel = conf_allow_channel; achannel; achannel = (ConfigItem_allow_channel *)achannel->next)
		{
			if (!match(achannel->channel, name))
				break;
		}
		if (achannel)
			return NULL;
		else
			return (dchannel);
	}
	return NULL;
}

void init_dynconf(void)
{
	bzero(&iConf, sizeof(iConf));
	bzero(&tempiConf, sizeof(iConf));
}

char *pretty_time_val(long timeval)
{
	static char buf[512];

	if (timeval == 0)
		return "0";

	buf[0] = 0;

	if (timeval/86400)
		sprintf(buf, "%ld d�a%s ", timeval/86400, timeval/86400 != 1 ? "s" : "");
	if ((timeval/3600) % 24)
		sprintf(buf, "%s%ld hora%s ", buf, (timeval/3600)%24, (timeval/3600)%24 != 1 ? "s" : "");
	if ((timeval/60)%60)
		sprintf(buf, "%s%ld minuto%s ", buf, (timeval/60)%60, (timeval/60)%60 != 1 ? "s" : "");
	if ((timeval%60))
		sprintf(buf, "%s%ld segundo%s", buf, timeval%60, timeval%60 != 1 ? "s" : "");
	return buf;
}

/*
 * Actual config parser funcs
*/

int	_conf_include(ConfigFile *conf, ConfigEntry *ce)
{
	int	ret = 0;
#ifdef GLOBH
	glob_t files;
	int i;
#elif defined(_WIN32)
	HANDLE hFind;
	WIN32_FIND_DATA FindData;
	char cPath[MAX_PATH], *cSlash = NULL, *path;
#endif
	if (!ce->ce_vardata)
	{
		config_status("%s:%i: include: falta archivo",
			ce->ce_fileptr->cf_filename,
			ce->ce_varlinenum);
		return -1;
	}
#ifdef USE_LIBCURL
	if (url_is_valid(ce->ce_vardata))
		return remote_include(ce);
#endif
#if !defined(_WIN32) && !defined(_AMIGA) && DEFAULT_PERMISSIONS != 0
	chmod(ce->ce_vardata, DEFAULT_PERMISSIONS);
#endif
#ifdef GLOBH
#if defined(__OpenBSD__) && defined(GLOB_LIMIT)
	glob(ce->ce_vardata, GLOB_NOSORT|GLOB_NOCHECK|GLOB_LIMIT, NULL, &files);
#else
	glob(ce->ce_vardata, GLOB_NOSORT|GLOB_NOCHECK, NULL, &files);
#endif
	if (!files.gl_pathc) {
		globfree(&files);
		config_status("%s:%i: include %s: archivo inv�lido",
			ce->ce_fileptr->cf_filename, ce->ce_varlinenum,
			ce->ce_vardata);
		return -1;
	}	
	for (i = 0; i < files.gl_pathc; i++) {
		ret = load_conf(files.gl_pathv[i]);
		if (ret < 0)
		{
			globfree(&files);
			return ret;
		}
		add_include(files.gl_pathv[i]);
	}
	globfree(&files);
#elif defined(_WIN32)
	bzero(cPath,MAX_PATH);
	if (strchr(ce->ce_vardata, '/') || strchr(ce->ce_vardata, '\\')) {
		strncpyzt(cPath,ce->ce_vardata,MAX_PATH);
		cSlash=cPath+strlen(cPath);
		while(*cSlash != '\\' && *cSlash != '/' && cSlash > cPath)
			cSlash--; 
		*(cSlash+1)=0;
	}
	if ( (hFind = FindFirstFile(ce->ce_vardata, &FindData)) == INVALID_HANDLE_VALUE )
	{
		config_status("%s:%i: include %s: archivo inv�lido",
			ce->ce_fileptr->cf_filename, ce->ce_varlinenum,
			ce->ce_vardata);
		return -1;
	}
	if (cPath) {
		path = MyMalloc(strlen(cPath) + strlen(FindData.cFileName)+1);
		strcpy(path,cPath);
		strcat(path,FindData.cFileName);
		ret = load_conf(path);
		if (ret >= 0)
			add_include(path);
		free(path);

	}
	else
	{
		ret = load_conf(FindData.cFileName);
		if (ret >= 0)
			add_include(FindData.cFileName);
	}
	if (ret < 0)
	{
		FindClose(hFind);
		return ret;
	}

	ret = 0;
	while (FindNextFile(hFind, &FindData) != 0) {
		if (cPath) {
			path = MyMalloc(strlen(cPath) + strlen(FindData.cFileName)+1);
			strcpy(path,cPath);
			strcat(path,FindData.cFileName);
			ret = load_conf(path);
			if (ret >= 0)
			{
				add_include(path);
				free(path);
			}
			else
			{
				free(path);
				break;
			}
		}
		else
		{
			ret = load_conf(FindData.cFileName);
			if (ret >= 0)
				add_include(FindData.cFileName);
		}
	}
	FindClose(hFind);
	if (ret < 0)
		return ret;
#else
	ret = load_conf(ce->ce_vardata);
	if (ret >= 0)
		add_include(ce->ce_vardata);
	return ret;
#endif
	return 1;
}

int	_test_include(ConfigFile *conf, ConfigEntry *ce)
{
	return 0;
}

int	_conf_admin(ConfigFile *conf, ConfigEntry *ce)
{
	ConfigEntry *cep;
	ConfigItem_admin *ca;

	for (cep = ce->ce_entries; cep; cep = cep->ce_next)
	{
		ca = MyMallocEx(sizeof(ConfigItem_admin));
		if (!conf_admin)
			conf_admin_tail = ca;
		ircstrdup(ca->line, cep->ce_varname);
		AddListItem(ca, conf_admin);
	}
	return 1;
}

int	_test_admin(ConfigFile *conf, ConfigEntry *ce)
{
	ConfigEntry *cep;
	int 	    errors = 0;
	for (cep = ce->ce_entries; cep; cep = cep->ce_next)
	{
		if (!cep->ce_varname)
		{
			config_error("%s:%i: �tem vac�o",
				cep->ce_fileptr->cf_filename,
				cep->ce_varlinenum);
			errors++;
			continue;
		}
	}
	requiredstuff.conf_admin = 1;
	return errors;
}

int	_conf_me(ConfigFile *conf, ConfigEntry *ce)
{
	ConfigEntry *cep;

	if (!conf_me)
	{
		conf_me = MyMallocEx(sizeof(ConfigItem_me));
	}
	cep = config_find_entry(ce->ce_entries, "name");
	ircfree(conf_me->name);
	ircstrdup(conf_me->name, cep->ce_vardata);
	cep = config_find_entry(ce->ce_entries, "info");
	ircfree(conf_me->info);
	ircstrdup(conf_me->info, cep->ce_vardata);
	cep = config_find_entry(ce->ce_entries, "numeric");
	conf_me->numeric = atol(cep->ce_vardata);
	return 1;
}

int	_test_me(ConfigFile *conf, ConfigEntry *ce)
{
	ConfigEntry *cep;
	long	    l;
	int	    errors = 0;
	
	if (!(cep = config_find_entry(ce->ce_entries, "name")))
	{
		config_error("%s:%i: me::name missing",
			ce->ce_fileptr->cf_filename, ce->ce_varlinenum);
		errors++;
	}
	else
	{
		if (cep->ce_vardata)
		{
			char *p;
			if (!strchr(cep->ce_vardata, '.'))
			{	
				config_error("%s:%i: illegal me::especifica el host entero",
					cep->ce_fileptr->cf_filename, cep->ce_varlinenum);
				errors++;
			}
			if (!valid_host(cep->ce_vardata))
			{
				config_error("%s:%i: illegal me::name contiene caracteres inv�lidos, s�lo a-z, 0-9, _, -, .",
					cep->ce_fileptr->cf_filename, cep->ce_varlinenum);
				errors++;
			}
		}
	}
	if (!(cep = config_find_entry(ce->ce_entries, "info")))
	{
		config_error("%s:%i: me::info falta",
			ce->ce_fileptr->cf_filename, ce->ce_varlinenum);
		errors++;
	}
	else
	{

		if (cep->ce_vardata)
		{
			int valid = 0;
			char *p;
			if (strlen(cep->ce_vardata) > (REALLEN-1))
			{
				config_error("%s:%i: muy largo::info, m�ximo. %i caracteres",
					ce->ce_fileptr->cf_filename, ce->ce_varlinenum, REALLEN-1);
				errors++;
		
			}
			/* Valid me::info? Any data except spaces is ok */
			for (p=cep->ce_vardata; *p; p++)
				if (*p != ' ')
				{
					valid = 1;
					break;
				}
			if (!valid)
			{
				config_error("%s:%i: me::info est� vac�o, deber�a contener la descripci�n del servidor.",
					ce->ce_fileptr->cf_filename, ce->ce_varlinenum);
				errors++;
			}
		}
	}
	if (!(cep = config_find_entry(ce->ce_entries, "numeric")))
	{
		config_error("%s:%i: me::numeric falta",
			ce->ce_fileptr->cf_filename, ce->ce_varlinenum);
		errors++;
	}
	else
	{
		if (cep->ce_vardata)
		{
			l = atol(cep->ce_vardata);
			if ((l < 0) || (l > 254))
			{
				config_error("%s:%i: ilegal me::numeric error (entre 0-254)",
					cep->ce_fileptr->cf_filename,
					cep->ce_varlinenum);
				errors++;
			}
		}
	}
	for (cep = ce->ce_entries; cep; cep = cep->ce_next)
	{
		if (!cep->ce_varname)
		{
			config_error("%s:%i: l�nea en blanco",
				cep->ce_fileptr->cf_filename,
				cep->ce_varlinenum);
			errors++;
			continue;
		}
		if (!cep->ce_vardata)
		{
			config_error("%s:%i: me::%s sin par�metro",
				cep->ce_fileptr->cf_filename,
				cep->ce_varlinenum,
				cep->ce_varname);
			errors++;
			continue;
		}
		if (!strcmp(cep->ce_varname, "name"))
		{} else
		if (!strcmp(cep->ce_varname, "info"))
		{} else
		if (!strcmp(cep->ce_varname, "numeric"))
		{}
		else
		{
			config_error("%s:%i: directriz desconocida me::%s",
				cep->ce_fileptr->cf_filename,
				cep->ce_varlinenum,
				cep->ce_varname);
			errors++; continue;
		}
	}
	requiredstuff.conf_me = 1;
	return errors;
}

/*
 * The oper {} block parser
*/

int	_conf_oper(ConfigFile *conf, ConfigEntry *ce)
{
	ConfigEntry *cep;
	ConfigEntry *cepp;
	ConfigItem_oper *oper = NULL;
	ConfigItem_oper_from *from;
	OperFlag *ofp = NULL;
	unsigned char	isnew = 0;

	if (!ce->ce_vardata)
	{
		config_status("%s:%i: oper sin nombre",
			ce->ce_fileptr->cf_filename, ce->ce_varlinenum);
		return -1;
	}

	if (!(oper = Find_oper(ce->ce_vardata)))
	{
		oper =  MyMallocEx(sizeof(ConfigItem_oper));
		oper->name = strdup(ce->ce_vardata);
		isnew = 1;
	}
	else
	{
		isnew = 0;
	}
	
	cep = config_find_entry(ce->ce_entries, "password");
	oper->auth = Auth_ConvertConf2AuthStruct(cep);
	cep = config_find_entry(ce->ce_entries, "class");
	oper->class = Find_class(cep->ce_vardata);
	if (!oper->class)
	{
		config_status("%s:%i: illegal oper::class, clase '%s' desconocida. Se usar� la clase 'default'",
				cep->ce_fileptr->cf_filename,
				cep->ce_varlinenum,
				cep->ce_vardata);
		oper->class = default_class;
	}
	
	cep = config_find_entry(ce->ce_entries, "flags");
	if (!cep->ce_entries)
	{
		char *m = "*";
		int *i, flag;

		for (m = (*cep->ce_vardata) ? cep->ce_vardata : m; *m; m++) {
			for (i = _OldOperFlags; (flag = *i); i += 2)
				if (*m == (char)(*(i + 1))) {
					oper->oflags |= flag;
					break;
				}
		}
	}
	else
	{
		for (cepp = cep->ce_entries; cepp; cepp = cepp->ce_next)
		{
			if ((ofp = config_binary_flags_search(_OperFlags, cepp->ce_varname, sizeof(_OperFlags)/sizeof(_OperFlags[0])))) 
				oper->oflags |= ofp->flag;
		}
	}
	if ((cep = config_find_entry(ce->ce_entries, "swhois")))
	{
		ircstrdup(oper->swhois, cep->ce_vardata);
	}
	if ((cep = config_find_entry(ce->ce_entries, "snomask")))
	{
		ircstrdup(oper->snomask, cep->ce_vardata);
	}
	if ((cep = config_find_entry(ce->ce_entries, "modes")))
	{
		oper->modes = set_usermode(cep->ce_vardata);
	}
	if ((cep = config_find_entry(ce->ce_entries, "maxlogins")))
	{
		oper->maxlogins = (int)config_checkval(cep->ce_vardata, CFG_TIME);
	}
	cep = config_find_entry(ce->ce_entries, "from");
	for (cepp = cep->ce_entries; cepp; cepp = cepp->ce_next)
	{
		if (!strcmp(cepp->ce_varname, "userhost"))
		{
			from = MyMallocEx(sizeof(ConfigItem_oper_from));
			ircstrdup(from->name, cepp->ce_vardata);
			AddListItem(from, oper->from);
		}
	}
	if (isnew)
		AddListItem(oper, conf_oper);
	return 1;
}

int	_test_oper(ConfigFile *conf, ConfigEntry *ce)
{
	ConfigEntry *cep;
	ConfigEntry *cepp;
	int	errors = 0;
	if (!ce->ce_vardata)
	{
		config_error("%s:%i: oper sin nombre",
			ce->ce_fileptr->cf_filename, ce->ce_varlinenum);
		errors++;
	}
	for (cep = ce->ce_entries; cep; cep = cep->ce_next)
	{
		if (!cep->ce_varname)
		{
			config_error("%s:%i: oper item sin nombre de variable",
				cep->ce_fileptr->cf_filename, cep->ce_varlinenum);
			errors++; continue;
		}
		if (!strcmp(cep->ce_varname, "password"))
		{
			if (Auth_CheckError(cep) < 0)
				errors++;
			/* should have some auth check if ok .. */
			continue;
		}
		if (!cep->ce_entries)
		{
			/* standard variable */
			if (!cep->ce_vardata)
			{
				config_error("%s:%i: oper::%s sin par�metro",
					cep->ce_fileptr->cf_filename,
					cep->ce_varlinenum,
					cep->ce_varname);
				errors++; continue;
			}
			if (!strcmp(cep->ce_varname, "class"))
			{
			}
			else if (!strcmp(cep->ce_varname, "swhois")) {
			}
			else if (!strcmp(cep->ce_varname, "snomask")) {
			}
			else if (!strcmp(cep->ce_varname, "modes")) {
			}
			else if (!strcmp(cep->ce_varname, "maxlogins"))
			{
				long l = config_checkval(cep->ce_vardata, CFG_TIME);
				if ((l < 0) || (l > 5000))
				{
					config_error("%s:%i: oper::maxlogins: valor (%ld) entre 0-5000",
						cep->ce_fileptr->cf_filename, cep->ce_varlinenum, l);
					errors++; continue;
				}
			}
			else if (!strcmp(cep->ce_varname, "flags"))
			{
			}
			else
			{
				config_error("%s:%i: directriz desconocida oper::%s",
					cep->ce_fileptr->cf_filename, cep->ce_varlinenum,
						cep->ce_varname);
				errors++; continue;
			}
		}
		else
		{
			/* Section */
			if (!strcmp(cep->ce_varname, "flags"))
			{
				for (cepp = cep->ce_entries; cepp; cepp = cepp->ce_next)
				{
					if (!cepp->ce_varname)
					{
						config_error("%s:%i: oper::flags item sin nombre de variable",
							cepp->ce_fileptr->cf_filename, cepp->ce_varlinenum);
						errors++; 
						continue;
					}
					if (!config_binary_flags_search(_OperFlags, cepp->ce_varname, sizeof(_OperFlags)/sizeof(_OperFlags[0]))) {
						if (!strcmp(cepp->ce_varname, "can_stealth"))
						{
						 config_status("%s:%i: modo oper obsoleto '%s'",
							cepp->ce_fileptr->cf_filename, cepp->ce_varlinenum,
							cepp->ce_varname);
						} else {
						 config_error("%s:%i: modo oper desconocido '%s'",
							cepp->ce_fileptr->cf_filename, cepp->ce_varlinenum,
							cepp->ce_varname);
						errors++; 
						}
					}
				}
				continue;
			}
			else
			if (!strcmp(cep->ce_varname, "from"))
			{
				for (cepp = cep->ce_entries; cepp; cepp = cepp->ce_next)
				{
					if (!cepp->ce_varname)
					{
						config_error("%s:%i: oper::from item sin nombre de variable",
							cepp->ce_fileptr->cf_filename, cepp->ce_varlinenum);
						errors++; continue;
					}
					if (!cepp->ce_vardata)
					{
						config_error("%s:%i: oper::from::%s sin par�metros",
							cepp->ce_fileptr->cf_filename,
							cepp->ce_varlinenum,
							cepp->ce_varname);
						errors++; continue;
					}
					if (!strcmp(cepp->ce_varname, "userhost"))
					{
					}
					else
					{
						config_error("%s:%i: directriz desconocida ::from::%s",
							cepp->ce_fileptr->cf_filename, cepp->ce_varlinenum,
							cepp->ce_varname);
						errors++; continue;
					}
				}
				continue;
			}
			else
			{
				config_error("%s:%i: directriz desconocida oper::%s (secci�n)",
					cep->ce_fileptr->cf_filename, cep->ce_varlinenum,
						cep->ce_varname);
				errors++; continue;
			}
		}

	}
	if (!config_find_entry(ce->ce_entries, "password"))
	{
		config_error("%s:%i: oper::password falta", ce->ce_fileptr->cf_filename,
			ce->ce_varlinenum);
		errors++;
	}	
	if (!config_find_entry(ce->ce_entries, "from"))
	{
		config_error("%s:%i: oper::from falta", ce->ce_fileptr->cf_filename,
			ce->ce_varlinenum);
		errors++;
	}	
	if (!config_find_entry(ce->ce_entries, "flags"))
	{
		config_error("%s:%i: oper::flags falta", ce->ce_fileptr->cf_filename,
			ce->ce_varlinenum);
		errors++;
	}	
	if (!config_find_entry(ce->ce_entries, "class"))
	{
		config_error("%s:%i: oper::class falta", ce->ce_fileptr->cf_filename,
			ce->ce_varlinenum);
		errors++;
	}	
	return errors;
	
}

/*
 * The class {} block parser
*/
int	_conf_class(ConfigFile *conf, ConfigEntry *ce)
{
	ConfigEntry *cep;
	ConfigItem_class *class;
	unsigned char isnew = 0;

	if (!(class = Find_class(ce->ce_vardata)))
	{
		class = MyMallocEx(sizeof(ConfigItem_class));
		ircstrdup(class->name, ce->ce_vardata);
		isnew = 1;
	}
	else
	{
		isnew = 0;
		class->flag.temporary = 0; /* clear!!! damnit */
	}
	cep = config_find_entry(ce->ce_entries, "pingfreq");
	class->pingfreq = atol(cep->ce_vardata);
	cep = config_find_entry(ce->ce_entries, "maxclients");
	class->maxclients = atol(cep->ce_vardata);
	cep = config_find_entry(ce->ce_entries, "sendq");
	class->sendq = atol(cep->ce_vardata);
	if ((cep = config_find_entry(ce->ce_entries, "recvq")))
	{
		class->recvq = atol(cep->ce_vardata);
	}
	if ((cep = config_find_entry(ce->ce_entries, "connfreq")))
	{
		class->connfreq = atol(cep->ce_vardata);
	}
	if (isnew) 
		AddListItem(class, conf_class);
	return 1;
}

int	_test_class(ConfigFile *conf, ConfigEntry *ce)
{
	ConfigEntry 	*cep;
	long		l;
	int		errors = 0;
	if (!ce->ce_vardata)
	{
		config_error("%s:%i: clase sin nombre",
			ce->ce_fileptr->cf_filename, ce->ce_varlinenum);
		errors++; 
	}
	for (cep = ce->ce_entries; cep; cep = cep->ce_next)
	{
		if (!cep->ce_varname)
		{
			config_error("%s:%i: clase sin nombre de variable",
				cep->ce_fileptr->cf_filename, cep->ce_varlinenum);
			errors++; continue;
		}
		if (!cep->ce_vardata)
		{
			config_error("%s:%i: class item sin par�metro",
				cep->ce_fileptr->cf_filename, cep->ce_varlinenum);
			errors++; continue;
		}
		if (!strcmp(cep->ce_varname, "pingfreq"))
		{
			int v = atol(cep->ce_vardata);
			if ((v < 30) || (v > 600))
			{
				config_error("%s:%i: class::pingfreq tiene que ser un valor razonable (30-600)",
					cep->ce_fileptr->cf_filename, cep->ce_varlinenum);
				errors++; continue;
			}
		} else
		if (!strcmp(cep->ce_varname, "maxclients"))
		{} else
		if (!strcmp(cep->ce_varname, "connfreq"))
		{} else
		if (!strcmp(cep->ce_varname, "sendq"))
		{} else
		if (!strcmp(cep->ce_varname, "recvq"))
		{}
		else
		{
			config_error("%s:%i: directriz desconocida class::%s",
				cep->ce_fileptr->cf_filename, cep->ce_varlinenum,
					cep->ce_varname);
			errors++; continue;
		}
	}
	if ((cep = config_find_entry(ce->ce_entries, "pingfreq")))
	{
		if (cep->ce_vardata)
		{
			l = atol(cep->ce_vardata);
			if ((l < 1) || (l > 1000000))
			{
				config_error("%s:%i: class::pingfreq con valor err�neo",
					cep->ce_fileptr->cf_filename, cep->ce_varlinenum);
				errors++;
			}
		}
	}
	else
	{
		config_error("%s:%i: class::pingfreq falta",
			ce->ce_fileptr->cf_filename, ce->ce_varlinenum);
		errors++;
	}
	if ((cep = config_find_entry(ce->ce_entries, "maxclients")))
	{
		if (cep->ce_vardata)
		{
			l = atol(cep->ce_vardata);
			if ((l < 1) || (l > 1000000))
			{
				config_error("%s:%i: class::maxclients con valor err�neo",
					cep->ce_fileptr->cf_filename, cep->ce_varlinenum);
				errors++;
			}
		}
	}
	else
	{
		config_error("%s:%i: class::maxclients falta",
			ce->ce_fileptr->cf_filename, ce->ce_varlinenum);
		errors++;
	}
	if ((cep = config_find_entry(ce->ce_entries, "sendq")))
	{
		if (cep->ce_vardata)
		{	
			l = atol(cep->ce_vardata);
			if ((l < 0) || (l > 2000000000))
			{
				config_error("%s:%i: class::sendq con valor err�neo",
					cep->ce_fileptr->cf_filename, cep->ce_varlinenum);
				errors++;
			}
		}
	}
	else
	{
		config_error("%s:%i: class::sendq falta",
			ce->ce_fileptr->cf_filename, ce->ce_varlinenum);
		errors++;
	}
	if ((cep = config_find_entry(ce->ce_entries, "connfreq")))
	{
		if (cep->ce_vardata)
		{
			l = atol(cep->ce_vardata);
			if ((l < 10) || (l > 604800))
			{
				config_error("%s:%i: class::connfreq con valor err�neo (<10)",
					cep->ce_fileptr->cf_filename, cep->ce_varlinenum);
				errors++;
			}
		}
	}
	if ((cep = config_find_entry(ce->ce_entries, "recvq")))
	{
		if (cep->ce_vardata)
		{	
			l = atol(cep->ce_vardata);
			if ((l < 512) || (l > 32768))
			{
				config_error("%s:%i: class::recvq con valor err�neo (<512)",
					cep->ce_fileptr->cf_filename, cep->ce_varlinenum);
				errors++;
			}
		}
	}
	
	return errors;
}

int     _conf_drpass(ConfigFile *conf, ConfigEntry *ce)
{
	ConfigEntry *cep;

	if (!conf_drpass) {
		conf_drpass =  MyMallocEx(sizeof(ConfigItem_drpass));
	}

	for (cep = ce->ce_entries; cep; cep = cep->ce_next)
	{
		if (!strcmp(cep->ce_varname, "restart"))
		{
			if (conf_drpass->restartauth)
				Auth_DeleteAuthStruct(conf_drpass->restartauth);
			
			conf_drpass->restartauth = Auth_ConvertConf2AuthStruct(cep);
		}
		else if (!strcmp(cep->ce_varname, "die"))
		{
			if (conf_drpass->dieauth)
				Auth_DeleteAuthStruct(conf_drpass->dieauth);
			
			conf_drpass->dieauth = Auth_ConvertConf2AuthStruct(cep);
		}
	}
	return 1;
}

int     _test_drpass(ConfigFile *conf, ConfigEntry *ce)
{
	ConfigEntry *cep;
	int errors = 0;
	for (cep = ce->ce_entries; cep; cep = cep->ce_next)
	{
		if (!cep->ce_varname)
		{
			config_error("%s:%i: drpass item sin variable de nombre",
			 cep->ce_fileptr->cf_filename, cep->ce_varlinenum);
			errors++; continue;
		}
		if (!cep->ce_vardata)
		{
			config_error("%s:%i: falta par�metro en drpass:%s",
			 cep->ce_fileptr->cf_filename, cep->ce_varlinenum,
			 	cep->ce_varname);
			errors++; continue;
		}
		if (!strcmp(cep->ce_varname, "restart"))
		{
			if (Auth_CheckError(cep) < 0)
				errors++;
			continue;
		}
		else if (!strcmp(cep->ce_varname, "die"))
		{
			if (Auth_CheckError(cep) < 0)
				errors++;
			continue;
		}
		else
		{
			config_status("%s:%i: advertencia: directriz drpass desconocida '%s'",
				 cep->ce_fileptr->cf_filename, cep->ce_varlinenum,
				 cep->ce_varname);
			errors++; continue;
		}
	}
	return errors;
}

/*
 * The ulines {} block parser
*/
int	_conf_ulines(ConfigFile *conf, ConfigEntry *ce)
{
	ConfigEntry *cep;
	ConfigItem_ulines *ca;

	for (cep = ce->ce_entries; cep; cep = cep->ce_next)
	{
		if (!cep->ce_varname)
		{
			config_status("%s:%i: uline item vac�o",
				cep->ce_fileptr->cf_filename,
				cep->ce_varlinenum);
			continue;
		}
		ca = MyMallocEx(sizeof(ConfigItem_ulines));
		ircstrdup(ca->servername, cep->ce_varname);
		AddListItem(ca, conf_ulines);
	}
	return 1;
}

int	_test_ulines(ConfigFile *conf, ConfigEntry *ce)
{
	ConfigEntry *cep;
	int 	    errors = 0;
	for (cep = ce->ce_entries; cep; cep = cep->ce_next)
	{
		if (!cep->ce_varname)
		{
			config_error("%s:%i: uline item vac�o",
				cep->ce_fileptr->cf_filename,
				cep->ce_varlinenum);
			errors++;
			continue;
		}
	}
	return errors;
}

int     _conf_tld(ConfigFile *conf, ConfigEntry *ce)
{
	ConfigEntry *cep;
	ConfigItem_tld *ca;

	ca = MyMallocEx(sizeof(ConfigItem_tld));
	cep = config_find_entry(ce->ce_entries, "mask");
	ca->mask = strdup(cep->ce_vardata);
	cep = config_find_entry(ce->ce_entries, "motd");
	ca->motd_file = strdup(cep->ce_vardata);
	ca->motd = read_file_ex(cep->ce_vardata, NULL, &ca->motd_tm);
 	if ((cep = config_find_entry(ce->ce_entries, "shortmotd")))
	{
		ca->smotd_file = strdup(cep->ce_vardata);
		ca->smotd = read_file_ex(cep->ce_vardata, NULL, &ca->smotd_tm);
	}

	cep = config_find_entry(ce->ce_entries, "rules");
	ca->rules_file = strdup(cep->ce_vardata);
	ca->rules = read_file(cep->ce_vardata, NULL);
	cep = config_find_entry(ce->ce_entries, "options");
	if (cep)
	{
		for (cep = cep->ce_entries; cep; cep = cep->ce_next)
		{
			if (!strcmp(cep->ce_varname, "ssl"))
				ca->options |= TLD_SSL;
			else if (!strcmp(cep->ce_varname, "remote"))
				ca->options |= TLD_REMOTE;
		}
	}	
	if ((cep = config_find_entry(ce->ce_entries, "channel")))
		ca->channel = strdup(cep->ce_vardata);
	AddListItem(ca, conf_tld);
	return 1;
}

int     _test_tld(ConfigFile *conf, ConfigEntry *ce)
{
	ConfigEntry *cep;
	int	    errors = 0;
	int	    fd = -1;
        for (cep = ce->ce_entries; cep; cep = cep->ce_next)
	{
		if (!cep->ce_varname)
		{
			config_error("%s:%i: tld item vac�o",
				cep->ce_fileptr->cf_filename,
				cep->ce_varlinenum);
			errors++; continue;
		}
		if (!cep->ce_vardata && strcmp(cep->ce_varname, "options"))
		{
			config_error("%s:%i: falta par�metro en tld::%s",
				cep->ce_fileptr->cf_filename, cep->ce_varlinenum,
				cep->ce_varname);
			errors++; continue;
		}
		if (!strcmp(cep->ce_varname, "mask")) {
		}
		else if (!strcmp(cep->ce_varname, "motd")) {
		}
		else if (!strcmp(cep->ce_varname, "rules")) {
		}
		else if (!strcmp(cep->ce_varname, "channel")) {
		}
		else if (!strcmp(cep->ce_varname, "shortmotd")) {
		}
		else if (!strcmp(cep->ce_varname, "options")) {
			ConfigEntry *cep2;
			for (cep2 = cep->ce_entries; cep2; cep2 = cep2->ce_next)
			{
				if (!strcmp(cep2->ce_varname, "ssl")) {
				}
				else if (!strcmp(cep2->ce_varname, "remote")) {
				}
				else
				{
					config_error("%s:%i: opci�n desconocida tld::options::%s",
						cep2->ce_fileptr->cf_filename, cep2->ce_varlinenum,
						cep2->ce_varname);
					errors++;
				}
			}
		}
		else
		{
			config_error("%s:%i: directriz desconocida tld::%s",
				cep->ce_fileptr->cf_filename, cep->ce_varlinenum,
				cep->ce_varname);
			errors++; continue;
		}
	}
	if (!(cep = config_find_entry(ce->ce_entries, "mask")))
	{
		config_error("%s:%i: tld::mask falta",
			ce->ce_fileptr->cf_filename, ce->ce_varlinenum);
		errors++;
	}
	if (!(cep = config_find_entry(ce->ce_entries, "motd")))
	{
		config_error("%s:%i: tld::motd falta",
			ce->ce_fileptr->cf_filename, ce->ce_varlinenum);
		errors++;
	}
	else
	{
		if (cep->ce_vardata)
		{
			if (((fd = open(cep->ce_vardata, O_RDONLY)) == -1))
			{
				config_error("%s:%i: tld::motd: %s: %s",
					cep->ce_fileptr->cf_filename, cep->ce_varlinenum,
					cep->ce_vardata, strerror(errno));
				errors++;
			}
			else
				close(fd);
		}
		
	}
	
	if (!(cep = config_find_entry(ce->ce_entries, "rules")))
	{
		config_error("%s:%i: tld::rules falta",
			ce->ce_fileptr->cf_filename, ce->ce_varlinenum);
		errors++;
	}
	else
	{
		if (cep->ce_vardata)
		{
			if (((fd = open(cep->ce_vardata, O_RDONLY)) == -1))
			{
				config_error("%s:%i: tld::rules: %s: %s",
					cep->ce_fileptr->cf_filename, cep->ce_varlinenum,
					cep->ce_vardata, strerror(errno));
				errors++;
			}
			else
				close(fd);
		}
	}
	
	return errors;
}

int	_conf_listen(ConfigFile *conf, ConfigEntry *ce)
{
	ConfigEntry *cep;
	ConfigEntry *cepp;
	ConfigItem_listen *listen = NULL;
	OperFlag    *ofp;
	char	    copy[256];
	char	    *ip;
	char	    *port;
	int	    start, end, iport;
	int tmpflags =0;
	unsigned char	isnew = 0;

	if (!ce->ce_vardata)
	{
		return -1;
	}

	strcpy(copy, ce->ce_vardata);
	/* Seriously cheap hack to make listen <port> work -Stskeeps */
	ipport_seperate(copy, &ip, &port);
	if (!ip || !*ip)
	{
		return -1;
	}
	if (strchr(ip, '*') && strcmp(ip, "*"))
	{
		return -1;
	}
	if (!port || !*port)
	{
		return -1;
	}
	port_range(port, &start, &end);
	if ((start < 0) || (start > 65535) || (end < 0) || (end > 65535))
	{
		return -1;
	}
	end++;
	for (cep = ce->ce_entries; cep; cep = cep->ce_next)
	{
		if (!strcmp(cep->ce_varname, "options"))
		{
			for (cepp = cep->ce_entries; cepp; cepp = cepp->ce_next)
			{
				if ((ofp = config_binary_flags_search(_ListenerFlags, cepp->ce_varname, sizeof(_ListenerFlags)/sizeof(_ListenerFlags[0]))))
					tmpflags |= ofp->flag;
			}
#ifndef USE_SSL
			if (tmpflags & LISTENER_SSL)
			{
				config_status("%s:%i: modo SSL en un ircd sin soporte SSL",
					cep->ce_fileptr->cf_filename, cep->ce_varlinenum);
				tmpflags &= ~LISTENER_SSL;
			}
#endif
		
		}
	}

	for (iport = start; iport < end; iport++)
	{
		
		if (!(listen = Find_listen(ip, iport)))
		{
			listen = MyMallocEx(sizeof(ConfigItem_listen));
			listen->ip = strdup(ip);
			listen->port = iport;
			isnew = 1;
		}
		else
			isnew = 0;

		if (listen->options & LISTENER_BOUND)
			tmpflags |= LISTENER_BOUND;

		listen->options = tmpflags;
		if (isnew)
			AddListItem(listen, conf_listen);
		listen->flag.temporary = 0;
	}
	return 1;
}

int	_test_listen(ConfigFile *conf, ConfigEntry *ce)
{
	ConfigEntry *cep;
	ConfigEntry *cepp;
	char	    copy[256];
	char	    *ip;
	char	    *port;
	int	    start, end;
	int	    errors = 0;

	if (!ce->ce_vardata)
	{
		config_error("%s:%i: listen sin ip:port",
			ce->ce_fileptr->cf_filename, ce->ce_varlinenum);
		return 1;
	}

	strcpy(copy, ce->ce_vardata);
	/* Seriously cheap hack to make listen <port> work -Stskeeps */
	ipport_seperate(copy, &ip, &port);
	if (!ip || !*ip)
	{
		config_error("%s:%i: listen: m�scara err�nea ip:port",
			ce->ce_fileptr->cf_filename, ce->ce_varlinenum);
		return 1;
	}
	if (strchr(ip, '*') && strcmp(ip, "*"))
	{
		config_error("%s:%i: listen: ip err�nea, no puede ser '*')",
			ce->ce_fileptr->cf_filename, ce->ce_varlinenum);
		return 1;
	}
	if (!port || !*port)
	{
		config_error("%s:%i: listen: falta puerto en m�scara",
			ce->ce_fileptr->cf_filename, ce->ce_varlinenum);
		return 1;
	}
#ifdef INET6
	if ((strlen(ip) > 6) && !strchr(ip, ':') && isdigit(ip[strlen(ip)-1]))
	{
		config_error("%s:%i: listen: ip fijada en '%s' (ipv4) en un ircd IPv6, "
		              "usa ::ffff:1.2.3.4",
					ce->ce_fileptr->cf_filename, ce->ce_varlinenum, ip);
		return 1;
	}
#endif
	port_range(port, &start, &end);
	if (start == end)
	{
		if ((start < 0) || (start > 65535))
		{
			config_error("%s:%i: listen: puerto err�neo (0-65535)",
				ce->ce_fileptr->cf_filename, ce->ce_varlinenum);
			return 1;
		}
	}
	else 
	{
		if (end < start)
		{
			config_error("%s:%i: listen: rango de puertos err�neo (final menor que inicial)",
				ce->ce_fileptr->cf_filename, ce->ce_varlinenum);
			return 1;
		}
		if (end - start >= 100)
		{
			config_error("%s:%i: listen: rango %d-%d, que son %d puertos "
				"seguramente no es lo que quieres.",
				ce->ce_fileptr->cf_filename, ce->ce_varlinenum, start, end, end - start);
			return 1;
		}
		if ((start < 0) || (start > 65535) || (end < 0) || (end > 65535))
		{
			config_error("%s:%i: listen: rango de puertos err�neo 0-65535",
				ce->ce_fileptr->cf_filename, ce->ce_varlinenum);
			return 1;
		}
	}
	for (cep = ce->ce_entries; cep; cep = cep->ce_next)
	{
		if (!cep->ce_varname)
		{
			config_error("%s:%i: listen item sin variable de nombre",
				cep->ce_fileptr->cf_filename, cep->ce_varlinenum);
			errors++; continue;
		}
		if (!strcmp(cep->ce_varname, "options"))
		{
			if (!cep->ce_entries)
			{
				config_error("%s:%i: listen::%s sin par�metro",
					cep->ce_fileptr->cf_filename,
					cep->ce_varlinenum,
					cep->ce_varname);
				errors++;
			}
			for (cepp = cep->ce_entries; cepp; cepp = cepp->ce_next)
			{
				if (!cepp->ce_varname)
				{
					config_error("%s:%i: listen::options item sin variable de nombre",
						cepp->ce_fileptr->cf_filename, cepp->ce_varlinenum);
					errors++; continue;
				}
				if (!config_binary_flags_search(_ListenerFlags, cepp->ce_varname, sizeof(_ListenerFlags)/sizeof(_ListenerFlags[0])))
				{
					config_error("%s:%i: opci�n desconocida listen '%s'",
						cepp->ce_fileptr->cf_filename, cepp->ce_varlinenum,
						cepp->ce_varname);
					errors++; continue;
				}
			}
		}
		else
		{
			config_error("%s:%i: directriz desconocida listen::%s",
				cep->ce_fileptr->cf_filename, cep->ce_varlinenum,
					cep->ce_varname);
			errors++; continue;
		}

	}
	requiredstuff.conf_listen = 1;
	return errors;
}


int	_conf_allow(ConfigFile *conf, ConfigEntry *ce)
{
	ConfigEntry *cep, *cepp;
	ConfigItem_allow *allow;
	Hook *h;
	struct irc_netmask tmp;
	if (ce->ce_vardata)
	{
		if (!strcmp(ce->ce_vardata, "channel"))
			return (_conf_allow_channel(conf, ce));
		else if (!strcmp(ce->ce_vardata, "dcc"))
			return (_conf_allow_dcc(conf, ce));
		else
		{
			int value;
			for (h = Hooks[HOOKTYPE_CONFIGRUN]; h; h = h->next)
			{
				value = (*(h->func.intfunc))(conf,ce,CONFIG_ALLOW);
				if (value == 1)
					break;
			}
			return 0;
		}
	}
	allow = MyMallocEx(sizeof(ConfigItem_allow));
	cep = config_find_entry(ce->ce_entries, "ip");
	allow->ip = strdup(cep->ce_vardata);
	/* CIDR */
	tmp.type = parse_netmask(allow->ip, &tmp);
	if (tmp.type != HM_HOST)
	{
		allow->netmask = MyMallocEx(sizeof(struct irc_netmask));
		bcopy(&tmp, allow->netmask, sizeof(struct irc_netmask));
	}
	
	cep = config_find_entry(ce->ce_entries, "hostname");
	allow->hostname = strdup(cep->ce_vardata);
	if ((cep = config_find_entry(ce->ce_entries, "password")))
	{
		allow->auth = Auth_ConvertConf2AuthStruct(cep);
	}
	cep = config_find_entry(ce->ce_entries, "class");
	allow->class = Find_class(cep->ce_vardata);
	if (!allow->class)
	{
		config_status("%s:%i: illegal allow::class, clase desconocida '%s'. Se usar� la clase 'default'",
			cep->ce_fileptr->cf_filename,
			cep->ce_varlinenum,
			cep->ce_vardata);
			allow->class = default_class;
	}
	if ((cep = config_find_entry(ce->ce_entries, "maxperip")))
	{
		allow->maxperip = atoi(cep->ce_vardata);
	}
	if ((cep = config_find_entry(ce->ce_entries, "redirect-server")))
	{
		allow->server = strdup(cep->ce_vardata);
	}
	if ((cep = config_find_entry(ce->ce_entries, "redirect-port")))
	{
		allow->port = atoi(cep->ce_vardata);
	}
	if ((cep = config_find_entry(ce->ce_entries, "options")))
	{
		for (cepp = cep->ce_entries; cepp; cepp = cepp->ce_next) {
			if (!strcmp(cepp->ce_varname, "noident"))
				allow->flags.noident = 1;
			else if (!strcmp(cepp->ce_varname, "useip")) 
				allow->flags.useip = 1;
			else if (!strcmp(cepp->ce_varname, "ssl")) 
				allow->flags.ssl = 1;
			else if (!strcmp(cepp->ce_varname, "nopasscont")) 
				allow->flags.nopasscont = 1;
		}
	
	}
	AddListItem(allow, conf_allow);
	return 1;
}

int	_test_allow(ConfigFile *conf, ConfigEntry *ce)
{
	ConfigEntry *cep, *cepp;
	int		errors = 0;
	Hook *h;
	
	if (ce->ce_vardata)
	{
		if (!strcmp(ce->ce_vardata, "channel"))
			return (_test_allow_channel(conf, ce));
		else if (!strcmp(ce->ce_vardata, "dcc"))
			return (_test_allow_dcc(conf, ce));
		else
		{
			int used = 0;
			for (h = Hooks[HOOKTYPE_CONFIGTEST]; h; h = h->next) 
			{
				int value, errs = 0;
				if (h->owner && !(h->owner->flags & MODFLAG_TESTING)
				    && !(h->owner->options & MOD_OPT_PERM))
					continue;
				value = (*(h->func.intfunc))(conf,ce,CONFIG_ALLOW,&errs);
				if (value == 2)
					used = 1;
				if (value == 1)
				{
					used = 1;
					break;
				}
				if (value == -1)
				{
					used = 1;
					errors += errs;
					break;
				}
				if (value == -2)
				{
					used = 1;
					errors += errs;
				}
			}
			if (!used) {
				config_error("%s:%i: allow item con tipo desconocido",
					ce->ce_fileptr->cf_filename, ce->ce_varlinenum);
				return 1;
			}
			return errors;
		}
	}

	for (cep = ce->ce_entries; cep; cep = cep->ce_next)
	{
		if (!cep->ce_varname)
		{
			config_status("%s:%i: allow item sin nombre de variable",
				cep->ce_fileptr->cf_filename, cep->ce_varlinenum);
			errors++; continue;
		}
		if (!strcmp(cep->ce_varname, "ip"))
		{
			if (!cep->ce_vardata)
			{
				config_error("%s:%i: allow::%s sin contenidos",
					cep->ce_fileptr->cf_filename,
					cep->ce_varlinenum,
					cep->ce_varname);
				errors++; continue;
			}
		} else
		if (!strcmp(cep->ce_varname, "maxperip"))
		{
			if (!cep->ce_vardata)
			{
				config_error("%s:%i: allow::%s sin contenidos",
					cep->ce_fileptr->cf_filename,
					cep->ce_varlinenum,
					cep->ce_varname);
				errors++; continue;
			}
		} else
		if (!strcmp(cep->ce_varname, "hostname"))
		{
			if (!cep->ce_vardata)
			{
				config_error("%s:%i: allow::%s sin contenidos",
					cep->ce_fileptr->cf_filename,
					cep->ce_varlinenum,
					cep->ce_varname);
				errors++; continue;
			}
		} else
		if (!strcmp(cep->ce_varname, "password"))
		{
			if (!cep->ce_vardata)
			{
				config_error("%s:%i: allow::%s sin contenidos",
					cep->ce_fileptr->cf_filename,
					cep->ce_varlinenum,
					cep->ce_varname);
				errors++; continue;
			}
		} else
		if (!strcmp(cep->ce_varname, "class"))
		{
			if (!cep->ce_vardata)
			{
				config_error("%s:%i: allow::%s sin contenidos",
					cep->ce_fileptr->cf_filename,
					cep->ce_varlinenum,
					cep->ce_varname);
				errors++; continue;
			}
		}
		else if (!strcmp(cep->ce_varname, "redirect-server"))
		{
			if (!cep->ce_vardata)
			{
				config_error("%s:%i: allow::%s sin contenidos",
					cep->ce_fileptr->cf_filename,
					cep->ce_varlinenum,
					cep->ce_varname);
				errors++; continue;
			}
		}
		else if (!strcmp(cep->ce_varname, "redirect-port")) {
			if (!cep->ce_vardata)
			{
				config_error("%s:%i: allow::%s sin contenidos",
					cep->ce_fileptr->cf_filename,
					cep->ce_varlinenum,
					cep->ce_varname);
				errors++; continue;
			}
		}
		else if (!strcmp(cep->ce_varname, "options")) {
		}
		else
		{
			config_error("%s:%i: directriz desconocida allow::%s",
				cep->ce_fileptr->cf_filename, cep->ce_varlinenum,
					cep->ce_varname);
			errors++; continue;
		}
	}
	if (!(cep = config_find_entry(ce->ce_entries, "ip")))
	{
		config_error("%s:%i: allow::ip falta",
			ce->ce_fileptr->cf_filename,
			ce->ce_varlinenum);
		errors++;
	}
	if (!(cep = config_find_entry(ce->ce_entries, "hostname")))
	{
		config_error("%s:%i: allow::hostname falta",
			ce->ce_fileptr->cf_filename,
			ce->ce_varlinenum);
		errors++;
	}
	if ((cep = config_find_entry(ce->ce_entries, "password")))
	{
		/* some auth check stuff? */
		if (Auth_CheckError(cep) < 0)
			errors++;
	}
	if (!(cep = config_find_entry(ce->ce_entries, "class")))
	{
		config_error("%s:%i: allow::class missing",
			ce->ce_fileptr->cf_filename,
			ce->ce_varlinenum);
		errors++;
	}
	if ((cep = config_find_entry(ce->ce_entries, "maxperip")))
	{
		if (cep->ce_vardata)
		{
			int v = atoi(cep->ce_vardata);
			if ((v <= 0) || (v > 65535))
			{
				config_error("%s:%i: allow::maxperip valor err�neo (>0)",
					cep->ce_fileptr->cf_filename, cep->ce_varlinenum);
				errors++;
			}
		}
	}
	if ((cep = config_find_entry(ce->ce_entries, "options")))
	{
		if (!cep->ce_entries)
		{
			config_error("%s:%i: allow::%s sin par�metro",
				cep->ce_fileptr->cf_filename,
				cep->ce_varlinenum,
				cep->ce_varname);
			errors++;
		}
		for (cepp = cep->ce_entries; cepp; cepp = cepp->ce_next) {
			if (!strcmp(cepp->ce_varname, "noident"))
			{}
			else if (!strcmp(cepp->ce_varname, "useip")) 
			{}
			else if (!strcmp(cepp->ce_varname, "ssl")) 
			{}
			else if (!strcmp(cepp->ce_varname, "nopasscont")) 
			{}
			else
			{
				config_error("%s:%i: allow::options item desconocido '%s'",
					cepp->ce_fileptr->cf_filename, cepp->ce_varlinenum, 
					cepp->ce_varname);
				errors++;
			}
		}
	
	}
	return errors;
}

int	_conf_allow_channel(ConfigFile *conf, ConfigEntry *ce)
{
	ConfigItem_allow_channel 	*allow = NULL;
	ConfigEntry 	    	*cep;

	for (cep = ce->ce_entries; cep; cep = cep->ce_next)
	{
		if (!strcmp(cep->ce_varname, "channel"))
		{
			allow = MyMallocEx(sizeof(ConfigItem_allow_channel));
			ircstrdup(allow->channel, cep->ce_vardata);
			AddListItem(allow, conf_allow_channel);
		}
	}
	return 1;
}

int	_test_allow_channel(ConfigFile *conf, ConfigEntry *ce)
{
	ConfigEntry		*cep;
	int			errors = 0;
	
	for (cep = ce->ce_entries; cep; cep = cep->ce_next)
	{
		if (!cep->ce_varname || !cep->ce_vardata)
		{
			config_error("%s:%i: allow channel item sin contenidos",
				cep->ce_fileptr->cf_filename, cep->ce_varlinenum);
			errors++; continue;
		}
		if (!strcmp(cep->ce_varname, "channel"))
		{
		}
		else
		{
			config_error("%s:%i: unknown allow channel directive %s",
				cep->ce_fileptr->cf_filename, cep->ce_varlinenum, 
				cep->ce_varname);
			errors++;
		}
	}
	return errors;
}

int	_conf_allow_dcc(ConfigFile *conf, ConfigEntry *ce)
{
ConfigItem_allow_dcc *allow = NULL;
ConfigEntry *cep;

	allow = MyMallocEx(sizeof(ConfigItem_allow_dcc));
	
	for (cep = ce->ce_entries; cep; cep = cep->ce_next)
	{
		if (!strcmp(cep->ce_varname, "filename"))
			ircstrdup(allow->filename, cep->ce_vardata);
		else if (!strcmp(cep->ce_varname, "soft"))
		{
			int x = config_checkval(cep->ce_vardata,CFG_YESNO);
			if (x)
				allow->flag.type = DCCDENY_SOFT;
		}
	}
	AddListItem(allow, conf_allow_dcc);
	return 1;
}

int	_test_allow_dcc(ConfigFile *conf, ConfigEntry *ce)
{
ConfigEntry *cep;
int errors = 0, gotfilename=0;
	
	for (cep = ce->ce_entries; cep; cep = cep->ce_next)
	{
		if (!cep->ce_varname || !cep->ce_vardata)
		{
			config_error("%s:%i: allow dcc item without contents",
				cep->ce_fileptr->cf_filename, cep->ce_varlinenum);
			errors++; continue;
		}
		if (!strcmp(cep->ce_varname, "filename"))
			gotfilename=1;
		else if (!strcmp(cep->ce_varname, "soft"))
			;
		else
		{
			config_error("%s:%i: directriz desconocida allow channel %s",
				cep->ce_fileptr->cf_filename, cep->ce_varlinenum, 
				cep->ce_varname);
			errors++;
		}
	}
	if (!gotfilename)
	{
		config_error("%s:%i: allow dcc: no 'filename' specified.",
			ce->ce_fileptr->cf_filename, ce->ce_varlinenum);
		errors++;
	}
	return errors;
}

int     _conf_except(ConfigFile *conf, ConfigEntry *ce)
{

	ConfigEntry *cep, *cep2, *cep3;
	ConfigItem_except *ca;
	Hook *h;
	struct irc_netmask tmp;

	if (!strcmp(ce->ce_vardata, "ban")) {
		for (cep = ce->ce_entries; cep; cep = cep->ce_next)
		{
			if (!strcmp(cep->ce_varname, "mask")) {
				ca = MyMallocEx(sizeof(ConfigItem_except));
				ca->mask = strdup(cep->ce_vardata);
				tmp.type = parse_netmask(ca->mask, &tmp);
				if (tmp.type != HM_HOST)
				{
					ca->netmask = MyMallocEx(sizeof(struct irc_netmask));
					bcopy(&tmp, ca->netmask, sizeof(struct irc_netmask));
				}
				ca->flag.type = CONF_EXCEPT_BAN;
				AddListItem(ca, conf_except);
			}
			else {
			}
		}
	}
#ifdef THROTTLING
	else if (!strcmp(ce->ce_vardata, "throttle")) {
		for (cep = ce->ce_entries; cep; cep = cep->ce_next)
		{
			if (!strcmp(cep->ce_varname, "mask")) {
				ca = MyMallocEx(sizeof(ConfigItem_except));
				ca->mask = strdup(cep->ce_vardata);
				tmp.type = parse_netmask(ca->mask, &tmp);
				if (tmp.type != HM_HOST)
				{
					ca->netmask = MyMallocEx(sizeof(struct irc_netmask));
					bcopy(&tmp, ca->netmask, sizeof(struct irc_netmask));
				}
				ca->flag.type = CONF_EXCEPT_THROTTLE;
				AddListItem(ca, conf_except);
			}
			else {
			}
		}

	}
#endif
	else if (!strcmp(ce->ce_vardata, "tkl")) {
		cep2 = config_find_entry(ce->ce_entries, "mask");
		cep3 = config_find_entry(ce->ce_entries, "type");
		ca = MyMallocEx(sizeof(ConfigItem_except));
		ca->mask = strdup(cep2->ce_vardata);
		if (!strcmp(cep3->ce_vardata, "gline"))
			ca->type = TKL_KILL|TKL_GLOBAL;
		else if (!strcmp(cep3->ce_vardata, "qline"))
			ca->type = TKL_NICK;
		else if (!strcmp(cep3->ce_vardata, "gqline"))
			ca->type = TKL_NICK|TKL_GLOBAL;
		else if (!strcmp(cep3->ce_vardata, "gzline"))
			ca->type = TKL_ZAP|TKL_GLOBAL;
		else if (!strcmp(cep3->ce_vardata, "shun"))
			ca->type = TKL_SHUN|TKL_GLOBAL;
		else 
		{}
		
		if (ca->type & TKL_KILL || ca->type & TKL_ZAP || ca->type & TKL_SHUN)
		{
			tmp.type = parse_netmask(ca->mask, &tmp);
			if (tmp.type != HM_HOST)
			{
				ca->netmask = MyMallocEx(sizeof(struct irc_netmask));
				bcopy(&tmp, ca->netmask, sizeof(struct irc_netmask));
			}
		}
		ca->flag.type = CONF_EXCEPT_TKL;
		AddListItem(ca, conf_except);
	}
	else {
		int value;
		for (h = Hooks[HOOKTYPE_CONFIGRUN]; h; h = h->next)
		{
			value = (*(h->func.intfunc))(conf,ce,CONFIG_EXCEPT);
			if (value == 1)
				break;
		}
	}
	return 1;
}

int     _test_except(ConfigFile *conf, ConfigEntry *ce)
{

	ConfigEntry *cep, *cep3;
	int	    errors = 0;
	Hook *h;

	if (!ce->ce_vardata)
	{
		config_error("%s:%i: except without type",
			ce->ce_fileptr->cf_filename, ce->ce_varlinenum);
		return 1;
	}

	if (!strcmp(ce->ce_vardata, "ban")) {
		if (!config_find_entry(ce->ce_entries, "mask"))
		{
			config_error("%s:%i: except ban sin m�scara",
				ce->ce_fileptr->cf_filename, ce->ce_varlinenum);
			return 1;
		}
		for (cep = ce->ce_entries; cep; cep = cep->ce_next)
		{
			if (!cep->ce_vardata)
			{
				config_error("%s:%i: except ban item sin contenidos",
					cep->ce_fileptr->cf_filename, cep->ce_varlinenum);
				errors++;
				continue;
			}
			if (!strcmp(cep->ce_varname, "mask"))
			{
			}
			else
			{
				config_error("%s:%i: directriz desconocida except ban %s",
					cep->ce_fileptr->cf_filename, cep->ce_varlinenum, cep->ce_varname);
				errors++;
				continue;
			}
		}
		return errors;
	}
#ifdef THROTTLING
	else if (!strcmp(ce->ce_vardata, "throttle")) {
		if (!config_find_entry(ce->ce_entries, "mask"))
		{
			config_error("%s:%i: except throttle sin m�scara",
				ce->ce_fileptr->cf_filename, ce->ce_varlinenum);
			return 1;
		}
		for (cep = ce->ce_entries; cep; cep = cep->ce_next)
		{
			if (!cep->ce_vardata)
			{
				config_error("%s:%i: except throttle item sin contenidos",
					cep->ce_fileptr->cf_filename, cep->ce_varlinenum);
				errors++;
				continue;
			}
			if (!strcmp(cep->ce_varname, "mask"))
			{
			}
			else
			{
				config_error("%s:%i: directriz desconocida except throttle %s",
					cep->ce_fileptr->cf_filename, cep->ce_varlinenum, cep->ce_varname);
				errors++;
				continue;
			}
		}
		return errors;
	}
#endif
	else if (!strcmp(ce->ce_vardata, "tkl")) {
		if (!config_find_entry(ce->ce_entries, "mask"))
		{
			config_error("%s:%i: except tkl sin m�scara",
				ce->ce_fileptr->cf_filename, ce->ce_varlinenum);
			return 1;
		}
		if (!(cep3 = config_find_entry(ce->ce_entries, "type")))
		{
			config_error("%s:%i: except tkl sin tipo",
				ce->ce_fileptr->cf_filename, ce->ce_varlinenum);
			return 1;
		}
		for (cep = ce->ce_entries; cep; cep = cep->ce_next)
		{
			if (!cep->ce_vardata)
			{
				config_error("%s:%i: except tkl item sin contenidos",
					cep->ce_fileptr->cf_filename, cep->ce_varlinenum);
				errors++;
				continue;
			}
			if (!strcmp(cep->ce_varname, "mask"))
			{
			}
			else if (!strcmp(cep->ce_varname, "type")) {}
			else
			{
				config_error("%s:%i: directriz desconocida except tkl %s",
					cep->ce_fileptr->cf_filename, cep->ce_varlinenum, cep->ce_varname);
				errors++;
				continue;
			}
		}
		if (!strcmp(cep3->ce_vardata, "gline")) {}
		else if (!strcmp(cep3->ce_vardata, "qline")) {}
		else if (!strcmp(cep3->ce_vardata, "gqline")) {}
		else if (!strcmp(cep3->ce_vardata, "gzline")){}
		else if (!strcmp(cep3->ce_vardata, "shun")) {}
		else if (!strcmp(cep3->ce_vardata, "tkline")) {
			config_error("%s:%i: except tkl para tkline inv�lido. Usa ban {}", 
				cep3->ce_fileptr->cf_filename, cep3->ce_varlinenum);
			errors++;
		}
		else if (!strcmp(cep3->ce_vardata, "tzline")) {
			config_error("%s:%i: except tkl para tzline inv�lido. Usa ban {}", 
				cep3->ce_fileptr->cf_filename, cep3->ce_varlinenum);
			errors++;
		}
		else 
		{
			config_error("%s:%i: tipo desconocido except tkl %s",
				cep3->ce_fileptr->cf_filename, cep3->ce_varlinenum,
				cep3->ce_vardata);
			return 1;

		}
		return errors;
	}
	else {
		int used = 0;
		for (h = Hooks[HOOKTYPE_CONFIGTEST]; h; h = h->next) 
		{
			int value, errs = 0;
			if (h->owner && !(h->owner->flags & MODFLAG_TESTING)
			    && !(h->owner->options & MOD_OPT_PERM))
				continue;
			value = (*(h->func.intfunc))(conf,ce,CONFIG_EXCEPT,&errs);
			if (value == 2)
				used = 1;
			if (value == 1)
			{
				used = 1;
				break;
			}
			if (value == -1)
			{
				used = 1;
				errors += errs;
				break;
			}
			if (value == -2)
			{
				used = 1;
				errors += errs;
			}
		}
		if (!used) {
			config_error("%s:%i: tipo desconocido except %s",
				ce->ce_fileptr->cf_filename, ce->ce_varlinenum, 
				ce->ce_vardata);
			return 1;
		}
	}
	return errors;
}

/*
 * vhost {} block parser
*/
int	_conf_vhost(ConfigFile *conf, ConfigEntry *ce)
{
	ConfigItem_vhost *vhost;
	ConfigItem_oper_from *from;
	ConfigEntry *cep, *cepp;
	vhost = MyMallocEx(sizeof(ConfigItem_vhost));
	cep = config_find_entry(ce->ce_entries, "vhost");
	{
		char *user, *host;
		user = strtok(cep->ce_vardata, "@");
		host = strtok(NULL, "");
		if (!host)
			vhost->virthost = strdup(user);
		else {
			vhost->virtuser = strdup(user);
			vhost->virthost = strdup(host);
		}
	}
	cep = config_find_entry(ce->ce_entries, "login");
	vhost->login = strdup(cep->ce_vardata);	
	cep = config_find_entry(ce->ce_entries, "password");
	vhost->auth = Auth_ConvertConf2AuthStruct(cep);
	cep = config_find_entry(ce->ce_entries, "from");
	for (cepp = cep->ce_entries; cepp; cepp = cepp->ce_next)
	{
		if (!strcmp(cepp->ce_varname, "userhost"))
		{
			from = MyMallocEx(sizeof(ConfigItem_oper_from));
			ircstrdup(from->name, cepp->ce_vardata);
			AddListItem(from, vhost->from);
		}
	}
	if ((cep = config_find_entry(ce->ce_entries, "swhois")))
		vhost->swhois = strdup(cep->ce_vardata);
	AddListItem(vhost, conf_vhost);
	return 1;
}

int	_test_vhost(ConfigFile *conf, ConfigEntry *ce)
{
	int errors = 0;
	ConfigEntry *vhost, *swhois, *from, *login, *password, *cep;
	if (!ce->ce_entries)
	{
		config_error("%s:%i: empty vhost block", 
			ce->ce_fileptr->cf_filename, ce->ce_varlinenum);
		return 1;
	}
	if (!(vhost = config_find_entry(ce->ce_entries, "vhost")))
	{
		config_error("%s:%i: vhost::vhost falta",
			ce->ce_fileptr->cf_filename, ce->ce_varlinenum);
		errors++;
	}
	else
	{
		char *at, *tmp, *host;
		if (!vhost->ce_vardata)
		{
			config_error("%s:%i: vhost::vhost sin contenidos",
				vhost->ce_fileptr->cf_filename, vhost->ce_varlinenum);
			errors++;
		}	
		if ((at = strchr(vhost->ce_vardata, '@')))
		{
			for (tmp = vhost->ce_vardata; tmp != at; tmp++)
			{
				if (*tmp == '~' && tmp == vhost->ce_vardata)
					continue;
				if (!isallowed(*tmp))
					break;
			}
			if (tmp != at)
			{
				config_error("%s:%i: vhost::vhost contiene una ident inv�lida",
					ce->ce_fileptr->cf_filename, ce->ce_varlinenum);
				errors++;
			}
			host = at+1;
		}
		else
			host = vhost->ce_vardata;
		if (!*host)
		{
			config_error("%s:%i: vhost::vhost no tiene host relacionado",
				ce->ce_fileptr->cf_filename, ce->ce_varlinenum);
			errors++;
		}
		else
		{
			for (; *host; host++)
			{
				if (!isallowed(*host) && *host != ':')
				{
					config_error("%s:%i: vhost::vhost contiene host err�neo",
						ce->ce_fileptr->cf_filename, ce->ce_varlinenum);
					errors++;
					break;
				}
			}
		}
	}
	if (!(login = config_find_entry(ce->ce_entries, "login")))
	{
		config_error("%s:%i: vhost::login falta",
			ce->ce_fileptr->cf_filename, ce->ce_varlinenum);
		errors++;
		
	}
	else
	{
		if (!login->ce_vardata)
		{
			config_error("%s:%i: vhost::login sin contenidos",
				login->ce_fileptr->cf_filename, login->ce_varlinenum);
			errors++;
		}
	}
	if (!(password = config_find_entry(ce->ce_entries, "password")))
	{
		config_error("%s:%i: vhost::password falta",
			ce->ce_fileptr->cf_filename, ce->ce_varlinenum);
		errors++;
	}
	else
	{
		if (Auth_CheckError(password) < 0)
			errors++;
	}
	if (!(from = config_find_entry(ce->ce_entries, "from")))
	{
		config_error("%s:%i: vhost::from falta",
			ce->ce_fileptr->cf_filename, ce->ce_varlinenum);
		errors++;
	}
	else
	{
		if (!from->ce_entries)
		{
			config_error("%s:%i: vhost::from block sin contenidos",
				from->ce_fileptr->cf_filename, from->ce_varlinenum);
			errors++;
		}
		else
		{
			for (cep = from->ce_entries; cep; cep = cep->ce_next)
			{
				if (!cep->ce_varname)
				{
					config_error("%s:%i: vhost::from block item sin variable de nombre",
						cep->ce_fileptr->cf_filename, cep->ce_varlinenum);
					errors++;
					continue;
				}
				
				if (!strcmp(cep->ce_varname, "userhost"))
				{
					if (!cep->ce_vardata)
					{
						config_error("%s:%i: vhost::from::userhost item sin contenidos",
							cep->ce_fileptr->cf_filename, cep->ce_varlinenum);
						errors++;
						continue;	
					}
				}
				else
				{
					config_error("%s:%i: vhost::from desconocido block item '%s'",
						cep->ce_fileptr->cf_filename, cep->ce_varlinenum, 
						cep->ce_varname);
					errors++;
					continue;	
				}
			}
		}
	}
	if ((swhois = config_find_entry(ce->ce_entries, "swhois")))
	{
		if (!swhois->ce_vardata)
		{
			config_error("%s:%i: vhost::swhois sin contenidos",
				swhois->ce_fileptr->cf_filename, swhois->ce_varlinenum);
			errors++;
		}
	}
	for (cep = ce->ce_entries; cep; cep = cep->ce_next)
	{
		if (!cep->ce_varname)
		{
			config_error("%s:%i: vhost item sin contenidos",
				cep->ce_fileptr->cf_filename, cep->ce_varlinenum);
			errors++; continue;
		}
		if (!cep->ce_vardata)
		{
			if (strcmp(cep->ce_varname, "from"))
			{
				config_error("%s:%i: vhost item sin contenidos",
					cep->ce_fileptr->cf_filename, cep->ce_varlinenum);
				errors++; continue;
			}
		}
		if (!stricmp(cep->ce_varname, "vhost")) {}
		else if (!strcmp(cep->ce_varname, "login")) {}
		else if (!strcmp(cep->ce_varname, "password")) {}
		else if (!strcmp(cep->ce_varname, "from")) {}
		else if (!strcmp(cep->ce_varname, "swhois")) {}
		else
		{
			config_error("%s:%i: directriz desconocida unknown vhost::%s",
				cep->ce_fileptr->cf_filename, cep->ce_varlinenum, 
				cep->ce_varname);
			errors++;
		}
	}

	return errors;
}

#ifdef STRIPBADWORDS

static ConfigItem_badword *copy_badword_struct(ConfigItem_badword *ca, int regex, int regflags)
{
	ConfigItem_badword *x = MyMalloc(sizeof(ConfigItem_badword));
	memcpy(x, ca, sizeof(ConfigItem_badword));
	x->word = strdup(ca->word);
	if (ca->replace)
		x->replace = strdup(ca->replace);
	if (regex) 
	{
		memset(&x->expr, 0, sizeof(regex_t));
		regcomp(&x->expr, x->word, regflags);
	}
	return x;
}

int     _conf_badword(ConfigFile *conf, ConfigEntry *ce)
{
	ConfigEntry *cep;
	ConfigItem_badword *ca;
	char *tmp;
	short regex = 0;
	int regflags = 0;
#ifdef FAST_BADWORD_REPLACE
	int ast_l = 0, ast_r = 0;
#endif

	ca = MyMallocEx(sizeof(ConfigItem_badword));
	ca->action = BADWORD_REPLACE;
	regflags = REG_ICASE|REG_EXTENDED;
	if ((cep = config_find_entry(ce->ce_entries, "action")))
	{
		if (!strcmp(cep->ce_vardata, "block"))
		{
			ca->action = BADWORD_BLOCK;
			/* If it is set to just block, then we don't need to worry about
			 * replacements 
			 */
			regflags |= REG_NOSUB;
		}
	}
	cep = config_find_entry(ce->ce_entries, "word");
#ifdef FAST_BADWORD_REPLACE
	/* The fast badwords routine can do: "blah" "*blah" "blah*" and "*blah*",
	 * in all other cases use regex.
	 */
	for (tmp = cep->ce_vardata; *tmp; tmp++) {
		if ((int)*tmp < 65 || (int)*tmp > 123) {
			if ((cep->ce_vardata == tmp) && (*tmp == '*')) {
				ast_l = 1; /* Asterisk at the left */
				continue;
			}
			if ((*(tmp + 1) == '\0') && (*tmp == '*')) {
				ast_r = 1; /* Asterisk at the right */
				continue;
			}
			regex = 1;
			break;
		}
	}
	if (regex) {
		ca->type = BADW_TYPE_REGEX;
		ircstrdup(ca->word, cep->ce_vardata);
		regcomp(&ca->expr, ca->word, regflags);
	} else {
		char *tmpw;
		ca->type = BADW_TYPE_FAST;
		ca->word = tmpw = MyMalloc(strlen(cep->ce_vardata) - ast_l - ast_r + 1);
		/* Copy except for asterisks */
		for (tmp = cep->ce_vardata; *tmp; tmp++)
			if (*tmp != '*')
				*tmpw++ = *tmp;
		*tmpw = '\0';
		if (ast_l)
			ca->type |= BADW_TYPE_FAST_L;
		if (ast_r)
			ca->type |= BADW_TYPE_FAST_R;
	}
#else
	for (tmp = cep->ce_vardata; *tmp; tmp++) {
		if ((int)*tmp < 65 || (int)*tmp > 123) {
			regex = 1;
			break;
		}
	}
	if (regex) {
		ircstrdup(ca->word, cep->ce_vardata);
	}
	else {
		ca->word = MyMalloc(strlen(cep->ce_vardata) + strlen(PATTERN) -1);
		ircsprintf(ca->word, PATTERN, cep->ce_vardata);
	}
	/* Yes this is called twice, once in test, and once here, but it is still MUCH
	   faster than calling it each time a message is received like before. -- codemastr
	 */
	regcomp(&ca->expr, ca->word, regflags);
#endif
	if ((cep = config_find_entry(ce->ce_entries, "replace"))) {
		ircstrdup(ca->replace, cep->ce_vardata);
	}
	else
		ca->replace = NULL;
	if (!strcmp(ce->ce_vardata, "channel"))
		AddListItem(ca, conf_badword_channel);
	else if (!strcmp(ce->ce_vardata, "message"))
		AddListItem(ca, conf_badword_message);
	else if (!strcmp(ce->ce_vardata, "quit"))
		AddListItem(ca, conf_badword_quit);
	else if (!strcmp(ce->ce_vardata, "all"))
	{
		AddListItem(ca, conf_badword_channel);
		AddListItem(copy_badword_struct(ca,regex,regflags), conf_badword_message);
		AddListItem(copy_badword_struct(ca,regex,regflags), conf_badword_quit);
	}
	return 1;
}

int _test_badword(ConfigFile *conf, ConfigEntry *ce) { 
	int errors = 0;
	ConfigEntry *word, *replace, *cep;
	regex_t expr;
	if (!ce->ce_entries)
	{
		config_error("%s:%i: badword block vac�o", 
			ce->ce_fileptr->cf_filename, ce->ce_varlinenum);
		return 1;
	}
	if (!ce->ce_vardata)
	{
		config_error("%s:%i: badword sin tipo",
			ce->ce_fileptr->cf_filename, ce->ce_varlinenum);
		return 1;
	}
	else if (strcmp(ce->ce_vardata, "channel") && strcmp(ce->ce_vardata, "message") && 
	         strcmp(ce->ce_vardata, "quit") && strcmp(ce->ce_vardata, "all")) {
			config_error("%s:%i: badword tipo desconocido",
				ce->ce_fileptr->cf_filename, ce->ce_varlinenum);
		return 1;
	}
	if (!(word = config_find_entry(ce->ce_entries, "word")))
	{
		config_error("%s:%i: badword::word falta",
			ce->ce_fileptr->cf_filename, ce->ce_varlinenum);
		errors++;
	}
	else
	{
		if (!word->ce_vardata)
		{
			config_error("%s:%i: badword::word sin contenidos",
				word->ce_fileptr->cf_filename, word->ce_varlinenum);
			errors++;
		}
		else 
		{
			char *errbuf = unreal_checkregex(word->ce_vardata,1,0);
			if (errbuf)
			{
				config_error("%s:%i: badword::%s regex no v�lida: %s",
					word->ce_fileptr->cf_filename,
					word->ce_varlinenum,
					word->ce_varname, errbuf);
				errors++;
			}
		}

	}
	if ((replace = config_find_entry(ce->ce_entries, "replace")))
	{
		if (!replace->ce_vardata)
		{
			config_error("%s:%i: badword::replace sin contenidos",
				replace->ce_fileptr->cf_filename, replace->ce_varlinenum);
			errors++;
		}
	}
	for (cep = ce->ce_entries; cep; cep = cep->ce_next)
	{
		if (!cep->ce_varname || !cep->ce_vardata)
		{
			config_error("%s:%i: badword item sin contenidos",
				cep->ce_fileptr->cf_filename, cep->ce_varlinenum);
			errors++; continue;
		}
		if (!stricmp(cep->ce_varname, "word"))
			;
		else if (!strcmp(cep->ce_varname, "replace"))
			;
		else if (!strcmp(cep->ce_varname, "action"))
		{
			if (!strcmp(cep->ce_vardata, "replace"))
				;
			else if (!strcmp(cep->ce_vardata, "block"))
			{
				if (replace)
				{
					config_error("%s:%i: badword::action incompatible con badword::replace",
						cep->ce_fileptr->cf_filename, cep->ce_varlinenum);
					errors++;
					continue;
				}
			}
			else
			{
				config_error("%s:%i: action desconocida %s",
					cep->ce_fileptr->cf_filename, cep->ce_varlinenum, 
					cep->ce_vardata);
				errors++;
			}
		}
		else
		{
			config_error("%s:%i: directriz desconocida badword::%s",
				cep->ce_fileptr->cf_filename, cep->ce_varlinenum, 
				cep->ce_varname);
			errors++;
		}
	}

	
	return errors; 
}
#endif

int _conf_spamfilter(ConfigFile *conf, ConfigEntry *ce)
{
	ConfigEntry *cep;
	aTKline *nl = MyMallocEx(sizeof(aTKline));
	int target = 0, action = 0;
	char *word;
	
	cep = config_find_entry(ce->ce_entries, "regex");
	word = cep->ce_vardata;
		
	nl->type = TKL_SPAMF;
	nl->expire_at = 0;
	nl->set_at = TStime();
	nl->reason = strdup(word);

	cep = config_find_entry(ce->ce_entries, "target");
	if (cep->ce_vardata)
		target = spamfilter_getconftargets(cep->ce_vardata);
	else {
		for (cep = cep->ce_entries; cep; cep = cep->ce_next)
			target |= spamfilter_getconftargets(cep->ce_varname);
	}

	strncpyzt(nl->usermask, spamfilter_target_inttostring(target), sizeof(nl->usermask));
	nl->subtype = target;

	cep = config_find_entry(ce->ce_entries, "action");
	action = banact_stringtoval(cep->ce_vardata);
	nl->hostmask = strdup(cep->ce_vardata);
	nl->setby = BadPtr(me.name) ? NULL : strdup(me.name); /* Hmm! */
	
	nl->ptr.spamf = unreal_buildspamfilter(word);
	nl->ptr.spamf->action = action;

	if ((cep = config_find_entry(ce->ce_entries, "reason")))
		nl->ptr.spamf->tkl_reason = strdup(unreal_encodespace(cep->ce_vardata));
	else
		nl->ptr.spamf->tkl_reason = strdup("(a�adida por el ircd)");

	if ((cep = config_find_entry(ce->ce_entries, "ban-time")))
		nl->ptr.spamf->tkl_duration = config_checkval(cep->ce_vardata, CFG_TIME);
	else
		nl->ptr.spamf->tkl_duration = (SPAMFILTER_BAN_TIME ? SPAMFILTER_BAN_TIME : 86400);
		
	AddListItem(nl, tklines[tkl_hash('f')]);
	return 1;
}

int _test_spamfilter(ConfigFile *conf, ConfigEntry *ce)
{
	ConfigEntry *cep;
	int errors = 0;
	int got = 0;
	char *regex = NULL, *reason = NULL;
	
	for (cep = ce->ce_entries; cep; cep = cep->ce_next)
	{
		if (!cep->ce_varname)
		{
			config_error("%s:%i: spamfilter �tem vac�o",
				cep->ce_fileptr->cf_filename, cep->ce_varlinenum);
			errors++; continue;
		}
		if (!strcmp(cep->ce_varname, "target"))
			continue;
		if (!cep->ce_vardata)
		{
			config_error("%s:%i: spamfilter::%s sin valor",
				cep->ce_fileptr->cf_filename, cep->ce_varlinenum, cep->ce_varname);
			errors++; continue;
		}
		if (!strcmp(cep->ce_varname, "reason"))
			reason = cep->ce_vardata;
		if (!strcmp(cep->ce_varname, "regex") || !strcmp(cep->ce_varname, "action") ||
		    !strcmp(cep->ce_varname, "reason") || !strcmp(cep->ce_varname, "ban-time"))
			continue;
		
		config_error("%s:%i: directriz desconocida spamfilter::%s",
			cep->ce_fileptr->cf_filename, cep->ce_varlinenum, cep->ce_varname);
		errors++;
	}

	if (!(cep = config_find_entry(ce->ce_entries, "regex")))
	{
		config_error("%s:%i: spamfilter::regex falta",
			ce->ce_fileptr->cf_filename, ce->ce_varlinenum);
		errors++;
	} else if (cep->ce_vardata) {
		/* Check if it's a valid one */
		char *errbuf = unreal_checkregex(cep->ce_vardata,0,0);
		regex = cep->ce_vardata;
		if (errbuf)
		{
			config_error("%s:%i: spamfilter::regex regex no v�lida: %s",
				cep->ce_fileptr->cf_filename,
				cep->ce_varlinenum,
				errbuf);
			errors++;
		}
	}

	if (!(cep = config_find_entry(ce->ce_entries, "target")))
	{
		config_error("%s:%i: spamfilter::target falta",
			ce->ce_fileptr->cf_filename, ce->ce_varlinenum);
		errors++;
	} else if (cep->ce_vardata) {
		if (!spamfilter_getconftargets(cep->ce_vardata))
		{
			config_error("%s:%i: spamfilter desconocido tipo '%s'",
				cep->ce_fileptr->cf_filename, cep->ce_varlinenum, cep->ce_vardata);
			errors++;
		}
	} else if (cep->ce_entries) {
		for (cep = cep->ce_entries; cep; cep = cep->ce_next)
		{
			if (!cep->ce_varname)
			{
				config_error("%s:%i: spamfiler::target �tem vac�o",
					cep->ce_fileptr->cf_filename, cep->ce_varlinenum);
				errors++; continue; /* I don't understand how this would be possible, but.. */
			}
			if (!spamfilter_getconftargets(cep->ce_varname))
			{
				config_error("%s:%i: tipo desconocido '%s'",
					cep->ce_fileptr->cf_filename, cep->ce_varlinenum, cep->ce_varname);
				errors++;
			}
		}
	} else {
		config_error("%s:%i: spamfilter::target bloque vac�o",
			ce->ce_fileptr->cf_filename, ce->ce_varlinenum);
		errors++;
	}

	if (!(cep = config_find_entry(ce->ce_entries, "action")))
	{
		config_error("%s:%i: spamfilter::action falta",
			ce->ce_fileptr->cf_filename, ce->ce_varlinenum);
		errors++;
	} else if (cep->ce_vardata) {
		if (!banact_stringtoval(cep->ce_vardata))
		{
			config_error("%s:%i: spamfilter::action tipo desconocido '%s'",
				ce->ce_fileptr->cf_filename, ce->ce_varlinenum, cep->ce_vardata);
			errors++;
		}
	}

	if (regex && reason && (strlen(regex) + strlen(reason) > 505))
	{
		config_error("%s:%i: spamfilter block problem: regex + reason field are together over 505 bytes, "
		             "please choose a shorter regex or reason",
		             ce->ce_fileptr->cf_filename, ce->ce_varlinenum);
		errors++;
	}

	return errors;
}

int     _conf_help(ConfigFile *conf, ConfigEntry *ce)
{
	ConfigEntry *cep;
	ConfigItem_help *ca;
	aMotd *last = NULL, *temp;
	ca = MyMallocEx(sizeof(ConfigItem_help));

	if (!ce->ce_vardata)
		ca->command = NULL;
	else
		ca->command = strdup(ce->ce_vardata);

	for (cep = ce->ce_entries; cep; cep = cep->ce_next)
	{
		temp = MyMalloc(sizeof(aMotd));
		temp->line = strdup(cep->ce_varname);
		temp->next = NULL;
		if (!ca->text)
			ca->text = temp;
		else
			last->next = temp;
		last = temp;
	}
	AddListItem(ca, conf_help);
	return 1;

}

int _test_help(ConfigFile *conf, ConfigEntry *ce) { 
	int errors = 0;
	ConfigEntry *cep;
	if (!ce->ce_entries)
	{
		config_error("%s:%i: help block vac�o", 
			ce->ce_fileptr->cf_filename, ce->ce_varlinenum);
		return 1;
	}
	for (cep = ce->ce_entries; cep; cep = cep->ce_next)
	{
		if (!cep->ce_varname)
		{
			config_error("%s:%i: help item vac�o",
				cep->ce_fileptr->cf_filename, cep->ce_varlinenum);
			errors++; continue;
		}
	}
	return errors; 
}

int     _conf_log(ConfigFile *conf, ConfigEntry *ce)
{
	ConfigEntry *cep, *cepp;
	ConfigItem_log *ca;
	OperFlag *ofp = NULL;

	ca = MyMallocEx(sizeof(ConfigItem_log));
	ircstrdup(ca->file, ce->ce_vardata);

	for (cep = ce->ce_entries; cep; cep = cep->ce_next)
	{
		if (!strcmp(cep->ce_varname, "maxsize")) {
			ca->maxsize = config_checkval(cep->ce_vardata,CFG_SIZE);
		}
		else if (!strcmp(cep->ce_varname, "flags")) {
			for (cepp = cep->ce_entries; cepp; cepp = cepp->ce_next)
			{
				if ((ofp = config_binary_flags_search(_LogFlags, cepp->ce_varname, sizeof(_LogFlags)/sizeof(_LogFlags[0])))) 
					ca->flags |= ofp->flag;
			}
		}
	}
	AddListItem(ca, conf_log);
	return 1;

}

int _test_log(ConfigFile *conf, ConfigEntry *ce) { 
	int errors = 0;
	ConfigEntry *cep, *flags, *maxsize, *cepp;

	if (!ce->ce_vardata)
	{
		config_error("%s:%i: log block sin nombre de archivo", 
			ce->ce_fileptr->cf_filename, ce->ce_varlinenum);
		return 1;
	}
	if (!ce->ce_entries)
	{
		config_error("%s:%i: log block vac�o" , 
			ce->ce_fileptr->cf_filename, ce->ce_varlinenum);
		return 1;
	}
	for (cep = ce->ce_entries; cep; cep = cep->ce_next)
	{
		if (!cep->ce_varname)
		{
			config_error("%s:%i: log item vac�o",
				cep->ce_fileptr->cf_filename, cep->ce_varlinenum);
			errors++; continue;
		}
		if (!strcmp(cep->ce_varname, "flags")) {}
		else if (!strcmp(cep->ce_varname, "maxsize")) {
		}
		else {
			config_error("%s:%i: directriz desconocida log::%s",
				cep->ce_fileptr->cf_filename, cep->ce_varlinenum,
				cep->ce_varname);
			errors++; continue;
		}
	}
	if ((maxsize = config_find_entry(ce->ce_entries, "maxsize"))) 
	{
		if (!maxsize->ce_vardata) 
		{
			config_error("%s:%i: log::maxsize sin contenidos",
				maxsize->ce_fileptr->cf_filename, maxsize->ce_varlinenum);
			errors++;
		}
	}
	if (!(flags = config_find_entry(ce->ce_entries, "flags"))) {
		config_error("%s:%i: log::flags falta",
			ce->ce_fileptr->cf_filename, ce->ce_varlinenum);
		errors++;
	}
	else {
		if (!flags->ce_entries) {
			config_error("%s:%i: log::flags sin contenidos",
				flags->ce_fileptr->cf_filename, flags->ce_varlinenum);
			errors++;
		}
		else {
			for (cepp = flags->ce_entries; cepp; cepp = cepp->ce_next)
			{
				if (!cepp->ce_varname)
				{
					config_error("%s:%i: log::flags item sin variable de nombre",
						cepp->ce_fileptr->cf_filename, cepp->ce_varlinenum);
					errors++; continue;
				}
				if (!config_binary_flags_search(_LogFlags, cepp->ce_varname, sizeof(_LogFlags)/sizeof(_LogFlags[0]))) {
					 config_error("%s:%i: modo desconocido log '%s'",
						cepp->ce_fileptr->cf_filename, cepp->ce_varlinenum,
						cepp->ce_varname);

					errors++; 
				}
			}
		}
	}
	return errors; 
}


int	_conf_link(ConfigFile *conf, ConfigEntry *ce)
{
	ConfigEntry *cep;
	ConfigEntry *cepp;
	ConfigItem_link *link = NULL;
	OperFlag    *ofp;

	link = (ConfigItem_link *) MyMallocEx(sizeof(ConfigItem_link));
	link->servername = strdup(ce->ce_vardata);
	/* ugly, but it works. if it fails, we know _test_link failed miserably */
	link->username = strdup(config_find_entry(ce->ce_entries, "username")->ce_vardata);
	link->hostname = strdup(config_find_entry(ce->ce_entries, "hostname")->ce_vardata);
	link->bindip = strdup(config_find_entry(ce->ce_entries, "bind-ip")->ce_vardata);
	link->port = atol(config_find_entry(ce->ce_entries, "port")->ce_vardata);
	link->recvauth = Auth_ConvertConf2AuthStruct(config_find_entry(ce->ce_entries, "password-receive"));
	link->connpwd = strdup(config_find_entry(ce->ce_entries, "password-connect")->ce_vardata);
	cep = config_find_entry(ce->ce_entries, "class");
	link->class = Find_class(cep->ce_vardata);
	if (!link->class)
	{
		config_status("%s:%i: illegal link::class, clase desconocida '%s'. Se usar� la clase 'default'",
			cep->ce_fileptr->cf_filename,
			cep->ce_varlinenum,
			cep->ce_vardata);
		link->class = default_class;
	}
	link->class->xrefcount++;
	for (cep = ce->ce_entries; cep; cep = cep->ce_next)
	{
		if (!strcmp(cep->ce_varname, "options"))
		{
			/* remove options */
			link->options = 0;
			for (cepp = cep->ce_entries; cepp; cepp = cepp->ce_next)
			{
				if (!cepp->ce_varname)
				{
					config_status("%s:%i: link::flag item sin variable de nombre",
						cepp->ce_fileptr->cf_filename, cepp->ce_varlinenum);
					continue;
				}
				if ((ofp = config_binary_flags_search(_LinkFlags, cepp->ce_varname, sizeof(_LinkFlags)/sizeof(_LinkFlags[0])))) 
					link->options |= ofp->flag;

			}
		} else
		if (!strcmp(cep->ce_varname, "hub"))
		{
			link->hubmask = strdup(cep->ce_vardata);
		} else
		if (!strcmp(cep->ce_varname, "leaf"))
		{
			link->leafmask = strdup(cep->ce_vardata);
		} else
		if (!strcmp(cep->ce_varname, "leafdepth"))
		{
			link->leafdepth = atol(cep->ce_vardata);
		} 
#ifdef USE_SSL
		else if (!strcmp(cep->ce_varname, "ciphers"))
		{
			link->ciphers = strdup(cep->ce_vardata);
		}
#endif
#ifdef ZIP_LINKS
		else if (!strcmp(cep->ce_varname, "compression-level"))
		{
			link->compression_level = atoi(cep->ce_vardata);
		}
#endif
	}
	AddListItem(link, conf_link);
	return 0;
}

int	_test_link(ConfigFile *conf, ConfigEntry *ce)
{
	ConfigEntry	*cep, *cepp;
	OperFlag 	*ofp;
	int		errors = 0;
	char 		**p;
	char		*requiredsections[] = {
				"username", "hostname", "bind-ip", "port",
				"password-receive", "password-connect",
				"class", NULL
			};
	char		*knowndirc[] = 
			{
				"username", "hostname", "bind-ip",
				"port", "password-receive",
				"password-connect", "class",
				"hub", "leaf", 
				"leafdepth", "ciphers", "compression-level",
				NULL
			};
	if (!ce->ce_vardata)
	{
		config_error("%s:%i: link sin nombre de servidor",
			ce->ce_fileptr->cf_filename, ce->ce_varlinenum);
		return 1;

	}
	if (!strchr(ce->ce_vardata, '.'))
	{
		config_error("%s:%i: link: nombre de servidor err�neo",
			ce->ce_fileptr->cf_filename, ce->ce_varlinenum);
		return 1;
	}
	
	for (p = requiredsections; *p; p++)
	{
		if ((cep = config_find_entry(ce->ce_entries, *p)))
		{
			if (!cep->ce_vardata)
			{
				config_error("%s:%i: link::%s sin contenidos",
					cep->ce_fileptr->cf_filename,
					cep->ce_varlinenum, cep->ce_varname);
				errors++;
			}
		}
		else
		{
			config_error("%s:%i: link::%s falta",
				ce->ce_fileptr->cf_filename,
				ce->ce_varlinenum, *p);
			errors++;
		}
	}
#ifdef INET6
	/* I'm nice... I'll help those poort ipv6 users. -- Syzop */
	if ((cep = config_find_entry(ce->ce_entries, "hostname")))
	{
		/* [ not null && len>6 && has not a : in it && last character is a digit ] */
		if (cep->ce_vardata && (strlen(cep->ce_vardata) > 6) && !strchr(cep->ce_vardata, ':') &&
		    isdigit(cep->ce_vardata[strlen(cep->ce_vardata)-1]))
		{
			config_error("%s:%i: link %s has link::hostname set to '%s' (IPv4) on a IPv6 compile, "
			              "use the ::ffff:1.2.3.4 form instead",
						cep->ce_fileptr->cf_filename, cep->ce_varlinenum, ce->ce_vardata,
						cep->ce_vardata);
			errors++;
		}
	}
#endif
	if ((cep = config_find_entry(ce->ce_entries, "password-receive")))
	{
		if (Auth_CheckError(cep) < 0)
			errors++;
	}
	if ((cep = config_find_entry(ce->ce_entries, "password-connect")))
	{
		if (cep->ce_entries)
		{
			config_error("%s:%i: link::password-connect no pueden estar encriptadas",
				     ce->ce_fileptr->cf_filename, ce->ce_varlinenum);
			errors++;
		}
	}
#ifdef ZIP_LINKS
		if ((cep = config_find_entry(ce->ce_entries, "compression-level")))
		{
			if (!cep->ce_vardata)
			{
				config_error("%s:%i: link::%s sin contenidos",
					cep->ce_fileptr->cf_filename,
					cep->ce_varlinenum, cep->ce_varname);
				errors++;
			} else {
				if ((atoi(cep->ce_vardata) < 1) || (atoi(cep->ce_vardata) > 9))
				{
					config_error("%s:%i: compression-level 1..9",
						cep->ce_fileptr->cf_filename, cep->ce_varlinenum);
					errors++;
				}
			}
		}
#endif
	if (errors > 0)
		return errors;
	for (cep = ce->ce_entries; cep; cep = cep->ce_next)
	{
		if (!strcmp(cep->ce_varname, "options")) 
		{
			for (cepp = cep->ce_entries; cepp; cepp = cepp->ce_next)
			{
				if (!cepp->ce_varname)
				{
					config_error("%s:%i: link::options item sin variable de nombre",
							cepp->ce_fileptr->cf_filename, cepp->ce_varlinenum);
						errors++; 
						continue;
				}
				if (!(ofp = config_binary_flags_search(_LinkFlags, cepp->ce_varname, sizeof(_LinkFlags)/sizeof(_LinkFlags[0])))) {
					 config_error("%s:%i: opci�n desconcida link '%s'",
						cepp->ce_fileptr->cf_filename, cepp->ce_varlinenum,
						cepp->ce_varname);
					errors++; 
				}
				else 
				{
#ifndef USE_SSL
					if (ofp->flag == CONNECT_SSL)
					{
						config_status("%s:%i: link %s con SSL en un ircd sin soporte SSL",
							cep->ce_fileptr->cf_filename, cep->ce_varlinenum, ce->ce_vardata);
						errors++;
					}
#endif
#ifndef ZIP_LINKS
					if (ofp->flag == CONNECT_ZIP)
					{
						config_status("%s:%i: link %s con ZIP en un ircd sin soporte ZIP",
							cep->ce_fileptr->cf_filename, cep->ce_varlinenum, ce->ce_vardata);
						errors++;
					}
#endif
				}
			}
			continue;
		}
		for (p = knowndirc; *p; p++)
			if (!strcmp(cep->ce_varname, *p))
				break;
		if (!*p)
		{
			config_error("%s:%i: directriz desconocida link::%s",
				cep->ce_fileptr->cf_filename, cep->ce_varlinenum,
				cep->ce_varname);
			errors++;
		} else
		if (!cep->ce_vardata) {
			config_error("%s:%i: link::%s without contenidos",
				cep->ce_fileptr->cf_filename,
				cep->ce_varlinenum, cep->ce_varname);
			errors++;
		}
	}
	return errors;
		
}

int     _conf_ban(ConfigFile *conf, ConfigEntry *ce)
{

	ConfigEntry *cep;
	ConfigItem_ban *ca;
	Hook *h;

	ca = MyMallocEx(sizeof(ConfigItem_ban));
	if (!strcmp(ce->ce_vardata, "nick"))
	{
		aTKline *nl = MyMallocEx(sizeof(aTKline));
		nl->type = TKL_NICK;
		cep = config_find_entry(ce->ce_entries, "mask");
		nl->hostmask = strdup(cep->ce_vardata);
		cep = config_find_entry(ce->ce_entries, "reason");
		nl->reason = strdup(cep->ce_vardata);
		strcpy(nl->usermask, "*");
		AddListItem(nl, tklines[tkl_hash('q')]);
		free(ca);
		return 0;
	}
	else if (!strcmp(ce->ce_vardata, "ip"))
		ca->flag.type = CONF_BAN_IP;
	else if (!strcmp(ce->ce_vardata, "server"))
		ca->flag.type = CONF_BAN_SERVER;
	else if (!strcmp(ce->ce_vardata, "user"))
		ca->flag.type = CONF_BAN_USER;
	else if (!strcmp(ce->ce_vardata, "realname"))
		ca->flag.type = CONF_BAN_REALNAME;
	else if (!strcmp(ce->ce_vardata, "version"))
	{
		ca->flag.type = CONF_BAN_VERSION;
		tempiConf.use_ban_version = 1;
	}
	else {
		int value;
		free(ca); /* ca isn't used, modules have their own list. */
		for (h = Hooks[HOOKTYPE_CONFIGRUN]; h; h = h->next)
		{
			value = (*(h->func.intfunc))(conf,ce,CONFIG_BAN);
			if (value == 1)
				break;
		}
		return 0;
	}
	cep = config_find_entry(ce->ce_entries, "mask");	
	ca->mask = strdup(cep->ce_vardata);
	if (ca->flag.type == CONF_BAN_IP || ca->flag.type == CONF_BAN_USER)
	{
		struct irc_netmask tmp;
		tmp.type = parse_netmask(ca->mask, &tmp);
		if (tmp.type != HM_HOST)
		{
			ca->netmask = MyMallocEx(sizeof(struct irc_netmask));
			bcopy(&tmp, ca->netmask, sizeof(struct irc_netmask));
		}
	}

	cep = config_find_entry(ce->ce_entries, "reason");
	ca->reason = strdup(cep->ce_vardata);
	cep = config_find_entry(ce->ce_entries, "action");
	if (cep)
		ca ->action = banact_stringtoval(cep->ce_vardata);
	AddListItem(ca, conf_ban);
	return 0;
}

int     _test_ban(ConfigFile *conf, ConfigEntry *ce)
{
	ConfigEntry *cep;
	int	    errors = 0;
	Hook *h;
	
	if (!ce->ce_vardata)
	{
		config_error("%s:%i: ban without type",	
			ce->ce_fileptr->cf_filename, ce->ce_varlinenum);
		return 1;
	}
	if (!strcmp(ce->ce_vardata, "nick"))
	{}
	else if (!strcmp(ce->ce_vardata, "ip"))
	{}
	else if (!strcmp(ce->ce_vardata, "server"))
	{}
	else if (!strcmp(ce->ce_vardata, "user"))
	{}
	else if (!strcmp(ce->ce_vardata, "realname"))
	{}
	else if (!strcmp(ce->ce_vardata, "version"))
	{}
	else
	{
		int used = 0;
		for (h = Hooks[HOOKTYPE_CONFIGTEST]; h; h = h->next) 
		{
			int value, errs = 0;
			if (h->owner && !(h->owner->flags & MODFLAG_TESTING)
			    && !(h->owner->options & MOD_OPT_PERM))
				continue;
			value = (*(h->func.intfunc))(conf,ce,CONFIG_BAN, &errs);
			if (value == 2)
				used = 1;
			if (value == 1)
			{
				used = 1;
				break;
			}
			if (value == -1)
			{
				used = 1;
				errors += errs;
				break;
			}
			if (value == -2)
			{
				used = 1;
				errors += errs;
			}
		}
		if (!used) {
			config_error("%s:%i: tipo de ban desconocido %s",
				ce->ce_fileptr->cf_filename, ce->ce_varlinenum,
				ce->ce_vardata);
			return 1;
		}
		return errors;
	}
	
	if (!(cep = config_find_entry(ce->ce_entries, "mask")))
	{
		config_error("%s:%i: ban %s::mask falta",
			ce->ce_fileptr->cf_filename, ce->ce_varlinenum, ce->ce_vardata);
		errors++;
	}
	else {
		if (!cep->ce_vardata)
		{
			config_error("%s:%i: ban::%s sin contenidos",
				cep->ce_fileptr->cf_filename,
				cep->ce_varlinenum,
				cep->ce_varname);
			errors++;
		}
	}

	cep = config_find_entry(ce->ce_entries, "action");
	if (cep)
	{
		if (!banact_stringtoval(cep->ce_vardata))
		{
			config_error("%s:%i: ban %s::action acci�n desconocida '%s'",
				ce->ce_fileptr->cf_filename, ce->ce_varlinenum, ce->ce_vardata, cep->ce_vardata);
			errors++;
		}
	}

	if (!(cep = config_find_entry(ce->ce_entries, "reason")))
	{
		config_error("%s:%i: ban %s::reason falta",
			ce->ce_fileptr->cf_filename, ce->ce_varlinenum, ce->ce_vardata);
		errors++;
	}
	else {
		if (!cep->ce_vardata)
		{
			config_error("%s:%i: ban::%s sin contenidos",
				cep->ce_fileptr->cf_filename,
				cep->ce_varlinenum,
				cep->ce_varname);
			errors++;
		}
	}
	return errors;	
}

int	_conf_set(ConfigFile *conf, ConfigEntry *ce)
{
	ConfigEntry *cep, *cepp, *ceppp;
	OperFlag 	*ofl = NULL;
	char	    temp[512];
	Hook *h;

	for (cep = ce->ce_entries; cep; cep = cep->ce_next)
	{
		if (!strcmp(cep->ce_varname, "kline-address")) {
			ircstrdup(tempiConf.kline_address, cep->ce_vardata);
		}
		else if (!strcmp(cep->ce_varname, "modes-on-connect")) {
			tempiConf.conn_modes = (long) set_usermode(cep->ce_vardata);
		}
		else if (!strcmp(cep->ce_varname, "modes-on-oper")) {
			tempiConf.oper_modes = (long) set_usermode(cep->ce_vardata);
		}
		else if (!strcmp(cep->ce_varname, "modes-on-join")) {
			set_channelmodes(cep->ce_vardata, &tempiConf.modes_on_join, 0);
		}
		else if (!strcmp(cep->ce_varname, "snomask-on-oper")) {
			ircstrdup(tempiConf.oper_snomask, cep->ce_vardata);
		}
		else if (!strcmp(cep->ce_varname, "snomask-on-connect")) {
			ircstrdup(tempiConf.user_snomask, cep->ce_vardata);
		}
		else if (!strcmp(cep->ce_varname, "static-quit")) {
			ircstrdup(tempiConf.static_quit, cep->ce_vardata);
		}
		else if (!strcmp(cep->ce_varname, "static-part")) {
			ircstrdup(tempiConf.static_part, cep->ce_vardata);
		}
		else if (!strcmp(cep->ce_varname, "who-limit")) {
			tempiConf.who_limit = atol(cep->ce_vardata);
		}
		else if (!strcmp(cep->ce_varname, "silence-limit")) {
			tempiConf.silence_limit = atol(cep->ce_vardata);
		}
		else if (!strcmp(cep->ce_varname, "auto-join")) {
			ircstrdup(tempiConf.auto_join_chans, cep->ce_vardata);
		}
		else if (!strcmp(cep->ce_varname, "oper-auto-join")) {
			ircstrdup(tempiConf.oper_auto_join_chans, cep->ce_vardata);
		}
		else if (!strcmp(cep->ce_varname, "allow-userhost-change")) {
			if (!stricmp(cep->ce_vardata, "always"))
				tempiConf.userhost_allowed = UHALLOW_ALWAYS;
			else if (!stricmp(cep->ce_vardata, "never"))
				tempiConf.userhost_allowed = UHALLOW_NEVER;
			else if (!stricmp(cep->ce_vardata, "not-on-channels"))
				tempiConf.userhost_allowed = UHALLOW_NOCHANS;
			else
				tempiConf.userhost_allowed = UHALLOW_REJOIN;
		}
		else if (!strcmp(cep->ce_varname, "channel-command-prefix")) {
			ircstrdup(tempiConf.channel_command_prefix, cep->ce_vardata);
		}
		else if (!strcmp(cep->ce_varname, "restrict-usermodes")) {
			int i;
			char *p = MyMalloc(strlen(cep->ce_vardata) + 1), *x = p;
			/* The data should be something like 'Gw' or something,
			 * but just in case users use '+Gw' then ignore the + (and -).
			 */
			for (i=0; i < strlen(cep->ce_vardata); i++)
				if ((cep->ce_vardata[i] != '+') && (cep->ce_vardata[i] != '-'))
					*x++ = cep->ce_vardata[i];
			*x = '\0';
			tempiConf.restrict_usermodes = p;
		}
		else if (!strcmp(cep->ce_varname, "restrict-channelmodes")) {
			int i;
			char *p = MyMalloc(strlen(cep->ce_vardata) + 1), *x = p;
			/* The data should be something like 'GL' or something,
			 * but just in case users use '+GL' then ignore the + (and -).
			 */
			for (i=0; i < strlen(cep->ce_vardata); i++)
				if ((cep->ce_vardata[i] != '+') && (cep->ce_vardata[i] != '-'))
					*x++ = cep->ce_vardata[i];
			*x = '\0';
			tempiConf.restrict_channelmodes = p;
		}
		else if (!strcmp(cep->ce_varname, "restrict-extendedbans")) {
			ircstrdup(tempiConf.restrict_extendedbans, cep->ce_vardata);
		}
		else if (!strcmp(cep->ce_varname, "anti-spam-quit-message-time")) {
			tempiConf.anti_spam_quit_message_time = config_checkval(cep->ce_vardata,CFG_TIME);
		}
		else if (!strcmp(cep->ce_varname, "oper-only-stats")) {
			if (!cep->ce_entries)
			{
				ircstrdup(tempiConf.oper_only_stats, cep->ce_vardata);
			}
			else
			{
				for (cepp = cep->ce_entries; cepp; cepp = cepp->ce_next)
				{
					OperStat *os = MyMallocEx(sizeof(OperStat));
					ircstrdup(os->flag, cepp->ce_varname);
					AddListItem(os, tempiConf.oper_only_stats_ext);
				}
			}
		}
		else if (!strcmp(cep->ce_varname, "maxchannelsperuser")) {
			tempiConf.maxchannelsperuser = atoi(cep->ce_vardata);
		}
		else if (!strcmp(cep->ce_varname, "maxdccallow")) {
			tempiConf.maxdccallow = atoi(cep->ce_vardata);
		}
		else if (!strcmp(cep->ce_varname, "network-name")) {
			char *tmp;
			ircstrdup(tempiConf.network.x_ircnetwork, cep->ce_vardata);
			for (tmp = cep->ce_vardata; *cep->ce_vardata; cep->ce_vardata++) {
				if (*cep->ce_vardata == ' ')
					*cep->ce_vardata='-';
			}
			ircstrdup(tempiConf.network.x_ircnet005, tmp);
			cep->ce_vardata = tmp;
		}
		else if (!strcmp(cep->ce_varname, "default-server")) {
			ircstrdup(tempiConf.network.x_defserv, cep->ce_vardata);
		}
		else if (!strcmp(cep->ce_varname, "services-server")) {
			ircstrdup(tempiConf.network.x_services_name, cep->ce_vardata);
		}
		else if (!strcmp(cep->ce_varname, "stats-server")) {
			ircstrdup(tempiConf.network.x_stats_server, cep->ce_vardata);
		}
		else if (!strcmp(cep->ce_varname, "help-channel")) {
			ircstrdup(tempiConf.network.x_helpchan, cep->ce_vardata);
		}
		else if (!strcmp(cep->ce_varname, "hiddenhost-prefix")) {
			ircstrdup(tempiConf.network.x_hidden_host, cep->ce_vardata);
		}
		else if (!strcmp(cep->ce_varname, "prefix-quit")) {
			if (*cep->ce_vardata == '0')
			{
				ircstrdup(tempiConf.network.x_prefix_quit, "");
			}
			else
				ircstrdup(tempiConf.network.x_prefix_quit, cep->ce_vardata);
		}
		else if (!strcmp(cep->ce_varname, "dns")) {
			for (cepp = cep->ce_entries; cepp; cepp = cepp->ce_next) {
				if (!strcmp(cepp->ce_varname, "timeout")) {
					tempiConf.host_timeout = config_checkval(cepp->ce_vardata,CFG_TIME);
				}
				else if (!strcmp(cepp->ce_varname, "retries")) {
					tempiConf.host_retries = config_checkval(cepp->ce_vardata,CFG_TIME);
				}
				else if (!strcmp(cepp->ce_varname, "nameserver")) {
					ircstrdup(tempiConf.name_server, cepp->ce_vardata);
				}
			}
		}
#ifdef THROTTLING
		else if (!strcmp(cep->ce_varname, "throttle")) {
			for (cepp = cep->ce_entries; cepp; cepp = cepp->ce_next) {
				if (!strcmp(cepp->ce_varname, "period")) 
					tempiConf.throttle_period = config_checkval(cepp->ce_vardata,CFG_TIME);
				else if (!strcmp(cepp->ce_varname, "connections"))
					tempiConf.throttle_count = atoi(cepp->ce_vardata);
			}
		}
#endif
		else if (!strcmp(cep->ce_varname, "anti-flood")) {
			for (cepp = cep->ce_entries; cepp; cepp = cepp->ce_next) {
				if (!strcmp(cepp->ce_varname, "unknown-flood-bantime")) 
					tempiConf.unknown_flood_bantime = config_checkval(cepp->ce_vardata,CFG_TIME);
				else if (!strcmp(cepp->ce_varname, "unknown-flood-amount"))
					tempiConf.unknown_flood_amount = atol(cepp->ce_vardata);
#ifdef NO_FLOOD_AWAY
				else if (!strcmp(cepp->ce_varname, "away-count"))
					tempiConf.away_count = atol(cepp->ce_vardata);
				else if (!strcmp(cepp->ce_varname, "away-period"))
					tempiConf.away_period = config_checkval(cepp->ce_vardata, CFG_TIME);
				else if (!strcmp(cepp->ce_varname, "away-flood"))
				{
					int cnt, period;
					config_parse_flood(cepp->ce_vardata, &cnt, &period);
					tempiConf.away_count = cnt;
					tempiConf.away_period = period;
				}
#endif
				else if (!strcmp(cepp->ce_varname, "nick-flood"))
				{
					int cnt, period;
					config_parse_flood(cepp->ce_vardata, &cnt, &period);
					tempiConf.nick_count = cnt;
					tempiConf.nick_period = period;
				}

			}
		}
		else if (!strcmp(cep->ce_varname, "options")) {
			for (cepp = cep->ce_entries; cepp; cepp = cepp->ce_next) {
				if (!strcmp(cepp->ce_varname, "webtv-support")) {
					tempiConf.webtv_support = 1;
				}
				else if (!strcmp(cepp->ce_varname, "hide-ulines")) {
					tempiConf.hide_ulines = 1;
				}
				else if (!strcmp(cepp->ce_varname, "flat-map")) {
					tempiConf.flat_map = 1;
				}
				else if (!strcmp(cepp->ce_varname, "no-stealth")) {
					tempiConf.no_oper_hiding = 1;
				}
				else if (!strcmp(cepp->ce_varname, "show-opermotd")) {
					tempiConf.som = 1;
				}
				else if (!strcmp(cepp->ce_varname, "identd-check")) {
					tempiConf.ident_check = 1;
				}
				else if (!strcmp(cepp->ce_varname, "fail-oper-warn")) {
					tempiConf.fail_oper_warn = 1;
				}
				else if (!strcmp(cepp->ce_varname, "show-connect-info")) {
					tempiConf.show_connect_info = 1;
				}
				else if (!strcmp(cepp->ce_varname, "dont-resolve")) {
					tempiConf.dont_resolve = 1;
				}
				else if (!strcmp(cepp->ce_varname, "mkpasswd-for-everyone")) {
					tempiConf.mkpasswd_for_everyone = 1;
				}
				else if (!strcmp(cepp->ce_varname, "allow-part-if-shunned")) {
					tempiConf.allow_part_if_shunned = 1;
				}
			}
		}
		else if (!strcmp(cep->ce_varname, "hosts")) {
			for (cepp = cep->ce_entries; cepp; cepp = cepp->ce_next)
			{
				if (!strcmp(cepp->ce_varname, "local")) {
					ircstrdup(tempiConf.network.x_locop_host, cepp->ce_vardata);
				}
				else if (!strcmp(cepp->ce_varname, "global")) {
					ircstrdup(tempiConf.network.x_oper_host, cepp->ce_vardata);
				}
				else if (!strcmp(cepp->ce_varname, "coadmin")) {
					ircstrdup(tempiConf.network.x_coadmin_host, cepp->ce_vardata);
				}
				else if (!strcmp(cepp->ce_varname, "admin")) {
					ircstrdup(tempiConf.network.x_admin_host, cepp->ce_vardata);
				}
				else if (!strcmp(cepp->ce_varname, "servicesadmin")) {
					ircstrdup(tempiConf.network.x_sadmin_host, cepp->ce_vardata);
				}
				else if (!strcmp(cepp->ce_varname, "netadmin")) {
					ircstrdup(tempiConf.network.x_netadmin_host, cepp->ce_vardata);
				}
				else if (!strcmp(cepp->ce_varname, "host-on-oper-up")) {
					tempiConf.network.x_inah = config_checkval(cepp->ce_vardata,CFG_YESNO);
				}
			}
		}
		else if (!strcmp(cep->ce_varname, "cloak-keys"))
		{
			for (h = Hooks[HOOKTYPE_CONFIGRUN]; h; h = h->next)
			{
				int value;
				value = (*(h->func.intfunc))(conf, cep, CONFIG_CLOAKKEYS);
				if (value == 1)
					break;
			}
		}
		else if (!strcmp(cep->ce_varname, "ident"))
		{
			for (cepp = cep->ce_entries; cepp; cepp = cepp->ce_next)
			{
				if (!strcmp(cepp->ce_varname, "connect-timeout"))
					tempiConf.ident_connect_timeout = config_checkval(cepp->ce_vardata,CFG_TIME);
				if (!strcmp(cepp->ce_varname, "read-timeout"))
					tempiConf.ident_read_timeout = config_checkval(cepp->ce_vardata,CFG_TIME);
			}
		}
		else if (!strcmp(cep->ce_varname, "spamfilter"))
		{
			for (cepp = cep->ce_entries; cepp; cepp = cepp->ce_next)
			{
				if (!strcmp(cepp->ce_varname, "ban-time"))
					tempiConf.spamfilter_ban_time = config_checkval(cepp->ce_vardata,CFG_TIME);
				if (!strcmp(cepp->ce_varname, "ban-reason"))
					ircstrdup(tempiConf.spamfilter_ban_reason, cepp->ce_vardata);
				if (!strcmp(cepp->ce_varname, "virus-help-channel"))
					ircstrdup(tempiConf.spamfilter_virus_help_channel, cepp->ce_vardata);
				if (!strcmp(cepp->ce_varname, "virus-help-channel-deny"))
					tempiConf.spamfilter_vchan_deny = config_checkval(cepp->ce_vardata,CFG_YESNO);
				if (!strcmp(cepp->ce_varname, "except"))
				{
					char *name, *p;
					SpamExcept *e;
					ircstrdup(tempiConf.spamexcept_line, cepp->ce_vardata);
					for (name = strtoken(&p, cepp->ce_vardata, ","); name; name = strtoken(&p, NULL, ","))
					{
						if (*name == ' ')
							name++;
						if (*name)
						{
							e = MyMallocEx(sizeof(SpamExcept) + strlen(name));
							strcpy(e->name, name);
							AddListItem(e, tempiConf.spamexcept);
						}
					}
				}
			}
		}
		else if (!strcmp(cep->ce_varname, "default-bantime"))
		{
			tempiConf.default_bantime = config_checkval(cep->ce_vardata,CFG_TIME);
		}
		else if (!strcmp(cep->ce_varname, "ban-version-tkl-time"))
		{
			tempiConf.ban_version_tkl_time = config_checkval(cep->ce_vardata,CFG_TIME);
		}
#ifdef NEWCHFLOODPROT
		else if (!strcmp(cep->ce_varname, "modef-default-unsettime")) {
			int v = atoi(cep->ce_vardata);
			tempiConf.modef_default_unsettime = (unsigned char)v;
		}
		else if (!strcmp(cep->ce_varname, "modef-max-unsettime")) {
			int v = atoi(cep->ce_vardata);
			tempiConf.modef_max_unsettime = (unsigned char)v;
		}
#endif
		else if (!strcmp(cep->ce_varname, "ssl")) {
#ifdef USE_SSL
			for (cepp = cep->ce_entries; cepp; cepp = cepp->ce_next) {
				if (!strcmp(cepp->ce_varname, "egd")) {
					tempiConf.use_egd = 1;
					if (cepp->ce_vardata)
						tempiConf.egd_path = strdup(cepp->ce_vardata);
				}
				else if (!strcmp(cepp->ce_varname, "certificate"))
				{
					ircstrdup(tempiConf.x_server_cert_pem, cepp->ce_vardata);	
				}
				else if (!strcmp(cepp->ce_varname, "key"))
				{
					ircstrdup(tempiConf.x_server_key_pem, cepp->ce_vardata);	
				}
				else if (!strcmp(cepp->ce_varname, "trusted-ca-file"))
				{
					ircstrdup(tempiConf.trusted_ca_file, cepp->ce_vardata);
				}
				else if (!strcmp(cepp->ce_varname, "options"))
				{
					tempiConf.ssl_options = 0;
					for (ceppp = cepp->ce_entries; ceppp; ceppp = ceppp->ce_next)
					{
						for (ofl = _SSLFlags; ofl->name; ofl++)
						{
							if (!strcmp(ceppp->ce_varname, ofl->name))
							{	
								tempiConf.ssl_options |= ofl->flag;
								break;
							}
						}
					}
					if (tempiConf.ssl_options & SSLFLAG_DONOTACCEPTSELFSIGNED)
						if (!tempiConf.ssl_options & SSLFLAG_VERIFYCERT)
							tempiConf.ssl_options |= SSLFLAG_VERIFYCERT;
				}	
				
			}
#endif
		}
		else 
		{
			int value;
			for (h = Hooks[HOOKTYPE_CONFIGRUN]; h; h = h->next)
			{
				value = (*(h->func.intfunc))(conf,cep,CONFIG_SET);
				if (value == 1)
					break;
			}
		}
	}
	return 0;
}

int	_test_set(ConfigFile *conf, ConfigEntry *ce)
{
	ConfigEntry *cep, *cepp, *ceppp;
	OperFlag 	*ofl = NULL;
	long		templong, l1, l2,l3;
	int		tempi;
	int	    i;
	int	    errors = 0;
	Hook	*h;
#define CheckNull(x) if ((!(x)->ce_vardata) || (!(*((x)->ce_vardata)))) { config_error("%s:%i: missing parameter", (x)->ce_fileptr->cf_filename, (x)->ce_varlinenum); errors++; continue; }
	for (cep = ce->ce_entries; cep; cep = cep->ce_next)
	{
		if (!cep->ce_varname)
		{
			config_error("%s:%i: item vac�o",
				cep->ce_fileptr->cf_filename,
				cep->ce_varlinenum);
			errors++;
			continue;
		}
		if (!strcmp(cep->ce_varname, "kline-address")) {
			CheckNull(cep);
			if (!strchr(cep->ce_vardata, '@') && !strchr(cep->ce_vardata, ':'))
			{
				config_error("%s:%i: set::kline-address tiene que ser un email o una web",
					cep->ce_fileptr->cf_filename, cep->ce_varlinenum);
				errors++;
				continue;
			}
			else if (!match("*@unrealircd.com", cep->ce_vardata) || !match("*@unrealircd.org",cep->ce_vardata) || !match("unreal-*@lists.sourceforge.net",cep->ce_vardata)) 
			{
				config_error("%s:%i: set::kline-address no puede ser la direcci�n de UnrealIRCd",
					cep->ce_fileptr->cf_filename, cep->ce_varlinenum);
				errors++; continue;
			}
			requiredstuff.settings.kline_address = 1;
		}
		else if (!strcmp(cep->ce_varname, "modes-on-connect")) {
			CheckNull(cep);
			templong = (long) set_usermode(cep->ce_vardata);
			if (templong & UMODE_OPER)
			{
				config_error("%s:%i: set::modes-on-connect contiene el modo +o",
					cep->ce_fileptr->cf_filename,
					cep->ce_varlinenum);
				errors++;
				continue;
			}
		}
		else if (!strcmp(cep->ce_varname, "modes-on-join")) {
			char *c;
			struct ChMode temp;
			bzero(&temp, sizeof(temp));
			CheckNull(cep);
			for (c = cep->ce_vardata; *c; c++)
			{
				if (*c == ' ')
					break; /* don't check the parameter ;p */
				switch (*c)
				{
					case 'q':
					case 'a':
					case 'o':
					case 'h':
					case 'v':
					case 'b':
					case 'e':
					case 'O':
					case 'A':
					case 'z':
					case 'l':
					case 'k':
					case 'L':
						config_error("%s:%i: set::modes-on-join contiene +%c", 
							cep->ce_fileptr->cf_filename, cep->ce_varlinenum, *c);
						errors++;
						break;
				}
			}
			set_channelmodes(cep->ce_vardata, &temp, 1);
			if (temp.mode & MODE_NOKNOCK && !(temp.mode & MODE_INVITEONLY))
			{
				config_error("%s:%i: set::modes-on-join tiene +K pero no +i",
					cep->ce_fileptr->cf_filename, cep->ce_varlinenum);
				errors++;
			}
			if (temp.mode & MODE_NOCOLOR && temp.mode & MODE_STRIP)
			{
				config_error("%s:%i: set::modes-on-join tiene +c y +S",
					cep->ce_fileptr->cf_filename, cep->ce_varlinenum);
				errors++;
			}
			if (temp.mode & MODE_SECRET && temp.mode & MODE_PRIVATE)
			{
				config_error("%s:%i: set::modes-on-join tiene +s y +p",
					cep->ce_fileptr->cf_filename, cep->ce_varlinenum);
				errors++;
			}
			
		}
		else if (!strcmp(cep->ce_varname, "modes-on-oper")) {
			CheckNull(cep);
			templong = (long) set_usermode(cep->ce_vardata);
		}
		else if (!strcmp(cep->ce_varname, "snomask-on-oper")) {
			CheckNull(cep);
		}
		else if (!strcmp(cep->ce_varname, "snomask-on-connect")) {
			CheckNull(cep);
		}
		else if (!strcmp(cep->ce_varname, "static-quit")) {
			CheckNull(cep);
		}
		else if (!strcmp(cep->ce_varname, "static-part")) {
			CheckNull(cep);
		}
		else if (!strcmp(cep->ce_varname, "who-limit")) {
			CheckNull(cep);
		}
		else if (!strcmp(cep->ce_varname, "silence-limit")) {
			CheckNull(cep);
		}
		else if (!strcmp(cep->ce_varname, "auto-join")) {
			CheckNull(cep);
		}
		else if (!strcmp(cep->ce_varname, "oper-auto-join")) {
			CheckNull(cep);
		}
		else if (!strcmp(cep->ce_varname, "channel-command-prefix")) {
			CheckNull(cep);
		}
		else if (!strcmp(cep->ce_varname, "allow-userhost-change")) {
			CheckNull(cep);
			if (stricmp(cep->ce_vardata, "always") && 
			    stricmp(cep->ce_vardata, "never") &&
			    stricmp(cep->ce_vardata, "not-on-channels") &&
			    stricmp(cep->ce_vardata, "force-rejoin"))
			{
				config_error("%s:%i: set::allow-userhost-change inv�lido",
					cep->ce_fileptr->cf_filename,
					cep->ce_varlinenum);
				errors++;
				continue;
			}
		}
		else if (!strcmp(cep->ce_varname, "anti-spam-quit-message-time")) {
			CheckNull(cep);
		}
		else if (!strcmp(cep->ce_varname, "oper-only-stats")) {
			if (!cep->ce_entries)
			{
				CheckNull(cep);
			}
			else
			{
				for (cepp = cep->ce_entries; cepp; cepp = cepp->ce_next)
				{
					if (!cepp->ce_varname)
						config_error("%s:%i: set::oper-only-stats item vac�o",
							cepp->ce_fileptr->cf_filename,
							cepp->ce_varlinenum);
				}
			}
		}
		else if (!strcmp(cep->ce_varname, "maxchannelsperuser")) {
			CheckNull(cep);
			tempi = atoi(cep->ce_vardata);
			if (tempi < 1)
			{
				config_error("%s:%i: set::maxchannelsperuser err�neo (> 0)",
					cep->ce_fileptr->cf_filename,
					cep->ce_varlinenum);
				errors++;
				continue;
			}
			requiredstuff.settings.maxchannelsperuser = 1;
		}
		else if (!strcmp(cep->ce_varname, "maxdccallow")) {
			CheckNull(cep);
		}
		else if (!strcmp(cep->ce_varname, "network-name")) {
			CheckNull(cep);
			requiredstuff.settings.irc_network = 1;
		}
		else if (!strcmp(cep->ce_varname, "default-server")) {
			CheckNull(cep);
			requiredstuff.settings.defaultserv = 1;
		}
		else if (!strcmp(cep->ce_varname, "services-server")) {
			CheckNull(cep);
			requiredstuff.settings.servicesserv = 1;
		}
		else if (!strcmp(cep->ce_varname, "stats-server")) {
			CheckNull(cep);
		}
		else if (!strcmp(cep->ce_varname, "help-channel")) {
			CheckNull(cep);
			requiredstuff.settings.hlpchan = 1;
		}
		else if (!strcmp(cep->ce_varname, "hiddenhost-prefix")) {
			CheckNull(cep);
			if (strchr(cep->ce_vardata, ' ') || (*cep->ce_vardata == ':'))
			{
				config_error("%s:%i: set::hiddenhost-prefix no puede contener espacios o empezar con ':'",
					cep->ce_fileptr->cf_filename, cep->ce_varlinenum);
				errors++;
				continue;
			}
			requiredstuff.settings.hidhost = 1;
		}
		else if (!strcmp(cep->ce_varname, "prefix-quit")) {
			CheckNull(cep);
		}
		else if (!strcmp(cep->ce_varname, "restrict-usermodes"))
		{
			CheckNull(cep);
			if (cep->ce_varname) {
				int warn = 0;
				char *p;
				for (p = cep->ce_vardata; *p; p++)
					if ((*p == '+') || (*p == '-'))
						warn = 1;
				if (warn) {
					config_status("%s:%i: advertencia: set::restrict-usermodes: s�lo modos, no + o -.\n",
						cep->ce_fileptr->cf_filename, cep->ce_varlinenum);
				}
			}
		}
		else if (!strcmp(cep->ce_varname, "restrict-channelmodes"))
		{
			CheckNull(cep);
			if (cep->ce_varname) {
				int warn = 0;
				char *p;
				for (p = cep->ce_vardata; *p; p++)
					if ((*p == '+') || (*p == '-'))
						warn = 1;
				if (warn) {
					config_status("%s:%i: advertencia: set::restrict-channelmodes: s�lo modos, no + o -.\n",
						cep->ce_fileptr->cf_filename, cep->ce_varlinenum);
				}
			}
		}
		else if (!strcmp(cep->ce_varname, "restrict-extendedbans"))
		{
			CheckNull(cep);
		}
		else if (!strcmp(cep->ce_varname, "dns")) {
			for (cepp = cep->ce_entries; cepp; cepp = cepp->ce_next) {
				CheckNull(cepp);
				if (!strcmp(cepp->ce_varname, "timeout")) {
					requiredstuff.settings.host_timeout = 1;
				}
				else if (!strcmp(cepp->ce_varname, "retries")) {
					requiredstuff.settings.host_retries = 1;
				}
				else if (!strcmp(cepp->ce_varname, "nameserver")) {
					struct in_addr in;
					
					in.s_addr = inet_addr(cepp->ce_vardata);
					if (strcmp((char *)inet_ntoa(in), cepp->ce_vardata))
					{
						config_error("%s:%i: set::dns::nameserver (%s) IP err�nea",
							cepp->ce_fileptr->cf_filename, cepp->ce_varlinenum,
							cepp->ce_vardata);
						errors++;
						continue;
					}
					requiredstuff.settings.name_server = 1;
				}
				else
				{
					config_error("%s:%i: unknown option set::dns::%s",
						cepp->ce_fileptr->cf_filename,
						cepp->ce_varlinenum,
						cepp->ce_varname);
						errors++;
				}
			}
		}
#ifdef THROTTLING
		else if (!strcmp(cep->ce_varname, "throttle")) {
			for (cepp = cep->ce_entries; cepp; cepp = cepp->ce_next) {
				CheckNull(cepp);
				if (!strcmp(cepp->ce_varname, "period")) {
					int x = config_checkval(cepp->ce_vardata,CFG_TIME);
					if (x > 86400*7)
					{
						config_error("%s:%i: insane set::throttle::period value",
							cepp->ce_fileptr->cf_filename,
							cepp->ce_varlinenum);
						errors++;
						continue;
					}
				}
				else if (!strcmp(cepp->ce_varname, "connections")) {
					int x = atoi(cepp->ce_vardata);
					if ((x < 1) || (x > 127))
					{
						config_error("%s:%i: set::throttle::connections out of range, should be 1-127",
							cepp->ce_fileptr->cf_filename, cepp->ce_varlinenum);
						errors++;
						continue;
					}
				}
				else
				{
					config_error("%s:%i: unknown option set::throttle::%s",
						cepp->ce_fileptr->cf_filename,
						cepp->ce_varlinenum,
						cepp->ce_varname);
					errors++;
					continue;
				}
			}
		}
#endif
		else if (!strcmp(cep->ce_varname, "anti-flood")) {
			for (cepp = cep->ce_entries; cepp; cepp = cepp->ce_next) {
				CheckNull(cepp);
				if (!strcmp(cepp->ce_varname, "unknown-flood-bantime")) {
				}
				else if (!strcmp(cepp->ce_varname, "unknown-flood-amount")) {
				}
#ifdef NO_FLOOD_AWAY
				else if (!strcmp(cepp->ce_varname, "away-count")) {
					int temp = atol(cepp->ce_vardata);
					if (temp < 1 || temp > 255)
					{
						config_error("%s:%i: set::anti-flood::away-count valor entre 1 y 255",
							cepp->ce_fileptr->cf_filename, cepp->ce_varlinenum);
						errors++;
					}
				}
				else if (!strcmp(cepp->ce_varname, "away-period")) {
					int temp = config_checkval(cepp->ce_vardata, CFG_TIME);
					if (temp < 10)
					{
						config_error("%s:%i: set::anti-flood::away-period mayor que 9",
							cepp->ce_fileptr->cf_filename, cepp->ce_varlinenum);
						errors++;
					}
				}
				else if (!strcmp(cepp->ce_varname, "away-flood"))
				{
					int cnt, period;
					if (!config_parse_flood(cepp->ce_vardata, &cnt, &period) ||
					    (cnt < 1) || (cnt > 255) || (period < 10))
					{
						config_error("%s:%i: set::anti-flood::away-flood error. Sintaxis '<v>:<s>' (ej 5:60), "
						             "<v> 1-255, <s> mayor que 9",
							cepp->ce_fileptr->cf_filename, cepp->ce_varlinenum);
						errors++;
					}
				}
#endif
				else if (!strcmp(cepp->ce_varname, "nick-flood"))
				{
					int cnt, period;
					if (!config_parse_flood(cepp->ce_vardata, &cnt, &period) ||
					    (cnt < 1) || (cnt > 255) || (period < 5))
					{
						config_error("%s:%i: set::anti-flood::nick-flood error. error. Sintaxis '<v>:<s>' (ej 5:60), "
						             "<v> 1-255, <s> mayor que 4",
							cepp->ce_fileptr->cf_filename, cepp->ce_varlinenum);
						errors++;
					}
				}
				else
				{
					config_error("%s:%i: opci�n desconocida set::anti-flood::%s",
						cepp->ce_fileptr->cf_filename,
						cepp->ce_varlinenum,
						cepp->ce_varname);
					errors++;
					continue;
				}
			}
		}
		else if (!strcmp(cep->ce_varname, "options")) {
			for (cepp = cep->ce_entries; cepp; cepp = cepp->ce_next) {
				if (!strcmp(cepp->ce_varname, "webtv-support")) {
				}
				else if (!strcmp(cepp->ce_varname, "hide-ulines")) {
				}
				else if (!strcmp(cepp->ce_varname, "flat-map")) {
				}
				else if (!strcmp(cepp->ce_varname, "no-stealth")) {
				}
				else if (!strcmp(cepp->ce_varname, "show-opermotd")) {
				}
				else if (!strcmp(cepp->ce_varname, "identd-check")) {
				}
				else if (!strcmp(cepp->ce_varname, "fail-oper-warn")) {
				}
				else if (!strcmp(cepp->ce_varname, "show-connect-info")) {
				}
				else if (!strcmp(cepp->ce_varname, "dont-resolve")) {
				}
				else if (!strcmp(cepp->ce_varname, "mkpasswd-for-everyone")) {
				}
				else if (!strcmp(cepp->ce_varname, "allow-part-if-shunned")) {
				}
				else
				{
					config_error("%s:%i: opci�n desconocida set::options::%s",
						cepp->ce_fileptr->cf_filename,
						cepp->ce_varlinenum,
						cepp->ce_varname);
					errors++;
					continue;
				}
			}
		}
		else if (!strcmp(cep->ce_varname, "hosts")) {
			for (cepp = cep->ce_entries; cepp; cepp = cepp->ce_next)
			{
				char *c, *host;
				if (!cepp->ce_vardata)
				{
					config_error("%s:%i: set::hosts item vac�o",
						cepp->ce_fileptr->cf_filename, cepp->ce_varlinenum);
					errors++;
					continue;
				} 
				if (!strcmp(cepp->ce_varname, "local")) {
					requiredstuff.settings.locophost = 1;
				}
				else if (!strcmp(cepp->ce_varname, "global")) {
					requiredstuff.settings.operhost = 1;
				}
				else if (!strcmp(cepp->ce_varname, "coadmin")) {
					requiredstuff.settings.coadminhost = 1;
				}
				else if (!strcmp(cepp->ce_varname, "admin")) {
					requiredstuff.settings.adminhost = 1;
				}
				else if (!strcmp(cepp->ce_varname, "servicesadmin")) {
					requiredstuff.settings.sadminhost = 1;
				}
				else if (!strcmp(cepp->ce_varname, "netadmin")) {
					requiredstuff.settings.netadminhost = 1;
				}
				else if (!strcmp(cepp->ce_varname, "host-on-oper-up")) {
				}
				else
				{
					config_error("%s:%i: directriz desconocida set::hosts::%s",
						cepp->ce_fileptr->cf_filename,
						cepp->ce_varlinenum,
						cepp->ce_varname);
					errors++;
					continue;

				}
				if ((c = strchr(cepp->ce_vardata, '@')))
				{
					char *tmp;
					if (!(*(c+1)) || (c-cepp->ce_vardata) > USERLEN ||
					    c == cepp->ce_vardata)
					{
						config_error("%s:%i: illegal value for set::hosts::%s",
							     cepp->ce_fileptr->cf_filename,
							     cepp->ce_varlinenum, 
							     cepp->ce_varname);
						errors++;
						continue;
					}
					for (tmp = cepp->ce_vardata; tmp != c; tmp++)
					{
						if (*tmp == '~' && tmp == cepp->ce_vardata)
							continue;
						if (!isallowed(*tmp))
							break;
					}
					if (tmp != c)
					{
						config_error("%s:%i: illegal value for set::hosts::%s",
							     cepp->ce_fileptr->cf_filename,
							     cepp->ce_varlinenum, 
							     cepp->ce_varname);
						errors++;
						continue;
					}
					host = c+1;
				}
				else
					host = cepp->ce_vardata;
				if (strlen(host) > HOSTLEN)
				{
					config_error("%s:%i: illegal value for set::hosts::%s",
						     cepp->ce_fileptr->cf_filename,
						     cepp->ce_varlinenum, 
						     cepp->ce_varname);
					errors++;
					continue;
				}
				for (; *host; host++)
				{
					if (!isallowed(*host) && *host != ':')
					{
						config_error("%s:%i: illegal value for set::hosts::%s",
							     cepp->ce_fileptr->cf_filename,
							     cepp->ce_varlinenum, 
							     cepp->ce_varname);
						errors++;
						continue;
					}
				}
			}
		}
		else if (!strcmp(cep->ce_varname, "cloak-keys"))
		{
			for (h = Hooks[HOOKTYPE_CONFIGTEST]; h; h = h->next)
			{
				int value, errs = 0;
				if (h->owner && !(h->owner->flags & MODFLAG_TESTING)
				    && !(h->owner->options & MOD_OPT_PERM))
					continue;
				value = (*(h->func.intfunc))(conf, cep, CONFIG_CLOAKKEYS, &errs);

				if (value == 1)
					break;
				if (value == -1)
				{
					errors += errs;
					break;
				}
				if (value == -2) 
					errors += errs;
			}
		}
		else if (!strcmp(cep->ce_varname, "scan")) {
			config_status("%s:%i: set::scan: advertencia: esc�ner de puertos deshabilitado, "
			    "usa BOPM: http://www.blitzed.org/bopm/ (*NIX) / http://vulnscan.org/winbopm/ (Windows)",
				cep->ce_fileptr->cf_filename, cep->ce_varlinenum);
		}
		else if (!strcmp(cep->ce_varname, "ident")) {
			for (cepp = cep->ce_entries; cepp; cepp = cepp->ce_next)
			{
				CheckNull(cepp);
				if (!strcmp(cepp->ce_varname, "connect-timeout") || !strcmp(cepp->ce_varname, "read-timeout"))
				{
					int v = config_checkval(cepp->ce_vardata,CFG_TIME);;
					if ((v > 60) || (v < 1))
					{
						config_error("%s:%i: set::ident::%s valor fuera de rango (%d), entre 1 y 60.",
							cepp->ce_fileptr->cf_filename, cepp->ce_varlinenum, cepp->ce_varname, v);
						errors++;
						continue;
					}
				} else {
					config_error("%s:%i: directriz desconocida set::ident::%s",
						cepp->ce_fileptr->cf_filename, cepp->ce_varlinenum, cepp->ce_varname);
					errors++;
					continue;
				}
			}
		}
		else if (!strcmp(cep->ce_varname, "spamfilter")) {
			for (cepp = cep->ce_entries; cepp; cepp = cepp->ce_next)
			{
				CheckNull(cepp);
				if (!strcmp(cepp->ce_varname, "ban-time"))
				{
					long x;
					x = config_checkval(cepp->ce_vardata,CFG_TIME);
					if ((x < 0) > (x > 2000000000))
					{
						config_error("%s:%i: set::spamfilter:ban-time: valor '%ld' fuera de rango",
							cep->ce_fileptr->cf_filename, cep->ce_varlinenum, x);
						errors++;
						continue;
					}
				} else
				if (!strcmp(cepp->ce_varname, "ban-reason"))
				{ } else
				if (!strcmp(cepp->ce_varname, "virus-help-channel"))
				{
					if ((cepp->ce_vardata[0] != '#') || (strlen(cepp->ce_vardata) > CHANNELLEN))
					{
						config_error("%s:%i: set::spamfilter:virus-help-channel: "
						             "specified channelname is too long or contains invalid characters (%s)",
						             cep->ce_fileptr->cf_filename, cep->ce_varlinenum,
						             cepp->ce_vardata);
						errors++;
						continue;
					}
				} else 
				if (!strcmp(cepp->ce_varname, "virus-help-channel-deny"))
				{ } else
				if (!strcmp(cepp->ce_varname, "except"))
				{ } else
				{
					config_error("%s:%i: unknown directive set::spamfilter::%s",
						cepp->ce_fileptr->cf_filename, cepp->ce_varlinenum, cepp->ce_varname);
					errors++;
					continue;
				}
			}
		}
		else if (!strcmp(cep->ce_varname, "default-bantime") ||
		         !strcmp(cep->ce_varname, "ban-version-tkl-time")) {
			long x;
			x = config_checkval(cep->ce_vardata,CFG_TIME);
			if ((x < 0) > (x > 2000000000))
			{
				config_error("%s:%i: set::%s: valor '%ld' fuera de rango",
					cep->ce_fileptr->cf_filename, cep->ce_varlinenum, cep->ce_varname, x);
				errors++;
			}
		}
#ifdef NEWCHFLOODPROT
		else if (!strcmp(cep->ce_varname, "modef-default-unsettime")) {
			int v = atoi(cep->ce_vardata);
			if ((v <= 0) || (v > 255))
			{
				config_error("%s:%i: set::modef-default-unsettime: valor '%d' fuera de rango (1-255)",
					cep->ce_fileptr->cf_filename, cep->ce_varlinenum, v);
				errors++;
			}
		}
		else if (!strcmp(cep->ce_varname, "modef-max-unsettime")) {
			int v = atoi(cep->ce_vardata);
			if ((v <= 0) || (v > 255))
			{
				config_error("%s:%i: set::modef-max-unsettime: valor '%d' fuera de rango (1-255)",
					cep->ce_fileptr->cf_filename, cep->ce_varlinenum, v);
				errors++;
			}
		}
#endif
		else if (!strcmp(cep->ce_varname, "ssl")) {
#ifdef USE_SSL
			for (cepp = cep->ce_entries; cepp; cepp = cepp->ce_next) {
				if (!strcmp(cepp->ce_varname, "egd")) {
				}
				else if (!strcmp(cepp->ce_varname, "certificate"))
				{
					CheckNull(cepp);
				}
				else if (!strcmp(cepp->ce_varname, "key"))
				{
					CheckNull(cepp);
				}
				else if (!strcmp(cepp->ce_varname, "trusted-ca-file"))
				{
					CheckNull(cepp);
				}
				else if (!strcmp(cepp->ce_varname, "options"))
				{
					for (ceppp = cepp->ce_entries; ceppp; ceppp = ceppp->ce_next)
					{
						for (ofl = _SSLFlags; ofl->name; ofl++)
						{
							if (!strcmp(ceppp->ce_varname, ofl->name))
							{	
								break;
							}
						}
					}
					if (ofl && !ofl->name)
					{
						config_error("%s:%i: modo SSL desconcido '%s'",
							ceppp->ce_fileptr->cf_filename, 
							ceppp->ce_varlinenum, ceppp->ce_varname);
					}
				}	
				
			}
#endif
		}
		else
		{
			int used = 0;
			for (h = Hooks[HOOKTYPE_CONFIGTEST]; h; h = h->next) 
			{
				int value, errs = 0;
				if (h->owner && !(h->owner->flags & MODFLAG_TESTING) &&
				                !(h->owner->options & MOD_OPT_PERM))
					continue;
				value = (*(h->func.intfunc))(conf,cep,CONFIG_SET, &errs);
				if (value == 2)
					used = 1;
				if (value == 1)
				{
					used = 1;
					break;
				}
				if (value == -1)
				{
					used = 1;
					errors += errs;
					break;
				}
				if (value == -2)
				{
					used = 1;
					errors += errs;
				}
			}
			if (!used) {
				config_error("%s:%i: directriz desconcida set::%s",
					cep->ce_fileptr->cf_filename, cep->ce_varlinenum,
					cep->ce_varname);
				errors++;
			}
		}
	}
	return errors;
}

int	_conf_loadmodule(ConfigFile *conf, ConfigEntry *ce)
{
#ifdef GLOBH
	glob_t files;
	int i;
#elif defined(_WIN32)
	HANDLE hFind;
	WIN32_FIND_DATA FindData;
	char cPath[MAX_PATH], *cSlash = NULL, *path;
#endif
	char *ret;
	if (!ce->ce_vardata)
	{
		config_status("%s:%i: loadmodule sin nombre de archivo",
			ce->ce_fileptr->cf_filename, ce->ce_varlinenum);
		return -1;
	}
#ifdef GLOBH
#if defined(__OpenBSD__) && defined(GLOB_LIMIT)
	glob(ce->ce_vardata, GLOB_NOSORT|GLOB_NOCHECK|GLOB_LIMIT, NULL, &files);
#else
	glob(ce->ce_vardata, GLOB_NOSORT|GLOB_NOCHECK, NULL, &files);
#endif
	if (!files.gl_pathc) {
		globfree(&files);
		config_status("%s:%i: loadmodule %s: falla al cargar",
			ce->ce_fileptr->cf_filename, ce->ce_varlinenum,
			ce->ce_vardata);
		return -1;
	}	
	for (i = 0; i < files.gl_pathc; i++) {
		if ((ret = Module_Create(files.gl_pathv[i]))) {
			config_status("%s:%i: loadmodule %s: falla al cargar: %s",
				ce->ce_fileptr->cf_filename, ce->ce_varlinenum,
				files.gl_pathv[i], ret);
			return -1;
		}
	}
	globfree(&files);
#elif defined(_WIN32)
	bzero(cPath,MAX_PATH);
	if (strchr(ce->ce_vardata, '/') || strchr(ce->ce_vardata, '\\')) {
		strncpyzt(cPath,ce->ce_vardata,MAX_PATH);
		cSlash=cPath+strlen(cPath);
		while(*cSlash != '\\' && *cSlash != '/' && cSlash > cPath)
			cSlash--; 
		*(cSlash+1)=0;
	}
	hFind = FindFirstFile(ce->ce_vardata, &FindData);
	if (!FindData.cFileName || hFind == INVALID_HANDLE_VALUE) {
		config_status("%s:%i: loadmodule %s: falla al cargar",
			ce->ce_fileptr->cf_filename, ce->ce_varlinenum,
			ce->ce_vardata);
		FindClose(hFind);
		return -1;
	}

	if (cPath) {
		path = MyMalloc(strlen(cPath) + strlen(FindData.cFileName)+1);
		strcpy(path,cPath);
		strcat(path,FindData.cFileName);
		if ((ret = Module_Create(path))) {
			config_status("%s:%i: loadmodule %s: no puede cargar: %s",
				ce->ce_fileptr->cf_filename, ce->ce_varlinenum,
				path, ret);
			free(path);
			return -1;
		}
		free(path);
	}
	else
	{
		if ((ret = Module_Create(FindData.cFileName))) {
			config_status("%s:%i: loadmodule %s: no puede cargar: %s",
				ce->ce_fileptr->cf_filename, ce->ce_varlinenum,
				FindData.cFileName, ret);
			return -1;
		}
	}
	while (FindNextFile(hFind, &FindData) != 0) {
		if (cPath) {
			path = MyMalloc(strlen(cPath) + strlen(FindData.cFileName)+1);
			strcpy(path,cPath);
			strcat(path,FindData.cFileName);		
			if ((ret = Module_Create(path)))
			{
				config_status("%s:%i: loadmodule %s: no puede cargar: %s",
					ce->ce_fileptr->cf_filename, ce->ce_varlinenum,
					FindData.cFileName, ret);
				free(path);
				return -1;
			}
			free(path);
		}
		else
		{
			if ((ret = Module_Create(FindData.cFileName)))
			{
				config_status("%s:%i: loadmodule %s: no puede cargar: %s",
					ce->ce_fileptr->cf_filename, ce->ce_varlinenum,
					FindData.cFileName, ret);
				return -1;
			}
		}
	}
	FindClose(hFind);
#else
	if ((ret = Module_Create(ce->ce_vardata))) {
			config_status("%s:%i: loadmodule %s: falla al cargar: %s",
				ce->ce_fileptr->cf_filename, ce->ce_varlinenum,
				ce->ce_vardata, ret);
				return -1;
	}
#endif
	return 1;
}

int	_test_loadmodule(ConfigFile *conf, ConfigEntry *ce)
{
	return 0;
}

/*
 * Actually use configuration
*/

void	run_configuration(void)
{
	ConfigItem_listen 	*listenptr;

	for (listenptr = conf_listen; listenptr; listenptr = (ConfigItem_listen *) listenptr->next)
	{
		if (!(listenptr->options & LISTENER_BOUND))
		{
			if (add_listener2(listenptr) == -1)
			{
				ircd_log(LOG_ERROR, "Falla enlace a %s:%i", listenptr->ip, listenptr->port);
			}
				else
			{
			}
		}
		else
		{
			if (listenptr->listener)
			{
				listenptr->listener->umodes = 
					(listenptr->options & ~LISTENER_BOUND) ? listenptr->options : LISTENER_NORMAL;
				listenptr->listener->umodes |= LISTENER_BOUND;
			}
		}
	}
}

int	_conf_offchans(ConfigFile *conf, ConfigEntry *ce)
{
	ConfigEntry *cep, *cepp;

	for (cep = ce->ce_entries; cep; cep = cep->ce_next)
	{
		ConfigItem_offchans *of = MyMallocEx(sizeof(ConfigItem_offchans));
		strlcpy(of->chname, cep->ce_varname, CHANNELLEN+1);
		for (cepp = cep->ce_entries; cepp; cepp = cepp->ce_next)
		{
			if (!strcmp(cepp->ce_varname, "topic"))
				of->topic = strdup(cepp->ce_vardata);
		}
		AddListItem(of, conf_offchans);
	}
	return 0;
}

int	_test_offchans(ConfigFile *conf, ConfigEntry *ce)
{
	int errors = 0;
	ConfigEntry *cep, *cep2;
	char checkchan[CHANNELLEN + 1];
	
	if (!ce->ce_entries)
	{
		config_error("%s:%i: official-channels vac�o", 
			ce->ce_fileptr->cf_filename, ce->ce_varlinenum);
		return 1;
	}
	for (cep = ce->ce_entries; cep; cep = cep->ce_next)
	{
		if (strlen(cep->ce_varname) > CHANNELLEN)
		{
			config_error("%s:%i: official-channels: '%s' nombre demasiado largo (max %d).",
				cep->ce_fileptr->cf_filename, cep->ce_varlinenum, cep->ce_varname, CHANNELLEN);
			errors++;
			continue;
		}
		strcpy(checkchan, cep->ce_varname); /* safe */
		clean_channelname(checkchan);
		if (strcmp(checkchan, cep->ce_varname) || (*cep->ce_varname != '#'))
		{
			config_error("%s:%i: official-channels: '%s' no es un nombre v�lido de canal.",
				cep->ce_fileptr->cf_filename, cep->ce_varlinenum, cep->ce_varname);
			errors++;
			continue;
		}
		for (cep2 = cep->ce_entries; cep2; cep2 = cep2->ce_next)
		{
			if (!cep2->ce_vardata)
			{
				config_error("%s:%i: official-channels::%s: %s no tiene valor",
					cep2->ce_fileptr->cf_filename, cep2->ce_varlinenum, cep->ce_varname, cep2->ce_varname);
				errors++;
				continue;
			}
			if (!strcmp(cep2->ce_varname, "topic"))
			{
				if (strlen(cep2->ce_vardata) > TOPICLEN)
				{
					config_error("%s:%i: official-channels::%s: topic demasiado largo (max %d).",
						cep2->ce_fileptr->cf_filename, cep2->ce_varlinenum, cep->ce_varname, TOPICLEN);
					errors++;
					continue;
				}
			} else {
				config_error("%s:%i: official-channels::%s: directriz desconocida '%s'.",
					cep2->ce_fileptr->cf_filename, cep2->ce_varlinenum, cep->ce_varname, cep2->ce_varname);
				errors++;
				continue;
			}
		}
	}
	return errors;
}


int	_conf_alias(ConfigFile *conf, ConfigEntry *ce)
{
	ConfigItem_alias *alias = NULL;
	ConfigItem_alias_format *format;
	ConfigEntry 	    	*cep, *cepp;
	aCommand *cmptr;

	if (!ce->ce_vardata)
	{
		config_status("%s:%i: alias sin nombre",
			ce->ce_fileptr->cf_filename, ce->ce_varlinenum);
		return -1;
	}
	if ((cmptr = find_Command(ce->ce_vardata, 0, M_ALIAS)))
		del_Command(ce->ce_vardata, NULL, cmptr->func);
	if ((alias = Find_alias(ce->ce_vardata)))
		DelListItem(alias, conf_alias);
	alias = MyMallocEx(sizeof(ConfigItem_alias));
	ircstrdup(alias->alias, ce->ce_vardata);
	for (cep = ce->ce_entries; cep; cep = cep->ce_next)
	{
		if (!strcmp(cep->ce_varname, "format")) {
			format = MyMallocEx(sizeof(ConfigItem_alias_format));
			ircstrdup(format->format, cep->ce_vardata);
			regcomp(&format->expr, cep->ce_vardata, REG_ICASE|REG_EXTENDED);
			for (cepp = cep->ce_entries; cepp; cepp = cepp->ce_next) {
				if (!strcmp(cepp->ce_varname, "nick")) {
					ircstrdup(format->nick, cepp->ce_vardata);
				}
				else if (!strcmp(cepp->ce_varname, "parameters")) {
					ircstrdup(format->parameters, cepp->ce_vardata);
				}
				else if (!strcmp(cepp->ce_varname, "type")) {
					if (!strcmp(cepp->ce_vardata, "services"))
						format->type = ALIAS_SERVICES;
					else if (!strcmp(cepp->ce_vardata, "stats"))
						format->type = ALIAS_STATS;
					else if (!strcmp(cepp->ce_vardata, "normal"))
						format->type = ALIAS_NORMAL;
				}
			}
			AddListItem(format, alias->format);
		}		
				
		else if (!strcmp(cep->ce_varname, "nick")) {
			ircstrdup(alias->nick, cep->ce_vardata);
		}
		else if (!strcmp(cep->ce_varname, "type")) {
			if (!strcmp(cep->ce_vardata, "services"))
				alias->type = ALIAS_SERVICES;
			else if (!strcmp(cep->ce_vardata, "stats"))
				alias->type = ALIAS_STATS;
			else if (!strcmp(cep->ce_vardata, "normal"))
				alias->type = ALIAS_NORMAL;
			else if (!strcmp(cep->ce_vardata, "command"))
				alias->type = ALIAS_COMMAND;
		}
			
	}
	if (BadPtr(alias->nick) && alias->type != ALIAS_COMMAND) {
		ircstrdup(alias->nick, alias->alias); 
	}
	add_CommandX(alias->alias, NULL, m_alias, 1, M_USER|M_ALIAS);
	AddListItem(alias, conf_alias);
	return 0;
}


int _test_alias(ConfigFile *conf, ConfigEntry *ce) { 
	int errors = 0;
	ConfigEntry *cep, *cepp;
	if (!ce->ce_entries)
	{
		config_error("%s:%i: alias vac�o", 
			ce->ce_fileptr->cf_filename, ce->ce_varlinenum);
		return 1;
	}
	if (!ce->ce_vardata) 
	{
		config_error("%s:%i: alias sin nombre", 
			ce->ce_fileptr->cf_filename, ce->ce_varlinenum);
		errors++;
	}
	else if (!find_Command(ce->ce_vardata, 0, M_ALIAS) && find_Command(ce->ce_vardata, 0, 0)) {
		config_status("%s:%i: %s es un comando, no un alias",
			ce->ce_fileptr->cf_filename, ce->ce_varlinenum, ce->ce_vardata);
		errors++;
	}
	if (!config_find_entry(ce->ce_entries, "type"))
	{
		config_error("%s:%i: alias::type falta", ce->ce_fileptr->cf_filename,
			ce->ce_varlinenum);
		errors++;
	}
	for (cep = ce->ce_entries; cep; cep = cep->ce_next)
	{
		if (!cep->ce_varname)
		{
			config_error("%s:%i: alias item vac�o",
				cep->ce_fileptr->cf_filename, cep->ce_varlinenum);
			errors++; continue;
		}
		if (!cep->ce_vardata)
		{
			config_error("%s:%i: alias::%s sin par�metro",
				cep->ce_fileptr->cf_filename,
				cep->ce_varlinenum,
				cep->ce_varname);
			errors++; continue;
		}

		if (!strcmp(cep->ce_varname, "format")) {
			int errorcode, errorbufsize;
			char *errorbuf;
			regex_t expr;
			errorcode = regcomp(&expr, cep->ce_vardata, REG_ICASE|REG_EXTENDED);
                        if (errorcode > 0)
                        {
                                errorbufsize = regerror(errorcode, &expr, NULL, 0)+1;
                                errorbuf = MyMalloc(errorbufsize);
                                regerror(errorcode, &expr, errorbuf, errorbufsize);
                                config_error("%s:%i: alias::format regex err�neo: %s",
 					cep->ce_fileptr->cf_filename,
 					cep->ce_varlinenum,
 					errorbuf);
                                errors++;
                                free(errorbuf);
                        }
			regfree(&expr);	
			if (!config_find_entry(cep->ce_entries, "type"))
			{
				config_error("%s:%i: alias::format::type falta", cep->ce_fileptr->cf_filename,
				cep->ce_varlinenum);
				errors++;
			}
			if (!config_find_entry(cep->ce_entries, "nick"))
			{
				config_error("%s:%i: alias::format::nick falta", cep->ce_fileptr->cf_filename,
					cep->ce_varlinenum);
				errors++;
			}
			for (cepp = cep->ce_entries; cepp; cepp = cepp->ce_next) {
				if (!cepp->ce_vardata)
				{
					config_error("%s:%i: alias::format::%s sin par�metros",
						cepp->ce_fileptr->cf_filename,
						cepp->ce_varlinenum,
						cepp->ce_varname);
					errors++; continue;
				}
				if (!strcmp(cepp->ce_varname, "nick")) 
					;
				else if (!strcmp(cepp->ce_varname, "type"))
				{
					if (!strcmp(cepp->ce_vardata, "services"))
						;
					else if (!strcmp(cepp->ce_vardata, "stats"))
						;
					else if (!strcmp(cepp->ce_vardata, "normal"))
						;
					else {
						config_status("%s:%i: unknown alias type",
						cepp->ce_fileptr->cf_filename, cepp->ce_varlinenum);
						errors++;
					}
				}
				else if (!strcmp(cepp->ce_varname, "parameters")) 
					;
				else {
					config_status("%s:%i: directriz desconocida alias::format::%s",
						cepp->ce_fileptr->cf_filename, cepp->ce_varlinenum, cepp->ce_varname);
					errors++;
				}
			}
		}
		else if (!strcmp(cep->ce_varname, "nick")) 
			;
		else if (!strcmp(cep->ce_varname, "type")) {
			if (!strcmp(cep->ce_vardata, "services"))
				;
			else if (!strcmp(cep->ce_vardata, "stats"))
				;
			else if (!strcmp(cep->ce_vardata, "normal"))
				;
			else if (!strcmp(cep->ce_vardata, "command"))
				;
			else {
				config_status("%s:%i: desconocido tipo alias",
					cep->ce_fileptr->cf_filename, cep->ce_varlinenum);
				errors++;
			}
		}
		else {
			config_error("%s:%i: directriz desconocida alias::%s",
				cep->ce_fileptr->cf_filename, cep->ce_varlinenum,
				cep->ce_varname);
			errors++;
		}
	}
	return errors; 
}

int	_conf_deny(ConfigFile *conf, ConfigEntry *ce)
{
Hook *h;

	if (!strcmp(ce->ce_vardata, "dcc"))
		_conf_deny_dcc(conf, ce);
	else if (!strcmp(ce->ce_vardata, "channel"))
		_conf_deny_channel(conf, ce);
	else if (!strcmp(ce->ce_vardata, "link"))
		_conf_deny_link(conf, ce);
	else if (!strcmp(ce->ce_vardata, "version"))
		_conf_deny_version(conf, ce);
	else
	{
		int value;
		for (h = Hooks[HOOKTYPE_CONFIGRUN]; h; h = h->next)
		{
			value = (*(h->func.intfunc))(conf,ce,CONFIG_DENY);
			if (value == 1)
				break;
		}
		return 0;
	}
	return 0;
}

int	_conf_deny_dcc(ConfigFile *conf, ConfigEntry *ce)
{
	ConfigItem_deny_dcc 	*deny = NULL;
	ConfigEntry 	    	*cep;

	deny = MyMallocEx(sizeof(ConfigItem_deny_dcc));
	for (cep = ce->ce_entries; cep; cep = cep->ce_next)
	{
		if (!strcmp(cep->ce_varname, "filename"))
		{
			ircstrdup(deny->filename, cep->ce_vardata);
		}
		else if (!strcmp(cep->ce_varname, "reason"))
		{
			ircstrdup(deny->reason, cep->ce_vardata);
		}
		else if (!strcmp(cep->ce_varname, "soft"))
		{
			int x = config_checkval(cep->ce_vardata,CFG_YESNO);
			if (x == 1)
				deny->flag.type = DCCDENY_SOFT;
		}
	}
	if (!deny->reason)
	{
		if (deny->flag.type == DCCDENY_HARD)
			ircstrdup(deny->reason, "Possible infected virus file");
		else
			ircstrdup(deny->reason, "Possible executable content");
	}
	AddListItem(deny, conf_deny_dcc);
	return 0;
}

int	_conf_deny_channel(ConfigFile *conf, ConfigEntry *ce)
{
	ConfigItem_deny_channel 	*deny = NULL;
	ConfigEntry 	    	*cep;

	deny = MyMallocEx(sizeof(ConfigItem_deny_channel));
	for (cep = ce->ce_entries; cep; cep = cep->ce_next)
	{
		if (!strcmp(cep->ce_varname, "channel"))
		{
			ircstrdup(deny->channel, cep->ce_vardata);
		}
		else if (!strcmp(cep->ce_varname, "redirect"))
		{
			ircstrdup(deny->redirect, cep->ce_vardata);
		}
		else if (!strcmp(cep->ce_varname, "reason"))
		{
			ircstrdup(deny->reason, cep->ce_vardata);
		}
		else if (!strcmp(cep->ce_varname, "warn"))
		{
			deny->warn = config_checkval(cep->ce_vardata,CFG_YESNO);
		}
	}
	AddListItem(deny, conf_deny_channel);
	return 0;
}
int	_conf_deny_link(ConfigFile *conf, ConfigEntry *ce)
{
	ConfigItem_deny_link 	*deny = NULL;
	ConfigEntry 	    	*cep;

	deny = MyMallocEx(sizeof(ConfigItem_deny_link));
	for (cep = ce->ce_entries; cep; cep = cep->ce_next)
	{
		if (!strcmp(cep->ce_varname, "mask"))
		{
			ircstrdup(deny->mask, cep->ce_vardata);
		}
		else if (!strcmp(cep->ce_varname, "rule"))
		{
			deny->rule = (char *)crule_parse(cep->ce_vardata);
			ircstrdup(deny->prettyrule, cep->ce_vardata);
		}
		else if (!strcmp(cep->ce_varname, "type")) {
			if (!strcmp(cep->ce_vardata, "all"))
				deny->flag.type = CRULE_ALL;
			else if (!strcmp(cep->ce_vardata, "auto"))
				deny->flag.type = CRULE_AUTO;
		}
	}
	AddListItem(deny, conf_deny_link);
	return 0;
}

int	_conf_deny_version(ConfigFile *conf, ConfigEntry *ce)
{
	ConfigItem_deny_version *deny = NULL;
	ConfigEntry 	    	*cep;

	deny = MyMallocEx(sizeof(ConfigItem_deny_version));
	for (cep = ce->ce_entries; cep; cep = cep->ce_next)
	{
		if (!strcmp(cep->ce_varname, "mask"))
		{
			ircstrdup(deny->mask, cep->ce_vardata);
		}
		else if (!strcmp(cep->ce_varname, "version"))
		{
			ircstrdup(deny->version, cep->ce_vardata);
		}
		else if (!strcmp(cep->ce_varname, "flags"))
		{
			ircstrdup(deny->flags, cep->ce_vardata);
		}
	}
	AddListItem(deny, conf_deny_version);
	return 0;
}

int     _test_deny(ConfigFile *conf, ConfigEntry *ce)
{
	ConfigEntry *cep;
	int	    errors = 0;
	Hook	*h;
	
	if (!ce->ce_vardata)
	{
		config_error("%s:%i: deny sin tipo",	
			ce->ce_fileptr->cf_filename, ce->ce_varlinenum);
		return 1;
	}
	if (!strcmp(ce->ce_vardata, "dcc"))
	{
		for (cep = ce->ce_entries; cep; cep = cep->ce_next)
		{
			if (!cep->ce_varname)
			{
				config_error("%s:%i: deny item vac�o",
					cep->ce_fileptr->cf_filename, cep->ce_varlinenum);
				errors++; continue;
			}
			if (!cep->ce_vardata)
			{
				config_error("%s:%i: deny::%s sin contenidos",
					cep->ce_fileptr->cf_filename,
					cep->ce_varlinenum,
					cep->ce_varname);
				errors++; continue;
			}
			if (!strcmp(cep->ce_varname, "filename"))
			;
			else if (!strcmp(cep->ce_varname, "reason"))
			;
			else if (!strcmp(cep->ce_varname, "soft"))
			;
			else 
			{
				config_error("%s:%i: directriz desconocida deny::%s",
					cep->ce_fileptr->cf_filename, cep->ce_varlinenum,
					cep->ce_varname);
				errors++;
			}
		}
		if (!(cep = config_find_entry(ce->ce_entries, "filename")))
		{
			config_error("%s:%i: deny %s::filename falta",
				ce->ce_fileptr->cf_filename, ce->ce_varlinenum, ce->ce_vardata);
			errors++;
		}
		if (!(cep = config_find_entry(ce->ce_entries, "reason")))
		{
			config_error("%s:%i: deny %s::reason falta",
				ce->ce_fileptr->cf_filename, ce->ce_varlinenum, ce->ce_vardata);
			errors++;
		}
	}
	else if (!strcmp(ce->ce_vardata, "channel"))
	{
		for (cep = ce->ce_entries; cep; cep = cep->ce_next)
		{
			if (!cep->ce_varname)
			{
				config_error("%s:%i: deny item vac�o",
					cep->ce_fileptr->cf_filename, cep->ce_varlinenum);
				errors++; continue;
			}
			if (!cep->ce_vardata)
			{
				config_error("%s:%i: deny::%s sin contenidos",
					cep->ce_fileptr->cf_filename,
					cep->ce_varlinenum,
					cep->ce_varname);
				errors++; continue;
			}
			if (!strcmp(cep->ce_varname, "channel"))
				;
			else if (!strcmp(cep->ce_varname, "redirect"))
				;
			else if (!strcmp(cep->ce_varname, "reason"))
				;
			else if (!strcmp(cep->ce_varname, "warn"))
				;
			else 
			{
				config_error("%s:%i: directriz desconocida deny::%s",
					cep->ce_fileptr->cf_filename, cep->ce_varlinenum,
					cep->ce_varname);
				errors++;
			}
		}
		if (!(cep = config_find_entry(ce->ce_entries, "channel")))
		{
			config_error("%s:%i: deny %s::channel falta",
				ce->ce_fileptr->cf_filename, ce->ce_varlinenum, ce->ce_vardata);
			errors++;
		}
		if (!(cep = config_find_entry(ce->ce_entries, "reason")))
		{
			config_error("%s:%i: deny %s::reason falta",
				ce->ce_fileptr->cf_filename, ce->ce_varlinenum, ce->ce_vardata);
			errors++;
		}
	}
	else if (!strcmp(ce->ce_vardata, "link"))
	{
		for (cep = ce->ce_entries; cep; cep = cep->ce_next)
		{
			if (!cep->ce_varname)
			{
				config_error("%s:%i: deny item vac�o",
					cep->ce_fileptr->cf_filename, cep->ce_varlinenum);
				errors++; continue;
			}
			if (!cep->ce_vardata)
			{
				config_error("%s:%i: deny::%s sin contenidos",
					cep->ce_fileptr->cf_filename,
					cep->ce_varlinenum,
					cep->ce_varname);
				errors++; continue;
			}
			if (!strcmp(cep->ce_varname, "mask"))
			;
			else if (!strcmp(cep->ce_varname, "rule"))
			{
				int val = 0;
				if ((val = crule_test(cep->ce_vardata)))
				{
					config_error("%s:%i: deny::%s expresi�n incorrecta: %s",
						cep->ce_fileptr->cf_filename,
						cep->ce_varlinenum,
						cep->ce_varname, crule_errstring(val));
					errors++;
				}
			}
			else if (!strcmp(cep->ce_varname, "type"))
			{
				if (!strcmp(cep->ce_vardata, "auto"))
				;
				else if (!strcmp(cep->ce_vardata, "all"))
				;
				else {
					config_status("%s:%i: tipo desconocido link",
					cep->ce_fileptr->cf_filename, cep->ce_varlinenum);
					errors++;
				}
			}	
			else 
			{
				config_error("%s:%i: directriz desconcida deny::%s",
					cep->ce_fileptr->cf_filename, cep->ce_varlinenum,
					cep->ce_varname);
				errors++;
			}
		}
		if (!(cep = config_find_entry(ce->ce_entries, "mask")))
		{
			config_error("%s:%i: deny %s::mask falta",
				ce->ce_fileptr->cf_filename, ce->ce_varlinenum, ce->ce_vardata);
			errors++;
		}	
		if (!(cep = config_find_entry(ce->ce_entries, "rule")))
		{
			config_error("%s:%i: deny %s::rule falta",
				ce->ce_fileptr->cf_filename, ce->ce_varlinenum, ce->ce_vardata);
			errors++;
		}
		if (!(cep = config_find_entry(ce->ce_entries, "type")))
		{
			config_error("%s:%i: deny %s::type falta",
				ce->ce_fileptr->cf_filename, ce->ce_varlinenum, ce->ce_vardata);
			errors++;
		}
	}
	else if (!strcmp(ce->ce_vardata, "version"))
	{
		for (cep = ce->ce_entries; cep; cep = cep->ce_next)
		{
			if (!cep->ce_varname)
			{
				config_error("%s:%i: deny item vac�o",
					cep->ce_fileptr->cf_filename, cep->ce_varlinenum);
				errors++; continue;
			}
			if (!cep->ce_vardata)
			{
				config_error("%s:%i: deny::%s sin contenidos",
					cep->ce_fileptr->cf_filename,
					cep->ce_varlinenum,
					cep->ce_varname);
				errors++; continue;
			}
			if (!strcmp(cep->ce_varname, "mask"))
			;
			else if (!strcmp(cep->ce_varname, "version"))
			;
			else if (!strcmp(cep->ce_varname, "flags"))
			;
			else 
			{
				config_error("%s:%i: directriz desconocida deny::%s",
					cep->ce_fileptr->cf_filename, cep->ce_varlinenum,
					cep->ce_varname);
				errors++;
			}
		}
		if (!(cep = config_find_entry(ce->ce_entries, "mask")))
		{
			config_error("%s:%i: deny %s::mask falta",
				ce->ce_fileptr->cf_filename, ce->ce_varlinenum, ce->ce_vardata);
			errors++;
		}
		if (!(cep = config_find_entry(ce->ce_entries, "version")))
		{
			config_error("%s:%i: deny %s::version falta",
				ce->ce_fileptr->cf_filename, ce->ce_varlinenum, ce->ce_vardata);
			errors++;
		}
		if (!(cep = config_find_entry(ce->ce_entries, "flags")))
		{
			config_error("%s:%i: deny %s::flags falta",
				ce->ce_fileptr->cf_filename, ce->ce_varlinenum, ce->ce_vardata);
			errors++;
		}
	}
	else
	{
		int used = 0;
		for (h = Hooks[HOOKTYPE_CONFIGTEST]; h; h = h->next) 
		{
			int value, errs = 0;
			if (h->owner && !(h->owner->flags & MODFLAG_TESTING)
			    && !(h->owner->options & MOD_OPT_PERM))
				continue;
			value = (*(h->func.intfunc))(conf,ce,CONFIG_DENY, &errs);
			if (value == 2)
				used = 1;
			if (value == 1)
			{
				used = 1;
				break;
			}
			if (value == -1)
			{
				used = 1;
				errors += errs;
				break;
			}
			if (value == -2)
			{
				used = 1;
				errors += errs;
			}
		}
		if (!used) {
			config_error("%s:%i: deny tipo desconocido %s",
				ce->ce_fileptr->cf_filename, ce->ce_varlinenum,
				ce->ce_vardata);
			return 1;
		}
		return errors;
	}

	return errors;	
}

#ifdef USE_LIBCURL
static void conf_download_complete(char *url, char *file, char *errorbuf, int cached)
{
	ConfigItem_include *inc;
	if (!loop.ircd_rehashing)
	{
		remove(file);
		return;
	}
	for (inc = conf_include; inc; inc = (ConfigItem_include *)inc->next)
	{
		if (!(inc->flag.type & INCLUDE_REMOTE))
			continue;
		if (inc->flag.type & INCLUDE_NOTLOADED)
			continue;
		if (!stricmp(url, inc->url))
		{
			inc->flag.type &= ~INCLUDE_DLQUEUED;
			break;
		}
	}
	if (!file && !cached)
		add_remote_include(file, url, 0, errorbuf);
	else
	{
		if (cached)
		{
			char *urlfile = url_getfilename(url);
			char *file = unreal_getfilename(urlfile);
			char *tmp = unreal_mktemp("tmp", file);
			unreal_copyfile(inc->file, tmp);
			add_remote_include(tmp, url, 0, NULL);
			free(urlfile);
		}
		else
			add_remote_include(file, url, 0, NULL);
	}
	for (inc = conf_include; inc; inc = (ConfigItem_include *)inc->next)
	{
		if (inc->flag.type & INCLUDE_DLQUEUED)
			return;
	}
	rehash_internal(loop.rehash_save_cptr, loop.rehash_save_sptr, loop.rehash_save_sig);
}
#endif

int     rehash(aClient *cptr, aClient *sptr, int sig)
{
#ifdef USE_LIBCURL
	ConfigItem_include *inc;
	char found_remote = 0;
	if (loop.ircd_rehashing)
	{
		if (!sig)
			sendto_one(sptr, ":%s NOTICE %s :A rehash is already in progress",
				me.name, sptr->name);
		return 0;
	}

	loop.ircd_rehashing = 1;
	loop.rehash_save_cptr = cptr;
	loop.rehash_save_sptr = sptr;
	loop.rehash_save_sig = sig;
	for (inc = conf_include; inc; inc = (ConfigItem_include *)inc->next)
	{
		time_t modtime;
		if (!(inc->flag.type & INCLUDE_REMOTE))
			continue;

		if (inc->flag.type & INCLUDE_NOTLOADED)
			continue;
		found_remote = 1;
		modtime = unreal_getfilemodtime(inc->file);
		inc->flag.type |= INCLUDE_DLQUEUED;
		download_file_async(inc->url, modtime, conf_download_complete);
	}
	if (!found_remote)
		return rehash_internal(cptr, sptr, sig);
	return 0;
#else
	return rehash_internal(cptr, sptr, sig);
#endif
}

int	rehash_internal(aClient *cptr, aClient *sptr, int sig)
{
	flush_connections(&me);
	if (sig == 1)
	{
		sendto_ops("SIGHUP, cargando archivo %s", configfile);
#ifdef	ULTRIX
		if (fork() > 0)
			exit(0);
		write_pidfile();
#endif
	}
	if (init_conf(configfile, 1) == 0)
		run_configuration();
	if (sig == 1)
		reread_motdsandrules();
	unload_all_unused_snomasks();
	unload_all_unused_umodes();
#ifdef UDB
	loop.ircd_rehashing = 1;
	loadbdds();
#endif	
	loop.ircd_rehashing = 0;	
	return 1;
}

void	link_cleanup(ConfigItem_link *link_ptr)
{
	ircfree(link_ptr->servername);
	ircfree(link_ptr->username);
	ircfree(link_ptr->bindip);
	ircfree(link_ptr->hostname);
	ircfree(link_ptr->hubmask);
	ircfree(link_ptr->leafmask);
	ircfree(link_ptr->connpwd);
#ifdef USE_SSL
	ircfree(link_ptr->ciphers);
#endif
	Auth_DeleteAuthStruct(link_ptr->recvauth);
	link_ptr->recvauth = NULL;
}

void delete_linkblock(ConfigItem_link *link_ptr)
{
	Debug((DEBUG_ERROR, "delete_linkblock: deleting %s, refcount=%d",
		link_ptr->servername, link_ptr->refcount));
	if (link_ptr->class)
	{
		link_ptr->class->xrefcount--;
		/* Perhaps the class is temporary too and we need to free it... */
		if (link_ptr->class->flag.temporary && 
		    !link_ptr->class->clients && !link_ptr->class->xrefcount)
		{
			delete_classblock(link_ptr->class);
			link_ptr->class = NULL;
		}
	}
	link_cleanup(link_ptr);
	DelListItem(link_ptr, conf_link);
	MyFree(link_ptr);
}

void delete_classblock(ConfigItem_class *class_ptr)
{
	Debug((DEBUG_ERROR, "delete_classblock: deleting %s, clients=%d, xrefcount=%d",
		class_ptr->name, class_ptr->clients, class_ptr->xrefcount));
	ircfree(class_ptr->name);
	DelListItem(class_ptr, conf_class);
	MyFree(class_ptr);
}

void	listen_cleanup()
{
	int	i = 0;
	ConfigItem_listen *listen_ptr;
	ListStruct *next;
	for (listen_ptr = conf_listen; listen_ptr; listen_ptr = (ConfigItem_listen *)next)
	{
		next = (ListStruct *)listen_ptr->next;
		if (listen_ptr->flag.temporary && !listen_ptr->clients)
		{
			ircfree(listen_ptr->ip);
			DelListItem(listen_ptr, conf_listen);
			MyFree(listen_ptr);
			i++;
		}
	}
	if (i)
		close_listeners();
}

#ifdef USE_LIBCURL
char *find_remote_include(char *url, char **errorbuf)
{
	ConfigItem_include *inc;
	for (inc = conf_include; inc; inc = (ConfigItem_include *)inc->next)
	{
		if (!(inc->flag.type & INCLUDE_NOTLOADED))
			continue;
		if (!(inc->flag.type & INCLUDE_REMOTE))
			continue;
		if (!stricmp(url, inc->url))
		{
			*errorbuf = inc->errorbuf;
			return inc->file;
		}
	}
	return NULL;
}

char *find_loaded_remote_include(char *url)
{
	ConfigItem_include *inc;
	for (inc = conf_include; inc; inc = (ConfigItem_include *)inc->next)
	{
		if ((inc->flag.type & INCLUDE_NOTLOADED))
			continue;
		if (!(inc->flag.type & INCLUDE_REMOTE))
			continue;
		if (!stricmp(url, inc->url))
			return inc->file;
	}
	return NULL;
}	

int remote_include(ConfigEntry *ce)
{
	char *errorbuf = NULL;
	char *file = find_remote_include(ce->ce_vardata, &errorbuf);
	int ret;
	if (!loop.ircd_rehashing || (loop.ircd_rehashing && !file && !errorbuf))
	{
		char *error;
		if (config_verbose > 0)
			config_status("Downloading %s", ce->ce_vardata);
		file = download_file(ce->ce_vardata, &error);
		if (!file)
		{
			config_error("%s:%i: include: error downloading '%s': %s",
				ce->ce_fileptr->cf_filename, ce->ce_varlinenum,
				 ce->ce_vardata, error);
			return -1;
		}
		else
		{
			if ((ret = load_conf(file)) >= 0)
				add_remote_include(file, ce->ce_vardata, INCLUDE_USED, NULL);
			free(file);
			return ret;
		}
	}
	else
	{
		if (errorbuf)
		{
			config_error("%s:%i: include: error downloading '%s': %s",
                                ce->ce_fileptr->cf_filename, ce->ce_varlinenum,
                                ce->ce_vardata, errorbuf);
			return -1;
		}
		if (config_verbose > 0)
			config_status("Loading %s from download", ce->ce_vardata);
		if ((ret = load_conf(file)) >= 0)
			add_remote_include(file, ce->ce_vardata, INCLUDE_USED, NULL);
		return ret;
	}
	return 0;
}
#endif
		
void add_include(char *file)
{
	ConfigItem_include *inc;
	if (!stricmp(file, CPATH))
		return;

	for (inc = conf_include; inc; inc = (ConfigItem_include *)inc->next)
	{
		if (!(inc->flag.type & INCLUDE_NOTLOADED))
			continue;
		if (inc->flag.type & INCLUDE_REMOTE)
			continue;
		if (!stricmp(file, inc->file))
			return;
	}
	inc = MyMallocEx(sizeof(ConfigItem_include));
	inc->file = strdup(file);
	inc->flag.type = INCLUDE_NOTLOADED|INCLUDE_USED;
	AddListItem(inc, conf_include);
}

#ifdef USE_LIBCURL
void add_remote_include(char *file, char *url, int flags, char *errorbuf)
{
	ConfigItem_include *inc;

	for (inc = conf_include; inc; inc = (ConfigItem_include *)inc->next)
	{
		if (!(inc->flag.type & INCLUDE_REMOTE))
			continue;
		if (!(inc->flag.type & INCLUDE_NOTLOADED))
			continue;
		if (!stricmp(url, inc->url))
		{
			inc->flag.type |= flags;
			return;
		}
	}

	inc = MyMallocEx(sizeof(ConfigItem_include));
	if (file)
		inc->file = strdup(file);
	inc->url = strdup(url);
	inc->flag.type = (INCLUDE_NOTLOADED|INCLUDE_REMOTE|flags);
	if (errorbuf)
		inc->errorbuf = strdup(errorbuf);
	AddListItem(inc, conf_include);
}
#endif

void unload_notloaded_includes(void)
{
	ConfigItem_include *inc, *next;

	for (inc = conf_include; inc; inc = next)
	{
		next = (ConfigItem_include *)inc->next;
		if ((inc->flag.type & INCLUDE_NOTLOADED) || !(inc->flag.type & INCLUDE_USED))
		{
#ifdef USE_LIBCURL
			if (inc->flag.type & INCLUDE_REMOTE)
			{
				remove(inc->file);
				free(inc->url);
				if (inc->errorbuf)
					free(inc->errorbuf);
			}
#endif
			free(inc->file);
			DelListItem(inc, conf_include);
			free(inc);
		}
	}
}

void unload_loaded_includes(void)
{
	ConfigItem_include *inc, *next;

	for (inc = conf_include; inc; inc = next)
	{
		next = (ConfigItem_include *)inc->next;
		if (!(inc->flag.type & INCLUDE_NOTLOADED) || !(inc->flag.type & INCLUDE_USED))
		{
#ifdef USE_LIBCURL
			if (inc->flag.type & INCLUDE_REMOTE)
			{
				remove(inc->file);
				free(inc->url);
				if (inc->errorbuf)
					free(inc->errorbuf);
			}
#endif
			free(inc->file);
			DelListItem(inc, conf_include);
			free(inc);
		}
	}
}
			
void load_includes(void)
{
	ConfigItem_include *inc;

	/* Doing this for all the modules should actually be faster
	 * than only doing it for modules that are not-loaded
	 */
	for (inc = conf_include; inc; inc = (ConfigItem_include *)inc->next)
		inc->flag.type &= ~INCLUDE_NOTLOADED; 
}
