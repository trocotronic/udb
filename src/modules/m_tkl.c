/*
 * Module skeleton, by Carsten V. Munk 2001 <stskeeps@tspre.org>
 * May be used, modified, or changed by anyone, no license applies.
 * You may relicense this, to any license
 */
#include "config.h"
#include "struct.h"
#include "common.h"
#include "sys.h"
#include "numeric.h"
#include "msg.h"
#include "channel.h"
#include <time.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <io.h>
#endif
#include <fcntl.h>
#include "h.h"
#include "proto.h"
#ifdef STRIPBADWORDS
#include "badwords.h"
#endif
#ifdef _WIN32
#include "version.h"
#endif

DLLFUNC int m_gline(aClient *cptr, aClient *sptr, int parc, char *parv[]);
DLLFUNC int m_shun(aClient *cptr, aClient *sptr, int parc, char *parv[]);
DLLFUNC int m_gzline(aClient *cptr, aClient *sptr, int parc, char *parv[]);
DLLFUNC int m_tkline(aClient *cptr, aClient *sptr, int parc, char *parv[]);
DLLFUNC int m_tzline(aClient *cptr, aClient *sptr, int parc, char *parv[]);
DLLFUNC int m_tkl_line(aClient *cptr, aClient *sptr, int parc, char *parv[], char* type);
DLLFUNC int m_spamfilter(aClient *cptr, aClient *sptr, int parc, char *parv[]);

/* Place includes here */
#define MSG_GLINE "GLINE"
#define TOK_GLINE "}"
#define MSG_SHUN "SHUN"
#define TOK_SHUN "BL"
#define MSG_GZLINE "GZLINE"
#define MSG_KLINE "KLINE"
#define MSG_ZLINE "ZLINE"
#define MSG_SPAMFILTER	"SPAMFILTER"
#define TOK_NONE ""

ModuleHeader MOD_HEADER(m_tkl)
  = {
	"tkl",	/* Name of module */
	"$Id: m_tkl.c,v 1.1.1.2 2004-02-18 18:24:17 Trocotronic Exp $", /* Version */
	"commands /gline etc", /* Short description of module */
	"3.2-b8-1",
	NULL 
    };

/* This is called on module init, before Server Ready */
DLLFUNC int MOD_INIT(m_tkl)(ModuleInfo *modinfo)
{
	MARK_AS_OFFICIAL_MODULE(modinfo);
	/*
	 * We call our add_Command crap here
	*/
	add_Command(MSG_GLINE, TOK_GLINE, m_gline, 3);
	add_Command(MSG_SHUN, TOK_SHUN, m_shun, 3);
	add_Command(MSG_ZLINE, TOK_NONE, m_tzline, 3);
	add_Command(MSG_KLINE, TOK_NONE, m_tkline, 3);
	add_Command(MSG_GZLINE, TOK_NONE, m_gzline, 3);
	add_Command(MSG_SPAMFILTER, TOK_NONE, m_spamfilter, 4);
	MARK_AS_OFFICIAL_MODULE(modinfo);
	return MOD_SUCCESS;
}

/* Is first run when server is 100% ready */
DLLFUNC int MOD_LOAD(m_tkl)(int module_load)
{
	return MOD_SUCCESS;
}

/* Called when module is unloaded */
DLLFUNC int MOD_UNLOAD(m_tkl)(int module_unload)
{
	if ((del_Command(MSG_GLINE, TOK_GLINE, m_gline) < 0) ||
	    (del_Command(MSG_SHUN, TOK_SHUN, m_shun) < 0 ) ||
	    (del_Command(MSG_ZLINE, TOK_NONE, m_tzline) < 0) ||
	    (del_Command(MSG_GZLINE, TOK_NONE, m_gzline) < 0) ||
	    (del_Command(MSG_KLINE, TOK_NONE, m_tkline) < 0))

	{
		sendto_realops("Failed to delete commands when unloading %s",
				MOD_HEADER(m_tkl).name);
	}
	return MOD_SUCCESS;
}

/*
** m_gline (oper function - /TKL takes care of distribution)
** /gline [+|-]u@h mask time :reason
**
** parv[0] = sender
** parv[1] = [+|-]u@h mask
** parv[2] = for how long
** parv[3] = reason
*/

DLLFUNC int m_gline(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
	if (IsServer(sptr))
		return 0;

	if (!OPCanTKL(sptr) || !IsOper(sptr))
	{
		sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name,
		sptr->name);
		return 0;
	}

	if (parc == 1)
	{
		tkl_stats(sptr, TKL_KILL|TKL_GLOBAL, NULL);
		sendto_one(sptr, rpl_str(RPL_ENDOFSTATS), me.name, sptr->name, 'g');
		return 0;
	}

	return m_tkl_line(cptr, sptr, parc, parv, "G");

}

DLLFUNC int m_gzline(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
	if (IsServer(sptr))
		return 0;

	if (!OPCanGZL(sptr) || !IsOper(sptr))
	{
		sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name,
		sptr->name);
		return 0;
	}

	if (parc == 1)
	{
		tkl_stats(sptr, TKL_GLOBAL|TKL_ZAP, NULL);
		sendto_one(sptr, rpl_str(RPL_ENDOFSTATS), me.name, sptr->name, 'g');
		return 0;
	}

	return m_tkl_line(cptr, sptr, parc, parv, "Z");

}

DLLFUNC int m_shun(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
	if (IsServer(sptr))
		return 0;

	if (!OPCanTKL(sptr) || !IsOper(sptr))
	{
		sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name,
		sptr->name);
		return 0;
	}

	if (parc == 1)
	{
		tkl_stats(sptr, TKL_GLOBAL|TKL_SHUN, NULL);
		sendto_one(sptr, rpl_str(RPL_ENDOFSTATS), me.name, sptr->name, 'g');
		return 0;
	}

	return m_tkl_line(cptr, sptr, parc, parv, "s");

}

DLLFUNC int m_tkline(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
	if (IsServer(sptr))
		return 0;

	if (!OPCanKline(sptr) || !IsAnOper(sptr))
	{
		sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name,
		sptr->name);
		return 0;
	}

	if (parc == 1)
	{
		tkl_stats(sptr, TKL_KILL, NULL);
		sendto_one(sptr, rpl_str(RPL_ENDOFSTATS), me.name, sptr->name, 'g');
		return 0;
	}
	if (!OPCanUnKline(sptr) && *parv[1] == '-')
	{
		sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name, parv[0]);
		return 0;
	}
	return m_tkl_line(cptr, sptr, parc, parv, "k");

}

DLLFUNC int m_tzline(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
	if (IsServer(sptr))
		return 0;

	if (!OPCanZline(sptr) || !IsAnOper(sptr))
	{
		sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name,
		sptr->name);
		return 0;
	}

	if (parc == 1)
	{
		tkl_stats(sptr, TKL_ZAP, NULL);
		sendto_one(sptr, rpl_str(RPL_ENDOFSTATS), me.name, sptr->name, 'g');
		return 0;
	}

	return m_tkl_line(cptr, sptr, parc, parv, "z");

}



/*
** m_tkl_line (oper function - /TKL takes care of distribution)
** /gline [+|-]u@h mask time :reason
**
** parv[0] = sender
** parv[1] = [+|-]u@h mask
** parv[2] = for how long
** parv[3] = reason
*/

DLLFUNC int  m_tkl_line(aClient *cptr, aClient *sptr, int parc, char *parv[], char* type) {
	TS   secs;
	int  whattodo = 0;	/* 0 = add  1 = del */
	int  i;
	aClient *acptr = NULL;
	char *mask = NULL;
	char mo[1024], mo2[1024];
	char *p, *usermask, *hostmask;
	char *tkllayer[9] = {
		me.name,	/*0  server.name */
		NULL,		/*1  +|- */
		NULL,		/*2  G   */
		NULL,		/*3  user */
		NULL,		/*4  host */
		NULL,		/*5  setby */
		"0",		/*6  expire_at */
		NULL,		/*7  set_at */
		"no reason"	/*8  reason */
	};
	struct tm *t;

	if (parc == 1)
	{
		tkl_stats(sptr, 0, NULL);
		sendto_one(sptr, rpl_str(RPL_ENDOFSTATS), me.name, sptr->name, 'g');
		return 0;
	}

	mask = parv[1];
	if (*mask == '-')
	{
		whattodo = 1;
		mask++;
	}
	else if (*mask == '+')
	{
		whattodo = 0;
		mask++;
	}

	if (strchr(mask, '!'))
	{
		sendto_one(sptr, ":%s NOTICE %s :[error] Cannot have ! in masks.", me.name,
		    sptr->name);
		return 0;
	}
	if (strchr(mask, ' '))
		return 0;

	/* Check if its a hostmask and legal .. */
	p = strchr(mask, '@');
	if (p) {
		usermask = strtok(mask, "@");
		hostmask = strtok(NULL, "");
		if (BadPtr(hostmask)) {
			if (BadPtr(usermask)) {
				return 0;
			}
			hostmask = usermask;
			usermask = "*";
		}
		p = hostmask-1;
	}
	else
	{
		/* It's seemingly a nick .. let's see if we can find the user */
		if ((acptr = find_person(mask, NULL)))
		{
			usermask = "*";
			hostmask = acptr->user->realhost;
			p = hostmask - 1;
		}
		else
		{
			sendto_one(sptr, rpl_str(ERR_NOSUCHNICK), me.name, sptr->name, mask);
			return 0;
		}
	}	
	if (!whattodo)
	{
		p++;
		i = 0;
		while (*p)
		{
			if (*p != '*' && *p != '.' && *p != '?')
				i++;
			p++;
		}
		if (i < 4)
		{
			sendto_one(sptr,
			    ":%s NOTICE %s :*** [error] Too broad mask",
			    me.name, sptr->name);
			return 0;
		}
	}

	tkl_check_expire(NULL);

	secs = 0;

	if (whattodo == 0 && (parc > 3))
	{
		secs = atime(parv[2]);
		if (secs < 0)
		{
			sendto_one(sptr,
			    ":%s NOTICE %s :*** [error] The time you specified is out of range!",
			    me.name, sptr->name);
			return 0;
		}
	}
	tkllayer[1] = whattodo == 0 ? "+" : "-";
	tkllayer[2] = type;
	tkllayer[3] = usermask;
	tkllayer[4] = hostmask;
	tkllayer[5] =
	    make_nick_user_host(sptr->name, sptr->user->username, GetHost(sptr));
	if (whattodo == 0)
	{
		if (secs == 0)
		{
			if (DEFAULT_BANTIME && (parc <= 3))
				ircsprintf(mo, "%li", DEFAULT_BANTIME + TStime());
			else
				ircsprintf(mo, "%li", secs); /* "0" */
		}
		else
			ircsprintf(mo, "%li", secs + TStime());
		ircsprintf(mo2, "%li", TStime());
		tkllayer[6] = mo;
		tkllayer[7] = mo2;
		if (parc > 3) {
			tkllayer[8] = parv[3];
		} else if (parc > 2) {
			tkllayer[8] = parv[2];
		}
		/* Blerghhh... */
		i = atol(mo);
		t = gmtime((TS *)&i);
		if (!t)
		{
			sendto_one(sptr,
				":%s NOTICE %s :*** [error] The time you specified is out of range",
				me.name, sptr->name);
			return 0;
		}
		
		/* call the tkl layer .. */
		m_tkl(&me, &me, 9, tkllayer);
	}
	else
	{
		/* call the tkl layer .. */
		m_tkl(&me, &me, 6, tkllayer);

	}
	return 0;
}

int spamfilter_usage(aClient *sptr)
{
	sendnotice(sptr, "Use: /spamfilter [add|del|remove|+|-] [type] [action] [regex]");
	sendnotice(sptr, "See '/helpop ?spamfilter' for more information.");
	return 0;
}

DLLFUNC int m_spamfilter(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
int  whattodo = 0;	/* 0 = add  1 = del */
int  i;
aClient *acptr = NULL;
char *mask = NULL;
char mo2[1024];
char *p, *usermask, *hostmask;
char *tkllayer[9] = {
	me.name,	/*0  server.name */
	NULL,		/*1  +|- */
	"F",		/*2  F   */
	NULL,		/*3  usermask (targets) */
	NULL,		/*4  hostmask (action) */
	NULL,		/*5  setby */
	"0",		/*6  expire_at */
	"0",		/*7  set_at */
	""	/*8  regex */
};
struct tm *t;
int targets = 0, action = 0;
char targetbuf[64], actionbuf[2];

	if (IsServer(sptr))
		return 0;

	if (!OPCanTKL(sptr) || !IsOper(sptr))
	{
		sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name, sptr->name);
		return 0;
	}

	if (parc == 1)
	{
		tkl_stats(sptr, TKL_SPAMF, NULL);
		tkl_stats(sptr, TKL_SPAMF|TKL_GLOBAL, NULL);
		sendto_one(sptr, rpl_str(RPL_ENDOFSTATS), me.name, sptr->name, 'F');
		return 0;
	}
	if ((parc < 5) || BadPtr(parv[4]))
		return spamfilter_usage(sptr);

	/* parv[1]: [add|del|+|-]
	 * parv[2]: type
	 * parv[3]: action
	 * parv[4]: regex
	 */
	if (!strcasecmp(parv[1], "add") || !strcmp(parv[1], "+"))
		whattodo = 0;
	else if (!strcasecmp(parv[1], "del") || !strcmp(parv[1], "-") || !strcasecmp(parv[1], "remove"))
		whattodo = 1;
	else
	{
		sendto_one(sptr, ":%s NOTICE %s :1st parameter invalid", me.name, sptr->name);
		return spamfilter_usage(sptr);
	}

	targets = spamfilter_gettargets(parv[2], sptr);
	if (!targets)
		return spamfilter_usage(sptr);

	strncpyzt(targetbuf, spamfilter_target_inttostring(targets), sizeof(targetbuf));

	action = banact_stringtoval(parv[3]);
	if (!action)
	{
		sendto_one(sptr, ":%s NOTICE %s :Invalid 'action' field (%s)", me.name, sptr->name, parv[3]);
		return spamfilter_usage(sptr);
	}
	actionbuf[0] = banact_valtochar(action);
	actionbuf[1] = '\0';
	
	/* now check the regex... */
	p = unreal_checkregex(parv[4],0);
	if (p)
	{
		sendto_one(sptr, ":%s NOTICE %s :Error in regex '%s': %s",
			me.name, sptr->name, parv[4], p);
		return 0;
	}

	tkllayer[1] = whattodo ? "-" : "+";
	tkllayer[3] = targetbuf;
	tkllayer[4] = actionbuf;
	tkllayer[5] = make_nick_user_host(sptr->name, sptr->user->username, GetHost(sptr));
	tkllayer[8] = parv[4];
	
	if (whattodo == 0)
	{
		ircsprintf(mo2, "%li", TStime());
		tkllayer[7] = mo2;
		m_tkl(&me, &me, 9, tkllayer);
	}
	else
	{
		m_tkl(&me, &me, 9, tkllayer);
	}

	return 0;
}
