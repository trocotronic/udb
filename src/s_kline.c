/*
 *   Unreal Internet Relay Chat Daemon, src/s_kline.c
 *   (C) 1999-2000 Carsten Munk (Techie/Stskeeps) <stskeeps@tspre.org>
 *   File to take care of dynamic K:/G:/Z: lines
 *
 *
 *   See file AUTHORS in IRC package for additional names of
 *   the programmers.
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


aTKline *tklines = NULL;

#define AllocCpy(x,y) x = (char *) MyMalloc(strlen(y) + 1); strcpy(x,y)
#define GFreeStr(x) MyFree((char *) x)
#define GFreeGline(x) MyFree((aGline *) x)
extern char zlinebuf[BUFSIZE];

/*

 *     type =  TKL_*
 *	usermask@hostmask
 *	reason
 *	setby = whom set it
 *	expire_at = when to expire - 0 if not to expire
 *	set_at    = was set at
*/

int  tkl_add_line(int type, char *usermask, char *hostmask, char *reason, char *setby, TS expire_at, TS set_at)
{
	aTKline *nl;

	nl = (aTKline *) MyMalloc(sizeof(aTKline));

	if (!nl)
		return -1;

	nl->type = type;
	nl->expire_at = expire_at;
	nl->set_at = set_at;
	AllocCpy(nl->usermask, usermask);
	AllocCpy(nl->hostmask, hostmask);
	AllocCpy(nl->reason, reason);
	AllocCpy(nl->setby, setby);
	AddListItem(nl, tklines);
	return 0;
}

aTKline *tkl_del_line(aTKline *tkl)
{
	aTKline *p, *q;

	for (p = tklines; p; p = p->next)
	{
		if (p == tkl)
		{
			q = p->next;
			GFreeStr(p->hostmask);
			GFreeStr(p->usermask);
			GFreeStr(p->reason);
			GFreeStr(p->setby);
			DelListItem(p, tklines);
			MyFree((aTKline *) p);
			return q;
		}
	}
	return NULL;

}

/*
 * tkl_check_local_remove_shun:
 * removes shun from currently connected users affected by tmp.
 */
static void tkl_check_local_remove_shun(aTKline *tmp)
{
long i1, i;
char *chost, *cname, *cip;
int  is_ip;
aClient *acptr;

	for (i1 = 0; i1 <= 5; i1++)
	{
		/* winlocal
		for (i = 0; i <= (MAXCONNECTIONS - 1); i++)
		*/
		for (i = 0; i <= LastSlot; ++i)
		{
			if ((acptr = local[i]))
				if (MyClient(acptr) && IsShunned(acptr))
				{
					chost = acptr->sockhost;
					cname = acptr->user->username;

	
					cip = (char *)Inet_ia2p(&acptr->ip);

					if (!(*tmp->hostmask < '0') && (*tmp->hostmask > '9'))
						is_ip = 1;
					else
						is_ip = 0;

					if (is_ip ==
					    0 ? (!match(tmp->hostmask,
					    chost)
					    && !match(tmp->usermask,
					    cname)) : (!match(tmp->
					    hostmask, chost)
					    || !match(tmp->hostmask,
					    cip))
					    && !match(tmp->usermask,
					    cname))
					{
						ClearShunned(acptr);
#ifdef SHUN_NOTICES
						sendto_one(acptr,
						    ":%s NOTICE %s :*** Dejas de estar bajo shun",
						    me.name,
						    acptr->name);
#endif
					}
				}
		}
	}
}

aTKline *tkl_expire(aTKline * tmp)
{
	char whattype[512];

	if (!tmp)
		return NULL;

	whattype[0] = 0;

	if ((tmp->expire_at == 0) || (tmp->expire_at > TStime()))
	{
		sendto_ops
		    ("tkl_expire(): expire for not-yet-expired tkline %s@%s",
		    tmp->usermask, tmp->hostmask);
		return (tmp->next);
	}

	if (tmp->type & TKL_GLOBAL)
	{
		if (tmp->type & TKL_KILL)
		{
			strlcpy(whattype, "G:Line", sizeof whattype);
		}
		else if (tmp->type & TKL_ZAP)
		{
			strlcpy(whattype, "Global Z:Line", sizeof whattype);
		}
		else if (tmp->type & TKL_SHUN)
			strlcpy(whattype, "Shun", sizeof whattype);
	}
	else
	{
		if (tmp->type & TKL_KILL)
		{
			strlcpy(whattype, "Timed K:Line", sizeof whattype);
		}
		else if (tmp->type & TKL_ZAP)
		{
			strlcpy(whattype, "Timed Z:Line", sizeof whattype);
		}
		else if (tmp->type & TKL_SHUN)
			strlcpy(whattype, "Local Shun", sizeof whattype);
	}
	sendto_snomask(SNO_TKL,
	    "*** Expira %s (%s@%s) puesta por %s (Raz�n: %s) hace %li segundos",
	    whattype, tmp->usermask, tmp->hostmask, tmp->setby, tmp->reason,
	    TStime() - tmp->set_at);

	ircd_log
	    (LOG_TKL, "Expiring %s (%s@%s) made by %s (Reason: %s) set %li seconds ago",
	    whattype, tmp->usermask, tmp->hostmask, tmp->setby, tmp->reason,
	    TStime() - tmp->set_at);

	if (tmp->type & TKL_SHUN)
		tkl_check_local_remove_shun(tmp);

	return (tkl_del_line(tmp));
}

EVENT(tkl_check_expire)
{
	aTKline *gp, *next;
	TS   nowtime;

	nowtime = TStime();

	for (gp = tklines; gp; gp = next)
	{
		next = gp->next;
		if (gp->expire_at <= nowtime && !(gp->expire_at == 0))
		{
			tkl_expire(gp);
		}
	}
}



/*
	returns <0 if client exists (banned)
	returns 1 if it is excepted
*/

int  find_tkline_match(aClient *cptr, int xx)
{
	aTKline *lp;
	char *chost, *cname, *cip;
	TS   nowtime;
	char msge[1024];
	int	points = 0;
	ConfigItem_except *excepts;
	char host[NICKLEN+USERLEN+HOSTLEN+6], host2[NICKLEN+USERLEN+HOSTLEN+6];
	int match_type = 0;
	if (IsServer(cptr) || IsMe(cptr))
		return -1;

	nowtime = TStime();
	chost = cptr->sockhost;
	cname = cptr->user ? cptr->user->username : "unknown";
	cip = (char *)Inet_ia2p(&cptr->ip);


	for (lp = tklines; lp; lp = lp->next)
	{
		points = 0;
		if (lp->type & TKL_SHUN)
			continue;
		if (!match(lp->usermask, cname) && !match(lp->hostmask, chost))
			points = 1;
		if (!match(lp->usermask, cname) && !match(lp->hostmask, cip))
			points = 1;
		if (points == 1)
			break;
		else
			points = 0;
	}

	if (points != 1)
		return 1;
	strcpy(host, make_user_host(cname, chost));
	strcpy(host2, make_user_host(cname, cip));
	if (((lp->type & TKL_KILL) || (lp->type & TKL_ZAP)) && !(lp->type & TKL_GLOBAL))
		match_type = CONF_EXCEPT_BAN;
	else
		match_type = CONF_EXCEPT_TKL;
	for (excepts = conf_except; excepts; excepts = (ConfigItem_except *)excepts->next) {
		if (excepts->flag.type != match_type || (match_type == CONF_EXCEPT_TKL && 
		    excepts->type != lp->type))
			continue;
		if (!match(excepts->mask, host) || !match(excepts->mask, host2))
			return 1;		
	}
	
	if ((lp->type & TKL_KILL) && (xx != 2))
	{
		if (lp->type & TKL_GLOBAL)
		{
			ircstp->is_ref++;
			sendto_one(cptr,
				":%s NOTICE %s :*** Estas %s de %s (%s)",
					me.name, cptr->name,
					(lp->expire_at ? "baneado" : "permanentemente baneado"),
					ircnetwork, lp->reason);
			ircsprintf(msge, "Glined (%s)", lp->reason);
			return (exit_client(cptr, cptr, &me,
				msge));
		}
		else
		{
			ircstp->is_ref++;
			sendto_one(cptr,
				":%s NOTICE %s :*** Est�s %s de %s (%s)",
					me.name, cptr->name,
					(lp->expire_at ? "baneado" : "permanentemente baneado"),
				me.name, lp->reason);
			ircsprintf(msge, "Glined (%s)",	lp->reason);
			return (exit_client(cptr, cptr, &me,
				msge));

		}
	}
	if (lp->type & TKL_ZAP)
	{
		ircstp->is_ref++;
		ircsprintf(msge,
		    "Z:lined (%s)",lp->reason);
		return exit_client(cptr, cptr, &me, msge);
	}

	return 3;
}

int  find_shun(aClient *cptr)
{
	aTKline *lp;
	char *chost, *cname, *cip;
	TS   nowtime;
	int	points = 0;
	ConfigItem_except *excepts;
	char host[NICKLEN+USERLEN+HOSTLEN+6], host2[NICKLEN+USERLEN+HOSTLEN+6];
	int match_type = 0;
	if (IsServer(cptr) || IsMe(cptr))
		return -1;

	if (IsShunned(cptr))
		return 1;
	if (IsAdmin(cptr))
		return 1;

	nowtime = TStime();
	chost = cptr->sockhost;
	cname = cptr->user ? cptr->user->username : "unknown";
	cip = (char *)Inet_ia2p(&cptr->ip);


	for (lp = tklines; lp; lp = lp->next)
	{
		points = 0;
		
		if (!(lp->type & TKL_SHUN))
			continue;

		if (!match(lp->usermask, cname) && !match(lp->hostmask, chost))
			points = 1;
		if (!match(lp->usermask, cname) && !match(lp->hostmask, cip))
			points = 1;
		if (points == 1)
			break;
		else
			points = 0;
	}

	if (points != 1)
		return 1;
	strcpy(host, make_user_host(cname, chost));
	strcpy(host2, make_user_host(cname, cip));
		match_type = CONF_EXCEPT_TKL;
	for (excepts = conf_except; excepts; excepts = (ConfigItem_except *)excepts->next) {
		if (excepts->flag.type != match_type || (match_type == CONF_EXCEPT_TKL && 
		    excepts->type != lp->type))
			continue;
		if (!match(excepts->mask, host) || !match(excepts->mask, host2))
			return 1;		
	}
	
	SetShunned(cptr);
	return 2;
}

int  find_tkline_match_zap(aClient *cptr)
{
	aTKline *lp;
	char *cip;
	TS   nowtime;
	char msge[1024];
	ConfigItem_except *excepts;
	if (IsServer(cptr) || IsMe(cptr))
		return -1;


	nowtime = TStime();
	cip = (char *)Inet_ia2p(&cptr->ip);

	for (lp = tklines; lp; lp = lp->next)
	{
		if (lp->type & TKL_ZAP)
		{

			if (!match(lp->hostmask, cip))
			{
				for (excepts = conf_except; excepts; excepts = (ConfigItem_except *)excepts->next) {
					if (excepts->flag.type != CONF_EXCEPT_TKL || excepts->type != lp->type)
						continue;
					if (!match(excepts->mask, cip))
						return -1;		
				}
				ircstp->is_ref++;
				ircsprintf(msge,
				    "ERROR :Cierra link: [%s] Z:Lined (%s)\r\n",
#ifndef INET6
				    inetntoa((char *)&cptr->ip), lp->reason);
#else
				    inet_ntop(AF_INET6, (char *)&cptr->ip,
				    mydummy, MYDUMMY_SIZE), lp->reason);
#endif
				strlcpy(zlinebuf, msge, sizeof zlinebuf);
				return (1);
			}
		}
	}
	return -1;
}

#define BY_MASK 0x1
#define BY_REASON 0x2
#define NOT_BY_MASK 0x4
#define NOT_BY_REASON 0x8
#define BY_SETBY 0x10
#define NOT_BY_SETBY 0x20

typedef struct {
	int flags;
	char *mask;
	char *reason;
	char *setby;
} TKLFlag;

void parse_tkl_para(char *para, TKLFlag *flag)
{
	char *flags = strtok(para, " ");
	char *tmp;
	char what = '+';

	bzero(flag, sizeof(TKLFlag));
	for (; *flags; flags++)
	{
		switch (*flags)
		{
			case '+':
				what = '+';
				break;
			case '-':
				what = '-';
				break;
			case 'm':
				if (flag->mask || !(tmp = strtok(NULL, " ")))
					continue;
				if (what == '+')
					flag->flags |= BY_MASK;
				else
					flag->flags |= NOT_BY_MASK;
				flag->mask = tmp;
				break;
			case 'r':
				if (flag->reason || !(tmp = strtok(NULL, " ")))
					continue;
				if (what == '+')
					flag->flags |= BY_REASON;
				else
					flag->flags |= NOT_BY_REASON;
				flag->reason = tmp;
				break;
			case 's':
				if (flag->setby || !(tmp = strtok(NULL, " ")))
					continue;
				if (what == '+')
					flag->flags |= BY_SETBY;
				else
					flag->flags |= NOT_BY_SETBY;
				flag->setby = tmp;
				break;
		}
	}
}	

void tkl_stats(aClient *cptr, int type, char *para)
{
	aTKline *tk;
	TS   curtime;
	TKLFlag tklflags;
	/*
	   We output in this row:
	   Glines,GZlines,KLine, ZLIne
	   Character:
	   G, Z, K, z
	 */

	if (!BadPtr(para))
		parse_tkl_para(para, &tklflags);
	tkl_check_expire(NULL);
	curtime = TStime();
	for (tk = tklines; tk; tk = tk->next)
	{
		if (type && tk->type != type)
			continue;
		if (!BadPtr(para))
		{
			if (tklflags.flags & BY_MASK)
				if (match(tklflags.mask, make_user_host(tk->usermask,
					tk->hostmask)))
					continue;
			if (tklflags.flags & NOT_BY_MASK)
				if (!match(tklflags.mask, make_user_host(tk->usermask,
					tk->hostmask)))
					continue;
			if (tklflags.flags & BY_REASON)
				if (match(tklflags.reason, tk->reason))
					continue;
			if (tklflags.flags & NOT_BY_REASON)
				if (!match(tklflags.reason, tk->reason))
					continue;
			if (tklflags.flags & BY_SETBY)
				if (match(tklflags.setby, tk->setby))
					continue;
			if (tklflags.flags & NOT_BY_SETBY)
				if (!match(tklflags.setby, tk->setby))
					continue;
		}
		if (tk->type == (TKL_KILL | TKL_GLOBAL))
		{
			sendto_one(cptr, rpl_str(RPL_STATSGLINE), me.name,
			    cptr->name, 'G', tk->usermask, tk->hostmask,
			    (tk->expire_at !=
			    0) ? (tk->expire_at - curtime) : 0,
			    (curtime - tk->set_at), tk->setby, tk->reason);
		}
		if (tk->type == (TKL_ZAP | TKL_GLOBAL))
		{
			sendto_one(cptr, rpl_str(RPL_STATSGLINE), me.name,
			    cptr->name, 'Z', tk->usermask, tk->hostmask,
			    (tk->expire_at !=
			    0) ? (tk->expire_at - curtime) : 0,
			    (curtime - tk->set_at), tk->setby, tk->reason);
		}
		if (tk->type == (TKL_SHUN | TKL_GLOBAL))
		{
			sendto_one(cptr, rpl_str(RPL_STATSGLINE), me.name,
			    cptr->name, 's', tk->usermask, tk->hostmask,
			    (tk->expire_at !=
			    0) ? (tk->expire_at - curtime) : 0,
			    (curtime - tk->set_at), tk->setby, tk->reason);
		}
		if (tk->type == (TKL_KILL))
		{
			sendto_one(cptr, rpl_str(RPL_STATSGLINE), me.name,
			    cptr->name, 'K', tk->usermask, tk->hostmask,
			    (tk->expire_at !=
			    0) ? (tk->expire_at - curtime) : 0,
			    (curtime - tk->set_at), tk->setby, tk->reason);
		}
		if (tk->type == (TKL_ZAP))
		{
			sendto_one(cptr, rpl_str(RPL_STATSGLINE), me.name,
			    cptr->name, 'z', tk->usermask, tk->hostmask,
			    (tk->expire_at !=
			    0) ? (tk->expire_at - curtime) : 0,
			    (curtime - tk->set_at), tk->setby, tk->reason);
		}
	}

}

void tkl_synch(aClient *sptr)
{
	aTKline *tk;
	char typ = 0;

	for (tk = tklines; tk; tk = tk->next)
	{
		if (tk->type & TKL_GLOBAL)
		{
			if (tk->type & TKL_KILL)
				typ = 'G';
			if (tk->type & TKL_ZAP)
				typ = 'Z';
			if (tk->type & TKL_SHUN)
				typ = 's';
			sendto_one(sptr,
			    ":%s %s + %c %s %s %s %li %li :%s", me.name,
			    IsToken(sptr) ? TOK_TKL : MSG_TKL,
			    typ,
			    tk->usermask, tk->hostmask, tk->setby,
			    tk->expire_at, tk->set_at, tk->reason);
		}
	}
}

/*
  Service function for timed *:lines

  add:  TKL + type user host setby expire_at set_at reason
  del:  TKL - type user host removedby
  list: TKL ?

  only global lines are spread out this way.
     type= G = G:Line
           Z = Z:Line
*/

int m_tkl(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
	aTKline *tk;
	int  type;
	int  found = 0;
	char gmt[256], gmt2[256];
	char txt[256];
	TS   expiry_1, setat_1;


	if (!IsServer(sptr) && !IsOper(sptr) && !IsMe(sptr))
		return 0;
	if (parc < 2)
		return 0;

	tkl_check_expire(NULL);

	switch (*parv[1])
	{
	  case '+':
	  {
		  /* we relay on servers to be failsafe.. */
		  if (!IsServer(sptr) && !IsMe(sptr))
			  return 0;
		  if (parc < 9)
			  return 0;

		  if (parv[2][0] == 'G')
			  type = TKL_KILL | TKL_GLOBAL;
		  else if (parv[2][0] == 'Z')
			  type = TKL_ZAP | TKL_GLOBAL;
		  else if (parv[2][0] == 'z')
			  type = TKL_ZAP;
		  else if (parv[2][0] == 'k')
			  type = TKL_KILL;
		  else if (parv[2][0] == 's')
			  type = TKL_SHUN | TKL_GLOBAL;
		  else
			  return 0;

		  found = 0;
		  for (tk = tklines; tk; tk = tk->next)
		  {
			  if (tk->type == type)
			  {
				  if (!strcmp(tk->hostmask, parv[4])
				      && !strcmp(tk->usermask, parv[3]))
				  {
					  found = 1;
					  break;
				  }
			  }
		  }
		  /* G:Line already exists, don't add */
		  if (found == 1)
			  return 0;

		  expiry_1 = atol(parv[6]);
		  setat_1 = atol(parv[7]);

		  /* there is something fucked here? */
		  tkl_add_line(type, parv[3], parv[4], parv[8], parv[5],
		      expiry_1, setat_1);

		  strncpyzt(gmt, asctime(gmtime((TS *)&setat_1)), sizeof(gmt));
		  strncpyzt(gmt2, asctime(gmtime((TS *)&expiry_1)), sizeof(gmt2));
		  iCstrip(gmt);
		  iCstrip(gmt2);
		  switch (type)
		  {
		    case TKL_KILL:
			    strcpy(txt, "Kline");
			    break;
		    case TKL_ZAP:
			    strcpy(txt, "ZlLine");
			    break;
		    case TKL_KILL | TKL_GLOBAL:
			    strcpy(txt, "Gline");
			    break;
		    case TKL_ZAP | TKL_GLOBAL:
			    strcpy(txt, "Global Zline");
			    break;
		    case TKL_SHUN | TKL_GLOBAL:
			    strcpy(txt, "Shun");
			    break;
		    default:
			    strcpy(txt, "Unknown *:Line");
		  }
			  sendto_snomask(SNO_TKL,
			      "*** %s a�adida a %s@%s (desde %s GMT a %s: %s)",
			      txt, parv[3], parv[4], gmt, gmt2,
			      parv[8]);
			  ircd_log
			      (LOG_TKL, "%s added for %s@%s on %s GMT (from %s to expire at %s GMT: %s)",
			      txt, parv[3], parv[4], gmt, parv[5], gmt2,
			      parv[8]);

		  loop.do_bancheck = 1;
		  /* Makes check_pings be run ^^  */
		  if (type & TKL_GLOBAL)
		  {
			  sendto_serv_butone(cptr,
			      ":%s TKL %s %s %s %s %s %s %s :%s", sptr->name,
			      parv[1], parv[2], parv[3], parv[4], parv[5],
			      parv[6], parv[7], parv[8]);
		  }
		  return 0;
	  }
	  case '-':
		  if (!IsServer(sptr) && !IsMe(sptr))
			  return 0;
		  if (*parv[2] == 'G')
			  type = TKL_KILL | TKL_GLOBAL;
		  else if (*parv[2] == 'Z')
			  type = TKL_ZAP | TKL_GLOBAL;
		  else if (*parv[2] == 'z')
			  type = TKL_ZAP;
		  else if (*parv[2] == 'k')
			  type = TKL_KILL;
		  else if (*parv[2] == 's')
			  type = TKL_SHUN | TKL_GLOBAL;
		  else
			  return 0;

		  switch (type)
		  {
		    case TKL_KILL:
			    strcpy(txt, "Timed K:Line");
			    break;
		    case TKL_ZAP:
			    strcpy(txt, "Timed Z:Line");
			    break;
		    case TKL_KILL | TKL_GLOBAL:
			    strcpy(txt, "G:Line");
			    break;
		    case TKL_ZAP | TKL_GLOBAL:
			    strcpy(txt, "Global Z:line");
			    break;
		    case TKL_SHUN | TKL_GLOBAL:
			    strcpy(txt, "Shun");
			    break;
		    default:
			    strcpy(txt, "Unknown *:Line");
		  }

		  found = 0;
		  for (tk = tklines; tk; tk = tk->next)
		  {
			  if (tk->type == type)
			  {
				  if (!strcmp(tk->hostmask, parv[4])
				      && !strcmp(tk->usermask, parv[3]))
				  {
					  strncpyzt(gmt,
					      asctime(gmtime((TS *)&tk->
					      set_at)), sizeof(gmt));
					  iCstrip(gmt);
					  sendto_snomask(SNO_TKL,
					      "%s quita %s %s@%s (puesta %s: %s)",
					      parv[5], txt, tk->usermask,
					      tk->hostmask, gmt, tk->reason);
					  ircd_log(LOG_TKL, "%s removed %s %s@%s (set at %s - reason: %s)",
					      parv[5], txt, tk->usermask, tk->hostmask,
					      gmt, tk->reason);
					  if (type & TKL_SHUN)
					      tkl_check_local_remove_shun(tk);
					  tkl_del_line(tk);
					  if (type & TKL_GLOBAL)
						  sendto_serv_butone(cptr,
						      ":%s TKL %s %s %s %s %s",
						      sptr->name, parv[1],
						      parv[2], parv[3], parv[4],
						      parv[5]);
					  break;
				  }
			  }
		  }

		  break;

	  case '?':
		  if (IsAnOper(sptr))
			  tkl_stats(sptr,0,NULL);
	}
	return 0;
}

/* execute_ban_action, a tkl helper. (Syzop/2003)
 * PARAMETERS:
 * sptr:     the client which is affected
 * action:   type of ban (BAN_ACT*)
 * reason:   ban reason
 * duration: duration of ban in seconds
 * WHAT IT DOES:
 * This function will shun/kline/gline/zline the user.
 * If the action field is 0 (BAN_ACT_KILL) the user is
 * just killed (and the time parameter is ignored).
 * ASSUMES:
 * This function assumes that sptr is locally connected.
 * RETURN VALUE:
 * The return value is the usual return value about sptr,
 * eg: FLUSH_BUFFER (=sptr has been freed so don't touch!)
 * USED BY:
 * 
 */
int place_host_ban(aClient *sptr, int action, char *reason, long duration)
{
	switch(action)
	{
		case BAN_ACT_TEMPSHUN:
			/* We simply mark this connection as shunned and do not add a ban record */
			sendto_snomask(SNO_TKL, "Shun temporal a�adido a %s (%s@%s) [%s]",
				sptr->name,
				sptr->user ? sptr->user->username : "unknown",
				sptr->user ? sptr->user->realhost : Inet_ia2p(&sptr->ip),
				reason);
			SetShunned(sptr);
			break;
		case BAN_ACT_SHUN:
		case BAN_ACT_KLINE:
		case BAN_ACT_ZLINE:
		case BAN_ACT_GLINE:
		case BAN_ACT_GZLINE:
		{
			char hostip[128], mo[100], mo2[100];
			char *tkllayer[9] = {
				me.name,	/*0  server.name */
				"+",		/*1  +|- */
				"?",		/*2  type */
				"*",		/*3  user */
				NULL,		/*4  host */
				NULL,
				NULL,		/*6  expire_at */
				NULL,		/*7  set_at */
				NULL		/*8  reason */
			};

			strlcpy(hostip, Inet_ia2p(&sptr->ip), sizeof(hostip));

			if (action == BAN_ACT_KLINE)
				tkllayer[2] = "k";
			else if (action == BAN_ACT_ZLINE)
				tkllayer[2] = "z";
			else if (action == BAN_ACT_GZLINE)
				tkllayer[2] = "Z";
			else if (action == BAN_ACT_GLINE)
				tkllayer[2] = "G";
			else if (action == BAN_ACT_SHUN)
				tkllayer[2] = "S";
			tkllayer[4] = hostip;
			tkllayer[5] = me.name;
			ircsprintf(mo, "%li", duration + TStime());
			ircsprintf(mo2, "%li", TStime());
			tkllayer[6] = mo;
			tkllayer[7] = mo2;
			tkllayer[8] = reason;
			return m_tkl(&me, &me, 9, tkllayer);
		}
		case BAN_ACT_KILL:
		default:
			return exit_client(sptr, sptr, sptr, reason);
	}
	return 0;
}
