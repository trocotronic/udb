/*
 *   Unreal Internet Relay Chat Daemon, src/s_user.c
 *   Copyright (C) 1990 Jarkko Oikarinen and
 *                      University of Oulu, Computing Center
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

#ifndef CLEAN_COMPILE
static char sccsid[] =
    "@(#)s_user.c	2.74 2/8/94 (C) 1988 University of Oulu, \
Computing Center and Jarkko Oikarinen";
#endif
#include "macros.h"
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

#ifdef UDB
#include "s_bdd.h"
#endif

void send_umode_out(aClient *, aClient *, long);
void send_umode_out_nickv2(aClient *, aClient *, long);
void send_umode(aClient *, aClient *, long, long, char *);
void set_snomask(aClient *, char *);
void create_snomask(aClient *, anUser *, char *);
extern int short_motd(aClient *sptr);
extern aChannel *get_channel(aClient *cptr, char *chname, int flag);
/* static  Link    *is_banned(aClient *, aChannel *); */
int  dontspread = 0;
extern char *me_hash;
extern char backupbuf[];
static char buf[BUFSIZE];

void iNAH_host(aClient *sptr, char *host)
{
	DYN_LOCAL(char, did_parts, sptr->user->joined);
	if (!sptr->user)
	{
		DYN_FREE(did_parts);
		return;
	}

	if (UHOST_ALLOWED == UHALLOW_REJOIN)
		rejoin_doparts(sptr, did_parts);
	if (sptr->user->virthost)
	{
		MyFree(sptr->user->virthost);
		sptr->user->virthost = NULL;
	}
	sptr->user->virthost = strdup(host);
	if (MyConnect(sptr))
		sendto_serv_butone_token(&me, sptr->name, MSG_SETHOST,
		    TOK_SETHOST, "%s", sptr->user->virthost);
	sptr->umodes |= UMODE_SETHOST;
	
	if (UHOST_ALLOWED == UHALLOW_REJOIN)
		rejoin_dojoinandmode(sptr, did_parts);
	DYN_FREE(did_parts);
}

long set_usermode(char *umode)
{
	int  newumode;
	int  what;
	char *m;
	int i;

	newumode = 0;
	what = MODE_ADD;
	for (m = umode; *m; m++)
		switch (*m)
		{
		  case '+':
			  what = MODE_ADD;
			  break;
		  case '-':
			  what = MODE_DEL;
			  break;
		  case ' ':
		  case '\n':
		  case '\r':
		  case '\t':
			  break;
		  default:
		 	 for (i = 0; i <= Usermode_highest; i++)
		 	 {
		 	 	if (!Usermode_Table[i].flag)
		 	 		continue;
		 	 	if (*m == Usermode_Table[i].flag)
		 	 	{
		 	 		if (what == MODE_ADD)
			 	 		newumode |= Usermode_Table[i].mode;
			 	 	else
			 	 		newumode &= ~Usermode_Table[i].mode;
		 	 	}
		 	 } 	  
		}

	return (newumode);
}

/*
** m_functions execute protocol messages on this server:
**
**	cptr	is always NON-NULL, pointing to a *LOCAL* client
**		structure (with an open socket connected!). This
**		identifies the physical socket where the message
**		originated (or which caused the m_function to be
**		executed--some m_functions may call others...).
**
**	sptr	is the source of the message, defined by the
**		prefix part of the message if present. If not
**		or prefix not found, then sptr==cptr.
**
**		(!IsServer(cptr)) => (cptr == sptr), because
**		prefixes are taken *only* from servers...
**
**		(IsServer(cptr))
**			(sptr == cptr) => the message didn't
**			have the prefix.
**
**			(sptr != cptr && IsServer(sptr) means
**			the prefix specified servername. (?)
**
**			(sptr != cptr && !IsServer(sptr) means
**			that message originated from a remote
**			user (not local).
**
**		combining
**
**		(!IsServer(sptr)) means that, sptr can safely
**		taken as defining the target structure of the
**		message in this server.
**
**	*Always* true (if 'parse' and others are working correct):
**
**	1)	sptr->from == cptr  (note: cptr->from == cptr)
**
**	2)	MyConnect(sptr) <=> sptr == cptr (e.g. sptr
**		*cannot* be a local connection, unless it's
**		actually cptr!). [MyConnect(x) should probably
**		be defined as (x == x->from) --msa ]
**
**	parc	number of variable parameter strings (if zero,
**		parv is allowed to be NULL)
**
**	parv	a NULL terminated list of parameter pointers,
**
**			parv[0], sender (prefix string), if not present
**				this points to an empty string.
**			parv[1]...parv[parc-1]
**				pointers to additional parameters
**			parv[parc] == NULL, *always*
**
**		note:	it is guaranteed that parv[0]..parv[parc-1] are all
**			non-NULL pointers.
*/

/* #ifndef NO_FDLIST
** extern fdlist oper_fdlist;
** #endif
*/

/* Taken from xchat by Peter Zelezny
 * changed very slightly by codemastr
 * RGB color stripping support added -- codemastr
 */

unsigned char *StripColors(unsigned char *text) {
	int i = 0, len = strlen(text), save_len=0;
	char nc = 0, col = 0, rgb = 0, *save_text=NULL;
	static unsigned char new_str[4096];

	while (len > 0) 
	{
		if ((col && isdigit(*text) && nc < 2) || (col && *text == ',' && nc < 3)) 
		{
			nc++;
			if (*text == ',')
				nc = 0;
		}
		/* Syntax for RGB is ^DHHHHHH where H is a hex digit.
		 * If < 6 hex digits are specified, the code is displayed
		 * as text
		 */
		else if ((rgb && isxdigit(*text) && nc < 6) || (rgb && *text == ',' && nc < 7))
		{
			nc++;
			if (*text == ',')
				nc = 0;
		}
		else 
		{
			if (col)
				col = 0;
			if (rgb)
			{
				if (nc != 6)
				{
					text = save_text+1;
					len = save_len-1;
					rgb = 0;
					continue;
				}
				rgb = 0;
			}
			if (*text == '\003') 
			{
				col = 1;
				nc = 0;
			}
			else if (*text == '\004')
			{
				save_text = text;
				save_len = len;
				rgb = 1;
				nc = 0;
			}
			else 
			{
				new_str[i] = *text;
				i++;
			}
		}
		text++;
		len--;
	}
	new_str[i] = 0;
	return new_str;
}

/* strip color, bold, underline, and reverse codes from a string */
const char *StripControlCodes(unsigned char *text) 
{
	int i = 0, len = strlen(text), save_len=0;
	char nc = 0, col = 0, rgb = 0, *save_text=NULL;
	static unsigned char new_str[4096];
	while (len > 0) 
	{
		if ( col && ((isdigit(*text) && nc < 2) || (*text == ',' && nc < 3)))
		{
			nc++;
			if (*text == ',')
				nc = 0;
		}
		/* Syntax for RGB is ^DHHHHHH where H is a hex digit.
		 * If < 6 hex digits are specified, the code is displayed
		 * as text
		 */
		else if ((rgb && isxdigit(*text) && nc < 6) || (rgb && *text == ',' && nc < 7))
		{
			nc++;
			if (*text == ',')
				nc = 0;
		}
		else 
		{
			if (col)
				col = 0;
			if (rgb)
			{
				if (nc != 6)
				{
					text = save_text+1;
					len = save_len-1;
					rgb = 0;
					continue;
				}
				rgb = 0;
			}
			switch (*text)
			{
			case 3:
				/* color */
				col = 1;
				nc = 0;
				break;
			case 4:
				/* RGB */
				save_text = text;
				save_len = len;
				rgb = 1;
				nc = 0;
				break;
			case 2:
				/* bold */
				break;
			case 31:
				/* underline */
				break;
			case 22:
				/* reverse */
				break;
			case 15:
				/* plain */
				break;
			default:
				new_str[i] = *text;
				i++;
				break;
			}
		}
		text++;
		len--;
	}
	new_str[i] = 0;
	return new_str;
}

MODVAR char umodestring[UMODETABLESZ+1];

/*
** next_client
**	Local function to find the next matching client. The search
**	can be continued from the specified client entry. Normal
**	usage loop is:
**
**	for (x = client; x = next_client(x,mask); x = x->next)
**		HandleMatchingClient;
**
*/
aClient *next_client(aClient *next, char *ch)
{
	aClient *tmp = next;

	next = find_client(ch, tmp);
	if (tmp && tmp->prev == next)
		return NULL;
	if (next != tmp)
		return next;
	for (; next; next = next->next)
	{
		if (!match(ch, next->name) || !match(next->name, ch))
			break;
	}
	return next;
}

/*
** hunt_server
**
**	Do the basic thing in delivering the message (command)
**	across the relays to the specific server (server) for
**	actions.
**
**	Note:	The command is a format string and *MUST* be
**		of prefixed style (e.g. ":%s COMMAND %s ...").
**		Command can have only max 8 parameters.
**
**	server	parv[server] is the parameter identifying the
**		target server.
**
**	*WARNING*
**		parv[server] is replaced with the pointer to the
**		real servername from the matched client (I'm lazy
**		now --msa).
**
**	returns: (see #defines)
*/
int  hunt_server(aClient *cptr, aClient *sptr, char *command, int server, int parc, char *parv[])
{
	aClient *acptr;

	/*
	   ** Assume it's me, if no server
	 */
	if (parc <= server || BadPtr(parv[server]) ||
	    match(me.name, parv[server]) == 0 ||
	    match(parv[server], me.name) == 0)
		return (HUNTED_ISME);
	/*
	   ** These are to pickup matches that would cause the following
	   ** message to go in the wrong direction while doing quick fast
	   ** non-matching lookups.
	 */
	if ((acptr = find_client(parv[server], NULL)))
		if (acptr->from == sptr->from && !MyConnect(acptr))
			acptr = NULL;
	if (!acptr && (acptr = find_server_quick(parv[server])))
		if (acptr->from == sptr->from && !MyConnect(acptr))
			acptr = NULL;
	if (!acptr)
		for (acptr = client, (void)collapse(parv[server]);
		    (acptr = next_client(acptr, parv[server]));
		    acptr = acptr->next)
		{
			if (acptr->from == sptr->from && !MyConnect(acptr))
				continue;
			/*
			 * Fix to prevent looping in case the parameter for
			 * some reason happens to match someone from the from
			 * link --jto
			 */
			if (IsRegistered(acptr) && (acptr != cptr))
				break;
		}
	/* Fix for unregistered client receiving msgs: */
	if (acptr && MyConnect(acptr) && IsUnknown(acptr))
		acptr = NULL;
	if (acptr)
	{
		if (IsMe(acptr) || MyClient(acptr))
			return HUNTED_ISME;
		if (match(acptr->name, parv[server]))
			parv[server] = acptr->name;
		sendto_one(acptr, command, parv[0],
		    parv[1], parv[2], parv[3], parv[4],
		    parv[5], parv[6], parv[7], parv[8]);
		return (HUNTED_PASS);
	}
	sendto_one(sptr, err_str(ERR_NOSUCHSERVER), me.name,
	    parv[0], parv[server]);
	return (HUNTED_NOSUCH);
}


/*
** hunt_server_token
**
**	Do the basic thing in delivering the message (command)
**	across the relays to the specific server (server) for
**	actions. This works like hunt_server, except if the
**	server supports tokens, the token is used.
**
**	command specifies the command name
**	token specifies the token name
**	params is a formated parameter string
**	server	parv[server] is the parameter identifying the
**		target server.
**
**	*WARNING*
**		parv[server] is replaced with the pointer to the
**		real servername from the matched client (I'm lazy
**		now --msa).
**
**	returns: (see #defines)
*/
int  hunt_server_token(aClient *cptr, aClient *sptr, char *command, char *token, char
*params, int server, int parc, char *parv[])
{
	aClient *acptr;

	/*
	   ** Assume it's me, if no server
	 */
	if (parc <= server || BadPtr(parv[server]) ||
	    match(me.name, parv[server]) == 0 ||
	    match(parv[server], me.name) == 0)
		return (HUNTED_ISME);
	/*
	   ** These are to pickup matches that would cause the following
	   ** message to go in the wrong direction while doing quick fast
	   ** non-matching lookups.
	 */
	if ((acptr = find_client(parv[server], NULL)))
		if (acptr->from == sptr->from && !MyConnect(acptr))
			acptr = NULL;
	if (!acptr && (acptr = find_server_quick(parv[server])))
		if (acptr->from == sptr->from && !MyConnect(acptr))
			acptr = NULL;
	if (!acptr)
		for (acptr = client, (void)collapse(parv[server]);
		    (acptr = next_client(acptr, parv[server]));
		    acptr = acptr->next)
		{
			if (acptr->from == sptr->from && !MyConnect(acptr))
				continue;
			/*
			 * Fix to prevent looping in case the parameter for
			 * some reason happens to match someone from the from
			 * link --jto
			 */
			if (IsRegistered(acptr) && (acptr != cptr))
				break;
		}
	/* Fix for unregistered client receiving msgs: */
	if (acptr && MyConnect(acptr) && IsUnknown(acptr))
		acptr = NULL;
	if (acptr)
	{
		char buff[1024];
		if (IsMe(acptr) || MyClient(acptr))
			return HUNTED_ISME;
		if (match(acptr->name, parv[server]))
			parv[server] = acptr->name;
		if (IsToken(acptr->from)) {
			sprintf(buff, ":%s %s ", parv[0], token);
			strcat(buff, params);
			sendto_one(acptr, buff, parv[1], parv[2], parv[3], parv[4], parv[5], parv[6], parv[7], parv[8]);
		}
		else {
			sprintf(buff, ":%s %s ", parv[0], command);
			strcat(buff, params);
			sendto_one(acptr, buff, parv[1], parv[2],
			parv[3], parv[4], parv[5], parv[6], parv[7], parv[8]);
		}
		return (HUNTED_PASS);
	}
	sendto_one(sptr, err_str(ERR_NOSUCHSERVER), me.name,
	    parv[0], parv[server]);
	return (HUNTED_NOSUCH);
}

int  hunt_server_token_quiet(aClient *cptr, aClient *sptr, char *command, char *token, char
*params, int server, int parc, char *parv[])
{
	aClient *acptr;

	/*
	   ** Assume it's me, if no server
	 */
	if (parc <= server || BadPtr(parv[server]) ||
	    match(me.name, parv[server]) == 0 ||
	    match(parv[server], me.name) == 0)
		return (HUNTED_ISME);
	/*
	   ** These are to pickup matches that would cause the following
	   ** message to go in the wrong direction while doing quick fast
	   ** non-matching lookups.
	 */
	if ((acptr = find_client(parv[server], NULL)))
		if (acptr->from == sptr->from && !MyConnect(acptr))
			acptr = NULL;
	if (!acptr && (acptr = find_server_quick(parv[server])))
		if (acptr->from == sptr->from && !MyConnect(acptr))
			acptr = NULL;
	if (!acptr)
		for (acptr = client, (void)collapse(parv[server]);
		    (acptr = next_client(acptr, parv[server]));
		    acptr = acptr->next)
		{
			if (acptr->from == sptr->from && !MyConnect(acptr))
				continue;
			/*
			 * Fix to prevent looping in case the parameter for
			 * some reason happens to match someone from the from
			 * link --jto
			 */
			if (IsRegistered(acptr) && (acptr != cptr))
				break;
		}
	if (acptr)
	{
		char buff[1024];
		if (IsMe(acptr) || MyClient(acptr))
			return HUNTED_ISME;
		if (match(acptr->name, parv[server]))
			parv[server] = acptr->name;
		if (IsToken(acptr->from)) {
			sprintf(buff, ":%s %s ", parv[0], token);
			strcat(buff, params);
			sendto_one(acptr, buff, parv[1], parv[2], parv[3], parv[4], parv[5], parv[6], parv[7], parv[8]);
		}
		else {
			sprintf(buff, ":%s %s ", parv[0], command);
			strcat(buff, params);
			sendto_one(acptr, buff, parv[1], parv[2],
			parv[3], parv[4], parv[5], parv[6], parv[7], parv[8]);
		}
		return (HUNTED_PASS);
	}
	return (HUNTED_NOSUCH);
}




/*
** check_for_target_limit
**
** Return Values:
** True(1) == too many targets are addressed
** False(0) == ok to send message
**
*/
int  check_for_target_limit(aClient *sptr, void *target, const char *name)
{
#ifndef _WIN32			/* This is not windows compatible */
	u_char *p;
#ifndef __alpha
	u_int tmp = ((u_int)target & 0xffff00) >> 8;
#else
	u_int tmp = ((u_long)target & 0xffff00) >> 8;
#endif
	u_char hash = (tmp * tmp) >> 12;

	if (IsAnOper(sptr))
		return 0;
	if (sptr->targets[0] == hash)
		return 0;

	for (p = sptr->targets; p < &sptr->targets[MAXTARGETS - 1];)
		if (*++p == hash)
		{
			/* move targethash to first position... */
			memmove(&sptr->targets[1], &sptr->targets[0],
			    p - sptr->targets);
			sptr->targets[0] = hash;
			return 0;
		}

	if (TStime() < sptr->nexttarget)
	{
		sptr->since += TARGET_DELAY; /* lag them up */
		sptr->nexttarget += TARGET_DELAY;
		sendto_one(sptr, err_str(ERR_TARGETTOOFAST), me.name, sptr->name,
			name, sptr->nexttarget - TStime());

		return 1;
	}

	if (TStime() > sptr->nexttarget + TARGET_DELAY*MAXTARGETS)
	{
		sptr->nexttarget = TStime() - TARGET_DELAY*MAXTARGETS;
	}

	sptr->nexttarget += TARGET_DELAY;

	memmove(&sptr->targets[1], &sptr->targets[0], MAXTARGETS - 1);
	sptr->targets[0] = hash;
#endif
	return 0;
}

/*
** canonize
**
** reduce a string of duplicate list entries to contain only the unique
** items.  Unavoidably O(n^2).
*/
extern char *canonize(char *buffer)
{
	static char cbuf[BUFSIZ];
	char *s, *t, *cp = cbuf;
	int  l = 0;
	char *p = NULL, *p2;

	*cp = '\0';

	for (s = strtoken(&p, buffer, ","); s; s = strtoken(&p, NULL, ","))
	{
		if (l)
		{
			for (p2 = NULL, t = strtoken(&p2, cbuf, ","); t;
			    t = strtoken(&p2, NULL, ","))
				if (!mycmp(s, t))
					break;
				else if (p2)
					p2[-1] = ',';
		}
		else
			t = NULL;
		if (!t)
		{
			if (l)
				*(cp - 1) = ',';
			else
				l = 1;
			(void)strcpy(cp, s);
			if (p)
				cp += (p - s);
		}
		else if (p2)
			p2[-1] = ',';
	}
	return cbuf;
}


extern MODVAR char cmodestring[512];

/*
** register_user
**	This function is called when both NICK and USER messages
**	have been accepted for the client, in whatever order. Only
**	after this the USER message is propagated.
**
**	NICK's must be propagated at once when received, although
**	it would be better to delay them too until full info is
**	available. Doing it is not so simple though, would have
**	to implement the following:
**
**	1) user telnets in and gives only "NICK foobar" and waits
**	2) another user far away logs in normally with the nick
**	   "foobar" (quite legal, as this server didn't propagate
**	   it).
**	3) now this server gets nick "foobar" from outside, but
**	   has already the same defined locally. Current server
**	   would just issue "KILL foobar" to clean out dups. But,
**	   this is not fair. It should actually request another
**	   nick from local user or kill him/her...
*/
extern MODVAR aTKline *tklines;
extern int badclass;

int register_user(aClient *cptr, aClient *sptr, char *nick, char *username, char *umode, char *virthost, char *ip)
{
	ConfigItem_ban *bconf;
	char *parv[3], *tmpstr;
#ifdef HOSTILENAME
	char stripuser[USERLEN + 1], *u1 = stripuser, *u2, olduser[USERLEN + 1],
	    userbad[USERLEN * 2 + 1], *ubad = userbad, noident = 0;
#endif
#ifdef UDB
	Udb *reg, *bloq;
#endif
	int  xx;
	anUser *user = sptr->user;
	aClient *nsptr;
	int  i;
	char mo[256];
	char *tkllayer[9] = {
		me.name,	/*0  server.name */
		"+",		/*1  +|- */
		"z",		/*2  G   */
		"*",		/*3  user */
		NULL,		/*4  host */
		NULL,
		NULL,		/*6  expire_at */
		NULL,		/*7  set_at */
		NULL		/*8  reason */
	};
	ConfigItem_tld *tlds;
	cptr->last = TStime();
	parv[0] = sptr->name;
	parv[1] = parv[2] = NULL;
	nick = sptr->name; /* <- The data is always the same, but the pointer is sometimes not,
	                    *    I need this for one of my modules, so do not remove! ;) -- Syzop */
	
	if (MyConnect(sptr))
	{
		if ((i = check_client(sptr, username))) {
			/* This had return i; before -McSkaf */
			if (i == -5)
				return FLUSH_BUFFER;

			sendto_snomask(SNO_CLIENT,
			    "*** Notice -- %s desde %s.",
			    i == -3 ? "Demasiadas conexiones" :
			    "conexi�n no autorizada", get_client_host(sptr));
			ircstp->is_ref++;
			ircsprintf(mo, "This server is full.");
			return
			    exit_client(cptr, sptr, &me,
			    i ==
			    -3 ? mo :
			    "No est�s autorizado a conectar a este servidor");
		}
		if (sptr->hostp)
		{
			/* No control-chars or ip-like dns replies... I cheat :)
			   -- OnyxDragon */
			for (tmpstr = sptr->sockhost; *tmpstr > ' ' &&
			    *tmpstr < 127; tmpstr++);
			if (*tmpstr || !*user->realhost
			    || isdigit(*(tmpstr - 1)))
				strncpyzt(sptr->sockhost,
				    (char *)Inet_ia2p((struct IN_ADDR*)&sptr->ip), sizeof(sptr->sockhost));	/* Fix the sockhost for debug jic */
			strncpyzt(user->realhost, sptr->sockhost,
			    sizeof(sptr->sockhost));
		}
		else		/* Failsafe point, don't let the user define their
				   own hostname via the USER command --Cabal95 */
			strncpyzt(user->realhost, sptr->sockhost, HOSTLEN + 1);
		strncpyzt(user->realhost, user->realhost,
		    sizeof(user->realhost));
		/*
		 * I do not consider *, ~ or ! 'hostile' in usernames,
		 * as it is easy to differentiate them (Use \*, \? and \\)
		 * with the possible?
		 * exception of !. With mIRC etc. ident is easy to fake
		 * to contain @ though, so if that is found use non-ident
		 * username. -Donwulff
		 *
		 * I do, We only allow a-z A-Z 0-9 _ - and . now so the
		 * !strchr(sptr->username, '@') check is out of date. -Cabal95
		 *
		 * Moved the noident stuff here. -OnyxDragon
		 */
		if (!(sptr->flags & FLAGS_DOID)) 
			strncpyzt(user->username, username, USERLEN + 1);
		else if (sptr->flags & FLAGS_GOTID) 
			strncpyzt(user->username, sptr->username, USERLEN + 1);
		else
		{

			/* because username may point to user->username */
			char temp[USERLEN + 1];
			strncpyzt(temp, username, USERLEN + 1);
			if (IDENT_CHECK == 0) {
				strncpyzt(user->username, temp, USERLEN + 1);
			}
			else {
				*user->username = '~';
				strncpyzt((user->username + 1), temp, USERLEN);
#ifdef HOSTILENAME
				noident = 1;
#endif
			}

		}
#ifdef HOSTILENAME
		/*
		 * Limit usernames to just 0-9 a-z A-Z _ - and .
		 * It strips the "bad" chars out, and if nothing is left
		 * changes the username to the first 8 characters of their
		 * nickname. After the MOTD is displayed it sends numeric
		 * 455 to the user telling them what(if anything) happened.
		 * -Cabal95
		 *
		 * Moved the noident thing to the right place - see above
		 * -OnyxDragon
		 * 
		 * No longer use nickname if the entire ident is invalid,
                 * if thats the case, it is likely the user is trying to cause
		 * problems so just ban them. (Using the nick could introduce
		 * hostile chars) -- codemastr
		 */
		for (u2 = user->username + noident; *u2; u2++)
		{
			if (isallowed(*u2))
				*u1++ = *u2;
			else if (*u2 < 32)
			{
				/*
				 * Make sure they can read what control
				 * characters were in their username.
				 */
				*ubad++ = '^';
				*ubad++ = *u2 + '@';
			}
			else
				*ubad++ = *u2;
		}
		*u1 = '\0';
		*ubad = '\0';
		if (strlen(stripuser) != strlen(user->username + noident))
		{
			if (stripuser[0] == '\0')
			{
				return exit_client(cptr, cptr, cptr, "Username incorrecto. Usa s�lo 0-9 a-z A-Z _ - . en tu username.");
			}

			strcpy(olduser, user->username + noident);
			strncpy(user->username + 1, stripuser, USERLEN - 1);
			user->username[0] = '~';
			user->username[USERLEN] = '\0';
		}
		else
			u1 = NULL;
#endif

		/*
		 * following block for the benefit of time-dependent K:-lines
		 */
		if ((bconf =
		    Find_ban(sptr, make_user_host(user->username, user->realhost),
		    CONF_BAN_USER)))
		{
			ircstp->is_ref++;
			sendto_one(cptr,
			    ":%s %d %s :*** No puedes acceder en este servidor (%s)"
			    " Env�a un email a %s para m�s informaci�n.",
			    me.name, ERR_YOUREBANNEDCREEP,
			    cptr->name, bconf->reason ? bconf->reason : "",
			    KLINE_ADDRESS);
			return exit_client(cptr, cptr, cptr, "Est�s baneado.");
		}
		if ((bconf = Find_ban(NULL, sptr->info, CONF_BAN_REALNAME)))
		{
			ircstp->is_ref++;
			sendto_one(cptr,
			    ":%s %d %s :*** Tu GECOS (real name) no est� permitido en este servidor (%s)."
			    " C�mbiatelo y reconecta",
			    me.name, ERR_YOUREBANNEDCREEP,
			    cptr->name, bconf->reason ? bconf->reason : "");

			return exit_client(cptr, sptr, &me,
			    "Tu GECOS (real name) est� baneado de este servidor.");
		}
		tkl_check_expire(NULL);
		/* Check G/Z lines before shuns -- kill before quite -- codemastr */
		if ((xx = find_tkline_match(sptr, 0)) < 0)
		{
			ircstp->is_ref++;
			return xx;
		}
		find_shun(sptr);
		xx = find_spamfilter_user(sptr);
		if (xx < 0)
			return xx;
		RunHookReturnInt(HOOKTYPE_PRE_LOCAL_CONNECT, sptr, !=0);
	}
	else
	{
		strncpyzt(user->username, username, USERLEN + 1);
	}
	SetClient(sptr);
	IRCstats.clients++;
	if (sptr->srvptr && sptr->srvptr->serv)
		sptr->srvptr->serv->users++;
#ifdef UDB
	user->virthost = (char *)make_virtualhost(sptr, user->realhost, user->virthost, 1);
    	if ((reg = busca_registro(BDD_NICKS, sptr->name)))
    	{
    		if ((bloq = busca_bloque("swhois", reg)))
		{
			if (sptr->user->swhois)
				MyFree(sptr->user->swhois);
			sptr->user->swhois = strdup(bloq->data_char);
		}
    		if ((bloq = busca_bloque("snomasks", reg)))
    		{
    			set_snomask(sptr, bloq->data_char);
    			if (sptr->user->snomask)
			{
				sptr->user->snomask |= SNO_SNOTICE; /* set +s if needed */
				sptr->umodes |= UMODE_SERVNOTICE;
			}
		}
	}
#else
	user->virthost =
	    (char *)make_virthost(user->realhost, user->virthost, 1);
#endif	 	    
	if (MyConnect(sptr))
	{
		IRCstats.unknown--;
		IRCstats.me_clients++;
		if (IsHidden(sptr))
			ircd_log(LOG_CLIENT, "Connect - %s!%s@%s [VHOST %s]", nick,
				user->username, user->realhost, user->virthost);
		else
			ircd_log(LOG_CLIENT, "Connect - %s!%s@%s", nick, user->username,
				user->realhost);
		sendto_one(sptr, rpl_str(RPL_WELCOME), me.name, nick,
		    ircnetwork, nick, user->username, user->realhost);
		/* This is a duplicate of the NOTICE but see below... */
			sendto_one(sptr, rpl_str(RPL_YOURHOST), me.name, nick,
			    me.name, version);
		sendto_one(sptr, rpl_str(RPL_CREATED), me.name, nick, creation);
		if (!(sptr->listener->umodes & LISTENER_JAVACLIENT))
			sendto_one(sptr, rpl_str(RPL_MYINFO), me.name, parv[0],
			    me.name, version, umodestring, cmodestring);
		else
			sendto_one(sptr, ":%s 004 %s %s CR1.8.03-%s %s %s",
				    me.name, parv[0],
				    me.name, version, umodestring, cmodestring);
		{
			extern char *IsupportStrings[];
			int i;
			for (i = 0; IsupportStrings[i]; i++)
				sendto_one(sptr, rpl_str(RPL_ISUPPORT), me.name, nick, IsupportStrings[i]);
		}
#ifdef USE_SSL
		if (sptr->flags & FLAGS_SSL)
			if (sptr->ssl)
				sendto_one(sptr,
				    ":%s NOTICE %s :*** Est�s conectado a  %s con %s",
				    me.name, sptr->name, me.name,
				    ssl_get_cipher(sptr->ssl));
#endif
		do_cmd(sptr, sptr, "LUSERS", 1, parv);
		short_motd(sptr);
#ifdef EXPERIMENTAL
		sendto_one(sptr,
		    ":%s NOTICE %s :*** \2NOTE:\2 Este servidor (%s) est� bajo desarrollo experimental. Si aprecias alg�n error, comun�calo a la Adminsitraci�n.",
		    me.name, sptr->name, me.name);
#endif
#ifdef HOSTILENAME
		/*
		 * Now send a numeric to the user telling them what, if
		 * anything, happened.
		 */
		if (u1)
			sendto_one(sptr, err_str(ERR_HOSTILENAME), me.name,
			    sptr->name, olduser, userbad, stripuser);
#endif
		nextping = TStime();
		sendto_connectnotice(nick, user, sptr, 0, NULL);
		if (IsSecure(sptr))
			sptr->umodes |= UMODE_SECURE;
	}
	else if (IsServer(cptr))
	{
		aClient *acptr;

		if (!(acptr = (aClient *)find_server_quick(user->server)))
		{
			sendto_ops
			    ("Bad USER [%s] :%s USER %s %s : Falta servidor",
			    cptr->name, nick, user->username, user->server);
			sendto_one(cptr, ":%s KILL %s :%s (Falta servidor: %s)",
			    me.name, sptr->name, me.name, user->server);
			sptr->flags |= FLAGS_KILLED;
			return exit_client(sptr, sptr, &me,
			    "USER sin prefijo(2.8) o err�neo");
		}
		else if (acptr->from != sptr->from)
		{
			sendto_ops("Bad User [%s] :%s USER %s %s, != %s[%s]",
			    cptr->name, nick, user->username, user->server,
			    acptr->name, acptr->from->name);
			sendto_one(cptr, ":%s KILL %s :%s (%s != %s[%s])",
			    me.name, sptr->name, me.name, user->server,
			    acptr->from->name, acptr->from->sockhost);
			sptr->flags |= FLAGS_KILLED;
			return exit_client(sptr, sptr, &me,
			    "USER servidor incorrecto");
		}
		else
			sptr->flags |= acptr->flags;
		/* *FINALL* this gets in ircd... -- Barubary */
		/* We change this a bit .. */
		if (IsULine(sptr->srvptr))
			sptr->flags |= FLAGS_ULINE;
	}
	if (sptr->umodes & UMODE_INVISIBLE)
	{
		IRCstats.invisible++;
	}

	if (virthost && umode)
	{
		tkllayer[0] = nick;
		tkllayer[1] = nick;
		tkllayer[2] = umode;
		dontspread = 1;
		do_cmd(cptr, sptr, "MODE", 3, tkllayer);
		dontspread = 0;
		if (virthost && *virthost != '*')
		{
			if (sptr->user->virthost)
			{
				MyFree(sptr->user->virthost);
				sptr->user->virthost = NULL;
			}
			/* Here pig.. yeah you .. -Stskeeps */
			sptr->user->virthost = strdup(virthost);
		}
		if (ip && (*ip != '*'))
			sptr->user->ip_str = strdup(decode_ip(ip));
	}

	hash_check_watch(sptr, RPL_LOGON);	/* Uglier hack */
	send_umode(NULL, sptr, 0, SEND_UMODES|UMODE_SERVNOTICE, buf);
	/* NICKv2 Servers ! */
	sendto_serv_butone_nickcmd(cptr, sptr, nick,
	    sptr->hopcount + 1, sptr->lastnick, user->username, user->realhost,
	    user->server, user->servicestamp, sptr->info,
	    (!buf || *buf == '\0' ? "+" : buf),
	    sptr->umodes & UMODE_SETHOST ? sptr->user->virthost : NULL);

	/* Send password from sptr->passwd to NickServ for identification,
	 * if passwd given and if NickServ is online.
	 * - by taz, modified by Wizzu
	 */
	if (MyConnect(sptr))
	{
		char userhost[USERLEN + HOSTLEN + 6];
		if (sptr->passwd && (nsptr = find_person(NickServ, NULL)))
			sendto_one(nsptr, ":%s %s %s@%s :IDENTIFY %s",
			    sptr->name,
			    (IsToken(nsptr->from) ? TOK_PRIVATE : MSG_PRIVATE),
			    NickServ, SERVICES_NAME, sptr->passwd);
		/* Force the user to join the given chans -- codemastr */
		if (buf[0] != '\0' && buf[1] != '\0')
			sendto_one(cptr, ":%s MODE %s :%s", cptr->name,
			    cptr->name, buf);
		if (user->snomask)
			sendto_one(sptr, rpl_str(RPL_SNOMASK),
				me.name, sptr->name, get_snostr(user->snomask));
		strcpy(userhost,make_user_host(cptr->user->username, cptr->user->realhost));

		for (tlds = conf_tld; tlds; tlds = (ConfigItem_tld *) tlds->next) {
			if (!match(tlds->mask, userhost))
				break;
		}
		if (tlds && !BadPtr(tlds->channel)) {
			char *chans[3] = {
				sptr->name,
				tlds->channel,
				NULL
			};
			do_cmd(sptr, sptr, "JOIN", 3, chans);
		}
		else if (!BadPtr(AUTO_JOIN_CHANS) && strcmp(AUTO_JOIN_CHANS, "0"))
		{
			char *chans[3] = {
				sptr->name,
				AUTO_JOIN_CHANS,
				NULL
			};
			do_cmd(sptr, sptr, "JOIN", 3, chans);
		}
	}

	if (MyConnect(sptr) && !BadPtr(sptr->passwd))
	{
		MyFree(sptr->passwd);
		sptr->passwd = NULL;
	}
	return 0;
}

/*
** get_mode_str
** by vmlinuz
** returns an ascii string of modes
*/
char *get_sno_str(aClient *sptr) {
	int i;
	char *m;

	m = buf;

	*m++ = '+';
	for (i = 0; i <= Snomask_highest && (m - buf < BUFSIZE - 4); i++)
		if (Snomask_Table[i].flag && sptr->user->snomask & Snomask_Table[i].mode)
			*m++ = Snomask_Table[i].flag;
	*m = 0;
	return buf;
}

char *get_mode_str(aClient *acptr)
{
	int  i;
	char *m;

	m = buf;
	*m++ = '+';
	for (i = 0; (i <= Usermode_highest) && (m - buf < BUFSIZE - 4); i++)
		if (Usermode_Table[i].flag && (acptr->umodes & Usermode_Table[i].mode))
			*m++ = Usermode_Table[i].flag;
	*m = '\0';
	return buf;
}


char *get_modestr(long umodes)
{
	int  i;
	char *m;

	m = buf;
	*m++ = '+';
	for (i = 0; (i <= Usermode_highest) && (m - buf < BUFSIZE - 4); i++)
		
		if (Usermode_Table[i].flag && (umodes & Usermode_Table[i].mode))
			*m++ = Usermode_Table[i].flag;
	*m = '\0';
	return buf;
}

char *get_snostr(long sno) {
	int i;
	char *m;

	m = buf;

	*m++ = '+';
	for (i = 0; i <= Snomask_highest && (m - buf < BUFSIZE - 4); i++)
		if (Snomask_Table[i].flag && sno & Snomask_Table[i].mode)
			*m++ = Snomask_Table[i].flag;
	*m = 0;
	return buf;
}


void set_snomask(aClient *sptr, char *snomask) {
	int what = MODE_ADD; /* keep this an int. -- Syzop */
	char *p;
	int i;
	if (snomask == NULL) {
		sptr->user->snomask = 0;
		return;
	}
	
	for (p = snomask; p && *p; p++) {
		switch (*p) {
			case '+':
				what = MODE_ADD;
				break;
			case '-':
				what = MODE_DEL;
				break;
			default:
		 	 for (i = 0; i <= Snomask_highest; i++)
		 	 {
		 	 	if (!Snomask_Table[i].flag)
		 	 		continue;
		 	 	if (*p == Snomask_Table[i].flag)
		 	 	{
					if (Snomask_Table[i].allowed && !Snomask_Table[i].allowed(sptr,what))
						continue;
		 	 		if (what == MODE_ADD)
			 	 		sptr->user->snomask |= Snomask_Table[i].mode;
			 	 	else
			 	 		sptr->user->snomask &= ~Snomask_Table[i].mode;
		 	 	}
		 	 }				
		}
	}
}

void create_snomask(aClient *sptr, anUser *user, char *snomask) {
	int what = MODE_ADD; /* keep this an int. -- Syzop */
	char *p;
	int i;
	if (snomask == NULL) {
		user->snomask = 0;
		return;
	}
	
	for (p = snomask; p && *p; p++) {
		switch (*p) {
			case '+':
				what = MODE_ADD;
				break;
			case '-':
				what = MODE_DEL;
				break;
			default:
		 	 for (i = 0; i <= Snomask_highest; i++)
		 	 {
		 	 	if (!Snomask_Table[i].flag)
		 	 		continue;
		 	 	if (*p == Snomask_Table[i].flag)
		 	 	{
					if (Snomask_Table[i].allowed && !Snomask_Table[i].allowed(sptr,what))
						continue;
		 	 		if (what == MODE_ADD)
			 	 		user->snomask |= Snomask_Table[i].mode;
			 	 	else
			 	 		user->snomask &= ~Snomask_Table[i].mode;
		 	 	}
		 	 }				
		}
	}
}

/*
 * send the MODE string for user (user) to connection cptr
 * -avalon
 */
void send_umode(aClient *cptr, aClient *sptr, long old, long sendmask, char *umode_buf)
{
	int i;
	long flag;
	char *m;
	int  what = MODE_NULL;

	/*
	 * build a string in umode_buf to represent the change in the user's
	 * mode between the new (sptr->flag) and 'old'.
	 */
	m = umode_buf;
	*m = '\0';
	for (i = 0; i <= Usermode_highest; i++)
	{
		if (!Usermode_Table[i].flag)
			continue;
		flag = Usermode_Table[i].mode;
		if (MyClient(sptr) && !(flag & sendmask))
			continue;
		if ((flag & old) && !(sptr->umodes & flag))
		{
			if (what == MODE_DEL)
				*m++ = Usermode_Table[i].flag;
			else
			{
				what = MODE_DEL;
				*m++ = '-';
				*m++ = Usermode_Table[i].flag;
			}
		}
		else if (!(flag & old) && (sptr->umodes & flag))
		{
			if (what == MODE_ADD)
				*m++ = Usermode_Table[i].flag;
			else
			{
				what = MODE_ADD;
				*m++ = '+';
				*m++ = Usermode_Table[i].flag;
			}
		}
	}
	*m = '\0';
	if (*umode_buf && cptr)
		sendto_one(cptr, ":%s %s %s :%s", sptr->name,
		    (IsToken(cptr) ? TOK_MODE : MSG_MODE),
		    sptr->name, umode_buf);
}

/*
 * added Sat Jul 25 07:30:42 EST 1992
 */
void send_umode_out(aClient *cptr, aClient *sptr, long old)
{
	int  i;
	aClient *acptr;

	send_umode(NULL, sptr, old, SEND_UMODES, buf);

	for (i = LastSlot; i >= 0; i--)
		if ((acptr = local[i]) && IsServer(acptr) &&
		    (acptr != cptr) && (acptr != sptr) && *buf) {
			if (!SupportUMODE2(acptr))
			{
				sendto_one(acptr, ":%s MODE %s :%s",
				    sptr->name, sptr->name, buf);
			}
			else
			{
				sendto_one(acptr, ":%s %s %s",
				    sptr->name,
				    (IsToken(acptr) ? TOK_UMODE2 : MSG_UMODE2),
				    buf);
			}
		}
	if (cptr && MyClient(cptr))
		send_umode(cptr, sptr, old, ALL_UMODES, buf);

}

void send_umode_out_nickv2(aClient *cptr, aClient *sptr, long old)
{
	int  i;
	aClient *acptr;

	send_umode(NULL, sptr, old, SEND_UMODES, buf);

	for (i = LastSlot; i >= 0; i--)
		if ((acptr = local[i]) && IsServer(acptr)
		    && !SupportNICKv2(acptr) && (acptr != cptr)
		    && (acptr != sptr) && *buf)
			sendto_one(acptr, ":%s MODE %s :%s", sptr->name,
			    sptr->name, buf);

	if (cptr && MyClient(cptr))
		send_umode(cptr, sptr, old, ALL_UMODES, buf);

}




int  del_silence(aClient *sptr, char *mask)
{
	Link **lp;
	Link *tmp;

	for (lp = &(sptr->user->silence); *lp; lp = &((*lp)->next))
		if (mycmp(mask, (*lp)->value.cp) == 0)
		{
			tmp = *lp;
			*lp = tmp->next;
			MyFree(tmp->value.cp);
			free_link(tmp);
			return 0;
		}
	return -1;
}

int add_silence(aClient *sptr, char *mask, int senderr)
{
	Link *lp;
	int  cnt = 0;

	for (lp = sptr->user->silence; lp; lp = lp->next)
	{
		if (MyClient(sptr))
			if ((strlen(lp->value.cp) > MAXSILELENGTH) || (++cnt >= SILENCE_LIMIT))
			{
				if (senderr)
					sendto_one(sptr, err_str(ERR_SILELISTFULL), me.name, sptr->name, mask);
				return -1;
			}
			else
			{
				if (!match(lp->value.cp, mask))
					return -1;
			}
		else if (!mycmp(lp->value.cp, mask))
			return -1;
	}
	lp = make_link();
	bzero((char *)lp, sizeof(Link));
	lp->next = sptr->user->silence;
	lp->value.cp = (char *)MyMalloc(strlen(mask) + 1);
	(void)strcpy(lp->value.cp, mask);
	sptr->user->silence = lp;
	return 0;
}
