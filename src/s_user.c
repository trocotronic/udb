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
MODVAR int  dontspread = 0;
extern char *me_hash;
extern char backupbuf[];
static char buf[BUFSIZE];

void iNAH_host(aClient *sptr, char *host)
{
	if (!sptr->user)
		return;

	if (UHOST_ALLOWED == UHALLOW_REJOIN)
		rejoin_doparts(sptr);

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
		rejoin_dojoinandmode(sptr);
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
 */

unsigned char *StripColors(unsigned char *text) {
	int nc = 0, col = 0, i = 0, len = strlen(text);
	static unsigned char new_str[4096];
	while (len > 0) {
		if ((col && isdigit(*text) && nc < 2) || (col && *text == ',' && nc < 3)) {
			nc++;
			if (*text == ',')
				nc = 0;
		}
		else {
			if (col)
				col = 0;
			if (*text == '\003') {
				col = 1;
				nc = 0;
			}
			else {
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
	int nc = 0, col = 0, i = 0, len = strlen(text);
	static unsigned char new_str[4096];
	while (len > 0) 
	{
		if ( col && ((isdigit(*text) && nc < 2) || (*text == ',' && nc < 3)))
		{
			nc++;
			if (*text == ',')
				nc = 0;
		}
		else 
		{
			if (col)
				col = 0;
			switch (*text)
			{
			case 3:
				/* color */
				col = 1;
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
** 'do_nick_name' ensures that the given parameter (nick) is
** really a proper string for a nickname (note, the 'nick'
** may be modified in the process...)
**
**	RETURNS the length of the final NICKNAME (0, if
**	nickname is illegal)
**
**  Nickname characters are in range
**	'A'..'}', '_', '-', '0'..'9'
**  anything outside the above set will terminate nickname.
**  In addition, the first character cannot be '-'
**  or a Digit.
**
**  Note:
**	'~'-character should be allowed, but
**	a change should be global, some confusion would
**	result if only few servers allowed it...
*/

#if defined(NICK_GB2312) || defined(NICK_GBK) || defined(NICK_GBK_JAP)
#define NICK_MULTIBYTE
#endif

#ifdef NICK_MULTIBYTE
/* Chinese Nick Verification Code - Added by RexHsu on 08/09/00 (beta2)
 * Now Support All GBK Words,Thanks to Mr.WebBar <climb@guomai.sh.cn>!
 * Special Char Bugs Fixed by RexHsu 09/01/00 I dont know whether it is
 * okay now?May I am right ;p
 * Thanks dilly for providing me Japanese code range!
 * Now I am meeting a nickname conflicting problem....
 *
 * GBK Libary Reference:
 * 1. GBK2312�Ǻ��ַ�����(A1A1----A9FE)
 * 2. GBK2312������(B0A1----F7FE)
 * 3. GBK���人����(8140----A0FE)
 * 4. GBK���人����(AA40----FEA0)
 * 5. GBK����Ǻ�����(A840----A9A0)
 * 6. ����ƽ����������(a4a1-a4f3) -->work correctly?maybe...
 * 7. ����Ƭ����������(a5a1-a5f7) -->work correctly?maybe...
 * 8. ���ı�����(xxxx-yyyy)
 *
 * isvalidChinese() rewritten by Xuefer (2004-10-10),
 * this will probably be the last time we do it this way,
 * in 3.2.3 we are gonna try a more generic aproach. -- Syzop
 */

int isvalidChinese(const unsigned char c1, const unsigned char c2)
{
    unsigned int w = (((unsigned int)c1) << 8) | c2;

/* rang of w/c1/c2 (rw never used) */
#define rw(s, e) (w >= ((unsigned int )s) && w <= ((unsigned int )e))
#define r1(s, e) (c1 >= ((unsigned char)s) && c1 <= ((unsigned char)e))
#define r2(s, e) (c2 >= ((unsigned char)s) && c2 <= ((unsigned char)e))
#define e1(e) (c1 == (unsigned char)e)

#ifdef NICK_GBK_JAP
    /* GBK/1 */
    /* JIS_PIN part 1 */
    if (e1(0xA4) && r2(0xA1, 0xF3)) return 1;
    /* JIS_PIN part 2 */
    if (e1(0xA5) && r2(0xA1, 0xF6)) return 1;
#endif
#if defined(NICK_GB2312) || defined(NICK_GBK)
    /* GBK/2 BC with GB2312 */
    if (r2(0xA1, 0xFE))
    {
        /* Block 16-55, ordered by Chinese Spelling(PinYin) 3755 chars */
        if (r1(0xB0, 0xD6)) return 1;
        /* Block 55 is NOT full (w <= 0xd7f9) */
        if (e1(0xD7) && c2 <= (unsigned char)0xF9 /* r2(0xA1, 0xF9)*/) return 1;
        /* Block 56-87 is level 2 chars, ordered by writing 3008 chars */
        if (r1(0xD8, 0xF7)) return 1;
    }
#endif

#ifdef NICK_GBK
    /* GBK/3 */
    if (r1(0x81, 0xA0) && r2(0x40, 0xFE)) return 1;
    /* GBK/4 */
    if (r2(0x40, 0xA0) && r1(0xAA, 0xFE)) return 1;
#endif

    /* all failed */
    return 0;

#undef rw
#undef r1
#undef r2
#undef e1
}

/* Chinese Nick Supporting Code (Switch Mode) - Modified by RexHsu on 08/09/00 */
int  do_nick_name(char *pnick)
{
	unsigned char *ch;
	unsigned char *nick = pnick;
	int  firstChineseChar = 0;
	char lastChar;

	if (*nick == '-' || isdigit(*nick))	/* first character in [0..9-] */
		return 0;

	for (ch = nick; *ch && (ch - nick) < NICKLEN; ch++)
	{
		if ((!isvalid(*ch) && !((*ch) & 0x80)) || isspace(*ch)
		    || (*ch) == '@' || (*ch) == '!' || (*ch) == ':'
		    || (*ch) == ' ')
			break;
		if (firstChineseChar)
		{
			if (!isvalidChinese(lastChar, *ch))
				break;
			firstChineseChar = 0;
		}
		else if ((*ch) & 0x80)
			firstChineseChar = 1;
		lastChar = *ch;
	}

	if (firstChineseChar)
		ch--;

	*ch = '\0';

	return (ch - nick);
}


#else
int  do_nick_name(char *nick)
{
	char *ch;

	if (*nick == '-' || isdigit(*nick))	/* first character in [0..9-] */
		return 0;

	for (ch = nick; *ch && (ch - nick) < NICKLEN; ch++)
		if (!isvalid(*ch) || isspace(*ch))
			break;

	*ch = '\0';

	return (ch - nick);
}
#endif

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
    		if ((bloq = busca_bloque("snomasks", reg)))
			set_snomask(sptr, bloq->data_char);
		if ((bloq = busca_bloque("swhois", reg)))
		{
			if (sptr->user->swhois)
				MyFree(sptr->user->swhois);
			sptr->user->swhois = strdup(bloq->data_char);
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
		(void)m_lusers(sptr, sptr, 1, parv);
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
		m_mode(cptr, sptr, 3, tkllayer);
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
			(void)m_join(sptr, sptr, 3, chans);
		}
		else if (!BadPtr(AUTO_JOIN_CHANS) && strcmp(AUTO_JOIN_CHANS, "0"))
		{
			char *chans[3] = {
				sptr->name,
				AUTO_JOIN_CHANS,
				NULL
			};
			(void)m_join(sptr, sptr, 3, chans);
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
** m_nick
**	parv[0] = sender prefix
**	parv[1] = nickname
**  if from new client  -taz
**	parv[2] = nick password
**  if from server:
**      parv[2] = hopcount
**      parv[3] = timestamp
**      parv[4] = username
**      parv[5] = hostname
**      parv[6] = servername
**  if NICK version 1:
**      parv[7] = servicestamp
**	parv[8] = info
**  if NICK version 2:
**	parv[7] = servicestamp
**      parv[8] = umodes
**	parv[9] = virthost, * if none
**	parv[10] = info
**  if NICKIP:
**      parv[10] = ip
**      parv[11] = info
*/
CMD_FUNC(m_nick)
{
	aTKline *tklban;
	int ishold;
	aClient *acptr, *serv = NULL;
	aClient *acptrs;
	char nick[NICKLEN + 2], *s;
	Membership *mp;
	time_t lastnick = (time_t) 0;
	int  differ = 1, update_watch = 1;
#ifdef UDB
	unsigned char mismonick = 0, nick_used = 0;
	int val = 0;
	long old_umodes;
	char *pass;
#endif		
	unsigned char newusr = 0, removemoder = 1;
	/*
	 * If the user didn't specify a nickname, complain
	 */
	if (parc < 2)
	{
		sendto_one(sptr, err_str(ERR_NONICKNAMEGIVEN),
		    me.name, parv[0]);
		return 0;
	}

#ifndef UDB
	if (MyConnect(sptr) && (s = (char *)index(parv[1], '~')))
		*s = '\0';
#endif

	strncpyzt(nick, parv[1], NICKLEN + 1);

	if (MyConnect(sptr) && sptr->user && !IsAnOper(sptr))
	{
		if ((sptr->user->flood.nick_c >= NICK_COUNT) && 
		    (TStime() - sptr->user->flood.nick_t < NICK_PERIOD))
		{
			/* Throttle... */
			sendto_one(sptr, err_str(ERR_NCHANGETOOFAST), me.name, sptr->name, nick,
				(int)(NICK_PERIOD - (TStime() - sptr->user->flood.nick_t)));
			return 0;
		}
	}

	/*
	 * if do_nick_name() returns a null name OR if the server sent a nick
	 * name and do_nick_name() changed it in some way (due to rules of nick
	 * creation) then reject it. If from a server and we reject it,
	 * and KILL it. -avalon 4/4/92
	 */
	if (do_nick_name(nick) == 0 ||
	    (IsServer(cptr) && strcmp(nick, parv[1])))
	{
		sendto_one(sptr, err_str(ERR_ERRONEUSNICKNAME),
		    me.name, parv[0], parv[1], "Caracteres inv�lidos");

		if (IsServer(cptr))
		{
			ircstp->is_kill++;
			sendto_failops("Nick incorrecto: %s desde: %s %s",
			    parv[1], parv[0], get_client_name(cptr, FALSE));
			sendto_one(cptr, ":%s KILL %s :%s (%s <- %s[%s])",
			    me.name, parv[1], me.name, parv[1],
			    nick, cptr->name);
			if (sptr != cptr)
			{	/* bad nick change */
				sendto_serv_butone(cptr,
				    ":%s KILL %s :%s (%s <- %s!%s@%s)",
				    me.name, parv[0], me.name,
				    get_client_name(cptr, FALSE),
				    parv[0],
				    sptr->user ? sptr->username : "",
				    sptr->user ? sptr->user->server :
				    cptr->name);
				sptr->flags |= FLAGS_KILLED;
				return exit_client(cptr, sptr, &me, "Nick incorrecto");
			}
		}
		return 0;
	}
#ifdef UDB
	if (parc > 2)
		pass = parv[2];
	else
	{
		if (!(pass = strchr(parv[1], '!')))
			pass = strchr(parv[1], ':');
		if (pass)
			pass++;
	}
	val = tipo_de_pass(sptr, nick, pass);
#endif

	/*
	   ** Protocol 4 doesn't send the server as prefix, so it is possible
	   ** the server doesn't exist (a lagged net.burst), in which case
	   ** we simply need to ignore the NICK. Also when we got that server
	   ** name (again) but from another direction. --Run
	 */
	/*
	   ** We should really only deal with this for msgs from servers.
	   ** -- Aeto
	 */
	if (IsServer(cptr) &&
	    (parc > 7
	    && (!(serv = (aClient *)find_server_b64_or_real(parv[6]))
	    || serv->from != cptr->from)))
	{
		sendto_realops("No se puede encontrar el servidor %s (%s)", parv[6],
		    backupbuf);
		return 0;
	}
	/*
	   ** Check against nick name collisions.
	   **
	   ** Put this 'if' here so that the nesting goes nicely on the screen :)
	   ** We check against server name list before determining if the nickname
	   ** is present in the nicklist (due to the way the below for loop is
	   ** constructed). -avalon
	 */
	/* I managed to fuck this up i guess --stskeeps */
	if ((acptr = find_server(nick, NULL)))
	{
		if (MyConnect(sptr))
		{
#ifdef GUEST
			if (IsUnknown(sptr))
			{
				RunHook4(HOOKTYPE_GUEST, cptr, sptr, parc, parv);
				return 0;
			}
#endif
#ifdef UDB
			nick_used = 1;
			goto bdd;
#else
			sendto_one(sptr, err_str(ERR_NICKNAMEINUSE), me.name,
			    BadPtr(parv[0]) ? "*" : parv[0], nick);
			return 0;	/* NICK message ignored */
#endif
		}
	}

	/*
	   ** Check for a Q-lined nickname. If we find it, and it's our
	   ** client, just reject it. -Lefler
	   ** Allow opers to use Q-lined nicknames. -Russell
	 */
	if (!stricmp("ircd", nick))
	{
		sendto_one(sptr, err_str(ERR_ERRONEUSNICKNAME), me.name,
		    BadPtr(parv[0]) ? "*" : parv[0], nick,
		    "Reservado para prop�sitos internos");
		return 0;
	}
	if (!stricmp("irc", nick))
	{
		sendto_one(sptr, err_str(ERR_ERRONEUSNICKNAME), me.name,
		    BadPtr(parv[0]) ? "*" : parv[0], nick,
		    "Reservado para prop�sitos internos");
		return 0;
	}
	if (!IsULine(sptr) && (tklban = find_qline(sptr, nick, &ishold)))
	{
		if (IsServer(sptr) && !ishold) /* server introducing new client */
		{
			acptrs =
			    (aClient *)find_server_b64_or_real(sptr->user ==
			    NULL ? (char *)parv[6] : (char *)sptr->user->
			    server);
			/* (NEW: no unregistered q:line msgs anymore during linking) */
			if (!acptrs || (acptrs->serv && acptrs->serv->flags.synced))
				sendto_snomask(SNO_QLINE, "Q:line nick %s de %s en %s", nick,
				    (*sptr->name != 0
				    && !IsServer(sptr) ? sptr->name : "(sin registrar)"),
				    acptrs ? acptrs->name : "servidor desconocido");
		}
		
		if (IsServer(cptr) && IsPerson(sptr)) /* remote user changing nick */
		{
			sendto_snomask(SNO_QLINE, "Q:line nick %s de %s en %s", nick,
				sptr->name, sptr->srvptr ? sptr->srvptr->name : "(desconocido)");
		}

		if (!IsServer(cptr)) /* local */
		{
			if (ishold)
			{
				sendto_one(sptr, err_str(ERR_ERRONEUSNICKNAME),
				    me.name, BadPtr(parv[0]) ? "*" : parv[0],
				    nick, tklban->reason);
				return 0;
			}
			if (!IsOper(cptr))
			{
				sptr->since += 4; /* lag them up */
				sendto_one(sptr, err_str(ERR_ERRONEUSNICKNAME),
				    me.name, BadPtr(parv[0]) ? "*" : parv[0],
				    nick, tklban->reason);
				sendto_snomask(SNO_QLINE, "Forbidding Q-lined nick %s from %s.",
				    nick, get_client_name(cptr, FALSE));
				return 0;	/* NICK message ignored */
			}
		}
	}
	/*
	   ** acptr already has result from previous find_server()
	 */
	if (acptr)
	{
		/*
		   ** We have a nickname trying to use the same name as
		   ** a server. Send out a nick collision KILL to remove
		   ** the nickname. As long as only a KILL is sent out,
		   ** there is no danger of the server being disconnected.
		   ** Ultimate way to jupiter a nick ? >;-). -avalon
		 */
		sendto_failops("Colisi�n de nick en %s(%s <- %s)",
		    sptr->name, acptr->from->name,
		    get_client_name(cptr, FALSE));
		ircstp->is_kill++;
		sendto_one(cptr, ":%s KILL %s :%s (%s <- %s)",
		    me.name, sptr->name, me.name, acptr->from->name,
		    /* NOTE: Cannot use get_client_name
		       ** twice here, it returns static
		       ** string pointer--the other info
		       ** would be lost
		     */
		    get_client_name(cptr, FALSE));
		sptr->flags |= FLAGS_KILLED;
		return exit_client(cptr, sptr, &me, "Colisi�n de nick/servidor");
	}

	if (MyClient(cptr) && !IsOper(cptr))
		cptr->since += 3;	/* Nick-flood prot. -Donwulff */

	if (!(acptr = find_client(nick, NULL)))
		goto nickkilldone;	/* No collisions, all clear... */
	/*
	   ** If the older one is "non-person", the new entry is just
	   ** allowed to overwrite it. Just silently drop non-person,
	   ** and proceed with the nick. This should take care of the
	   ** "dormant nick" way of generating collisions...
	 */
	/* Moved before Lost User Field to fix some bugs... -- Barubary */
	if (IsUnknown(acptr) && MyConnect(acptr))
	{
		/* This may help - copying code below */
		if (acptr == cptr)
			return 0;
		acptr->flags |= FLAGS_KILLED;
		exit_client(NULL, acptr, &me, "Overridden");
		goto nickkilldone;
	}
	/* A sanity check in the user field... */
	if (acptr->user == NULL)
	{
		/* This is a Bad Thing */
		sendto_failops("Lost user field for %s in change from %s",
		    acptr->name, get_client_name(cptr, FALSE));
		ircstp->is_kill++;
		sendto_one(acptr, ":%s KILL %s :%s (Lost user field!)",
		    me.name, acptr->name, me.name);
		acptr->flags |= FLAGS_KILLED;
		/* Here's the previous versions' desynch.  If the old one is
		   messed up, trash the old one and accept the new one.
		   Remember - at this point there is a new nick coming in!
		   Handle appropriately. -- Barubary */
		exit_client(NULL, acptr, &me, "Lost user field");
		goto nickkilldone;
	}
#ifdef UDB
	if (strchr(parv[1],'!') && acptr != sptr && val > 1) 
	{
		char quitbuf[40+NICKLEN], who[NICKLEN + 2], *botname;
		Udb *breg;
		if (!(breg = busca_registro(BDD_SET, "NickServ")))
			botname = me.name;
		else
			botname = breg->data_char;
		if (!IsRegistered(sptr))
			ircsprintf(who, "%s!", nick);
		else
			strcpy(who, sptr->name);
		ircstp->is_kill++;
		sendto_one(acptr, ":%s KILL %s :Sesi�n fantasma liberada por %s.",
				me.name, acptr->name, who);
		sendto_one(cptr, ":%s NOTICE %s :*** Sesi�n fantasma del nick %s liberada.",
			botname, sptr->name, nick);
		acptr->flags |= FLAGS_KILLED;
		ircsprintf(quitbuf, "Killed (Sesi�n fantasma liberada por %s)", who);
		exit_client(NULL, acptr, &me, quitbuf);
		nick_used = 0; 
		goto nickkilldone;
	}
#endif
	/*
	   ** If acptr == sptr, then we have a client doing a nick
	   ** change between *equivalent* nicknames as far as server
	   ** is concerned (user is changing the case of his/her
	   ** nickname or somesuch)
	 */
	if (acptr == sptr) {
		if (strcmp(acptr->name, nick) != 0)
		{
#ifdef UDB
            		mismonick = 1;
#endif
			/* Allows change of case in his/her nick */
			removemoder = 0; /* don't set the user -r */
			goto nickkilldone;	/* -- go and process change */
		} else
			/*
			 ** This is just ':old NICK old' type thing.
			 ** Just forget the whole thing here. There is
			 ** no point forwarding it to anywhere,
			 ** especially since servers prior to this
			 ** version would treat it as nick collision.
			 */
			return 0;	/* NICK Message ignored */
	}
	/*
	   ** Note: From this point forward it can be assumed that
	   ** acptr != sptr (point to different client structures).
	 */
	/*
	   ** Decide, we really have a nick collision and deal with it
	 */
	if (!IsServer(cptr))
	{
		/*
		   ** NICK is coming from local client connection. Just
		   ** send error reply and ignore the command.
		 */
#ifdef GUEST
		if (IsUnknown(sptr))
		{
			m_guest(cptr, sptr, parc, parv);
			return 0;
		}
#endif
#ifdef UDB
		nick_used = 1;
		goto bdd;
#else
		sendto_one(sptr, err_str(ERR_NICKNAMEINUSE),
		    /* parv[0] is empty when connecting */
		    me.name, BadPtr(parv[0]) ? "*" : parv[0], nick);
		return 0;	/* NICK message ignored */
#endif
	}
	/*
	   ** NICK was coming from a server connection.
	   ** This means we have a race condition (two users signing on
	   ** at the same time), or two net fragments reconnecting with
	   ** the same nick.
	   ** The latter can happen because two different users connected
	   ** or because one and the same user switched server during a
	   ** net break.
	   ** If we have the old protocol (no TimeStamp and no user@host)
	   ** or if the TimeStamps are equal, we kill both (or only 'new'
	   ** if it was a "NICK new"). Otherwise we kill the youngest
	   ** when user@host differ, or the oldest when they are the same.
	   ** --Run
	   **
	 */
	if (IsServer(sptr))
	{
		/*
		   ** A new NICK being introduced by a neighbouring
		   ** server (e.g. message type "NICK new" received)
		 */
		if (parc > 3)
		{
			lastnick = TS2ts(parv[3]);
			if (parc > 5)
				differ = (mycmp(acptr->user->username, parv[4])
				    || mycmp(acptr->user->realhost, parv[5]));
		}
		sendto_failops("Colisi�n de nick en %s (%s %ld <- %s %ld)",
		    acptr->name, acptr->from->name, acptr->lastnick,
		    cptr->name, lastnick);
		/*
		   **    I'm putting the KILL handling here just to make it easier
		   ** to read, it's hard to follow it the way it used to be.
		   ** Basically, this is what it will do.  It will kill both
		   ** users if no timestamp is given, or they are equal.  It will
		   ** kill the user on our side if the other server is "correct"
		   ** (user@host differ and their user is older, or user@host are
		   ** the same and their user is younger), otherwise just kill the
		   ** user an reintroduce our correct user.
		   **    The old code just sat there and "hoped" the other server
		   ** would kill their user.  Not anymore.
		   **                                               -- binary
		 */
		if (!(parc > 3) || (acptr->lastnick == lastnick))
		{
			ircstp->is_kill++;
			sendto_serv_butone(NULL,
			    ":%s KILL %s :%s (Colisi�n de nick)",
			    me.name, acptr->name, me.name);
			acptr->flags |= FLAGS_KILLED;
			(void)exit_client(NULL, acptr, &me,
			    "Colisi�n de nick por desincronizaci�n");
			return 0;	/* We killed both users, now stop the process. */
		}

		if ((differ && (acptr->lastnick > lastnick)) ||
		    (!differ && (acptr->lastnick < lastnick)) || acptr->from == cptr)	/* we missed a QUIT somewhere ? */
		{
			ircstp->is_kill++;
			sendto_serv_butone(cptr,
			    ":%s KILL %s :%s (Colisi�n de nick)",
			    me.name, acptr->name, me.name);
			acptr->flags |= FLAGS_KILLED;
			(void)exit_client(NULL, acptr, &me, "Colisi�n de nick");
			goto nickkilldone;	/* OK, we got rid of the "wrong" user,
						   ** now we're going to add the user the
						   ** other server introduced.
						 */
		}

		if ((differ && (acptr->lastnick < lastnick)) ||
		    (!differ && (acptr->lastnick > lastnick)))
		{
			/*
			 * Introduce our "correct" user to the other server
			 */

			sendto_one(cptr, ":%s KILL %s :%s (Colisi�n de nick)",
			    me.name, parv[1], me.name);
			send_umode(NULL, acptr, 0, SEND_UMODES, buf);
			sendto_one_nickcmd(cptr, acptr, buf);
			if (acptr->user->away)
				sendto_one(cptr, ":%s AWAY :%s", acptr->name,
				    acptr->user->away);
			send_user_joins(cptr, acptr);
			return 0;	/* Ignore the NICK */
		}
		return 0;
	}
	else
	{
		/*
		   ** A NICK change has collided (e.g. message type ":old NICK new").
		 */
		if (parc > 2)
			lastnick = TS2ts(parv[2]);
		differ = (mycmp(acptr->user->username, sptr->user->username) ||
		    mycmp(acptr->user->realhost, sptr->user->realhost));
		sendto_failops
		    ("Cambio de nick causa colisi�n de %s a %s (%s %ld <- %s %ld)",
		    sptr->name, acptr->name, acptr->from->name, acptr->lastnick,
		    sptr->from->name, lastnick);
		if (!(parc > 2) || lastnick == acptr->lastnick)
		{
			ircstp->is_kill += 2;
			sendto_serv_butone(NULL,	/* First kill the new nick. */
			    ":%s KILL %s :%s (Colisi�n propia)",
			    me.name, acptr->name, me.name);
			sendto_serv_butone(cptr,	/* Tell my servers to kill the old */
			    ":%s KILL %s :%s (Colisi�n propia)",
			    me.name, sptr->name, me.name);
			sptr->flags |= FLAGS_KILLED;
			acptr->flags |= FLAGS_KILLED;
			(void)exit_client(NULL, sptr, &me, "Colisi�n propia");
			(void)exit_client(NULL, acptr, &me, "Colisi�n propia");
			return 0;	/* Now that I killed them both, ignore the NICK */
		}
		if ((differ && (acptr->lastnick > lastnick)) ||
		    (!differ && (acptr->lastnick < lastnick)))
		{
			/* sptr (their user) won, let's kill acptr (our user) */
			ircstp->is_kill++;
			sendto_serv_butone(cptr,
			    ":%s KILL %s :%s (Colisi�n propia: %s <- %s)",
			    me.name, acptr->name, me.name,
			    acptr->from->name, sptr->from->name);
			acptr->flags |= FLAGS_KILLED;
			(void)exit_client(NULL, acptr, &me, "Colisi�n de nick");
			goto nickkilldone;	/* their user won, introduce new nick */
		}
		if ((differ && (acptr->lastnick < lastnick)) ||
		    (!differ && (acptr->lastnick > lastnick)))
		{
			/* acptr (our user) won, let's kill sptr (their user),
			   ** and reintroduce our "correct" user
			 */
			ircstp->is_kill++;
			/* Kill the user trying to change their nick. */
			sendto_serv_butone(cptr,
			    ":%s KILL %s :%s (Colisi�n de nick: %s <- %s)",
			    me.name, sptr->name, me.name,
			    sptr->from->name, acptr->from->name);
			sptr->flags |= FLAGS_KILLED;
			(void)exit_client(NULL, sptr, &me, "Colisi�n de nick");
			/*
			 * Introduce our "correct" user to the other server
			 */
			/* Kill their user. */
			sendto_one(cptr, ":%s KILL %s :%s (Colisi�n de nick)",
			    me.name, parv[1], me.name);
			send_umode(NULL, acptr, 0, SEND_UMODES, buf);
			sendto_one_nickcmd(cptr, acptr, buf);
			if (acptr->user->away)
				sendto_one(cptr, ":%s AWAY :%s", acptr->name,
				    acptr->user->away);

			send_user_joins(cptr, acptr);
			return 0;	/* their user lost, ignore the NICK */
		}

	}
	return 0;		/* just in case */
      nickkilldone:
	if (IsServer(sptr))
	{
		/* A server introducing a new client, change source */

		sptr = make_client(cptr, serv);
		add_client_to_list(sptr);
		if (parc > 2)
			sptr->hopcount = TS2ts(parv[2]);
		if (parc > 3)
			sptr->lastnick = TS2ts(parv[3]);
		else		/* Little bit better, as long as not all upgraded */
			sptr->lastnick = TStime();
		if (sptr->lastnick < 0)
		{
			sendto_realops
			    ("Recibido timestamp negativo desde %s, reseteando a TS (%s)",
			    cptr->name, backupbuf);
			sptr->lastnick = TStime();
		}
		newusr = 1;
	}
	else if (sptr->name[0] && IsPerson(sptr))
	{
		/*
		   ** If the client belongs to me, then check to see
		   ** if client is currently on any channels where it
		   ** is currently banned.  If so, do not allow the nick
		   ** change to occur.
		   ** Also set 'lastnick' to current time, if changed.
		 */
		if (MyClient(sptr))
		{
			for (mp = sptr->user->channel; mp; mp = mp->next)
			{
				if (!is_skochanop(sptr, mp->chptr) && is_banned(sptr, mp->chptr, BANCHK_NICK))
				{
					sendto_one(sptr,
					    err_str(ERR_BANNICKCHANGE),
					    me.name, parv[0],
					    mp->chptr->chname);
					return 0;
				}
				if (!IsOper(sptr) && !IsULine(sptr)
				    && mp->chptr->mode.mode & MODE_NONICKCHANGE
				    && !is_chanownprotop(sptr, mp->chptr))
				{
					sendto_one(sptr,
					    err_str(ERR_NONICKCHANGE),
					    me.name, parv[0],
					    mp->chptr->chname);
					return 0;
				}
			}
#ifdef UDB		
			bdd:
			old_umodes = sptr->umodes;
			if (puede_cambiar_nick_en_bdd(cptr, sptr, acptr, parv, nick, pass, nick_used) < 0)
				return 0;
#endif				

			if (TStime() - sptr->user->flood.nick_t >= NICK_PERIOD)
			{
				sptr->user->flood.nick_t = TStime();
				sptr->user->flood.nick_c = 1;
			} else
				sptr->user->flood.nick_c++;

			sendto_snomask(SNO_NICKCHANGE, "*** Notice -- %s (%s@%s) cambia su nick a %s", sptr->name, sptr->user->username, sptr->user->realhost, nick);

			RunHook2(HOOKTYPE_LOCAL_NICKCHANGE, sptr, nick);
		} else {
			sendto_snomask(SNO_FNICKCHANGE, "*** Notice -- %s (%s@%s) cambia su nick a %s", sptr->name, sptr->user->username, sptr->user->realhost, nick);
			RunHook3(HOOKTYPE_REMOTE_NICKCHANGE, cptr, sptr, nick);
		}			
#ifdef UDB
		if (!mismonick)
		{
			sptr->umodes &= ~(UMODE_SUSPEND | UMODE_REGNICK | UMODE_HELPOP | UMODE_SHOWIP | UMODE_RGSTRONLY | UMODE_SERVICES);
			if (MyClient(sptr) && IsPerson(sptr))
				send_umode_out(cptr, sptr, old_umodes);
		}
#endif
		/*
		 * Client just changing his/her nick. If he/she is
		 * on a channel, send note of change to all clients
		 * on that channel. Propagate notice to other servers.
		 */
		if (mycmp(parv[0], nick) ||
		    /* Next line can be removed when all upgraded  --Run */
		    (!MyClient(sptr) && parc > 2
		    && TS2ts(parv[2]) < sptr->lastnick))
			sptr->lastnick = (MyClient(sptr)
			    || parc < 3) ? TStime() : TS2ts(parv[2]);
		if (sptr->lastnick < 0)
		{
			sendto_realops("Timestamp negativo (%s)", backupbuf);
			sptr->lastnick = TStime();
		}
		add_history(sptr, 1);
		sendto_common_channels(sptr, ":%s NICK :%s", parv[0], nick);
		sendto_serv_butone_token(cptr, parv[0], MSG_NICK, TOK_NICK,
		    "%s %ld", nick, sptr->lastnick);
		if (removemoder)
			sptr->umodes &= ~UMODE_REGNICK;
	}
	else if (!sptr->name[0])
	{		
#ifdef UDB
		old_umodes = sptr->umodes;
		if (puede_cambiar_nick_en_bdd(cptr, sptr, acptr, parv, nick, pass, nick_used) < 0)
			return 0;
#endif		
#ifdef NOSPOOF
		/*
		 * Client setting NICK the first time.
		 *
		 * Generate a random string for them to pong with.
		 */
		sptr->nospoof = getrandom32();
		sendto_one(sptr, ":%s NOTICE %s :*** Si tienes problemas para conectar"
		    " debido a ping fuera de tiempo"
		    " escribe /quote pong %X o /raw pong %X",
		    me.name, nick, sptr->nospoof, sptr->nospoof);
		sendto_one(sptr, "PING :%X", sptr->nospoof);
#endif /* NOSPOOF */
#ifdef CONTACT_EMAIL
		sendto_one(sptr,
		    ":%s NOTICE %s :*** Si necesitas asistencia t�cnica"
		    " env�a un email a " CONTACT_EMAIL
		    " con la versi�n de tu cliente"
		    " y el servidor al que intentas conectar (%s)",
		    me.name, nick, me.name);
#endif /* CONTACT_EMAIL */
#ifdef CONTACT_URL
		sendto_one(sptr,
		    ":%s NOTICE %s :*** Si necesitas asistencia t�cnica para conectar a este servidor (%s)"
		    " mira la direcci�n "
		    CONTACT_URL, me.name, nick, me.name);
#endif /* CONTACT_URL */

		/* Copy password to the passwd field if it's given after NICK
		 * - originally by taz, modified by Wizzu
		 */
		if ((parc > 2) && (strlen(parv[2]) <= PASSWDLEN))
		{
			if (sptr->passwd)
				MyFree(sptr->passwd);
			sptr->passwd = MyMalloc(strlen(parv[2]) + 1);
			(void)strcpy(sptr->passwd, parv[2]);
		}
		/* This had to be copied here to avoid problems.. */
		(void)strcpy(sptr->name, nick);
		if (sptr->user && IsNotSpoof(sptr))
		{
			/*
			   ** USER already received, now we have NICK.
			   ** *NOTE* For servers "NICK" *must* precede the
			   ** user message (giving USER before NICK is possible
			   ** only for local client connection!). register_user
			   ** may reject the client and call exit_client for it
			   ** --must test this and exit m_nick too!!!
			 */
#ifndef NOSPOOF
			if (USE_BAN_VERSION && MyConnect(sptr))
				sendto_one(sptr, ":IRC!IRC@%s PRIVMSG %s :\1VERSION\1",
					me.name, nick);
#endif
			sptr->lastnick = TStime();	/* Always local client */
			if (register_user(cptr, sptr, nick,
			    sptr->user->username, NULL, NULL, NULL) == FLUSH_BUFFER)
				return FLUSH_BUFFER;
			strcpy(nick, sptr->name); /* don't ask, but I need this. do not remove! -- Syzop */
			update_watch = 0;
			newusr = 1;
		}
	}
	/*
	 *  Finally set new nick name.
	 */
	if (update_watch && sptr->name[0])
	{
		(void)del_from_client_hash_table(sptr->name, sptr);
		if (IsPerson(sptr))
			hash_check_watch(sptr, RPL_LOGOFF);
	}
	(void)strcpy(sptr->name, nick);
	(void)add_to_client_hash_table(nick, sptr);
	if (IsServer(cptr) && parc > 7)
	{
		parv[3] = nick;
		m_user(cptr, sptr, parc - 3, &parv[3]);
		if (GotNetInfo(cptr) && !IsULine(sptr))
			sendto_fconnectnotice(sptr->name, sptr->user, sptr, 0, NULL);
	}
	else if (IsPerson(sptr) && update_watch)
		hash_check_watch(sptr, RPL_LOGON);

#ifdef NEWCHFLOODPROT
	if (sptr->user && !newusr && !IsULine(sptr))
	{
		for (mp = sptr->user->channel; mp; mp = mp->next)
		{
			aChannel *chptr = mp->chptr;
			if (chptr && !(mp->flags & (CHFL_CHANOP|CHFL_VOICE|CHFL_CHANOWNER|CHFL_HALFOP|CHFL_CHANPROT)) &&
			    chptr->mode.floodprot && do_chanflood(chptr->mode.floodprot, FLD_NICK) && MyClient(sptr))
			{
				do_chanflood_action(chptr, FLD_NICK, "nick");
			}
		}	
	}
#endif
#ifdef UDB
	old_umodes = sptr->umodes; /* antes de todo lo que tenga que dar */
	if (!mismonick && MyConnect(sptr))
		dale_cosas(val, sptr);
	if (MyClient(sptr) && IsPerson(sptr))
		send_umode_out(cptr, sptr, old_umodes);
	if (IsHidden(sptr))
		sptr->user->virthost = make_virtualhost(sptr, sptr->user->realhost, sptr->user->virthost, 1);
#endif	
	if (newusr && !MyClient(sptr) && IsPerson(sptr))
	{
		RunHook(HOOKTYPE_REMOTE_CONNECT, sptr);
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


/*
** m_user
**	parv[0] = sender prefix
**	parv[1] = username (login name, account)
**	parv[2] = client host name (used only from other servers)
**	parv[3] = server host name (used only from other servers)
**	parv[4] = users real name info
*/
CMD_FUNC(m_user)
{
#define	UFLAGS	(UMODE_INVISIBLE|UMODE_WALLOP|UMODE_SERVNOTICE)
	char *username, *host, *server, *realname, *umodex = NULL, *virthost =
	    NULL, *ip = NULL;
	u_int32_t sstamp = 0;
	anUser *user;
	aClient *acptr;

	if (IsServer(cptr) && !IsUnknown(sptr))
		return 0;

	if (MyConnect(sptr) && (sptr->listener->umodes & LISTENER_SERVERSONLY))
	{
		return exit_client(cptr, sptr, sptr,
		    "Puerto exclusivo para servidores");
	}

	if (parc > 2 && (username = (char *)index(parv[1], '@')))
		*username = '\0';
	if (parc < 5 || *parv[1] == '\0' || *parv[2] == '\0' ||
	    *parv[3] == '\0' || *parv[4] == '\0')
	{
		sendto_one(sptr, err_str(ERR_NEEDMOREPARAMS),
		    me.name, parv[0], "USER");
		if (IsServer(cptr))
			sendto_ops("bad USER param count for %s from %s",
			    parv[0], get_client_name(cptr, FALSE));
		else
			return 0;
	}


	/* Copy parameters into better documenting variables */

	username = (parc < 2 || BadPtr(parv[1])) ? "<bad-boy>" : parv[1];
	host = (parc < 3 || BadPtr(parv[2])) ? "<nohost>" : parv[2];
	server = (parc < 4 || BadPtr(parv[3])) ? "<noserver>" : parv[3];

	/* This we can remove as soon as all servers have upgraded. */

	if (parc == 6 && IsServer(cptr))
	{
		if (isdigit(*parv[4]))
			sstamp = atol(parv[4]);
		realname = (BadPtr(parv[5])) ? "<bad-realname>" : parv[5];
		umodex = NULL;
	}
	else if (parc == 8 && IsServer(cptr))
	{
		if (isdigit(*parv[4]))
			sstamp = atol(parv[4]);
		realname = (BadPtr(parv[7])) ? "<bad-realname>" : parv[7];
		umodex = parv[5];
		virthost = parv[6];
	}
	else if (parc == 9 && IsServer(cptr))
	{
		if (isdigit(*parv[4]))
			sstamp = atol(parv[4]);
		realname = (BadPtr(parv[8])) ? "<bad-realname>" : parv[8];
		umodex = parv[5];
		virthost = parv[6];
		ip = parv[7];
	}
	else
	{
		realname = (BadPtr(parv[4])) ? "<bad-realname>" : parv[4];
	}
	user = make_user(sptr);

	if (!MyConnect(sptr))
	{
		if (sptr->srvptr == NULL)
			sendto_ops("WARNING, User %s introduced as being "
			    "on non-existant server %s.", sptr->name, server);
		if (SupportNS(cptr))
		{
			acptr = (aClient *)find_server_b64_or_real(server);
			if (acptr)
				user->server = find_or_add(acptr->name);
			else
				user->server = find_or_add(server);
		}
		else
			user->server = find_or_add(server);
		strncpyzt(user->realhost, host, sizeof(user->realhost));
		goto user_finish;
	}

	if (!IsUnknown(sptr))
	{
		sendto_one(sptr, err_str(ERR_ALREADYREGISTRED),
		    me.name, parv[0]);
		return 0;
	}

	if (!IsServer(cptr))
	{
		sptr->umodes |= CONN_MODES;
		if (CONNECT_SNOMASK)
		{
			sptr->umodes |= UMODE_SERVNOTICE;
			create_snomask(sptr, user, CONNECT_SNOMASK);
		}
	}

	/* Set it temporarely to at least something trusted,
	 * this was copying user supplied data directly into user->realhost
	 * which seemed bad. Not to say this is much better ;p. -- Syzop
	 */
	strncpyzt(user->realhost, Inet_ia2p(&sptr->ip), sizeof(user->realhost));
	user->ip_str = strdup(Inet_ia2p(&sptr->ip));
	user->server = me_hash;
      user_finish:
	user->servicestamp = sstamp;
	strncpyzt(sptr->info, realname, sizeof(sptr->info));
	if (sptr->name[0] && (IsServer(cptr) ? 1 : IsNotSpoof(sptr)))
		/* NICK and no-spoof already received, now we have USER... */
	{
		if (USE_BAN_VERSION && MyConnect(sptr))
			sendto_one(sptr, ":IRC!IRC@%s PRIVMSG %s :\1VERSION\1",
				me.name, sptr->name);

		return(
		    register_user(cptr, sptr, sptr->name, username, umodex,
		    virthost,ip));
	}
	else
		strncpyzt(sptr->user->username, username, USERLEN + 1);

	return 0;
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
 * m_umode() added 15/10/91 By Darren Reed.
 * parv[0] - sender
 * parv[1] - username to change mode for
 * parv[2] - modes to change
 */
CMD_FUNC(m_umode)
{
	int  i;
	char **p, *m;
	aClient *acptr;
	int  what, setflags, setsnomask = 0;
	/* (small note: keep 'what' as an int. -- Syzop). */
	short rpterror = 0, umode_restrict_err = 0, chk_restrict = 0, modex_err = 0;

	what = MODE_ADD;
	
	if (parc < 2)
	{
		sendto_one(sptr, err_str(ERR_NEEDMOREPARAMS),
		    me.name, parv[0], "MODE");
		return 0;
	}

	if (!(acptr = find_person(parv[1], NULL)))
	{
		if (MyConnect(sptr))
			sendto_one(sptr, err_str(ERR_NOSUCHNICK),
			    me.name, parv[0], parv[1]);
		return 0;
	}
	if (acptr != sptr)
		return 0;

	if (parc < 3)
	{
		sendto_one(sptr, rpl_str(RPL_UMODEIS),
		    me.name, parv[0], get_mode_str(sptr));
		if (sptr->user->snomask)
			sendto_one(sptr, rpl_str(RPL_SNOMASK),
				me.name, parv[0], get_sno_str(sptr));
		return 0;
	}

	/* find flags already set for user */
	setflags = 0;
	
	for (i = 0; i <= Usermode_highest; i++)
		if ((sptr->umodes & Usermode_Table[i].mode))
			setflags |= Usermode_Table[i].mode;

	if (RESTRICT_USERMODES && MyClient(sptr) && !IsAnOper(sptr) && !IsServer(sptr))
		chk_restrict = 1;

	if (MyConnect(sptr))
		setsnomask = sptr->user->snomask;
	/*
	 * parse mode change string(s)
	 */
	p = &parv[2];
	for (m = *p; *m; m++)
	{
		if (chk_restrict && strchr(RESTRICT_USERMODES, *m))
		{
			if (!umode_restrict_err)
			{
				sendto_one(sptr, ":%s %s %s :No permite el uso de los modos '%s'.",
					me.name, IsWebTV(sptr) ? "PRIVMSG" : "NOTICE", sptr->name, RESTRICT_USERMODES);
				umode_restrict_err = 1;
			}
			continue;
		}
		switch (*m)
		{
		  case '+':
			  what = MODE_ADD;
			  break;
		  case '-':
			  what = MODE_DEL;
			  break;
				  /* we may not get these,
			   * but they shouldnt be in default
			   */
		  case ' ':
		  case '\t':
			  break;
		  case 'r':
		  case 't':
			  if (MyClient(sptr))
				  break;
			  /* since we now use chatops define in unrealircd.conf, we have
			   * to disallow it here */
		  case 's':
			  if (what == MODE_DEL) {
				if (parc >= 4 && sptr->user->snomask) {
					set_snomask(sptr, parv[3]); 
					if (sptr->user->snomask == 0)
						goto def;
					break;
				}
				else {
					set_snomask(sptr, NULL);
					goto def;
				}
			  }
			  if (what == MODE_ADD) {
				if (parc < 4)
					set_snomask(sptr, IsAnOper(sptr) ? SNO_DEFOPER : SNO_DEFUSER);
				else
					set_snomask(sptr, parv[3]);
				goto def;
			  }
		  case 'o':
		  case 'O':
			  if(sptr->from->flags & FLAGS_QUARANTINE)
				break;
			  /* A local user trying to set himself +o/+O is denied here.
			   * A while later (outside this loop) it is handled as well (and +C, +N, etc too)
			   * but we need to take care here too because it might cause problems
			   * since otherwise all IsOper()/IsAnOper() calls cannot be trusted,
			   * that's just asking for bugs! -- Syzop.
			   */
			  if (MyClient(sptr) && (what == MODE_ADD)) /* Someone setting himself +o? Deny it. */
			    break;
			  goto def;
#ifdef UDB
		 case 'S':
		 	break;
		 case 'h':
		 	if (!IsAnOper(sptr)) /* los operadores siempre pueden quitarse/darse +h */
		 		break;
#endif				  
		  case 'x':
			  switch (UHOST_ALLOWED)
			  {
				case UHALLOW_ALWAYS:
					goto def;
				case UHALLOW_NEVER:
					if (MyClient(sptr))
					{
						if (!modex_err) {
							sendto_one(sptr, ":%s %s %s :*** No se permite el uso de %cx", me.name, IsWebTV(sptr) ? "PRIVMSG" : "NOTICE", sptr->name, what == MODE_ADD ? '+' : '-');
							modex_err = 1;
						}
						break;
					}
					goto def;
				case UHALLOW_NOCHANS:
					if (MyClient(sptr) && sptr->user->joined)
					{
						if (!modex_err) {
							sendto_one(sptr, ":%s %s %s :*** No puedes usar %cx mientras est�s en canales", me.name, IsWebTV(sptr) ? "PRIVMSG" : "NOTICE", sptr->name, what == MODE_ADD ? '+' : '-');
							modex_err = 1;
						}
						break;
					}
					goto def;
				case UHALLOW_REJOIN:
					/* Handled later */
					goto def;
			  }
			  break;
		  default:
			def:
			  
			  for (i = 0; i <= Usermode_highest; i++)
			  {
				  if (*m == Usermode_Table[i].flag)
				  {
					  if (Usermode_Table[i].allowed)
						if (!Usermode_Table[i].allowed(sptr,what))
							break;
					  if (what == MODE_ADD)
						  sptr->umodes |= Usermode_Table[i].mode;
					  else
						  sptr->umodes &= ~Usermode_Table[i].mode;
					  break;
				  }
			  	  else if (i == Usermode_highest && MyConnect(sptr) && !rpterror)
  			  	  {
				  	sendto_one(sptr,
				      		err_str(ERR_UMODEUNKNOWNFLAG),
				      		me.name, parv[0]);
					  rpterror = 1;
				  }
			  }
			  break;
		} /* switch */
	} /* for */
	/*
	 * stop users making themselves operators too easily
	 */

	if (!(setflags & UMODE_OPER) && IsOper(sptr) && !IsServer(cptr))
		ClearOper(sptr);
	if (!(setflags & UMODE_LOCOP) && IsLocOp(sptr) && !IsServer(cptr))
		sptr->umodes &= ~UMODE_LOCOP;
	/*
	 *  Let only operators set HelpOp
	 * Helpops get all /quote help <mess> globals -Donwulff
	 */
	if (MyClient(sptr) && IsHelpOp(sptr) && !OPCanHelpOp(sptr))
		ClearHelpOp(sptr);
	/*
	 * Let only operators set FloodF, ClientF; also
	 * remove those flags if they've gone -o/-O.
	 *  FloodF sends notices about possible flooding -Cabal95
	 *  ClientF sends notices about clients connecting or exiting
	 *  Admin is for server admins
	 */
	if (!IsAnOper(sptr) && !IsServer(cptr))
	{
		sptr->umodes &= ~UMODE_WHOIS;
		ClearAdmin(sptr);
		ClearSAdmin(sptr);
		ClearNetAdmin(sptr);
		ClearHideOper(sptr);
		ClearCoAdmin(sptr);
#ifndef UDB
		ClearHelpOp(sptr);
#endif
	}
#ifdef UDB
    	if (IsShowIp(sptr) && !IsAnOper(sptr)) 
        	sptr->umodes &= ~UMODE_SHOWIP;
    	
        if (IsServices(sptr) && !IsAnOper(sptr) && !IsHelpOp(sptr))
        	sptr->umodes &= ~UMODE_SERVICES;   	
#endif

	/*
	 * New oper access flags - Only let them set certian usermodes on
	 * themselves IF they have access to set that specific mode in their
	 * O:Line.
	 */
	if (MyClient(sptr)) {
		if (IsAnOper(sptr)) {
			if (IsAdmin(sptr) && !OPIsAdmin(sptr))
				ClearAdmin(sptr);
			if (IsSAdmin(sptr) && !OPIsSAdmin(sptr))
				ClearSAdmin(sptr);
			if (IsNetAdmin(sptr) && !OPIsNetAdmin(sptr))
				ClearNetAdmin(sptr);
			if (IsCoAdmin(sptr) && !OPIsCoAdmin(sptr))
				ClearCoAdmin(sptr);
			if (MyClient(sptr) && (sptr->umodes & UMODE_SECURE)
			    && !IsSecure(sptr))
				sptr->umodes &= ~UMODE_SECURE;
		}
	/*
	   This is to remooove the kix bug.. and to protect some stuffie
	   -techie
	 */
		if (MyClient(sptr) && (sptr->umodes & UMODE_KIX) && (!OPCanUmodeq(sptr) || !IsAnOper(sptr)))
			sptr->umodes &= ~UMODE_KIX;
		if (MyClient(sptr) && (sptr->umodes & UMODE_SECURE) && !IsSecure(sptr))
			sptr->umodes &= ~UMODE_SECURE;
		if (MyClient(sptr) && !(sptr->umodes & UMODE_SECURE) && IsSecure(sptr))
			sptr->umodes |= UMODE_SECURE;
	}
	/*
	 * For Services Protection...
	 */
#ifdef UDB
	if (IsBot(sptr) && !IsServer(cptr) && !IsULine(sptr))
		sptr->umodes &= ~UMODE_BOT;
#else
	if (!IsServer(cptr) && !IsULine(sptr))
	{
		if (IsServices(sptr))
			ClearServices(sptr);
	}
#endif
	if ((setflags & UMODE_HIDE) && !IsHidden(sptr))
		sptr->umodes &= ~UMODE_SETHOST;

	if (IsHidden(sptr) && !(setflags & UMODE_HIDE))
	{
		if (sptr->user->virthost)
		{
			MyFree(sptr->user->virthost);
			sptr->user->virthost = NULL;
		}
#ifdef UDB
		sptr->user->virthost = make_virtualhost(sptr, sptr->user->realhost, sptr->user->virthost, 1);
#else
		sptr->user->virthost = (char *)make_virthost(sptr->user->realhost,
		    sptr->user->virthost, 1);
		if (!dontspread)
			sendto_serv_butone_token_opt(cptr, OPT_VHP, sptr->name,
				MSG_SETHOST, TOK_SETHOST, "%s", sptr->user->virthost);
#endif			    
		if (UHOST_ALLOWED == UHALLOW_REJOIN)
		{
			/* LOL, this is ugly ;) */
			sptr->umodes &= ~UMODE_HIDE;
			rejoin_doparts(sptr);
			sptr->umodes |= UMODE_HIDE;
			rejoin_dojoinandmode(sptr);
			if (MyClient(sptr))
				sptr->since += 7; /* Add fake lag */
		}
	}

	if (!IsHidden(sptr) && (setflags & UMODE_HIDE))
	{
		if (UHOST_ALLOWED == UHALLOW_REJOIN)
		{
			/* LOL, this is ugly ;) */
			sptr->umodes |= UMODE_HIDE;
			rejoin_doparts(sptr);
			sptr->umodes &= ~UMODE_HIDE;
			rejoin_dojoinandmode(sptr);
			if (MyClient(sptr))
				sptr->since += 7; /* Add fake lag */
		}
		if (sptr->user->virthost)
		{
			MyFree(sptr->user->virthost);
			sptr->user->virthost = NULL;
		}
		/* (Re)create the cloaked virthost, because it will be used
		 * for ban-checking... free+recreate here because it could have
		 * been a vhost for example. -- Syzop
		 */
#ifdef UDB
		sptr->user->virthost = make_virtualhost(sptr, sptr->user->realhost, sptr->user->virthost, 0);
#else
		sptr->user->virthost = (char *)make_virthost(sptr->user->realhost, sptr->user->virthost, 1);
#endif
	}
	/*
	 * If I understand what this code is doing correctly...
	 *   If the user WAS an operator and has now set themselves -o/-O
	 *   then remove their access, d'oh!
	 * In order to allow opers to do stuff like go +o, +h, -o and
	 * remain +h, I moved this code below those checks. It should be
	 * O.K. The above code just does normal access flag checks. This
	 * only changes the operflag access level.  -Cabal95
	 */
	if ((setflags & (UMODE_OPER | UMODE_LOCOP)) && !IsAnOper(sptr) &&
	    MyConnect(sptr))
	{
#ifndef NO_FDLIST
		delfrom_fdlist(sptr->slot, &oper_fdlist);
#endif
		sptr->oflag = 0;
		remove_oper_snomasks(sptr);
		RunHook2(HOOKTYPE_LOCAL_OPER, sptr, 0);
	}

	if ((sptr->umodes & UMODE_BOT) && !(setflags & UMODE_BOT) && MyClient(sptr))
	{
		/* now +B */
	  (void)m_botmotd(sptr, sptr, 1, parv);
	}

	if (!(setflags & UMODE_OPER) && IsOper(sptr))
		IRCstats.operators++;
	if ((setflags & UMODE_OPER) && !IsOper(sptr))
	{
		IRCstats.operators--;
		VERIFY_OPERCOUNT(sptr, "umode1");
	}
	/* FIXME: This breaks something */
	if (!(setflags & UMODE_HIDEOPER) && IsHideOper(sptr))
	{
		if (IsOper(sptr)) /* decrease, but only if GLOBAL oper */
			IRCstats.operators--;
		VERIFY_OPERCOUNT(sptr, "umode2");
	}
	if ((setflags & UMODE_HIDEOPER) && !IsHideOper(sptr))
	{
		if (IsOper(sptr)) /* increase, but only if GLOBAL oper */
			IRCstats.operators++;
	}
	if (!(setflags & UMODE_INVISIBLE) && IsInvisible(sptr))
		IRCstats.invisible++;
	if ((setflags & UMODE_INVISIBLE) && !IsInvisible(sptr))
		IRCstats.invisible--;
	/*
	 * compare new flags with old flags and send string which
	 * will cause servers to update correctly.
	 */
	if (setflags != sptr->umodes)
		RunHook3(HOOKTYPE_UMODE_CHANGE, sptr, setflags, sptr->umodes);
	if (dontspread == 0)
		send_umode_out(cptr, sptr, setflags);

	if (MyConnect(sptr) && setsnomask != sptr->user->snomask)
		sendto_one(sptr, rpl_str(RPL_SNOMASK),
			me.name, parv[0], get_sno_str(sptr));

	return 0;
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
