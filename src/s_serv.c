/*
 *   Unreal Internet Relay Chat Daemon, src/s_serv.c
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
    "@(#)s_serv.c	2.55 2/7/94 (C) 1988 University of Oulu, Computing Center and Jarkko Oikarinen";
#endif
#define AllocCpy(x,y) x  = (char *) MyMalloc(strlen(y) + 1); strcpy(x,y)

#include "struct.h"
#include "common.h"
#include "sys.h"
#include "numeric.h"
#include "msg.h"
#include "channel.h"
#include "version.h"
#include <sys/stat.h>
#include <fcntl.h>
#ifdef _WIN32
#include <io.h>
#endif
#include <time.h>
#include "h.h"
#include "proto.h"
#include <string.h>
#ifdef USE_LIBCURL
#include <curl/curl.h>
#endif
extern VOIDSIG s_die();

static char buf[BUFSIZE];

MODVAR int  max_connection_count = 1, max_client_count = 1;
extern ircstats IRCstats;
extern int do_garbage_collect;
/* We need all these for cached MOTDs -- codemastr */
extern char *buildid;
aMotd *opermotd;
aMotd *rules;
aMotd *motd;
aMotd *svsmotd;
aMotd *botmotd;
aMotd *smotd;
struct tm motd_tm;
struct tm smotd_tm;
aMotd *read_file(char *filename, aMotd **list);
aMotd *read_file_ex(char *filename, aMotd **list, struct tm *);
extern aMotd *Find_file(char *, short);
/*
** m_functions execute protocol messages on this server:
**      CMD_FUNC(functionname) causes it to use the header
**            int functionname (aClient *cptr,
**  	      	aClient *sptr, int parc, char *parv[])
**
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
#ifndef NO_FDLIST
extern fdlist serv_fdlist;
#endif

/*
** m_version
**	parv[0] = sender prefix
**	parv[1] = remote server
*/
CMD_FUNC(m_version)
{
	extern char serveropts[];

	/* Only allow remote VERSIONs if registered -- Syzop */
	if (!IsPerson(sptr) && !IsServer(cptr))
		goto normal;

	if (hunt_server_token(cptr, sptr, MSG_VERSION, TOK_VERSION, ":%s", 1, parc,
	    parv) == HUNTED_ISME)
	{
		sendto_one(sptr, rpl_str(RPL_VERSION), me.name,
		    parv[0], version, debugmode, me.name,
		    serveropts, extraflags ? extraflags : "",
		    tainted ? "3" : "",
		    (IsAnOper(sptr) ? MYOSNAME : "*"), UnrealProtocol);
#ifdef USE_SSL
		if (IsAnOper(sptr))
			sendto_one(sptr, ":%s NOTICE %s :%s", me.name, sptr->name, OPENSSL_VERSION_TEXT);
#endif
#ifdef ZIP_LINKS
		if (IsAnOper(sptr))
			sendto_one(sptr, ":%s NOTICE %s :zlib %s", me.name, sptr->name, zlibVersion());
#endif
#ifdef USE_LIBCURL
		if (IsAnOper(sptr))
			sendto_one(sptr, ":%s NOTICE %s :%s", me.name, sptr->name, curl_version());
#endif
		if (MyClient(sptr)) {
normal:
			sendto_one(sptr, ":%s 005 %s " PROTOCTL_CLIENT_1, me.name, sptr->name, PROTOCTL_PARAMETERS_1);
			sendto_one(sptr, ":%s 005 %s " PROTOCTL_CLIENT_2, me.name, sptr->name, PROTOCTL_PARAMETERS_2);
		}
		else {
			sendto_one(sptr, ":%s 105 %s " PROTOCTL_CLIENT_1, me.name, sptr->name, PROTOCTL_PARAMETERS_1);
			sendto_one(sptr, ":%s 105 %s " PROTOCTL_CLIENT_2, me.name, sptr->name, PROTOCTL_PARAMETERS_2);
		}
	}
	return 0;
}

char *num = NULL;

/*
 * send_proto:
 * sends PROTOCTL message to server, taking care of whether ZIP
 * should be enabled or not.
 */
void send_proto(aClient *cptr, ConfigItem_link *aconf)
{
char buf[512];
	sprintf(buf, "CHANMODES=%s%s,%s%s,%s%s,%s%s",
		CHPAR1, EXPAR1, CHPAR2, EXPAR2, CHPAR3, EXPAR3, CHPAR4, EXPAR4);
#ifdef ZIP_LINKS
	if (aconf->options & CONNECT_ZIP)
	{
		sendto_one(cptr, "PROTOCTL %s ZIP %s", PROTOCTL_SERVER, buf);
	} else {
#endif
		sendto_one(cptr, "PROTOCTL %s %s", PROTOCTL_SERVER, buf);
#ifdef ZIP_LINKS
	}
#endif
#ifdef UDB
	sendto_one(cptr, "PROTOCTL UDB2");
#endif
}

#ifndef IRCDTOTALVERSION
#define IRCDTOTALVERSION BASE_VERSION PATCH1 PATCH2 PATCH3 PATCH4 PATCH5 PATCH6 PATCH7 PATCH8 PATCH9
#endif

/*
 * sends m_info into to sptr
*/

void m_info_send(aClient *sptr)
{
	sendto_one(sptr, ":%s %d %s :=-=-=-= %s =-=-=-=",
	    me.name, RPL_INFO, sptr->name, IRCDTOTALVERSION);
	sendto_one(sptr, ":%s %d %s :| Brought to you by the following people:",
	    me.name, RPL_INFO, sptr->name);
	sendto_one(sptr, ":%s %d %s :|", me.name, RPL_INFO, sptr->name);
	sendto_one(sptr, ":%s %d %s :| Head coders:", me.name, RPL_INFO, sptr->name);
	sendto_one(sptr, ":%s %d %s :|", me.name, RPL_INFO, sptr->name);
	sendto_one(sptr, ":%s %d %s :| * Stskeeps     <stskeeps@unrealircd.com>",
	    me.name, RPL_INFO, sptr->name);
	sendto_one(sptr, ":%s %d %s :| * codemastr    <codemastr@unrealircd.com>",
	    me.name, RPL_INFO, sptr->name);
	sendto_one(sptr, ":%s %d %s :| * Syzop        <syzop@unrealircd.com>",
	    me.name, RPL_INFO, sptr->name);
	sendto_one(sptr, ":%s %d %s :| * Luke         <luke@unrealircd.com>",
	    me.name, RPL_INFO, sptr->name);
	sendto_one(sptr, ":%s %d %s :|", me.name, RPL_INFO, sptr->name);
	sendto_one(sptr, ":%s %d %s :| Contributors:", me.name, RPL_INFO, sptr->name);
	sendto_one(sptr, ":%s %d %s :|", me.name, RPL_INFO, sptr->name);
	sendto_one(sptr, ":%s %d %s :| * McSkaf       <mcskaf@unrealircd.com>",
	    me.name, RPL_INFO, sptr->name);
	sendto_one(sptr, ":%s %d %s :| * Zogg         <zogg@unrealircd.org>",
	    me.name, RPL_INFO, sptr->name);
	sendto_one(sptr, ":%s %d %s :| * NiQuiL       <niquil@unrealircd.org>",
	    me.name, RPL_INFO, sptr->name);
	sendto_one(sptr, ":%s %d %s :| * assyrian     <assyrian@unrealircd.org>",
	    me.name, RPL_INFO, sptr->name);
	sendto_one(sptr, ":%s %d %s :| * chasm        <chasm@unrealircd.org>",
	    me.name, RPL_INFO, sptr->name);
	sendto_one(sptr, ":%s %d %s :| * DrBin        <drbin@unrealircd.com>",
	    me.name, RPL_INFO, sptr->name);
	sendto_one(sptr, ":%s %d %s :| * llthangel    <llthangel@unrealircd.com>",
	    me.name, RPL_INFO, sptr->name);
	sendto_one(sptr, ":%s %d %s :| * Griever      <griever@unrealircd.com>",
	    me.name, RPL_INFO, sptr->name);
	sendto_one(sptr, ":%s %d %s :| * nighthawk    <nighthawk@unrealircd.com>",
	    me.name, RPL_INFO, sptr->name);
	sendto_one(sptr, ":%s %d %s :|", me.name, RPL_INFO, sptr->name);
	sendto_one(sptr, ":%s %d %s :| Credits - Type /Credits",
	    me.name, RPL_INFO, sptr->name);
	sendto_one(sptr, ":%s %d %s :| DALnet Credits - Type /DalInfo",
	    me.name, RPL_INFO, sptr->name);
	sendto_one(sptr, ":%s %d %s :|", me.name, RPL_INFO, sptr->name);
	sendto_one(sptr, ":%s %d %s :| This is an UnrealIRCD-style server",
	    me.name, RPL_INFO, sptr->name);
	sendto_one(sptr, ":%s %d %s :| If you find any bugs, please mail",
	    me.name, RPL_INFO, sptr->name);
	sendto_one(sptr, ":%s %d %s :|  bugs@lists.unrealircd.org",
	    me.name, RPL_INFO, sptr->name);

	sendto_one(sptr,
	    ":%s %d %s :| UnrealIRCd Homepage: http://www.unrealircd.com",
	    me.name, RPL_INFO, sptr->name);

#ifdef _WIN32
#ifdef WIN32_SPECIFY
	sendto_one(sptr, ":%s %d %s :| wIRCd porter: | %s",
	    me.name, RPL_INFO, sptr->name, WIN32_PORTER);
	sendto_one(sptr, ":%s %d %s :|     >>URL:    | %s",
	    me.name, RPL_INFO, sptr->name, WIN32_URL);
#endif
#endif
#ifdef UDB
	sendto_one(sptr, ":%s %d %s :|", me.name, RPL_INFO, sptr->name);
	sendto_one(sptr,
	    ":%s %d %s :| Sistema y protocolo UDB, traducci�n al castellano y extendido a helpers implementado por:",
	    me.name, RPL_INFO, sptr->name);
	sendto_one(sptr,
	    ":%s %d %s :|          * Trocotronic (trocotronic@telefonica.net)", me.name, RPL_INFO, sptr->name);
	sendto_one(sptr,
	    ":%s %d %s :| Soporte de infrastructura y testeado por:", me.name, RPL_INFO, sptr->name);
	sendto_one(sptr,
	    ":%s %d %s :|          * MaD (mad@madito.net)", me.name, RPL_INFO, sptr->name);
	sendto_one(sptr, ":%s %d %s :| M�s informaci�n en %c\00312http://www.rallados.net", me.name, RPL_INFO, sptr->name, 31);
#endif
	sendto_one(sptr,
	    ":%s %d %s :-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=", me.name,
	    RPL_INFO, sptr->name);
	sendto_one(sptr, ":%s %d %s :Birth Date: %s, compile # %s", me.name,
	    RPL_INFO, sptr->name, creation, generation);
	sendto_one(sptr, ":%s %d %s :On-line since %s", me.name, RPL_INFO,
	    sptr->name, myctime(me.firsttime));
	sendto_one(sptr, ":%s %d %s :ReleaseID (%s)", me.name, RPL_INFO,
	    sptr->name, buildid);
	sendto_one(sptr, rpl_str(RPL_ENDOFINFO), me.name, sptr->name);
}

/*
** m_info
**	parv[0] = sender prefix
**	parv[1] = servername
**  Modified for hardcode by Stskeeps
*/

CMD_FUNC(m_info)
{

	if (hunt_server_token(cptr, sptr, MSG_INFO, TOK_INFO, ":%s", 1, parc,
	    parv) == HUNTED_ISME)
	{
		m_info_send(sptr);
	}

	return 0;
}

/*
** m_dalinfo
**      parv[0] = sender prefix
**      parv[1] = servername
*/
CMD_FUNC(m_dalinfo)
{
	char **text = dalinfotext;

	if (hunt_server_token(cptr, sptr, MSG_DALINFO, TOK_DALINFO, ":%s", 1, parc,
	    parv) == HUNTED_ISME)
	{
		while (*text)
			sendto_one(sptr, rpl_str(RPL_INFO),
			    me.name, parv[0], *text++);

		sendto_one(sptr, rpl_str(RPL_INFO), me.name, parv[0], "");
		sendto_one(sptr,
		    ":%s %d %s :Birth Date: %s, compile # %s",
		    me.name, RPL_INFO, parv[0], creation, generation);
		sendto_one(sptr, ":%s %d %s :On-line since %s",
		    me.name, RPL_INFO, parv[0], myctime(me.firsttime));
		sendto_one(sptr, rpl_str(RPL_ENDOFINFO), me.name, parv[0]);
	}

	return 0;
}

/*
** m_license
**      parv[0] = sender prefix
**      parv[1] = servername
*/
CMD_FUNC(m_license)
{
	char **text = gnulicense;

	if (hunt_server_token(cptr, sptr, MSG_LICENSE, TOK_LICENSE, ":%s", 1, parc,
	    parv) == HUNTED_ISME)
	{
		while (*text)
			sendto_one(sptr, rpl_str(RPL_INFO),
			    me.name, parv[0], *text++);

		sendto_one(sptr, rpl_str(RPL_INFO), me.name, parv[0], "");
		sendto_one(sptr, rpl_str(RPL_ENDOFINFO), me.name, parv[0]);
	}

	return 0;
}

/*
** m_credits
**      parv[0] = sender prefix
**      parv[1] = servername
*/
CMD_FUNC(m_credits)
{
	char **text = unrealcredits;

	if (hunt_server_token(cptr, sptr, MSG_CREDITS, TOK_CREDITS, ":%s", 1, parc,
	    parv) == HUNTED_ISME)
	{
		while (*text)
			sendto_one(sptr, rpl_str(RPL_INFO),
			    me.name, parv[0], *text++);

		sendto_one(sptr, rpl_str(RPL_INFO), me.name, parv[0], "");
		sendto_one(sptr,
		    ":%s %d %s :Birth Date: %s, compile # %s",
		    me.name, RPL_INFO, parv[0], creation, generation);
		sendto_one(sptr, ":%s %d %s :On-line since %s",
		    me.name, RPL_INFO, parv[0], myctime(me.firsttime));
		sendto_one(sptr, rpl_str(RPL_ENDOFINFO), me.name, parv[0]);
	}

	return 0;
}


/*
 * RPL_NOWON	- Online at the moment (Succesfully added to WATCH-list)
 * RPL_NOWOFF	- Offline at the moement (Succesfully added to WATCH-list)
 * RPL_WATCHOFF	- Succesfully removed from WATCH-list.
 * ERR_TOOMANYWATCH - Take a guess :>  Too many WATCH entries.
 */
static void show_watch(aClient *cptr, char *name, int rpl1, int rpl2)
{
	aClient *acptr;


	if ((acptr = find_person(name, NULL)))
	{
		sendto_one(cptr, rpl_str(rpl1), me.name, cptr->name,
		    acptr->name, acptr->user->username,
		    IsHidden(acptr) ? acptr->user->virthost : acptr->user->
		    realhost, acptr->lastnick);
	}
	else
		sendto_one(cptr, rpl_str(rpl2), me.name, cptr->name,
		    name, "*", "*", 0);
}

/*
 * m_watch
 */
CMD_FUNC(m_watch)
{
	aClient *acptr;
	char *s, **pav = parv, *user;
	char *p = NULL, *def = "l";



	if (parc < 2)
	{
		/*
		 * Default to 'l' - list who's currently online
		 */
		parc = 2;
		parv[1] = def;
	}

	for (s = (char *)strtoken(&p, *++pav, " "); s;
	    s = (char *)strtoken(&p, NULL, " "))
	{
		if ((user = (char *)index(s, '!')))
			*user++ = '\0';	/* Not used */

		/*
		 * Prefix of "+", they want to add a name to their WATCH
		 * list.
		 */
		if (*s == '+')
		{
			if (do_nick_name(s + 1))
			{
				if (sptr->watches >= MAXWATCH)
				{
					sendto_one(sptr,
					    err_str(ERR_TOOMANYWATCH), me.name,
					    cptr->name, s + 1);

					continue;
				}

				add_to_watch_hash_table(s + 1, sptr);
			}

			show_watch(sptr, s + 1, RPL_NOWON, RPL_NOWOFF);
			continue;
		}

		/*
		 * Prefix of "-", coward wants to remove somebody from their
		 * WATCH list.  So do it. :-)
		 */
		if (*s == '-')
		{
			del_from_watch_hash_table(s + 1, sptr);
			show_watch(sptr, s + 1, RPL_WATCHOFF, RPL_WATCHOFF);

			continue;
		}

		/*
		 * Fancy "C" or "c", they want to nuke their WATCH list and start
		 * over, so be it.
		 */
		if (*s == 'C' || *s == 'c')
		{
			hash_del_watch_list(sptr);

			continue;
		}

		/*
		 * Now comes the fun stuff, "S" or "s" returns a status report of
		 * their WATCH list.  I imagine this could be CPU intensive if its
		 * done alot, perhaps an auto-lag on this?
		 */
		if (*s == 'S' || *s == 's')
		{
			Link *lp;
			aWatch *anptr;
			int  count = 0;

			/*
			 * Send a list of how many users they have on their WATCH list
			 * and how many WATCH lists they are on.
			 */
			anptr = hash_get_watch(sptr->name);
			if (anptr)
				for (lp = anptr->watch, count = 1;
				    (lp = lp->next); count++)
					;
			sendto_one(sptr, rpl_str(RPL_WATCHSTAT), me.name,
			    parv[0], sptr->watches, count);

			/*
			 * Send a list of everybody in their WATCH list. Be careful
			 * not to buffer overflow.
			 */
			if ((lp = sptr->watch) == NULL)
			{
				sendto_one(sptr, rpl_str(RPL_ENDOFWATCHLIST),
				    me.name, parv[0], *s);
				continue;
			}
			*buf = '\0';
			strlcpy(buf, lp->value.wptr->nick, sizeof buf);
			count =
			    strlen(parv[0]) + strlen(me.name) + 10 +
			    strlen(buf);
			while ((lp = lp->next))
			{
				if (count + strlen(lp->value.wptr->nick) + 1 >
				    BUFSIZE - 2)
				{
					sendto_one(sptr, rpl_str(RPL_WATCHLIST),
					    me.name, parv[0], buf);
					*buf = '\0';
					count =
					    strlen(parv[0]) + strlen(me.name) +
					    10;
				}
				strcat(buf, " ");
				strcat(buf, lp->value.wptr->nick);
				count += (strlen(lp->value.wptr->nick) + 1);
			}
			sendto_one(sptr, rpl_str(RPL_WATCHLIST), me.name,
			    parv[0], buf);

			sendto_one(sptr, rpl_str(RPL_ENDOFWATCHLIST), me.name,
			    parv[0], *s);
			continue;
		}

		/*
		 * Well that was fun, NOT.  Now they want a list of everybody in
		 * their WATCH list AND if they are online or offline? Sheesh,
		 * greedy arn't we?
		 */
		if (*s == 'L' || *s == 'l')
		{
			Link *lp = sptr->watch;

			while (lp)
			{
				if ((acptr =
				    find_person(lp->value.wptr->nick, NULL)))
				{
					sendto_one(sptr, rpl_str(RPL_NOWON),
					    me.name, parv[0], acptr->name,
					    acptr->user->username,
					    IsHidden(acptr) ? acptr->user->
					    virthost : acptr->user->realhost,
					    acptr->lastnick);
				}
				/*
				 * But actually, only show them offline if its a capital
				 * 'L' (full list wanted).
				 */
				else if (isupper(*s))
					sendto_one(sptr, rpl_str(RPL_NOWOFF),
					    me.name, parv[0],
					    lp->value.wptr->nick, "*", "*",
					    lp->value.wptr->lasttime);
				lp = lp->next;
			}

			sendto_one(sptr, rpl_str(RPL_ENDOFWATCHLIST), me.name,
			    parv[0], *s);

			continue;
		}

		/*
		 * Hmm.. unknown prefix character.. Ignore it. :-)
		 */
	}

	return 0;
}

char *get_cptr_status(aClient *acptr)
{
	static char buf[10];
	char *p = buf;

	*p = '\0';
	*p++ = '[';
	if (acptr->flags & FLAGS_LISTEN)
	{
		if (acptr->umodes & LISTENER_NORMAL)
			*p++ = '*';
		if (acptr->umodes & LISTENER_SERVERSONLY)
			*p++ = 'S';
		if (acptr->umodes & LISTENER_CLIENTSONLY)
			*p++ = 'C';
#ifdef USE_SSL
		if (acptr->umodes & LISTENER_SSL)
			*p++ = 's';
#endif
		if (acptr->umodes & LISTENER_REMOTEADMIN)
			*p++ = 'R';
		if (acptr->umodes & LISTENER_JAVACLIENT)
			*p++ = 'J';
	}
	else
	{
#ifdef USE_SSL
		if (acptr->flags & FLAGS_SSL)
			*p++ = 's';
#endif
	}
	*p++ = ']';
	*p++ = '\0';
	return (buf);
}

/* Used to blank out ports -- Barubary */
char *get_client_name2(aClient *acptr, int showports)
{
	char *pointer = get_client_name(acptr, TRUE);

	if (!pointer)
		return NULL;
	if (showports)
		return pointer;
	if (!strrchr(pointer, '.'))
		return NULL;
	/*
	 * This may seem like wack but remind this is only used 
	 * in rows of get_client_name2's, so it's perfectly fair
	 * 
	*/
	strcpy((char *)strrchr((char *)pointer, '.'), ".0]");

	return pointer;
}

/*
** m_summon
** parv[0] = sender prefix
*/
CMD_FUNC(m_summon)
{
	/* /summon is old and out dated, we just return an error as
	 * required by RFC1459 -- codemastr
	 */ sendto_one(sptr, err_str(ERR_SUMMONDISABLED), me.name, parv[0]);
	return 0;
}
/*
** m_users
**	parv[0] = sender prefix
**	parv[1] = servername
*/ 
CMD_FUNC(m_users)
{
	/* /users is out of date, just return an error as  required by
	 * RFC1459 -- codemastr
	 */ sendto_one(sptr, err_str(ERR_USERSDISABLED), me.name, parv[0]);
	return 0;
}
/*
** Note: At least at protocol level ERROR has only one parameter,
** although this is called internally from other functions
** --msa
**
**	parv[0] = sender prefix
**	parv[*] = parameters
*/ 
CMD_FUNC(m_error)
{
	char *para;

	para = (parc > 1 && *parv[1] != '\0') ? parv[1] : "<>";

	Debug((DEBUG_ERROR, "Received ERROR message from %s: %s",
	    sptr->name, para));
	/*
	   ** Ignore error messages generated by normal user clients
	   ** (because ill-behaving user clients would flood opers
	   ** screen otherwise). Pass ERROR's from other sources to
	   ** the local operator...
	 */
	if (IsPerson(cptr) || IsUnknown(cptr))
		return 0;
	if (cptr == sptr)
	{
		sendto_serv_butone(&me, ":%s GLOBOPS :ERROR de %s -- %s",
		    me.name, get_client_name(cptr, FALSE), para);
		sendto_locfailops("ERROR :de %s -- %s",
		    get_client_name(cptr, FALSE), para);
	}
	else
	{
		sendto_serv_butone(&me,
		    ":%s GLOBOPS :ERROR de %s via %s -- %s", me.name,
		    sptr->name, get_client_name(cptr, FALSE), para);
		sendto_ops("ERROR :de %s via %s -- %s", sptr->name,
		    get_client_name(cptr, FALSE), para);
	}
	return 0;
}

Link *helpign = NULL;

/* Now just empty ignore-list, in future reload dynamic help.
 * Move out to help.c -Donwulff */
void reset_help(void)
{
	free_str_list(helpign);
}

/*
 * parv[0] = sender
 * parv[1] = server to query
 */
CMD_FUNC(m_lusers)
{
	if (hunt_server_token(cptr, sptr, MSG_LUSERS, TOK_LUSERS, ":%s", 1, parc,
	    parv) != HUNTED_ISME)
		return 0;
	/* Just to correct results ---Stskeeps */
	if (IRCstats.clients > IRCstats.global_max)
		IRCstats.global_max = IRCstats.clients;
	if (IRCstats.me_clients > IRCstats.me_max)
		IRCstats.me_max = IRCstats.me_clients;

	sendto_one(sptr, rpl_str(RPL_LUSERCLIENT), me.name, parv[0],
	    IRCstats.clients - IRCstats.invisible, IRCstats.invisible,
	    IRCstats.servers);

	if (IRCstats.operators)
		sendto_one(sptr, rpl_str(RPL_LUSEROP),
		    me.name, parv[0], IRCstats.operators);
	if (IRCstats.unknown)
		sendto_one(sptr, rpl_str(RPL_LUSERUNKNOWN),
		    me.name, parv[0], IRCstats.unknown);
	if (IRCstats.channels)
		sendto_one(sptr, rpl_str(RPL_LUSERCHANNELS),
		    me.name, parv[0], IRCstats.channels);
	sendto_one(sptr, rpl_str(RPL_LUSERME),
	    me.name, parv[0], IRCstats.me_clients, IRCstats.me_servers);
	sendto_one(sptr, rpl_str(RPL_LOCALUSERS),
	    me.name, parv[0], IRCstats.me_clients, IRCstats.me_max);
	sendto_one(sptr, rpl_str(RPL_GLOBALUSERS),
	    me.name, parv[0], IRCstats.clients, IRCstats.global_max);
	if ((IRCstats.me_clients + IRCstats.me_servers) > max_connection_count)
	{
		max_connection_count =
		    IRCstats.me_clients + IRCstats.me_servers;
		if (max_connection_count % 10 == 0)	/* only send on even tens */
			sendto_ops("M�ximo conexiones: %d (%d clientes)",
			    max_connection_count, IRCstats.me_clients);
	}
	return 0;
}


EVENT(save_tunefile)
{
	FILE *tunefile;

	tunefile = fopen(IRCDTUNE, "w");
	if (!tunefile)
	{
#if !defined(_WIN32) && !defined(_AMIGA)
		sendto_ops("Imposible escribir tunefile.. %s", strerror(errno));
#else
		sendto_ops("Imposible escribir tunefile..");
#endif
		return;
	}
	fprintf(tunefile, "%li\n", TSoffset);
	fprintf(tunefile, "%d\n", IRCstats.me_max);
	fclose(tunefile);
}

void load_tunefile(void)
{
	FILE *tunefile;
	char buf[1024];

	tunefile = fopen(IRCDTUNE, "r");
	if (!tunefile)
		return;
	fprintf(stderr, "* Cargando tunefile..\n");
	fgets(buf, 1023, tunefile);
	TSoffset = atol(buf);
	fgets(buf, 1023, tunefile);
	IRCstats.me_max = atol(buf);
	fclose(tunefile);
}

/** Rehash motd and rule files (MPATH/RPATH and all tld entries). */
void rehash_motdrules()
{
ConfigItem_tld *tlds;

	motd = (aMotd *) read_file_ex(MPATH, &motd, &motd_tm);
	rules = (aMotd *) read_file(RPATH, &rules);
	smotd = (aMotd *) read_file_ex(SMPATH, &smotd, &smotd_tm);
	for (tlds = conf_tld; tlds; tlds = (ConfigItem_tld *) tlds->next)
	{
		tlds->motd = read_file_ex(tlds->motd_file, &tlds->motd, &tlds->motd_tm);
		tlds->rules = read_file(tlds->rules_file, &tlds->rules);
		if (tlds->smotd_file)
			tlds->smotd = read_file_ex(tlds->smotd_file, &tlds->smotd, &tlds->smotd_tm);
	}
}

void reread_motdsandrules()
{
	motd = (aMotd *) read_file_ex(MPATH, &motd, &motd_tm);
	rules = (aMotd *) read_file(RPATH, &rules);
	smotd = (aMotd *) read_file_ex(SMPATH, &smotd, &smotd_tm);
	botmotd = (aMotd *) read_file(BPATH, &botmotd);
	opermotd = (aMotd *) read_file(OPATH, &opermotd);
}

/*
** m_rehash
** remote rehash by binary
** now allows the -flags in remote rehash
** ugly code but it seems to work :) -- codemastr
** added -all and fixed up a few lines -- niquil (niquil@programmer.net)
** fixed remote rehashing, but it's getting a bit weird code again -- Syzop
** removed '-all' code, this is now considered as '/rehash', this is ok
** since we rehash everything with simple '/rehash' now. Syzop/20040205
*/
CMD_FUNC(m_rehash)
{
	int  x;

	if (MyClient(sptr) && !OPCanRehash(sptr))
	{
		sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name, parv[0]);
		return 0;
	}
	if (!MyClient(sptr) && !IsNetAdmin(sptr)
	    && !IsULine(sptr))
	{
		sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name, parv[0]);
		return 0;
	}
	x = 0;

	if (BadPtr(parv[2])) {
		/* If the argument starts with a '-' (like -motd, -opermotd, etc) then it's
		 * assumed not to be a server. -- Syzop
		 */
		if (parv[1] && (parv[1][0] == '-'))
			x = HUNTED_ISME;
		else
			x = hunt_server_token(cptr, sptr, MSG_REHASH, TOK_REHASH, "%s", 1, parc, parv);
	} else {
		x = hunt_server_token(cptr, sptr, MSG_REHASH, TOK_REHASH, "%s %s", 1, parc, parv);
	}
	if (x != HUNTED_ISME)
		return 0; /* Now forwarded or server didnt exist */

	if (cptr != sptr)
	{
#ifndef REMOTE_REHASH
		sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name, parv[0]);
		return 0;
#endif
		if (parv[2] == NULL)
		{
			if (loop.ircd_rehashing)
			{
				sendto_one(sptr, ":%s NOTICE %s :A rehash is already in progress",
					me.name, sptr->name);
				return 0;
			}
			sendto_serv_butone(&me,
			    ":%s GLOBOPS :%s refresca configuraci�n",
			    me.name, sptr->name);
			sendto_ops
			    ("%s refresca configuraci�n",
			    parv[0]);
			reread_motdsandrules();
			return rehash(cptr, sptr,
			    (parc > 1) ? ((*parv[1] == 'q') ? 2 : 0) : 0);
		}
		parv[1] = parv[2];
	}

	if (!BadPtr(parv[1]) && strcmp(parv[1], "-all"))
	{

		if (!IsAdmin(sptr) && !IsCoAdmin(sptr))
		{
			sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name, parv[0]);
			return 0;
		}

		if (*parv[1] == '-')
		{
			if (!strnicmp("-gar", parv[1], 4))
			{
				loop.do_garbage_collect = 1;
				RunHook3(HOOKTYPE_REHASHFLAG, cptr, sptr, parv[1]);
				return 0;
			}
			if (!_match("-o*motd", parv[1]))
			{
				sendto_ops
				    ("%sRehashing OperMOTD on request of %s",
				    cptr != sptr ? "Remotely " : "",
				    sptr->name);
				if (cptr != sptr)
					sendto_serv_butone(&me, ":%s GLOBOPS :%s is remotely rehashing OperMOTD", me.name, sptr->name);
				opermotd = (aMotd *) read_file(OPATH, &opermotd);
				RunHook3(HOOKTYPE_REHASHFLAG, cptr, sptr, parv[1]);
				return 0;
			}
			if (!_match("-b*motd", parv[1]))
			{
				sendto_ops
				    ("%sRehashing BotMOTD on request of %s",
				    cptr != sptr ? "Remotely " : "",
				    sptr->name);
				if (cptr != sptr)
					sendto_serv_butone(&me, ":%s GLOBOPS :%s is remotely rehashing BotMOTD", me.name, sptr->name);
				botmotd = (aMotd *) read_file(BPATH, &botmotd);
				RunHook3(HOOKTYPE_REHASHFLAG, cptr, sptr, parv[1]);
				return 0;
			}
			if (!strnicmp("-motd", parv[1], 5)
			    || !strnicmp("-rules", parv[1], 6))
			{
				sendto_ops
				    ("%sRehashing all MOTDs and RULES on request of %s",
				    cptr != sptr ? "Remotely " : "",
				    sptr->name);
				if (cptr != sptr)
					sendto_serv_butone(&me, ":%s GLOBOPS :%s is remotely rehashing all MOTDs and RULES", me.name, sptr->name);
				rehash_motdrules();
				RunHook3(HOOKTYPE_REHASHFLAG, cptr, sptr, parv[1]);
				return 0;
			}
			RunHook3(HOOKTYPE_REHASHFLAG, cptr, sptr, parv[1]);
			return 0;
		}
	}
	else
	{
		if (loop.ircd_rehashing)
		{
			sendto_one(sptr, ":%s NOTICE %s :Ya se est� refrescando",
				me.name, sptr->name);
			return 0;
		}
		sendto_ops("%s refresca configuraci�n", parv[0]);
	}

	/* Normal rehash, rehash motds&rules too, just like the on in the tld block will :p */
	reread_motdsandrules();
	if (cptr == sptr)
		sendto_one(sptr, rpl_str(RPL_REHASHING), me.name, parv[0], configfile);
	return rehash(cptr, sptr, (parc > 1) ? ((*parv[1] == 'q') ? 2 : 0) : 0);
}

/*
** m_restart
**
** parv[1] - password *OR* reason if no X:line
** parv[2] - reason for restart (optional & only if X:line exists)
**
** The password is only valid if there is a matching X line in the
** config file. If it is not,  then it becomes the
*/
CMD_FUNC(m_restart)
{
	char *reason = NULL;
	/* Check permissions */
        if (MyClient(sptr) && !OPCanRestart(sptr))
        {
                sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name, parv[0]);
                return 0;
        }
        if (!MyClient(sptr) && !IsNetAdmin(sptr)
            && !IsULine(sptr))
        {
                sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name, parv[0]);
                return 0;
        }

	/* Syntax: /restart */
	if (parc == 1)
	{
		if (conf_drpass)
		{
			sendto_one(sptr, err_str(ERR_NEEDMOREPARAMS), me.name,
                            parv[0], "RESTART");
                        return 0;
		}
	}
	else if (parc == 2)
	{
		/* Syntax: /restart <pass> */
		if (conf_drpass)
		{
			int ret;
			ret = Auth_Check(cptr, conf_drpass->restartauth, parv[1]);
			if (ret == -1)
			{
				sendto_one(sptr, err_str(ERR_PASSWDMISMATCH), me.name,
					   parv[0]);
				return 0;
			}
			if (ret < 1)
				return 0;
		}
		/* Syntax: /rehash <reason> */
		else 
			reason = parv[1];
	}
	else if (parc == 3)
	{
		/* Syntax: /restart <pass> <reason> */
		if (conf_drpass)
		{
			int ret;
			ret = Auth_Check(cptr, conf_drpass->restartauth, parv[1]);
			if (ret == -1)
			{
				sendto_one(sptr, err_str(ERR_PASSWDMISMATCH), me.name,
					   parv[0]);
				return 0;
			}
			if (ret < 1)
				return 0;
		}
		reason = parv[2];
	}
	sendto_ops("%s resetea el servidor", parv[0]);
	server_reboot(reason ? reason : "Sin raz�n");
	return 0;
}

/*
 * Heavily modified from the ircu m_motd by codemastr
 * Also svsmotd support added
 */
int short_motd(aClient *sptr) {
	ConfigItem_tld *ptr;
	aMotd *temp, *temp2;
	struct tm *tm = &smotd_tm;
	char userhost[HOSTLEN + USERLEN + 6];
	char is_short = 1;
	strlcpy(userhost,make_user_host(sptr->user->username, sptr->user->realhost), sizeof userhost);
	ptr = Find_tld(sptr, userhost);

	if (ptr)
	{
		if (ptr->smotd)
		{
			temp = ptr->smotd;
			tm = &ptr->smotd_tm;
		}
		else if (smotd)
			temp = smotd;
		else
		{
			temp = ptr->motd;
			tm = &ptr->motd_tm;
			is_short = 0;
		}
	}
	else
	{
		if (smotd)
			temp = smotd;
		else
		{
			temp = motd;
			tm = &motd_tm;
			is_short = 0;
		}
	}

	if (!temp)
	{
		sendto_one(sptr, err_str(ERR_NOMOTD), me.name, sptr->name);
		return 0;
	}
	if (tm)
	{
		sendto_one(sptr, rpl_str(RPL_MOTDSTART), me.name, sptr->name,
		    me.name);
		sendto_one(sptr, ":%s %d %s :- %d/%d/%d %d:%02d", me.name,
		    RPL_MOTD, sptr->name, tm->tm_mday, tm->tm_mon + 1,
		    1900 + tm->tm_year, tm->tm_hour, tm->tm_min);
	}
	if (is_short)
	{
		sendto_one(sptr, rpl_str(RPL_MOTD), me.name, sptr->name,
			"This is the short MOTD. To view the complete MOTD type /motd");
		sendto_one(sptr, rpl_str(RPL_MOTD), me.name, sptr->name, "");
	}

	while (temp)
	{
		sendto_one(sptr, rpl_str(RPL_MOTD), me.name, sptr->name,
		    temp->line);
		temp = temp->next;
	}
	sendto_one(sptr, rpl_str(RPL_ENDOFMOTD), me.name, sptr->name);
	return 0;
}


/*
 * Heavily modified from the ircu m_motd by codemastr
 * Also svsmotd support added
 */
CMD_FUNC(m_motd)
{
	ConfigItem_tld *ptr;
	aMotd *temp, *temp2;
	struct tm *tm = &motd_tm;
	int  svsnofile = 0;
	char userhost[HOSTLEN + USERLEN + 6];

	if (IsServer(sptr))
		return 0;
	if (hunt_server_token(cptr, sptr, MSG_MOTD, TOK_MOTD, ":%s", 1, parc, parv) !=
HUNTED_ISME)
		return 0;
#ifndef TLINE_Remote
	if (!MyConnect(sptr))
	{
		temp = motd;
		goto playmotd;
	}
#endif
	strlcpy(userhost,make_user_host(cptr->user->username, cptr->user->realhost), sizeof userhost);
	ptr = Find_tld(sptr, userhost);

	if (ptr)
	{
		temp = ptr->motd;
		tm = &ptr->motd_tm;
	}
	else
		temp = motd;

      playmotd:
	if (temp == NULL)
	{
		sendto_one(sptr, err_str(ERR_NOMOTD), me.name, parv[0]);
		svsnofile = 1;
		goto svsmotd;

	}

	if (tm)
	{
		sendto_one(sptr, rpl_str(RPL_MOTDSTART), me.name, parv[0],
		    me.name);
		sendto_one(sptr, ":%s %d %s :- %d/%d/%d %d:%02d", me.name,
		    RPL_MOTD, parv[0], tm->tm_mday, tm->tm_mon + 1,
		    1900 + tm->tm_year, tm->tm_hour, tm->tm_min);
	}

	while (temp)
	{
		sendto_one(sptr, rpl_str(RPL_MOTD), me.name, parv[0],
		    temp->line);
		temp = temp->next;
	}
      svsmotd:
	temp2 = svsmotd;
	while (temp2)
	{
		sendto_one(sptr, rpl_str(RPL_MOTD), me.name, parv[0],
		    temp2->line);
		temp2 = temp2->next;
	}
	if (svsnofile == 0)
		sendto_one(sptr, rpl_str(RPL_ENDOFMOTD), me.name, parv[0]);
	return 0;
}
/*
 * Modified from comstud by codemastr
 */
CMD_FUNC(m_opermotd)
{
	aMotd *temp;

	if (!IsAnOper(sptr))
	{
		sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name, parv[0]);
		return 0;
	}

	if (opermotd == (aMotd *) NULL)
	{
		sendto_one(sptr, err_str(ERR_NOOPERMOTD), me.name, parv[0]);
		return 0;
	}
	sendto_one(sptr, rpl_str(RPL_MOTDSTART), me.name, parv[0], me.name);
	sendto_one(sptr, rpl_str(RPL_MOTD), me.name, parv[0],
	    "\2IRC Operator Message of the Day\2");

	temp = opermotd;
	while (temp)
	{
		sendto_one(sptr, rpl_str(RPL_MOTD), me.name, parv[0],
		    temp->line);
		temp = temp->next;
	}
	sendto_one(sptr, rpl_str(RPL_ENDOFMOTD), me.name, parv[0]);
	return 0;
}

/*
 * A merge from ircu and bahamut, and some extra stuff added by codemastr
 * we can now use 1 function for multiple files -- codemastr
 * Merged read_motd/read_rules stuff into this -- Syzop
 */

/** Read motd-like file, used for rules/motd/botmotd/opermotd/etc.
 * @param filename Filename of file to read.
 * @param list Reference to motd pointer (used for freeing if needed, can be NULL)
 * @returns Pointer to MOTD or NULL if reading failed.
 */
aMotd *read_file(char *filename, aMotd **list)
{
	return read_file_ex(filename, list, NULL);
}

/** Read motd-like file, used for rules/motd/botmotd/opermotd/etc.
 * @param filename Filename of file to read.
 * @param list Reference to motd pointer (used for freeing if needed, NULL allowed)
 * @param t Pointer to struct tm to store filedatetime info in (NULL allowed)
 * @returns Pointer to MOTD or NULL if reading failed.
 */
aMotd *read_file_ex(char *filename, aMotd **list, struct tm *t)
{

	int  fd = open(filename, O_RDONLY);
	aMotd *temp, *newmotd, *last, *old;
	char line[82];
	char *tmp;
	int  i;

	if (fd == -1)
		return NULL;

	if (list)
	{
		while (*list)
		{
			old = (*list)->next;
			MyFree((*list)->line);
			MyFree(*list);
			*list  = old;
		}
	}

	if (t)
	{
		struct tm *ttmp;
		struct stat sb;
		if (!fstat(fd, &sb))
		{
			ttmp = localtime(&sb.st_mtime);
			memcpy(t, ttmp, sizeof(struct tm));
		} else {
			/* Sure, fstat() shouldn't fail, but... */
			memset(t, 0, sizeof(struct tm));
		}
	}

	(void)dgets(-1, NULL, 0);	/* make sure buffer is at empty pos */

	newmotd = last = NULL;
	while ((i = dgets(fd, line, 81)) > 0)
	{
		line[i] = '\0';
		if ((tmp = (char *)strchr(line, '\n')))
			*tmp = '\0';
		if ((tmp = (char *)strchr(line, '\r')))
			*tmp = '\0';
		temp = (aMotd *) MyMalloc(sizeof(aMotd));
		if (!temp)
			outofmemory();
		AllocCpy(temp->line, line);
		temp->next = NULL;
		if (!newmotd)
			newmotd = temp;
		else
			last->next = temp;
		last = temp;
	}
	close(fd);
	return newmotd;

}

/*
 * Modified from comstud by codemastr
 */
CMD_FUNC(m_botmotd)
{
	aMotd *temp;
	if (hunt_server_token(cptr, sptr, MSG_BOTMOTD, TOK_BOTMOTD, ":%s", 1, parc,
	    parv) != HUNTED_ISME)
		return 0;

	if (botmotd == (aMotd *) NULL)
	{
		sendto_one(sptr, ":%s NOTICE %s :BOTMOTD No se encuentra archivo",
		    me.name, sptr->name);
		return 0;
	}
	sendto_one(sptr, ":%s NOTICE %s :- %s Bot Message of the Day - ",
	    me.name, sptr->name, me.name);

	temp = botmotd;
	while (temp)
	{
		sendto_one(sptr, ":%s NOTICE %s :- %s", me.name, sptr->name, temp->line);
		temp = temp->next;
	}
	sendto_one(sptr, ":%s NOTICE %s :Fin de /BOTMOTD.", me.name, sptr->name);
	return 0;
}

/* m_die, this terminates the server, and it intentionally does not
 * have a reason. If you use it you should first do a GLOBOPS and
 * then a server notice to let everyone know what is going down...
 */
CMD_FUNC(m_die)
{
	aClient *acptr;
	int  i;
	if (!MyClient(sptr) || !OPCanDie(sptr))
	{
		sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name, parv[0]);
		return 0;
	}

	if (conf_drpass)	/* See if we have and DIE/RESTART password */
	{
		if (parc < 2)	/* And if so, require a password :) */
		{
			sendto_one(sptr, err_str(ERR_NEEDMOREPARAMS), me.name,
			    parv[0], "DIE");
			return 0;
		}
		i = Auth_Check(cptr, conf_drpass->dieauth, parv[1]);
		if (i == -1)
		{
			sendto_one(sptr, err_str(ERR_PASSWDMISMATCH), me.name,
			    parv[0]);
			return 0;
		}
		if (i < 1)
		{
			return 0;
		}
	}

	/* Let the +s know what is going on */
	sendto_ops("Servidor detenido a petici�n de %s", parv[0]);

	for (i = 0; i <= LastSlot; i++)
	{
		if (!(acptr = local[i]))
			continue;
		if (IsClient(acptr))
			sendto_one(acptr,
			    ":%s %s %s :Servidor detenido. %s",
			    me.name, IsWebTV(acptr) ? "PRIVMSG" : "NOTICE", acptr->name, sptr->name);
		else if (IsServer(acptr))
			sendto_one(acptr, ":%s ERROR :Detenido por %s",
			    me.name, get_client_name(sptr, TRUE));
	}
	(void)s_die();
	return 0;
}

#ifdef _WIN32
/*
 * Added to let the local console shutdown the server without just
 * calling exit(-1), in Windows mode.  -Cabal95
 */
int  localdie(void)
{
	aClient *acptr;
	int  i;

	for (i = 0; i <= LastSlot; i++)
	{
		if (!(acptr = local[i]))
			continue;
		if (IsClient(acptr))
			sendto_one(acptr,
			    ":%s %s %s :Servidor detenido por consola",
			    me.name, IsWebTV(acptr) ? "PRIVMSG" : "NOTICE", acptr->name);
		else if (IsServer(acptr))
			sendto_one(acptr,
			    ":%s ERROR :Detenido por consola", me.name);
	}
	(void)s_die();
	return 0;
}

#endif

aClient *find_match_server(char *mask)
{
	aClient *acptr;

	if (BadPtr(mask))
		return NULL;
	for (acptr = client, collapse(mask); acptr; acptr = acptr->next)
	{
		if (!IsServer(acptr) && !IsMe(acptr))
			continue;
		if (!match(mask, acptr->name))
			break;
		continue;
	}
	return acptr;
}
