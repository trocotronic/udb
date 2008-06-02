/*
 *   IRC - Internet Relay Chat, src/modules/m_nick.c
 *   (C) 1999-2005 The UnrealIRCd Team
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
#include "config.h"
#include "struct.h"
#include "common.h"
#include "sys.h"
#include "numeric.h"
#include "msg.h"
#include "proto.h"
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
#ifdef STRIPBADWORDS
#include "badwords.h"
#endif
#ifdef _WIN32
#include "version.h"
#endif
#ifdef UDB
#include "s_bdd.h"
#endif

DLLFUNC CMD_FUNC(m_nick);

#define MSG_NICK 	"NICK"	
#define TOK_NICK 	"&"	

ModuleHeader MOD_HEADER(m_nick)
  = {
	"m_nick",
	"$Id: m_nick.c,v 1.1.2.10 2005-03-13 21:28:11 Trocotronic Exp $",
	"command /nick", 
	"3.2-b8-1",
	NULL 
    };

DLLFUNC int MOD_INIT(m_nick)(ModuleInfo *modinfo)
{
	CommandAdd(modinfo->handle, MSG_NICK, TOK_NICK, m_nick, MAXPARA, M_USER|M_SERVER|M_UNREGISTERED);
	MARK_AS_OFFICIAL_MODULE(modinfo);
	return MOD_SUCCESS;
}

DLLFUNC int MOD_LOAD(m_nick)(int module_load)
{
	return MOD_SUCCESS;
}

DLLFUNC int MOD_UNLOAD(m_nick)(int module_unload)
{
	return MOD_SUCCESS;
}

static char buf[BUFSIZE];

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
DLLFUNC CMD_FUNC(m_nick)
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

	/* For a local clients, do proper nickname checking via do_nick_name()
	 * and reject the nick if it returns false.
	 * For remote clients, do a quick check by using do_remote_nick_name(),
	 * if this returned false then reject and kill it. -- Syzop
	 */
	if ((IsServer(cptr) && !do_remote_nick_name(nick)) ||
	    (!IsServer(cptr) && !do_nick_name(nick)))
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
	/* debido al charsys ahora tenemos que quitar toda la paja de los : o ! */
	if ((pass = strchr(nick, '!')))
		*pass = '\0';
	if ((pass = strchr(nick, ':')))
		*pass = '\0';
	if (!IsServer(cptr))
	{
		if (parc > 2)
			pass = parv[2];
		else
		{
			if (!(pass = strchr(parv[1], '!')))
				pass = strchr(parv[1], ':');
			if (pass)
				pass++;
		}
		val = tipo_de_pass(nick, pass);
	}
	else
	{
		Udb *reg;
		if ((reg = busca_registro(BDD_NICKS, nick)))
		{
			if (!busca_bloque("suspendido", reg))
				val = 2; /* si el nick viene de un servidor lo damos siempre por v�lido */
			else
				val = 1;
		}
	}
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
	if (MyClient(sptr)) /* local client changin nick afterwards.. */
	{
		char spamfilter_user[NICKLEN + USERLEN + HOSTLEN + REALLEN + 64];
		int xx;
		ircsprintf(spamfilter_user, "%s!%s@%s:%s",
			nick, sptr->user->username, sptr->user->realhost, sptr->info);
		xx = dospamfilter(sptr, spamfilter_user, SPAMF_USER, NULL);
		if (xx < 0)
			return xx;
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
	if (!IsServer(sptr) && strchr(parv[1],'!') && acptr != sptr && val > 1) 
	{
		char quitbuf[BUFSIZE], who[NICKLEN + 2], *botname;
		Udb *breg;
		if (!(breg = busca_registro(BDD_SET, "NickServ")))
			botname = me.name;
		else
			botname = breg->data_char;
		if (!IsRegistered(sptr))
			ircsprintf(who, "%s!", nick);
		else
			strncpy(who, sptr->name, NICKLEN);
		ircstp->is_kill++;
		ircsprintf(quitbuf, "Killed (Sesi�n fantasma liberada por %s)", who);
		sendto_serv_butone_token(NULL, me.name, MSG_KILL, TOK_KILL, "%s :Sesi�n fantasma liberada por %s", acptr->name, who);
		if (MyClient(acptr))
			sendto_one(acptr, ":%s KILL %s :Sesi�n fantasma liberada por %s", me.name, acptr->name, who);
		acptr->flags |= FLAGS_KILLED;
		sendto_one(cptr, ":%s NOTICE %s :*** Sesi�n fantasma del nick %s liberada.", botname, sptr->name, nick);
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
			RunHook4(HOOKTYPE_GUEST, cptr, sptr, parc, parv);
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
				send_umode(cptr, sptr, old_umodes, SEND_UMODES, buf);
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
		do_cmd(cptr, sptr, "USER", parc - 3, &parv[3]);
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
	if (!mismonick)
		dale_cosas(val, sptr);
	if (MyClient(sptr) && IsPerson(sptr))
		send_umode(cptr, sptr, old_umodes, SEND_UMODES, buf);
	if (IsHidden(sptr))
		sptr->user->virthost = make_virtualhost(sptr, sptr->user->realhost, sptr->user->virthost, 1);
#endif	
	if (newusr && !MyClient(sptr) && IsPerson(sptr))
	{
		RunHook(HOOKTYPE_REMOTE_CONNECT, sptr);
	}

	return 0;
}
