/*
 *   Unreal Internet Relay Chat Daemon, src/modules/m_whois.c
 *   (C) 2000-2001 Carsten V. Munk and the UnrealIRCd Team
 *   Moved to modules by Fish (Justin Hammond)
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
#include "udb.h"
#endif

static char buf[BUFSIZE];

DLLFUNC int m_whois(aClient *cptr, aClient *sptr, int parc, char *parv[]);

/* Place includes here */
#define MSG_WHOIS       "WHOIS" /* WHOI */
#define TOK_WHOIS       "#"     /* 35 */

ModuleHeader MOD_HEADER(m_whois)
  = {
	"whois",	/* Name of module */
	"$Id: m_whois.c,v 1.1.1.1.2.17 2008/04/23 18:44:30 Trocotronic Exp $", /* Version */
	"command /whois", /* Short description of module */
	"3.2-b8-1",
	NULL
    };

/* This is called on module init, before Server Ready */
DLLFUNC int MOD_INIT(m_whois)(ModuleInfo *modinfo)
{
	/*
	 * We call our add_Command crap here
	*/
	add_Command(MSG_WHOIS, TOK_WHOIS, m_whois, MAXPARA);
	MARK_AS_OFFICIAL_MODULE(modinfo);
	return MOD_SUCCESS;
}

/* Is first run when server is 100% ready */
DLLFUNC int MOD_LOAD(m_whois)(int module_load)
{
	return MOD_SUCCESS;
}

/* Called when module is unloaded */
DLLFUNC int MOD_UNLOAD(m_whois)(int module_unload)
{
	if (del_Command(MSG_WHOIS, TOK_WHOIS, m_whois) < 0)
	{
		sendto_realops("Failed to delete commands when unloading %s",
				MOD_HEADER(m_whois).name);
	}
	return MOD_SUCCESS;
}


/*
** m_whois
**	parv[0] = sender prefix
**	parv[1] = nickname masklist
*/
DLLFUNC int  m_whois(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
	Membership *lp;
	anUser *user;
	aClient *acptr, *a2cptr;
	aChannel *chptr;
	char *nick, *tmp, *name;
	char *p = NULL;
	int  found, len, mlen, cnt = 0;
	char querybuf[BUFSIZE];

	if (IsServer(sptr))
		return 0;

	if (parc < 2)
	{
		sendto_one(sptr, err_str(ERR_NONICKNAMEGIVEN),
		    me.name, parv[0]);
		return 0;
	}

	if (parc > 2)
	{
		if (hunt_server_token(cptr, sptr, MSG_WHOIS, TOK_WHOIS, "%s :%s", 1, parc,
		    parv) != HUNTED_ISME)
			return 0;
		parv[1] = parv[2];
	}

	strcpy(querybuf, parv[1]);

	for (tmp = canonize(parv[1]); (nick = strtoken(&p, tmp, ",")); tmp = NULL)
	{
		unsigned char invis, showchannel, member, wilds, hideoper; /* <- these are all boolean-alike */

		if (++cnt > MAXTARGETS)
			break;

		found = 0;
		/* We do not support "WHOIS *" */
		wilds = (index(nick, '?') || index(nick, '*'));
		if (wilds)
			continue;

		if ((acptr = find_client(nick, NULL)))
		{
			if (IsServer(acptr))
				continue;
			/*
			 * I'm always last :-) and acptr->next == NULL!!
			 */
			if (IsMe(acptr))
				break;
			/*
			 * 'Rules' established for sending a WHOIS reply:
			 * - only send replies about common or public channels
			 *   the target user(s) are on;
			 */

			if (!IsPerson(acptr))
				continue;

			user = acptr->user;
			name = (!*acptr->name) ? "?" : acptr->name;

			invis = acptr != sptr && IsInvisible(acptr);
			member = (user->channel) ? 1 : 0;

			a2cptr = find_server_quick(user->server);

			hideoper = 0;
			if (IsHideOper(acptr) && (acptr != sptr) && !IsAnOper(sptr))
				hideoper = 1;

			if (IsWhois(acptr) && (sptr != acptr))
			{
				sendto_one(acptr,
				    ":%s %s %s :*** %s (%s@%s) Te hace /WHOIS",
				    me.name, IsWebTV(acptr) ? "PRIVMSG" : "NOTICE", acptr->name, sptr->name,
				    sptr->user->username, sptr->user->realhost);
			}
#ifdef UDB
			sendto_one(sptr, rpl_str(RPL_WHOISUSER), me.name,
				    parv[0], name, user->username,
				    GetVisibleHost(acptr, sptr), acptr->info);
#else
			sendto_one(sptr, rpl_str(RPL_WHOISUSER), me.name,
			    parv[0], name,
			    user->username,
			    IsHidden(acptr) ? user->virthost : user->realhost,
			    acptr->info);

#endif
			if (IsOper(sptr))
			{
				char sno[512];
				strcpy(sno, get_sno_str(acptr));

				/* send the target user's modes */
				sendto_one(sptr, rpl_str(RPL_WHOISMODES),
				    me.name, parv[0], name,
				    get_mode_str(acptr), sno[1] == 0 ? "" : sno);
			}
#ifndef UDB
			if ((acptr == sptr) || IsAnOper(sptr))
			{
				sendto_one(sptr, rpl_str(RPL_WHOISHOST),
				    me.name, parv[0], acptr->name,
					(MyConnect(acptr) && strcmp(acptr->username, "unknown")) ? acptr->username : "*",
					user->realhost, user->ip_str ? user->ip_str : "");
			}

			if (IsARegNick(acptr))
				sendto_one(sptr, rpl_str(RPL_WHOISREGNICK), me.name, parv[0], name);
#endif

			found = 1;
			mlen = strlen(me.name) + strlen(parv[0]) + 10 + strlen(name);
			for (len = 0, *buf = '\0', lp = user->channel; lp; lp = lp->next)
			{
				chptr = lp->chptr;
				showchannel = 0;
				if (ShowChannel(sptr, chptr))
					showchannel = 1;
				if (OPCanSeeSecret(sptr))
					showchannel = 1;
				if ((acptr->umodes & UMODE_HIDEWHOIS) && !IsMember(sptr, chptr) && !IsAnOper(sptr))
					showchannel = 0;
#ifdef UDB
				if (IsBot(acptr) && !IsNetAdmin(sptr) && !IsSAdmin(sptr))
#else
				if (IsServices(acptr) && !IsNetAdmin(sptr) && !IsSAdmin(sptr))
#endif
					showchannel = 0;
				if (acptr == sptr)
					showchannel = 1;
				/* Hey, if you are editting here... don't forget to change the webtv w_whois ;p. */

				if (showchannel)
				{
					long access;
					if (len + strlen(chptr->chname) > (size_t)BUFSIZE - 4 - mlen)
					{
						sendto_one(sptr,
						    ":%s %d %s %s :%s",
						    me.name,
						    RPL_WHOISCHANNELS,
						    parv[0], name, buf);
						*buf = '\0';
						len = 0;
					}
#ifdef SHOW_SECRET
					if (IsAnOper(sptr)
#else
					if (IsNetAdmin(sptr)
#endif
					    && SecretChannel(chptr) && !IsMember(sptr, chptr))
						*(buf + len++) = '?';
					if (acptr->umodes & UMODE_HIDEWHOIS && !IsMember(sptr, chptr)
#ifdef UDB
					&& IsHOper(sptr)
#else
						&& IsAnOper(sptr)
#endif
					)
						*(buf + len++) = '!';
					access = get_access(acptr, chptr);
#ifdef UDB
#ifdef PREFIX_AQ
					if (access & CHFL_CHANOWNER)
						*(buf + len++) = PF_OWN;
					else if (access & CHFL_CHANPROT)
						*(buf + len++) = PF_ADMIN;
					else
#endif
					if (access & CHFL_CHANOP)
						*(buf + len++) = PF_OP;
					else if (access & CHFL_HALFOP)
						*(buf + len++) = PF_HALF;
					else if (access & CHFL_VOICE)
						*(buf + len++) = PF_VOICE;
#else
#ifdef PREFIX_AQ
					if (access & CHFL_CHANOWNER)
						*(buf + len++) = '~';
					else if (access & CHFL_CHANPROT)
						*(buf + len++) = '&';
					else
#endif
					if (access & CHFL_CHANOP)
						*(buf + len++) = '@';
					else if (access & CHFL_HALFOP)
						*(buf + len++) = '%';
					else if (access & CHFL_VOICE)
						*(buf + len++) = '+';
#endif
					if (len)
						*(buf + len) = '\0';
					(void)strcpy(buf + len, chptr->chname);
					len += strlen(chptr->chname);
					(void)strcat(buf + len, " ");
					len++;
				}
			}

			if (buf[0] != '\0')
				sendto_one(sptr, rpl_str(RPL_WHOISCHANNELS), me.name, parv[0], name, buf);

                        if (!(IsULine(acptr) && !IsOper(sptr) && HIDE_ULINES))
				sendto_one(sptr, rpl_str(RPL_WHOISSERVER),
				    me.name, parv[0], name, user->server,
				    a2cptr ? a2cptr->info : "No est� en esta red");

			if (user->away)
				sendto_one(sptr, rpl_str(RPL_AWAY), me.name,
				    parv[0], name, user->away);
#ifdef UDB
 	  		if (IsARegNick(acptr))
	    			sendto_one(sptr, rpl_str(RPL_WHOISREGNICK), me.name, parv[0], name);

			if (IsBot(acptr))
	    			sendto_one(sptr, rpl_str(RPL_WHOISBOT), me.name, parv[0], name, ircnetwork);

			if (IsSuspended(acptr))
	    			sendto_one(sptr, rpl_str(RPL_WHOISSUSPEND), me.name, parv[0],
				name);

			if (LevelOperUdb(acptr->name) && !hideoper)
			{
				u_int level = LevelOperUdb(acptr->name);
				buf[0] = '\0';
				if (level >= BDD_ROOT)
					strlcat(buf, "ROOT de los servicios", sizeof buf);
				else if (level >= BDD_ADMIN)
					strlcat(buf, "ADMINistrador", sizeof buf);
				else if (level >= BDD_OPER)
					strlcat(buf, "OPERador de los servicios", sizeof buf);
				else
					strlcat(buf, "Que co�o es?", sizeof buf);
				if (buf[0])
					sendto_one(sptr, rpl_str(RPL_WHOISHELPOP), me.name, parv[0], name, buf);
			}

			if (IsHidden(acptr) && (IsShowIp(sptr) || acptr == sptr))
	    			sendto_one(sptr, rpl_str(RPL_WHOISHOST),
					me.name, parv[0], name, GetVisibleHost(acptr, NULL));
#endif
			/* makesure they aren't +H (we'll also check
			   before we display a helpop or IRCD Coder msg)
			   -- codemastr */
#ifdef UDB
			if ((IsAnOper(acptr) || IsBot(acptr))
#else
			if ((IsAnOper(acptr) || IsServices(acptr))
#endif
			&& !hideoper)
			{
				buf[0] = '\0';
				if (IsNetAdmin(acptr))
					strlcat(buf, "un Administrador de Red", sizeof buf);
				else if (IsSAdmin(acptr))
					strlcat(buf, "un Operador de Servicios", sizeof buf);
				else if (IsAdmin(acptr) && !IsCoAdmin(acptr))
					strlcat(buf, "un Administrador de Servidor", sizeof buf);
				else if (IsCoAdmin(acptr))
					strlcat(buf, "un Co Administrador", sizeof buf);
#ifdef UDB
				else if (IsBot(acptr))
#else
				else if (IsServices(acptr))
#endif
					strlcat(buf, "un Servicio de Red", sizeof buf);
				else if (IsOper(acptr))
					strlcat(buf, "un IRCop", sizeof buf);

				else
					strlcat(buf, "un IRCop Local", sizeof buf);
				if (buf[0])
					sendto_one(sptr,
					    rpl_str(RPL_WHOISOPERATOR), me.name,
					    parv[0], name, buf);
			}

#ifdef UDB
		  	if (IsRegNickMsg(acptr))
	    			sendto_one(sptr, rpl_str(RPL_MSGONLYREG), me.name, parv[0], name);
#else
			if (IsHelpOp(acptr) && !hideoper && !user->away)
				sendto_one(sptr, rpl_str(RPL_WHOISHELPOP), me.name, parv[0], name);

			if (acptr->umodes & UMODE_BOT)
				sendto_one(sptr, rpl_str(RPL_WHOISBOT), me.name, parv[0], name, ircnetwork);
#endif

			if (acptr->umodes & UMODE_SECURE)
				sendto_one(sptr, rpl_str(RPL_WHOISSECURE), me.name, parv[0], name,
					"usa una Conexi�n Segura");

			if (!BadPtr(user->swhois) && !hideoper)
					sendto_one(sptr, ":%s %d %s %s :%s",
					    me.name, RPL_WHOISSPECIAL, parv[0],
					    name, acptr->user->swhois);

			/*
			 * Fix /whois to not show idle times of
			 * global opers to anyone except another
			 * global oper or services.
			 * -CodeM/Barubary
			 */
			if (MyConnect(acptr))
				sendto_one(sptr, rpl_str(RPL_WHOISIDLE),
				    me.name, parv[0], name,
				    TStime() - acptr->last, acptr->firsttime);
		}
		if (!found)
			sendto_one(sptr, err_str(ERR_NOSUCHNICK),
			    me.name, parv[0], nick);
	}
	sendto_one(sptr, rpl_str(RPL_ENDOFWHOIS), me.name, parv[0], querybuf);

	return 0;
}
