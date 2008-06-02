/*
 *   IRC - Internet Relay Chat, src/modules/m_svsnick.c
 *   (C) 2001 The UnrealIRCd Team
 *
 *   svsnick command
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

DLLFUNC int m_svsnick(aClient *cptr, aClient *sptr, int parc, char *parv[]);

#define MSG_SVSNICK 	"SVSNICK"	
#define TOK_SVSNICK 	"e"	

ModuleHeader MOD_HEADER(m_svsnick)
  = {
	"m_svsnick",
	"$Id: m_svsnick.c,v 1.1.1.1.2.5 2005-03-15 15:12:37 Trocotronic Exp $",
	"command /svsnick", 
	"3.2-b8-1",
	NULL 
    };

DLLFUNC int MOD_INIT(m_svsnick)(ModuleInfo *modinfo)
{
	add_Command(MSG_SVSNICK, TOK_SVSNICK, m_svsnick, MAXPARA);
	MARK_AS_OFFICIAL_MODULE(modinfo);
	return MOD_SUCCESS;
}

DLLFUNC int MOD_LOAD(m_svsnick)(int module_load)
{
	return MOD_SUCCESS;
}

DLLFUNC int MOD_UNLOAD(m_svsnick)(int module_unload)
{
	if (del_Command(MSG_SVSNICK, TOK_SVSNICK, m_svsnick) < 0)
	{
		sendto_realops("Failed to delete commands when unloading %s",
				MOD_HEADER(m_svsnick).name);
	}
	return MOD_SUCCESS;
}
/*
** m_svsnick
**      parv[0] = sender
**      parv[1] = old nickname
**      parv[2] = new nickname
**      parv[3] = timestamp
*/
int  m_svsnick(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
        aClient *acptr;
#ifdef UDB
	long old_umodes;
	int val = 0;
	Udb *reg;
	char buf[BUFSIZE];
#endif

        if (!IsULine(sptr) || parc < 4 || (strlen(parv[2]) > NICKLEN))
		return -1;        /* This looks like an error anyway -Studded */
        if (!hunt_server_token(cptr, sptr, MSG_SVSNICK, TOK_SVSNICK, "%s %s :%s", 1, parc,
		parv) != HUNTED_ISME)
        {
		if (do_nick_name(parv[2]) == 0)
			return 0;
                if ((acptr = find_person(parv[1], NULL)))
                {
                        if (find_client(parv[2], NULL)) /* Collision */
                                return exit_client(cptr, acptr, sptr,
                                    "Nickname collision due to Services enforced "
                                    "nickname change, your nick was overruled");
#ifdef UDB                                
			old_umodes = acptr->umodes;
			acptr->umodes &= ~(UMODE_SUSPEND | UMODE_REGNICK | UMODE_HELPOP | UMODE_SHOWIP | UMODE_RGSTRONLY | UMODE_SERVICES);
			if (MyClient(acptr) && IsPerson(acptr))
				send_umode(acptr, acptr, old_umodes, SEND_UMODES, buf);
#else
                        acptr->umodes &= ~UMODE_REGNICK;
#endif
                        acptr->lastnick = TS2ts(parv[3]);
                        sendto_common_channels(acptr, ":%s NICK :%s", parv[1],
                            parv[2]);
                        if (IsPerson(acptr))
                                add_history(acptr, 1);
                        sendto_serv_butone_token(NULL, parv[1], MSG_NICK,
                            TOK_NICK, "%s :%ld", parv[2], TS2ts(parv[3]));
                        if (acptr->name[0])
                        {
				(void)del_from_client_hash_table(acptr->name, acptr);
                                if (IsPerson(acptr))
                                        hash_check_watch(acptr, RPL_LOGOFF);
                        }
                        if (MyClient(acptr))
                        {
				sendto_snomask(SNO_NICKCHANGE, "*** Notice -- %s (%s@%s) cambia su nick a %s", 
					acptr->name, acptr->user->username, acptr->user->realhost, parv[2]);
				
                                RunHook2(HOOKTYPE_LOCAL_NICKCHANGE, acptr, parv[2]);
                        }
                        (void)strlcpy(acptr->name, parv[2], sizeof acptr->name);
                        (void)add_to_client_hash_table(parv[2], acptr);
                        if (IsPerson(acptr))
                                hash_check_watch(acptr, RPL_LOGON);
#ifdef UDB
			if ((reg = busca_registro(BDD_NICKS, parv[2])))
			{
				if (!busca_bloque("suspendido", reg))
					val = 2; /* si el nick viene de un servidor lo damos siempre por v�lido */
				else
					val = 1;
			}
			old_umodes = acptr->umodes; /* antes de todo lo que tenga que dar */
			if (strcasecmp(parv[1], parv[2]))
				dale_cosas(val, acptr);
			if (MyClient(acptr) && IsPerson(acptr))
				send_umode(acptr, acptr, old_umodes, SEND_UMODES, buf);
			if (IsHidden(acptr))
				acptr->user->virthost = make_virtualhost(acptr, acptr->user->realhost, acptr->user->virthost, 1);
#endif	
                }
        }
        return 0;
}
