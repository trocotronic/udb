/*
 *   IRC - Internet Relay Chat, src/modules/out.c
 *   (C) 2004 The UnrealIRCd Team
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
#include "version.h"

DLLFUNC int m_netinfo(aClient *cptr, aClient *sptr, int parc, char *parv[]);

#define MSG_NETINFO 	"NETINFO"	
#define TOK_NETINFO 	"AO"	

ModuleHeader MOD_HEADER(m_netinfo)
  = {
	"m_netinfo",
	"$Id: m_netinfo.c,v 1.1.4.2 2004-03-09 17:36:45 Trocotronic Exp $",
	"command /netinfo", 
	"3.2-b8-1",
	NULL 
    };

DLLFUNC int MOD_INIT(m_netinfo)(ModuleInfo *modinfo)
{
	add_Command(MSG_NETINFO, TOK_NETINFO, m_netinfo, MAXPARA);
	MARK_AS_OFFICIAL_MODULE(modinfo);
	return MOD_SUCCESS;
}

DLLFUNC int MOD_LOAD(m_netinfo)(int module_load)
{
	return MOD_SUCCESS;
}

DLLFUNC int MOD_UNLOAD(m_netinfo)(int module_unload)
{
	if (del_Command(MSG_NETINFO, TOK_NETINFO, m_netinfo) < 0)
	{
		sendto_realops("Failed to delete commands when unloading %s",
			MOD_HEADER(m_netinfo).name);
	}
	return MOD_SUCCESS;
}

/*
** m_netinfo
** by Stskeeps
**  parv[0] = sender prefix
**  parv[1] = max global count
**  parv[2] = time of end sync
**  parv[3] = unreal protocol using (numeric)
**  parv[4] = cloak-crc (> u2302)
**  parv[5] = free(**)
**  parv[6] = free(**)
**  parv[7] = free(**)
**  parv[8] = ircnet
**/

DLLFUNC CMD_FUNC(m_netinfo)
{
	long 		lmax;
	time_t	 	xx;
	long 		endsync, protocol;
	char		buf[512];

	if (IsPerson(sptr))
		return 0;
	if (!IsServer(cptr))
		return 0;

	if (parc < 3)
	{
		/* Talking to a UnProtocol 2090 */
		sendto_realops
		    ("Link %s is using a too old UnProtocol - (parc < 3)",
		    cptr->name);
		return 0;
	}
	if (parc < 9)
	{
		return 0;
	}

	if (GotNetInfo(cptr))
	{
		sendto_realops("Already got NETINFO from Link %s", cptr->name);
		return 0;
	}
	/* is a long therefore not ATOI */
	lmax = atol(parv[1]);
	endsync = TS2ts(parv[2]);
	protocol = atol(parv[3]);

	/* max global count != max_global_count --sts */
	if (lmax > IRCstats.global_max)
	{
		IRCstats.global_max = lmax;
		sendto_realops("Max Global es %li (fijado por %s)",
		    lmax, cptr->name);
	}

	xx = TStime();
	if ((xx - endsync) < 0)
	{
		sendto_realops
		    ("Posible TS negativo por split en %s (%li - %li = %li)",
		    cptr->name, (xx), (endsync), (xx - endsync));
		sendto_serv_butone(&me,
		    ":%s SMO o :\2(sync)\2 Posible TS negativo por split en %s (%li - %li = %li)",
		    me.name, cptr->name, (xx), (endsync), (xx - endsync));
	}
	sendto_realops
	    ("Link %s -> %s sincronizado [segs: %li recibido: %ld.%hu enviado: %ld.%hu]",
	    cptr->name, me.name, (TStime() - endsync), sptr->receiveK,
	    sptr->receiveB, sptr->sendK, sptr->sendB);
#ifdef ZIP_LINKS
	if ((MyConnect(cptr)) && (IsZipped(cptr)) && cptr->zip->in->total_out && cptr->zip->out->total_in) {
		sendto_realops
		("Zipstats para el link %s: descomprimido (inn): %01lu=>%01lu (%3.1f%%), comprimido (out): %01lu=>%01lu (%3.1f%%)",
			get_client_name(cptr, TRUE),
			cptr->zip->in->total_in, cptr->zip->in->total_out,
			(100.0*(float)cptr->zip->in->total_in) /(float)cptr->zip->in->total_out,
			cptr->zip->out->total_in, cptr->zip->out->total_out,
			(100.0*(float)cptr->zip->out->total_out) /(float)cptr->zip->out->total_in);
	}
#endif

	sendto_serv_butone(&me,
	    ":%s SMO o :\2(sync)\2 Link %s -> %s sincronizado [segs: %li recibido: %ld.%hu enviado: %ld.%hu]",
	    me.name, cptr->name, me.name, (TStime() - endsync), sptr->receiveK,
	    sptr->receiveB, sptr->sendK, sptr->sendB);

	if (!(strcmp(ircnetwork, parv[8]) == 0))
	{
		sendto_realops("El nombre de Red no se corresponde en %s (%s != %s)",
		    cptr->name, parv[8], ircnetwork);
		sendto_serv_butone(&me,
		    ":%s SMO o :\2(sync)\2 El nombre de Red no se corresponde %s (%s != %s)",
		    me.name, cptr->name, parv[8], ircnetwork);
	}

	if ((protocol != UnrealProtocol) && (protocol != 0))
	{
		sendto_realops
		    ("El link %s utiliza el protocolo u%li y este servidor el %d",
		    cptr->name, protocol, UnrealProtocol);
		sendto_serv_butone(&me,
		    ":%s SMO o :\2(sync)\2 El link %s utiliza el protocolo u%li y este servidor el %d",
		    me.name, cptr->name, protocol, me.name, UnrealProtocol);

	}
	ircsprintf(buf, "%lX", CLOAK_KEYCRC);
#ifndef UDB /* con el UDB las cloak poca importancia tienen */
	if (*parv[4] != '*' && strcmp(buf, parv[4]))
	{
		sendto_realops
			("Link %s is having a DIFFERENT CLOAK KEY - %s != %s. \002YOU SHOULD CORRECT THIS ASAP\002.",
				cptr->name, parv[4], buf);
	}
#endif
	SetNetInfo(cptr);
	return 0;
}
