/*
 * =================================================================
 * Filename:		m_getinfo.c
 * =================================================================
 * Description:         This module provides command /getinfo to
 *                      retrieve information about either
 *                      a /server/client/channel.Now it uses
 *                      numeric 339 in reply messages.
 * =================================================================
 * Author:		AngryWolf
 * Email:		angrywolf@flashmail.com
 * =================================================================
 *
 * I accept bugreports, ideas and opinions, and if you have
 * questions, just send an email for me!
 *
 * Thank you for using my module!
 *
 * =================================================================
 * Requirements:
 * =================================================================
 *
 * o Unreal >=3.2-beta15
 * o One of the supported operating systems (see unreal32docs.html)
 *
 * =================================================================
 * Installation:
 * =================================================================
 *
 * See http://angrywolf.linktipp.org/compiling.php?lang=en
 *
 * =================================================================
 * Mirror files:
 * =================================================================
 *
 * http://angrywolf.linktipp.org/m_getinfo.c [Germany]
 * http://angrywolf.uw.hu/m_getinfo.c [Hungary]
 * http://angrywolf.fw.hu/m_getinfo.c [Hungary]
 *
 * =================================================================
 * Changes:
 * =================================================================
 *
 * 2003-07-19: Changed "NOTICE" messages to "339" numeric replies,
 *             since it was requested by much people (this should
 *             also fix some webtv problems)
 * 2003-04-27: Fixed compile warnings for win32
 * 2003-04-21: Changed declaration of some global variables
 *             to static
 * 2003-04-18: Made cFlagTab[] be extern
 * 2003-03-30: Cleaned code again
 * 2003-03-04: Updated documentation & cleaned up some code
 * 2003-02-26: Fixed a bug which made the module fail to load
 *             (reported by YESS)
 * 2003-02-16: Added compression level to Zipstats
 * 2003-02-15: Updated cFlagTab[] and installation instructions
 * 2003-02-08: Remote port is now displayed too
 * 2003-01-28: Added patch by Syzop to remove two unoccupied flags
 *             and allow users to see some zipstats information
 * 2003-01-20: Made message statistics more exact
 * 2003-01-19: Fixed so the IP address won't be displayed
 *             if IsMe(acptr)
 * 2003-01-18: Fixed so the correct IP address will be displayed for
 *             users/servers (reported by cyberboj)
 * 2003-01-18: Made the module restricted to opers (suggested
 *             by codemastr)
 * 2003-01-18: Added feature to display flags for users/servers
 *             (especially SSL which was suggested by codemstr)
 * 2003-01-18: Added feature to display IP address for
 *             users/servers (suggested by Syzop)
 * 2003-01-17: Added feature to display some time values for
 *             users/servers
 * 2003-01-16: Added support for channels
 * 2003-01-16: Recoded StatusText() and renamed to find_client_status()
 * 2002-12-15: Renamed module to m_getinfo and made some
 *             modifications, bugfixes
 * 2002-08-26: Coded m_clinfo
 *
 * =================================================================
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
#ifdef STRIPBADWORDS
#include "badwords.h"
#endif
#ifdef _WIN32
#include "version.h"
#endif

DLLFUNC int m_getinfo(aClient *cptr, aClient *sptr, int parc, char *parv[]);

/* Place includes here */
#define MSG_GETINFO 	"GETINFO"
#define TOK_GETINFO 	"GI"

ModuleHeader MOD_HEADER(m_getinfo)
  = {
	"getinfo",
	"$Id: m_getinfo.c,v 1.1.1.4 2004-05-17 15:46:30 Trocotronic Exp $",
	"command /getinfo",
	"3.2-b8-1",
	NULL 
    };


/* The purpose of these ifdefs, are that we can "static" link the ircd if we
 * want to
*/

/* This is called on module init, before Server Ready */
DLLFUNC int MOD_INIT(m_getinfo)(ModuleInfo *modinfo)
{
	/*
	 * We call our add_Command crap here
	*/
	add_Command(MSG_GETINFO, TOK_GETINFO, m_getinfo, MAXPARA);
	return MOD_SUCCESS;
}

/* Is first run when server is 100% ready */
DLLFUNC int MOD_LOAD(m_getinfo)(int module_load)
{
	return MOD_SUCCESS;
}


/* Called when module is unloaded */
DLLFUNC int MOD_UNLOAD(m_getinfo)(int module_unload)
{
	if (del_Command(MSG_GETINFO, TOK_GETINFO, m_getinfo) < 0)
	{
		sendto_realops("Failed to delete commands when unloading %s",
				MOD_HEADER(m_getinfo).name);
		return MOD_FAILED;
	}
	return MOD_SUCCESS;
}

// =================================================================
// Buffers
// =================================================================

char mybuf[201];

// =================================================================
// Structure type definitions
// =================================================================

typedef struct {
	short	number;
	char	*name;
} ShortNumStruct;

typedef struct {
	long	number;
	char	*name;
} LongNumStruct;

typedef struct {
	unsigned long	sendK;
	unsigned long	recvK;
	unsigned short	sendB;
	unsigned short	recvB;
} MessageStats;

// =================================================================
// Client status table
// =================================================================

static ShortNumStruct _ClientStatusTable[] = {
    { -7,	"LOG"			},
    { -6,	"CONNECTING"		},
    { -5,	"SSL_CONNECT_HANDSHAKE"	},
    { -4,	"SSL_ACCEPT_HANDSHAKE"	},
    { -3,	"HANDSHAKE"		},
    { -2,	"ME"			},
    { -1,	"UNKNOWN"		},
    { 0,	"SERVER"		},
    { 1,	"CLIENT"		},
};

#define CS_TABLE_SIZE sizeof(_ClientFlagsTable)/sizeof(_ClientFlagsTable[0])-1

// =================================================================
// List of supported protos
// =================================================================

static ShortNumStruct _ProtoctlTable[] = {
    { PROTO_NOQUIT,	"NOQUIT"	},
    { PROTO_TOKEN,	"TOKEN"		},
    { PROTO_SJOIN,	"SJOIN"		},
    { PROTO_NICKv2,	"NICKv2"	},
    { PROTO_SJOIN2,	"SJOIN2"	},
    { PROTO_UMODE2,	"UMODE2"	},
    { PROTO_NS,		"NS"		},
    { PROTO_ZIP,	"ZIP"		},
    { PROTO_VL,		"VL"		},
    { PROTO_SJ3,	"SJ3"		},
    { PROTO_VHP,	"VHP"		},
    { PROTO_SJB64,	"SJB64"		},
#ifdef UDB
    { PROTO_UDB,	"UDB2"		},
#endif    
};

#define PROTOCTL_TABLE_SIZE sizeof(_ProtoctlTable)/sizeof(_ProtoctlTable[0])-1

// =================================================================
// List of flags
// =================================================================

static LongNumStruct _ClientFlagsTable[] = {
    { FLAGS_PINGSENT,	"PINGSENT"	},
    { FLAGS_DEADSOCKET,	"DEADSOCKET"	},
    { FLAGS_KILLED,	"KILLED"	},
    { FLAGS_BLOCKED,	"BLOCKED"	},
    { FLAGS_CLOSING,	"CLOSING"	},
    { FLAGS_LISTEN,	"LISTEN"	},
    { FLAGS_CHKACCESS,	"CHKACCESS"	},
    { FLAGS_DOINGDNS,	"DOINGDNS"	},
    { FLAGS_AUTH,	"AUTH"		},
    { FLAGS_WRAUTH,	"WRAUTH"	},
    { FLAGS_LOCAL,	"LOCAL"		},
    { FLAGS_DOID,	"DOID"		},
    { FLAGS_GOTID,	"GOTID"		},
    { FLAGS_NONL,	"NONL"		},
    { FLAGS_TS8,	"TS8"		},
    { FLAGS_ULINE,	"ULINE"		},
    { FLAGS_SQUIT,	"SQUIT"		},
    { FLAGS_PROTOCTL,	"PROTOCTL"	},
    { FLAGS_PING,	"PING"		},
    { FLAGS_ASKEDPING,	"ASKEDPING"	},
    { FLAGS_NETINFO,	"NETINFO"	},
    { FLAGS_HYBNOTICE,	"HYBNOTICE"	},
    { FLAGS_QUARANTINE,	"QUARANTINE"	},
#ifdef ZIP_LINKS
    { FLAGS_ZIP,        "ZIP"		},
#endif
    { FLAGS_SHUNNED,	"SHUNNED"	},
#ifdef USE_SSL
    { FLAGS_SSL,	"SSL"		},
#endif
    { FLAGS_DCCBLOCK,	"DCCBLOCK"	},
    { FLAGS_MAP,	"MAP"		},
};

#define FLAGS_TABLE_SIZE sizeof(_ClientStatusTable)/sizeof(_ClientStatusTable[0])-1

// =================================================================
// find_client_status: Converts from status number to name
// =================================================================

ShortNumStruct *find_client_status(int sn)
{
	int i;

	for (i = 0; i <= FLAGS_TABLE_SIZE; i++)
        	if (sn == _ClientStatusTable[i].number)
            		return &_ClientStatusTable[i];

        return NULL;
}

// =================================================================
// get_proto_names: Sends back the protos supported by the client
// =================================================================

char *get_proto_names(short proto)
{
	char	*p;
	int	i, found;

	strcpy(mybuf, "");

	for (i = 0, found = 0; i <= PROTOCTL_TABLE_SIZE; i++)
        	if (proto & _ProtoctlTable[i].number)
		{
			if (found)
			    strcat(mybuf, ", ");
			else
			    found = 1;
			strcat(mybuf, _ProtoctlTable[i].name);
		}

	if (!strlen(mybuf))
	    strcpy(mybuf, "(vacío)");

	p = mybuf;
	return p;
}

// =================================================================
// get_flag_names: Sends back flagnames
// =================================================================

char *get_flag_names(long flags)
{
	char	*p;
	int	i, found;

	strcpy(mybuf, "");

	for (i = 0, found = 0; i <= CS_TABLE_SIZE; i++)
        	if (flags & _ClientFlagsTable[i].number)
		{
			if (found)
			    strcat(mybuf, ", ");
			else
			    found = 1;
			strcat(mybuf, _ClientFlagsTable[i].name);
		}

	if (!strlen(mybuf))
	    strcpy(mybuf, "(vacío)");

	p = mybuf;
	return p;
}

// =================================================================
// TS to full date conversion
// =================================================================

typedef struct {
	int year, month, day, hour, min, sec;
} aTime;

void TStoTime(TS time_in, aTime *time_back)
{
    struct tm *tm_time_in;

    tm_time_in = localtime(&time_in);

    time_back->year    = tm_time_in->tm_year + 1900;
    time_back->month   = tm_time_in->tm_mon + 1;
    time_back->day     = tm_time_in->tm_mday;
    time_back->hour    = tm_time_in->tm_hour;
    time_back->min     = tm_time_in->tm_min;
    time_back->sec     = tm_time_in->tm_sec;
}

char *FullDate(aTime *time_in)
{
    strcpy(mybuf, "");
    
    sprintf(mybuf, "%d-%s%d-%s%d %s%d:%s%d:%s%d",
	    time_in->year,
	    time_in->month < 10 ? "0" : "", time_in->month,
	    time_in->day   < 10 ? "0" : "", time_in->day,
	    time_in->hour  < 10 ? "0" : "", time_in->hour,
	    time_in->min   < 10 ? "0" : "", time_in->min,
	    time_in->sec   < 10 ? "0" : "", time_in->sec);

    return mybuf;
}

// =================================================================
// messagestats: Convert statistics sent to/received from aClient
//     to a readable one
// =================================================================

void messagestats(aClient *cptr, MessageStats *ms)
{
	ms->sendB	= cptr->sendB;
	ms->recvB	= cptr->receiveB;
	ms->sendK	= cptr->sendK;
	ms->recvK	= cptr->receiveK;

	if (ms->sendB > 1023)
	{
		ms->sendK += (ms->sendB >> 10);
		ms->sendB &= 0x3ff;
	}
	if (ms->recvB > 1023)
	{
		ms->recvK += (ms->recvB >> 10);
		ms->recvB &= 0x3ff;
	}
}

// =================================================================
// I needed a FULL channel mode string,
// so hacked up channel_modes() from src/channel.c
// =================================================================

void full_channel_modes(char *mbuf, char *pbuf, aChannel *chptr)
{
        long zode;
        aCtab *tab = &cFlagTab[0];
        char bcbuf[1024];

        *mbuf++ = '+';
        while (tab->mode != 0x0)
        {
                if ((chptr->mode.mode & tab->mode))
                {
                        zode = chptr->mode.mode;
                        if (!(zode & (MODE_LIMIT | MODE_KEY | MODE_LINK)))
                                if (!(zode & (MODE_CHANOP | MODE_VOICE |
                                    MODE_CHANOWNER)))
                                        if (!(zode & (MODE_BAN | MODE_EXCEPT |
                                            MODE_CHANPROT)))
                                                if (!(zode & (MODE_HALFOP)))
                                                        *mbuf++ = tab->flag;
                }
                tab++;
        }
        if (chptr->mode.limit)
        {
                *mbuf++ = 'l';
                (void)ircsprintf(pbuf, "%d ", chptr->mode.limit);
        }
        if (*chptr->mode.key)
        {
                *mbuf++ = 'k';
                /* FIXME: hope pbuf is long enough */
                (void)snprintf(bcbuf, sizeof bcbuf, "%s ", chptr->mode.key);
                (void)strcat(pbuf, bcbuf);
        }
        if (*chptr->mode.link)
        {
                *mbuf++ = 'L';
                /* FIXME: is pbuf long enough?  */
                (void)snprintf(bcbuf, sizeof bcbuf, "%s ", chptr->mode.link);
                (void)strcat(pbuf, bcbuf);
        }
#ifndef NEWCHFLOODPROT
        /* if we add more parameter modes, add a space to the strings here --Stskeeps */
        if (chptr->mode.per)
        {
                *mbuf++ = 'f';
                if (chptr->mode.kmode == 1)
                	ircsprintf(bcbuf, "*%i:%i ", chptr->mode.msgs,
                    		chptr->mode.per);
                else
                        ircsprintf(bcbuf, "%i:%i ", chptr->mode.msgs,
                        	chptr->mode.per);
                (void)strcat(pbuf, bcbuf);
        }
#endif
        *mbuf++ = '\0';
        return;

}

/*
** m_getinfo
**      parv[0] = sender prefix
**      parv[1] = nick/server/channel
*/

DLLFUNC int m_getinfo(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
	enum		ClientType { CT_User, CT_Server, CT_Channel, CT_None };
	aClient		*acptr;
	ShortNumStruct	*status;
	MessageStats	ms;
	aChannel	*chptr;
	aTime		mytime;
	int		ct;

        if (!MyClient(sptr) || !IsOper(sptr))
	{
        	sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name, parv[0]);
		return -1;
	}

        if (parc < 2)
	{
	        sendto_one(sptr, err_str(ERR_NEEDMOREPARAMS),
			me.name, parv[0], "GETINFO");
		return -1;
	}

	*modebuf = '\0';
	*parabuf = '\0';

	/* We need to know what we are going to get info from */

        if (*parv[1] == '#' && (chptr = find_channel(parv[1], NullChn)) != NullChn)
		ct = CT_Channel;		
        else if (acptr = find_person(parv[1], NULL))
		ct = CT_User;
	else if (acptr = find_server_quick(parv[1]))
		ct = CT_Server;
	else
		ct = CT_None;

	/* We can't get info about nothing */

	if (ct == CT_None)
	{
    	    if (!IsServer(sptr))
	        sendto_one(sptr, err_str(ERR_NOSUCHNICK),
		    me.name, sptr->name, parv[1]);
	        return -1;
	}

	/* Informing eyes users */

	if (ct == CT_Channel || strcasecmp(sptr->name, acptr->name))
		sendto_snomask(SNO_EYES, "*** %s (%s@%s) hace /getinfo a %s",
			sptr->name, sptr->user->username, GetHost(sptr),
			( ct == CT_Channel ? chptr->chname : acptr->name ));


	sendto_one(sptr, ":%s 339 %s :*** ===================================",
		me.name, sptr->name);

	/* FOR CHANNELS */

	if (ct == CT_Channel)
	{
		full_channel_modes(modebuf, parabuf, chptr);

		sendto_one(sptr, ":%s 339 %s :*** Info de: %s",
			me.name, sptr->name, chptr->chname);

		sendto_one(sptr, ":%s 339 %s :*** Modos: %s %s",
			me.name, sptr->name, modebuf, parabuf);

		sendto_one(sptr, ":%s 339 %s :*** Ususarios: %d",
			me.name, sptr->name, chptr->users);

		TStoTime(chptr->creationtime, &mytime);
		sendto_one(sptr, ":%s 339 %s :*** Creado el: %s",
			me.name, sptr->name, FullDate(&mytime));

		if (chptr->topic)
		{

			sendto_one(sptr, ":%s 339 %s :*** Topic: %s",
				me.name, sptr->name, chptr->topic);

			sendto_one(sptr, ":%s 339 %s :*** Topic puesto por: %s",
				me.name, sptr->name, chptr->topic_nick);

			TStoTime(chptr->topic_time, &mytime);
			sendto_one(sptr, ":%s 339 %s :*** Topic puesto el: %s",
				me.name, sptr->name, FullDate(&mytime));
		}

	}

	/* FOR BOTH USERS AND SERVERS */

	if (ct == CT_User || ct == CT_Server)
	{

		status = find_client_status(acptr->status);

		sendto_one(sptr, ":%s 339 %s :*** Info de: %s (%s)",
			me.name, sptr->name, acptr->name, acptr->info);

		sendto_one(sptr, ":%s N339 %s :*** Status: %s",
			me.name, sptr->name,
			( status ? status->name : "(vacío)" ));

		if (!IsMe(acptr))
			sendto_one(sptr, ":%s 339 %s :*** Protoctl: %s",
				me.name, sptr->name,
				get_proto_names(acptr->proto));

		sendto_one(sptr, ":%s 339 %s :*** Modos: %s",
			me.name, sptr->name,
			get_flag_names(acptr->flags));

		if (MyConnect(acptr))
		{

			if (!IsMe(acptr))
			{
				sendto_one(sptr, ":%s 339 %s :*** Conectado a %s en puerto %d [%s]",
					me.name, sptr->name,
					( IsClient(acptr) ? acptr->user->server : acptr->serv->up ),
					acptr->listener->port,
					( acptr->class ? acptr->class->name : "" ));

				sendto_one(sptr, ":%s 339 %s :*** IP: %s [puerto: %d]",
					me.name, sptr->name,
#ifdef INET6
                        		inetntop(AF_INET6,
                        		(char *)&acptr->ip, mydummy, MYDUMMY_SIZE),
#else
                        		inetntoa((char *)&acptr->ip),
#endif
					acptr->port);

			}

			messagestats(acptr, &ms);
			sendto_one(sptr, ":%s 339 %s :*** Mensajes enviados: %ld (%ld.%u kB), recibidos: %ld (%ld.%u kB)",
				me.name, sptr->name,
				acptr->sendM, ms.sendK, ms.sendB, acptr->receiveM, ms.recvK, ms.recvB);

			TStoTime(acptr->firsttime, &mytime);
			sendto_one(sptr, ":%s 339 %s :*** Creado el: %s",
				me.name, sptr->name, FullDate(&mytime));

			TStoTime(acptr->lasttime, &mytime);
			sendto_one(sptr, ":%s 339 %s :*** Último uso: %s",
				me.name, sptr->name, FullDate(&mytime));


			if (acptr->nexttarget)
			{
				TStoTime(acptr->nexttarget, &mytime);
				sendto_one(sptr, ":%s 339 %s :*** Próximo uso: %s",
					me.name, sptr->name, FullDate(&mytime));
			}

			if (acptr->nextnick)
			{
				TStoTime(acptr->nextnick, &mytime);
			        sendto_one(sptr, ":%s 339 %s :*** Próximo nick: %s",
					me.name, sptr->name, FullDate(&mytime));
			}

		}

		if (IsClient(acptr))
		{
			TStoTime(acptr->lastnick, &mytime);
			sendto_one(sptr, ":%s 339 %s :*** Último nick: %s",
				me.name, sptr->name, FullDate(&mytime));
		}
	}

	/* FOR SERVERS */

	if (ct == CT_Server)
	{

		sendto_one(sptr, ":%s 339 %s :*** Numeric: %d",
			me.name, sptr->name, acptr->serv->numeric);

		if (IsMe(acptr))
			sendto_one(sptr, ":%s 339 %s :*** Usuarios: %d",
				me.name, sptr->name, IRCstats.me_clients);
		else
			sendto_one(sptr, ":%s 339 %s :*** Usuarios: %d",
				me.name, sptr->name, acptr->serv->user);

		if (!IsMe(acptr))
			sendto_one(sptr, ":%s 339 %s :*** Link por: %s",
				me.name, sptr->name,
				*acptr->serv->by != '\0' ? acptr->serv->by : "<None>");

#ifdef ZIP_LINKS
		if (MyConnect(acptr) && IsZipped(acptr))
			sendto_one(sptr, ":%s 339 %s :*** Zipstats (out): %01lu -> %lu bytes (%3.1f%%), "
				"nivel de compresión: %d",
				me.name, sptr->name, acptr->zip->out->total_in, acptr->zip->out->total_out,
				(100.0*(float)acptr->zip->out->total_out) /(float)acptr->zip->out->total_in,
				acptr->serv->conf->compression_level ? acptr->serv->conf->compression_level : ZIP_DEFAULT_LEVEL);
#endif

	}

	/* FOR USERS */

	if (ct == CT_User)
	{

		if (IsHidden(acptr))
			sendto_one(sptr, ":%s 339 %s :*** Userhost: %s@%s [VHOST %s]",
				me.name, sptr->name,
				acptr->user->username, acptr->user->realhost,
				acptr->user->virthost);
		else		    	 
			sendto_one(sptr, ":%s 339 %s :*** Userhost: %s@%s",
				me.name, sptr->name,
				acptr->user->username, acptr->user->realhost);

		sendto_one(sptr, ":%s 339 %s :*** Modos: %s",
			me.name, sptr->name,
			get_mode_str(acptr));

		sendto_one(sptr, ":%s 339 %s :*** Snomasks: %s",
			me.name, sptr->name,
			get_sno_str(acptr));

		sendto_one(sptr, ":%s 339 %s :*** Modos IRCop: %s",
			me.name, sptr->name,
			oflagstr(acptr->oflag));

		if (acptr->user->swhois)
			if (*acptr->user->swhois != '\0')
				sendto_one(sptr, ":%s 339 %s :*** Info especial: %s",
					me.name, sptr->name, acptr->user->swhois);

 		if (acptr->user->away)
			if (*acptr->user->away != '\0')
				sendto_one(sptr, ":%s 339 %s :*** Mensaje away: %s",
					me.name, sptr->name, acptr->user->away);

		sendto_one(sptr, ":%s 339 %s :*** Está en %d canales",
			me.name, sptr->name, acptr->user->joined);


	}

	sendto_one(sptr, ":%s 339 %s :*** ===================================",
		me.name, sptr->name);

	sendto_one(sptr, ":%s 339 %s :*** Fin de /GETINFO",
		me.name, sptr->name);

	return 0;
}
