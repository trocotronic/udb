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
#ifdef UDB
#include "s_bdd.h"
#endif
#include "version.h"

DLLFUNC int m_server(aClient *cptr, aClient *sptr, int parc, char *parv[]);

#define MSG_SERVER 	"SERVER"	
#define TOK_SERVER 	"'"	

ModuleHeader MOD_HEADER(m_server)
  = {
	"m_server",
	"$Id: m_server.c,v 1.1.4.2 2004-05-17 15:46:30 Trocotronic Exp $",
	"command /server", 
	"3.2-b8-1",
	NULL 
    };

DLLFUNC int MOD_INIT(m_server)(ModuleInfo *modinfo)
{
	add_CommandX(MSG_SERVER, TOK_SERVER, m_server, MAXPARA, M_UNREGISTERED|M_SERVER);
	MARK_AS_OFFICIAL_MODULE(modinfo);
	return MOD_SUCCESS;
}

DLLFUNC int MOD_LOAD(m_server)(int module_load)
{
	return MOD_SUCCESS;
}

DLLFUNC int MOD_UNLOAD(m_server)(int module_unload)
{
	if (del_Command(MSG_SERVER, TOK_SERVER, m_server) < 0)
	{
		sendto_realops("Failed to delete commands when unloading %s",
			MOD_HEADER(m_server).name);
	}
	return MOD_SUCCESS;
}

int m_server_synch(aClient *cptr, long numeric, ConfigItem_link *conf);

/*
** m_server
**	parv[0] = sender prefix
**	parv[1] = servername
**      parv[2] = hopcount
**      parv[3] = numeric
**      parv[4] = serverinfo
**
** on old protocols, serverinfo is parv[3], and numeric is left out
**
**  Recode 2001 by Stskeeps
*/
DLLFUNC CMD_FUNC(m_server)
{
	char *servername = NULL;	/* Pointer for servername */
 /*	char *password = NULL; */
	char *ch = NULL;	/* */
	char *inpath = get_client_name(cptr, TRUE);
	aClient *acptr = NULL, *ocptr = NULL;
	ConfigItem_ban *bconf;
	int  hop = 0, numeric = 0;
	char info[REALLEN + 61];
	ConfigItem_link *aconf = NULL;
	ConfigItem_deny_link *deny;
	char *flags = NULL, *protocol = NULL, *inf = NULL, *num = NULL;


	/* Ignore it  */
	if (IsPerson(sptr))
	{
		sendto_one(cptr, err_str(ERR_ALREADYREGISTRED),
		    me.name, parv[0]);
		sendto_one(cptr,
		    ":%s %s %s :*** Sorry, but your IRC program doesn't appear to support changing servers.",
		    me.name, IsWebTV(cptr) ? "PRIVMSG" : "NOTICE", cptr->name);
		sptr->since += 7;
		return 0;
	}

	/*
	 *  We do some parameter checks now. We want atleast upto serverinfo now
	 */
	if (parc < 4 || (!*parv[3]))
	{
		sendto_one(sptr, "ERROR :Faltan par�metros");
		return exit_client(cptr, sptr, &me, 
			"Faltan par�metros");		
	}

	if (IsUnknown(cptr) && (cptr->listener->umodes & LISTENER_CLIENTSONLY))
	{
		return exit_client(cptr, sptr, &me,
		    "Puerto para clientes");
	}

	/* Now, let us take a look at the parameters we got
	 * Passes here:
	 *    Check for bogus server name
	 */

	servername = parv[1];
	/* Cut off if too big */
	if (strlen(servername) > HOSTLEN)
		servername[HOSTLEN] = '\0';
	/* Check if bogus, like spaces and ~'s */
	for (ch = servername; *ch; ch++)
		if (*ch <= ' ' || *ch > '~')
			break;
	if (*ch || !index(servername, '.'))
	{
		sendto_one(sptr, "ERROR :Servidor incorrecto (%s)",
		    sptr->name, servername);
		sendto_snomask
		    (SNO_JUNK,
		    "WARNING: Servidor incorrecto (%s) desde %s",
		    servername, get_client_name(cptr, TRUE));

		return exit_client(cptr, sptr, &me, "Servidor incorrecto");
	}

	if ((IsUnknown(cptr) || IsHandshake(cptr)) && !cptr->passwd)
	{
		sendto_one(sptr, "ERROR :Falta contrase�a");
		return exit_client(cptr, sptr, &me, "Falta contrase�a");
	}

	/*
	 * Now, we can take a look at it all
	 */
	if (IsUnknown(cptr) || IsHandshake(cptr))
	{
		char xerrmsg[256];
		ConfigItem_link *link;
		
		strcpy(xerrmsg, "No hay configuraci�n");
		/* First check if the server is in the list */
		if (!servername) {
			strcpy(xerrmsg, "Null servername");
			goto errlink;
		}
		for(link = conf_link; link; link = (ConfigItem_link *) link->next)
			if (!match(link->servername, servername))
				break;
		if (!link) {
			snprintf(xerrmsg, 256, "Sin configuraci�n (falta bloque) '%s'", servername);
			goto errlink;
		}
		if (link->username && match(link->username, cptr->username)) {
			snprintf(xerrmsg, 256, "Username inv�lido '%s' a '%s'",
				cptr->username, link->username);
			/* I assume nobody will have 2 link blocks with the same servername
			 * and different username. -- Syzop
			 */
			goto errlink;
		}
		/* For now, we don't check based on DNS, it is slow, and IPs are better.
		 * We also skip checking if link::options::nohostcheck is set.
		 */
		if (link->options & CONNECT_NOHOSTCHECK)
		{
			aconf = link;
			goto nohostcheck;
		}
		aconf = Find_link(cptr->username, cptr->sockhost, cptr->sockhost,
		    servername);
		
#ifdef INET6
		/*  
		 * We first try match on uncompressed form ::ffff:192.168.1.5 thing included
		*/
		if (!aconf)
			aconf = Find_link(cptr->username, cptr->sockhost, Inet_ia2pNB(&cptr->ip, 0), servername);
		/* 
		 * Then on compressed 
		*/
		if (!aconf)
			aconf = Find_link(cptr->username, cptr->sockhost, Inet_ia2pNB(&cptr->ip, 1), servername);
#endif		
		if (!aconf)
		{
			snprintf(xerrmsg, 256, "Servidor en configuraci�n pero no coincide IP/host");
errlink:
			/* Send the "simple" error msg to the server */
			sendto_one(cptr,
			    "ERROR :Link denegado (Sin configuraci�n) %s",
			    inpath);
			/* And send the "verbose" error msg only to local failops */
			sendto_locfailops
			    ("Link denegado para %s(%s@%s) (%s) %s",
			    servername, cptr->username, cptr->sockhost, xerrmsg, inpath);
			return exit_client(cptr, sptr, &me,
			    "Link denegado (Sin configuraci�n)");
		}
nohostcheck:
		/* Now for checking passwords */
		if (Auth_Check(cptr, aconf->recvauth, cptr->passwd) == -1)
		{
			sendto_one(cptr,
			    "ERROR :Link denegado (Autentificaci�n incorrecta) %s",
			    inpath);
			sendto_locfailops
			    ("Link denegado (Autentificaci�n incorrecta) %s", inpath);
			return exit_client(cptr, sptr, &me,
			    "Link denegado (Autentificaci�n incorrecta)");
		}

		/*
		 * Third phase, we check that the server does not exist
		 * already
		 */
		if ((acptr = find_server(servername, NULL)))
		{
			/* Found. Bad. Quit. */
			acptr = acptr->from;
			ocptr =
			    (cptr->firsttime > acptr->firsttime) ? acptr : cptr;
			acptr =
			    (cptr->firsttime > acptr->firsttime) ? cptr : acptr;
			sendto_one(acptr,
			    "ERROR :El servidor %s ya existe en %s",
			    servername,
			    (ocptr->from ? ocptr->from->name : "(sin cuerpo)"));
			sendto_realops
			    ("Link %s denegado, el servidor %s ya existe en %s",
			    get_client_name(acptr, TRUE), servername,
			    (ocptr->from ? ocptr->from->name : "(sin cuerpo)"));
			return exit_client(acptr, acptr, acptr,
			    "Servidor ya existe");
		}
		if ((bconf = Find_ban(servername, CONF_BAN_SERVER)))
		{
			sendto_realops
				("Link denegado %s, servidor baneado",
				get_client_name(cptr, TRUE));
			sendto_one(cptr, "ERROR :Servidor baneado (%s)", bconf->reason ? bconf->reason : "no reason");
			return exit_client(cptr, cptr, &me, "Servidor baneado");
		}
		if (aconf->class->clients + 1 > aconf->class->maxclients)
		{
			sendto_realops
				("Link denegado %s, clase llena",
					get_client_name(cptr, TRUE));
			return exit_client(cptr, cptr, &me, "Clase llena");
		}
		/* OK, let us check in the data now now */
		hop = TS2ts(parv[2]);
		numeric = (parc > 4) ? TS2ts(parv[3]) : 0;
		if ((numeric < 0) || (numeric > 255))
		{
			sendto_realops
				("Link denegado %s, numeric inv�lido",
					get_client_name(cptr, TRUE));
			return exit_client(cptr, cptr, &me, "Numeric inv�lido");
		}
		strncpyzt(info, parv[parc - 1], REALLEN + 61);
		strncpyzt(cptr->name, servername, sizeof(cptr->name));
		cptr->hopcount = hop;
#ifdef UDB
		if (aconf->hubmask) {
			if (!(cptr->proto) || !IsUDB(cptr)) {
			  sendto_one(cptr, "ERROR: Eres un HUB pero no soportas UDB");
			  return exit_client(cptr, sptr, &me, "Eres un HUB pero no soportas UDB");
			}
		}
#endif			
		/* Add ban server stuff */
		if (SupportVL(cptr))
		{
			/* we also have a fail safe incase they say they are sending
			 * VL stuff and don't -- codemastr
			 */
			ConfigItem_deny_version *vlines;
			inf = NULL;
			protocol = NULL;
			flags = NULL;
			num = NULL;
			protocol = (char *)strtok((char *)info, "-");
			if (protocol)
				flags = (char *)strtok((char *)NULL, "-");
			if (flags)
				num = (char *)strtok((char *)NULL, " ");
			if (num)
				inf = (char *)strtok((char *)NULL, "");
			if (inf) {
				strncpyzt(cptr->info, inf[0] ? inf : me.name,
				    sizeof(cptr->info));

				for (vlines = conf_deny_version; vlines; vlines = (ConfigItem_deny_version *) vlines->next) {
					if (!match(vlines->mask, cptr->name))
						break;
				}
				if (vlines) {
					char *proto = vlines->version;
					char *vflags = vlines->flags;
					int version, result = 0, i;
					protocol++;
					version = atoi(protocol);
					switch (*proto) {
						case '<':
							proto++;
							if (version < atoi(proto))
								result = 1;
							break;
						case '>':
							proto++;
							if (version > atoi(proto))
								result = 1;
							break;
						case '=':
							proto++;
							if (version == atoi(proto))
								result = 1;
							break;
						case '!':
							proto++;
							if (version != atoi(proto))
								result = 1;
							break;
						default:
							if (version == atoi(proto))
								result = 1;
							break;
					}
					if (version == 0 || *proto == '*')
						result = 0;

					if (result)
						return exit_client(cptr, cptr, cptr,
							"Denegado por by V:line");

					for (i = 0; vflags[i]; i++) {
						if (vflags[i] == '!') {
							i++;
							if (strchr(flags, vflags[i])) {
								result = 1;
								break;
							}
						}
						else if (!strchr(flags, vflags[i])) {
								result = 1;
								break;
						}
					}
					if (*vflags == '*' || !strcmp(flags, "0"))
						result = 0;
					if (result)
						return exit_client(cptr, cptr, cptr,
							"Denegado por V:line");
				}
			}
			else
				strncpyzt(cptr->info, info[0] ? info : me.name,
				    sizeof(cptr->info));

		}
		else
				strncpyzt(cptr->info, info[0] ? info : me.name,
					sizeof(cptr->info));
		/* Numerics .. */
		numeric = num ? atol(num) : numeric;
		if (numeric)
		{
			if ((numeric < 0) || (numeric > 254))
			{
				sendto_locfailops("Link %s denegado, numeric '%d' fuera de rango (should be 0-254)",
					inpath, numeric);

				return exit_client(cptr, cptr, cptr,
				    "Numeric fuera de rango (0-254)");
			}
			if (numeric_collides(numeric))
			{
				sendto_locfailops("Link %s denegado, colisi�n de numerics",
					inpath);

				return exit_client(cptr, cptr, cptr,
				    "Colisi�n de numerics. Escoge otro");
			}
		}
		for (deny = conf_deny_link; deny; deny = (ConfigItem_deny_link *) deny->next) {
			if (deny->flag.type == CRULE_ALL && !match(deny->mask, servername)
				&& crule_eval(deny->rule)) {
				sendto_ops("Conexi�n rechazada %s.",
					get_client_host(cptr));
				return exit_client(cptr, cptr, cptr,
					"Conexi�n rechazada");
			}
		}
		if (aconf->options & CONNECT_QUARANTINE)
			cptr->flags |= FLAGS_QUARANTINE;
		/* Start synch now */
		if (m_server_synch(cptr, numeric, aconf) == FLUSH_BUFFER)
			return FLUSH_BUFFER;
	}
	else
	{
		return m_server_remote(cptr, sptr, parc, parv);
	}
	return 0;
}

CMD_FUNC(m_server_remote)
{
	aClient *acptr, *ocptr, *bcptr;
	ConfigItem_link	*aconf;
	ConfigItem_ban *bconf;
	int 	hop;
	char	info[REALLEN + 61];
	long	numeric = 0;
	char	*servername = parv[1];
	int	i;

	if ((acptr = find_server(servername, NULL)))
	{
		/* Found. Bad. Quit. */
		acptr = acptr->from;
		ocptr =
		    (cptr->firsttime > acptr->firsttime) ? acptr : cptr;
		acptr =
		    (cptr->firsttime > acptr->firsttime) ? cptr : acptr;
		sendto_one(acptr,
		    "ERROR :El servidor %s ya existe en %s",
		    servername,
		    (ocptr->from ? ocptr->from->name : "(sin cuerpo)"));
		sendto_realops
		    ("Link %s denegado, el servidor %s ya existe en %s",
		    get_client_name(acptr, TRUE), servername,
		    (ocptr->from ? ocptr->from->name : "(sin cuerpo)"));
		if (acptr == cptr) {
			return exit_client(acptr, acptr, acptr, "Servidor existe");
		} else {
			/* AFAIK this can cause crashes if this happends remotely because
			 * we will still receive msgs for some time because of lag.
			 * Two possible solutions: unlink the directly connected server (cptr)
			 * and/or fix all those commands which blindly trust server input. -- Syzop
			 */
			exit_client(acptr, acptr, acptr, "Servidor existe");
			return 0;
		}
	}
	if ((bconf = Find_ban(servername, CONF_BAN_SERVER)))
	{
		sendto_realops
			("Link %s denegado, servidor baneado",
			get_client_name(cptr, TRUE), servername);
		sendto_one(cptr, "ERROR :Servidor baneado (%s)", bconf->reason ? bconf->reason : "sin raz�n");
		return exit_client(cptr, cptr, &me, "Servidor baneado");
	}
	/* OK, let us check in the data now now */
	hop = TS2ts(parv[2]);
	numeric = (parc > 4) ? TS2ts(parv[3]) : 0;
	if ((numeric < 0) || (numeric > 255))
	{
		sendto_realops
			("Link %s denegado, numeric inv�lido en %s",
				get_client_name(cptr, TRUE), servername);
		sendto_one(cptr, "ERROR :Numeric inv�lido (%s)",
			servername);
		return exit_client(cptr, cptr, &me, "Numeric remoto inv�lido");
	}
	strncpyzt(info, parv[parc - 1], REALLEN + 61);
	if (!cptr->serv->conf)
	{
		sendto_realops("Lost conf for %s!!, dropping link", cptr->name);
		return exit_client(cptr, cptr, cptr, "Lost configuration");
	}
	aconf = cptr->serv->conf;
	if (!aconf->hubmask)
	{
		sendto_locfailops("Link %s denegado, no es hub e introduce un leaf %s",
			cptr->name, servername);
		return exit_client(cptr, cptr, cptr, "No-Hub Link");
	}
	if (match(aconf->hubmask, servername))
	{
		sendto_locfailops("Link %s denegado %s, configuraci�n no permitida", cptr->name, servername);
		return exit_client(cptr, cptr, cptr, "Configuraci�n de hub no permitida");
	}
	if (aconf->leafmask)
	{
		if (match(aconf->leafmask, servername))
		{
			sendto_locfailops("Link %s(%s) denegado por configuraci�n de leaf", cptr->name, servername);
			return exit_client(cptr, cptr, cptr, "No permitido por configuraci�n de leaf");
		}
	}
	if (aconf->leafdepth && (hop > aconf->leafdepth))
	{
			sendto_locfailops("Link %s(%s) denegado, demasiados eslavones", cptr->name, servername);
			return exit_client(cptr, cptr, cptr, "Demasiados eslavones (leaf)");
	}
	if (numeric)
	{
		if ((numeric < 0) || (numeric > 254))
		{
			sendto_locfailops("Link %s(%s) denegado, numeric '%d' fuera de rango (0-254)",
				cptr->name, servername, numeric);
			return exit_client(cptr, cptr, cptr,
			    "Numeric fuera de rango (0-254)");
		}
		if (numeric_collides(numeric))
		{
			sendto_locfailops("Link %s(%s) denegado, colisi�n de numerics",
					cptr->name, servername);

			return exit_client(cptr, cptr, cptr,
			    "Colisi�n de numerics. Escoge otro");
		}
	}
	acptr = make_client(cptr, find_server_quick(parv[0]));
	(void)make_server(acptr);
	acptr->serv->numeric = numeric;
	acptr->hopcount = hop;
	strncpyzt(acptr->name, servername, sizeof(acptr->name));
	strncpyzt(acptr->info, info, sizeof(acptr->info));
	acptr->serv->up = find_or_add(parv[0]);
	SetServer(acptr);
	ircd_log(LOG_SERVER, "SERVER %s", acptr->name);
	/* Taken from bahamut makes it so all servers behind a U:lined
	 * server are also U:lined, very helpful if HIDE_ULINES is on
	 */
	if (IsULine(cptr)
	    || (Find_uline(acptr->name)))
		acptr->flags |= FLAGS_ULINE;
	add_server_to_table(acptr);
	IRCstats.servers++;
	(void)find_or_add(acptr->name);
	add_client_to_list(acptr);
	(void)add_to_client_hash_table(acptr->name, acptr);
	RunHook(HOOKTYPE_SERVER_CONNECT, acptr);
	for (i = 0; i <= LastSlot; i++)
	{
		if (!(bcptr = local[i]) || !IsServer(bcptr) ||
			    bcptr == cptr || IsMe(bcptr))
				continue;
		if (SupportNS(bcptr))
		{
			sendto_one(bcptr,
				"%c%s %s %s %d %ld :%s",
				(sptr->serv->numeric ? '@' : ':'),
				(sptr->serv->numeric ? base64enc(sptr->serv->numeric) : sptr->name),
				IsToken(bcptr) ? TOK_SERVER : MSG_SERVER,
				acptr->name, hop + 1, numeric, acptr->info);
		}
			else
		{
			sendto_one(bcptr, ":%s %s %s %d :%s",
			    parv[0],
			    IsToken(bcptr) ? TOK_SERVER : MSG_SERVER,
			    acptr->name, hop + 1, acptr->info);
		}
	}
	return 0;
}

int	m_server_synch(aClient *cptr, long numeric, ConfigItem_link *aconf)
{
	char		*inpath = get_client_name(cptr, TRUE);
	extern char 	serveropts[];
	aClient		*acptr;
	int		i;
#ifdef UDB
	char bdd;
#endif	
	char buf[BUFSIZE];

	ircd_log(LOG_SERVER, "SERVER %s", cptr->name);

	if (cptr->passwd)
	{
		MyFree(cptr->passwd);
		cptr->passwd = NULL;
	}
	if (IsUnknown(cptr))
	{
		/* If this is an incomming connection, then we have just received
		 * their stuff and now send our stuff back.
		 */
		send_proto(cptr, aconf);
		sendto_one(cptr, "PASS :%s", aconf->connpwd);
		sendto_one(cptr, "SERVER %s 1 :U%d-%s-%i %s",
			    me.name, UnrealProtocol,
			    serveropts, me.serv->numeric,
			    (me.info[0]) ? (me.info) : "Rallados");
	}
#ifdef ZIP_LINKS
	if (aconf->options & CONNECT_ZIP)
	{
		if (cptr->proto & PROTO_ZIP)
		{
			if (zip_init(cptr, aconf->compression_level ? aconf->compression_level : ZIP_DEFAULT_LEVEL) == -1)
			{
				zip_free(cptr);
				sendto_realops("Imposible de fijar configuraci�n para link zip %s", get_client_name(cptr, TRUE));
				return exit_client(cptr, cptr, &me, "zip_init() failed");
			}
			SetZipped(cptr);
			cptr->zip->first = 1;
		} else {
			sendto_realops("WARNING: Remote doesnt have link::options::zip set. Compression disabled.");
		}
	}
#endif

#if 0
/* Disabled because it may generate false warning when linking with cvs versions between b14 en b15 -- Syzop */
	if ((cptr->proto & PROTO_ZIP) && !(aconf->options & CONNECT_ZIP))
	{
#ifdef ZIP_LINKS
		sendto_realops("WARNING: Remote requested compressed link, but we don't have link::options::zip set. Compression disabled.");
#else
		sendto_realops("WARNING: Remote requested compressed link, but we don't have zip links support compiled in. Compression disabled.");
#endif
	}
#endif
	/* Set up server structure */
	SetServer(cptr);
	IRCstats.me_servers++;
	IRCstats.servers++;
	IRCstats.unknown--;
#ifndef NO_FDLIST
	addto_fdlist(cptr->slot, &serv_fdlist);
#endif
	if ((Find_uline(cptr->name)))
		cptr->flags |= FLAGS_ULINE;
	nextping = TStime();
	(void)find_or_add(cptr->name);
#ifdef USE_SSL
	if (IsSecure(cptr))
	{
		sendto_serv_butone(&me, ":%s SMO o :(\2link\2) Seguro %slink %s -> %s establecido (%s)",
			me.name,
			IsZipped(cptr) ? "ZIP" : "",
			me.name, inpath, (char *) ssl_get_cipher((SSL *)cptr->ssl));
		sendto_realops("(\2link\2) Seguro %slink %s -> %s establecido (%s)",
			IsZipped(cptr) ? "ZIP" : "",
			me.name, inpath, (char *) ssl_get_cipher((SSL *)cptr->ssl));
	}
	else
#endif
	{
		sendto_serv_butone(&me, ":%s SMO o :(\2link\2) %sLink %s -> %s establecido",
			me.name,
			IsZipped(cptr) ? "ZIP" : "",
			me.name, inpath);
		sendto_realops("(\2link\2) %sLink %s -> %s establecido",
			IsZipped(cptr) ? "ZIP" : "",
			me.name, inpath);
	}
	(void)add_to_client_hash_table(cptr->name, cptr);
	/* doesnt duplicate cptr->serv if allocted this struct already */
	(void)make_server(cptr);
	cptr->serv->up = me.name;
	cptr->srvptr = &me;
	cptr->serv->numeric = numeric;
	cptr->serv->conf = aconf;
	cptr->serv->conf->refcount++;
	cptr->serv->conf->class->clients++;
	cptr->class = cptr->serv->conf->class;
	add_server_to_table(cptr);
	RunHook(HOOKTYPE_SERVER_CONNECT, cptr);
	for (i = 0; i <= LastSlot; i++)
	{
		if (!(acptr = local[i]) || !IsServer(acptr) ||
		    acptr == cptr || IsMe(acptr))
			continue;

		if (SupportNS(acptr))
		{
			sendto_one(acptr, "%c%s %s %s 2 %i :%s",
			    (me.serv->numeric ? '@' : ':'),
			    (me.serv->numeric ? base64enc(me.
			    serv->numeric) : me.name),
			    (IsToken(acptr) ? TOK_SERVER : MSG_SERVER),
			    cptr->name, cptr->serv->numeric, cptr->info);
		}
		else
		{
			sendto_one(acptr, ":%s %s %s 2 :%s",
			    me.name,
			    (IsToken(acptr) ? TOK_SERVER : MSG_SERVER),
			    cptr->name, cptr->info);
		}
	}
	for (acptr = &me; acptr; acptr = acptr->prev)
	{
		/* acptr->from == acptr for acptr == cptr */
		if (acptr->from == cptr)
			continue;
		if (IsServer(acptr))
		{
			if (SupportNS(cptr))
			{
				/* this has to work. */
				numeric =
				    ((aClient *)find_server_quick(acptr->
				    serv->up))->serv->numeric;

				sendto_one(cptr, "%c%s %s %s %d %i :%s",
				    (numeric ? '@' : ':'),
				    (numeric ? base64enc(numeric) :
				    acptr->serv->up),
				    IsToken(cptr) ? TOK_SERVER : MSG_SERVER,
				    acptr->name, acptr->hopcount + 1,
				    acptr->serv->numeric, acptr->info);
			}
			else
				sendto_one(cptr, ":%s %s %s %d :%s",
				    acptr->serv->up,
				    (IsToken(cptr) ? TOK_SERVER : MSG_SERVER),
				    acptr->name, acptr->hopcount + 1,
				    acptr->info);

			/* Also signal to the just-linked server which
			 * servers are fully linked.
			 * Now you might ask yourself "Why don't we just
			 * assume every server you get during link phase
			 * is fully linked?", well.. there's a race condition
			 * if 2 servers link (almost) at the same time,
			 * then you would think the other one is fully linked
			 * while in fact he was not.. -- Syzop.
			 */
			if (acptr->serv->flags.synced)
			{
				sendto_one(cptr, ":%s %s", acptr->name,
					(IsToken(cptr) ? TOK_EOS : MSG_EOS));
#ifdef DEBUGMODE
				ircd_log(LOG_ERROR, "[EOSDBG] m_server_synch: sending to uplink '%s' with src %s...",
					cptr->name, acptr->name);
#endif
			}
		}
	}
#ifdef UDB
	if (IsUDB(cptr))
		for (bdd = PRIMERA_LETRA; bdd <= ULTIMA_LETRA; bdd++)
			sendto_one(cptr, ":%s DB %s %s J %09lu %c", me.name, cptr->name, corruptas[bdd] ? "C" : "0", series[bdd], bdd);
#endif		
	/* Synching nick information */
	for (acptr = &me; acptr; acptr = acptr->prev)
	{
		/* acptr->from == acptr for acptr == cptr */
		if (acptr->from == cptr)
			continue;
		if (IsPerson(acptr))
		{
			if (!SupportNICKv2(cptr))
			{
				sendto_one(cptr,
				    "%s %s %d %ld %s %s %s %lu :%s",
				    (IsToken(cptr) ? TOK_NICK : MSG_NICK),
				    acptr->name, acptr->hopcount + 1,
				    acptr->lastnick, acptr->user->username,
				    acptr->user->realhost,
				    acptr->user->server,
				    (unsigned long)acptr->user->servicestamp, acptr->info);
				send_umode(cptr, acptr, 0, SEND_UMODES, buf);
				if (IsHidden(acptr) && acptr->user->virthost)
					sendto_one(cptr, ":%s %s %s",
					    acptr->name,
					    (IsToken(cptr) ? TOK_SETHOST :
					    MSG_SETHOST),
					    acptr->user->virthost);
			}
			else
			{
				send_umode(NULL, acptr, 0, SEND_UMODES, buf);

				if (!SupportVHP(cptr))
				{
					if (SupportNS(cptr)
					    && acptr->srvptr->serv->numeric)
					{
						sendto_one(cptr,
						    ((cptr->proto & PROTO_SJB64) ?
						    "%s %s %d %B %s %s %b %lu %s %s :%s"
						    :
						    "%s %s %d %lu %s %s %b %lu %s %s :%s"),
						    (IsToken(cptr) ? TOK_NICK : MSG_NICK),
						    acptr->name,
						    acptr->hopcount + 1,
						    acptr->lastnick,
						    acptr->user->username,
						    acptr->user->realhost,
						    (long)(acptr->srvptr->serv->numeric),
						    (unsigned long)acptr->user->servicestamp,
						    (!buf || *buf == '\0' ? "+" : buf),
						    ((IsHidden(acptr) && (acptr->umodes & UMODE_SETHOST)) ? acptr->user->virthost : "*"),
						    acptr->info);
					}
					else
					{
						sendto_one(cptr,
						    (cptr->proto & PROTO_SJB64 ?
						    "%s %s %d %B %s %s %s %lu %s %s :%s"
						    :
						    "%s %s %d %lu %s %s %s %lu %s %s :%s"),
						    (IsToken(cptr) ? TOK_NICK : MSG_NICK),
						    acptr->name,
						    acptr->hopcount + 1,
						    acptr->lastnick,
						    acptr->user->username,
						    acptr->user->realhost,
						    acptr->user->server,
						    (unsigned long)acptr->user->servicestamp,
						    (!buf || *buf == '\0' ? "+" : buf),
						    ((IsHidden(acptr) && (acptr->umodes & UMODE_SETHOST)) ? acptr->user->virthost : "*"),
						    acptr->info);
					}
				}
				else
					sendto_one(cptr,
					    "%s %s %d %ld %s %s %s %lu %s %s :%s",
					    (IsToken(cptr) ? TOK_NICK :
					    MSG_NICK), acptr->name,
					    acptr->hopcount + 1,
					    acptr->lastnick,
					    acptr->user->username,
					    acptr->user->realhost,
					    (SupportNS(cptr) ?
					    (acptr->srvptr->serv->numeric ?
					    base64enc(acptr->srvptr->
					    serv->numeric) : acptr->
					    user->server) : acptr->user->
					    server), (unsigned long)acptr->user->servicestamp,
					    (!buf
					    || *buf == '\0' ? "+" : buf),
					    GetHost(acptr),
					    acptr->info);
			}

			if (acptr->user->away)
				sendto_one(cptr, ":%s %s :%s", acptr->name,
				    (IsToken(cptr) ? TOK_AWAY : MSG_AWAY),
				    acptr->user->away);
			if (acptr->user->swhois)
				if (*acptr->user->swhois != '\0')
					sendto_one(cptr, "%s %s :%s",
					    (IsToken(cptr) ? TOK_SWHOIS :
					    MSG_SWHOIS), acptr->name,
					    acptr->user->swhois);

			if (!SupportSJOIN(cptr))
				send_user_joins(cptr, acptr);
		}
	}
	/*
	   ** Last, pass all channels plus statuses
	 */
	{
		aChannel *chptr;
		for (chptr = channel; chptr; chptr = chptr->nextch)
		{
			if (!SupportSJOIN(cptr))
				send_channel_modes(cptr, chptr);
			else if (SupportSJOIN(cptr) && !SupportSJ3(cptr))
			{
				send_channel_modes_sjoin(cptr, chptr);
			}
			else
				send_channel_modes_sjoin3(cptr, chptr);
			if (chptr->topic_time)
				sendto_one(cptr,
				    (cptr->proto & PROTO_SJB64 ?
				    "%s %s %s %B :%s"
				    :
				    "%s %s %s %lu :%s"),
				    (IsToken(cptr) ? TOK_TOPIC : MSG_TOPIC),
				    chptr->chname, chptr->topic_nick,
				    chptr->topic_time, chptr->topic);
		}
	}
	/* pass on TKLs */
	tkl_synch(cptr);

	/* send out SVSFLINEs */
	dcc_sync(cptr);

	sendto_one(cptr, "%s %i %li %i %lX 0 0 0 :%s",
	    (IsToken(cptr) ? TOK_NETINFO : MSG_NETINFO),
	    IRCstats.global_max, TStime(), UnrealProtocol,
	    CLOAK_KEYCRC,
	    ircnetwork);

	/* Send EOS (End Of Sync) to the just linked server... */
	sendto_one(cptr, ":%s %s", me.name,
		(IsToken(cptr) ? TOK_EOS : MSG_EOS));
#ifdef DEBUGMODE
	ircd_log(LOG_ERROR, "[EOSDBG] m_server_synch: sending to justlinked '%s' with src ME...",
			cptr->name);
#endif
	return 0;

}
