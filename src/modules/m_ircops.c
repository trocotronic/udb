/*
 * =================================================================
 * Filename:      m_ircops.c
 * =================================================================
 * Description:   /ircops. Displays you a list of all IRC Operators
 *                available on IRC (except who are hiding (+H) if
 *                you aren't an IRC operator). Originally an m_ircops
 *                module already existed, however the author, whose
 *                name I don't know, deleted his module for some
 *                reasons, but people still needed, so I created it.
 * =================================================================
 * Author:        AngryWolf
 * Email:         angrywolf@flashmail.com
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
 * o Unreal >=3.2-beta17
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
 * http://angrywolf.linktipp.org/m_ircops.c [Germany]
 * http://angrywolf.uw.hu/m_ircops.c [Hungary]
 * http://angrywolf.fw.hu/m_ircops.c [Hungary]
 *
 * =================================================================
 * Changes:
 * =================================================================
 *
 * $Log: not supported by cvs2svn $
 * Revision 1.1.2.1  2004/03/21 18:45:12  Trocotronic
 * Añado el comando /ircops, para listar los ircops online (de AngryWolf).
 *
 * Revision 2.4  2004/03/08 21:25:24  angrywolf
 * - Fixed some bugs that could cause crash if you compile the module
 *   statically (for example, under Windows).
 *
 * Revision 2.3  2003/12/01 11:46:08  angrywolf
 * - Replaced add_Command and del_Command with CommandAdd and CommandDel.
 *
 * Revision 2.2  2003/10/07 18:38:48  angrywolf
 * - Now, instead of real name, the name of the server the
 *   client is using will be shown (requested by Jollino).
 *
 * Revision 2.1  2003/08/31 20:27:20  angrywolf
 * From now on I'm using RCS
 *
 * 2003-06-17: Recoded the whole module, based on TR-IRCD's m_ircops
 *             command. (Thanks to SerDar for his suggestion.)
 * 2003-06-11: Now local operators are displayed too (suggested by
 *             ChRiS)
 * 2003-06-01: Coded m_ircops (requested by Some3333 and LRL)
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

extern void			sendto_one(aClient *to, char *pattern, ...);

#define RPL_IRCOPS		337
#define RPL_ENDOFIRCOPS		338
#define MSG_IRCOPS 		"IRCOPS"
#define TOK_IRCOPS 		"IO"
#define IsAway(x)		(x)->user->away
#define IsSkoAdmin(sptr)	(IsAdmin(sptr) || IsNetAdmin(sptr) || IsSAdmin(sptr) || IsCoAdmin(sptr))
#define DelCommand(x)		if (x) CommandDel(x); x = NULL

static Command			*AddCommand(Module *module, char *msg, char *token, iFP func);
DLLFUNC int			m_ircops(aClient *cptr, aClient *sptr, int parc, char *parv[]);

Command				*CmdIrcops;

#ifndef DYNAMIC_LINKING
ModuleHeader m_ircops_Header
#else
#define m_ircops_Header Mod_Header
ModuleHeader Mod_Header
#endif
  = {
	"ircops",
	"$Id: m_ircops.c,v 1.1.4.1 2004-05-17 15:46:30 Trocotronic Exp $",
	"command /ircops",
	"3.2-b8-1",
	NULL 
    };


/* The purpose of these ifdefs, are that we can "static" link the ircd if we
 * want to
*/

/* This is called on module init, before Server Ready */
#ifdef DYNAMIC_LINKING
DLLFUNC int	Mod_Init(ModuleInfo *modinfo)
#else
int    m_ircops_Init(ModuleInfo *modinfo)
#endif
{
	CmdIrcops = AddCommand(modinfo->handle, MSG_IRCOPS, TOK_IRCOPS, m_ircops);

	if (!CmdIrcops)
		return MOD_FAILED;

	return MOD_SUCCESS;
}

/* Is first run when server is 100% ready */
#ifdef DYNAMIC_LINKING
DLLFUNC int	Mod_Load(int module_load)
#else
int    m_ircops_Load(int module_load)
#endif
{
	return MOD_SUCCESS;
}


/* Called when module is unloaded */
#ifdef DYNAMIC_LINKING
DLLFUNC int	Mod_Unload(int module_unload)
#else
int	m_ircops_Unload(int module_unload)
#endif
{
	DelCommand(CmdIrcops);

	return MOD_SUCCESS;
}

typedef struct
{
	unsigned long	*umode;
	char		*text;
} oflag;

static oflag otypes[] =
{
	{ &UMODE_NETADMIN,		"un Administrador de Red"	},
	{ &UMODE_SADMIN,		"un administrador de Servicios"	},
	{ &UMODE_ADMIN,			"un administrador de servidor"	},
	{ &UMODE_COADMIN,		"un Co administrador"		},
	{ &UMODE_OPER,			"un IRCop"		},
	{ &UMODE_LOCOP,			"un IRCop Local"		},
	{ NULL,				NULL				}
};

static char *find_otype(unsigned long umodes)
{
	unsigned int i;
	
	for (i = 0; otypes[i].umode; i++)
		if (*otypes[i].umode & umodes)
			return otypes[i].text;

	return "un operador desconocido";
}

static Command *AddCommand(Module *module, char *msg, char *token, iFP func)
{
	Command *cmd;

	if (CommandExists(msg))
    	{
		config_error("El comando %s ya existe", msg);
		return NULL;
    	}
    	if (CommandExists(token))
	{
		config_error("El token %s ya existe", token);
		return NULL;
    	}

	cmd = CommandAdd(module, msg, token, func, MAXPARA, 0);

#ifndef STATIC_LINKING
	if (ModuleGetError(module) != MODERR_NOERROR || !cmd)
#else
	if (!cmd)
#endif
	{
#ifndef STATIC_LINKING
		config_error("Error añadiendo el comando %s: %s", msg,
			ModuleGetErrorStr(module));
#else
		config_error("Error añadiendo el comando %s", msg);
#endif
		return NULL;
	}

	return cmd;
}

/*
 * m_ircops
 *
 *     parv[0]: sender prefix
 *
 *     Originally comes from TR-IRCD, but I changed it in several places.
 *     In addition, I didn't like to display network name. In addition,
 *     instead of realname, servername is shown. See the original
 *     header below.
 */

/************************************************************************
 * IRC - Internet Relay Chat, modules/m_ircops.c
 *
 *   Copyright (C) 2000-2002 TR-IRCD Development
 *
 *   Copyright (C) 1990 Jarkko Oikarinen and
 *                      University of Oulu, Co Center
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

int m_ircops(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
	aClient		*acptr;
	char		buf[BUFSIZE];
	int		opers = 0, admins = 0, globs = 0, aways = 0;

	for (acptr = client; acptr; acptr = acptr->next)
	{
		/* List only real IRC Operators */
		if (IsULine(acptr) || !IsPerson(acptr) || !IsAnOper(acptr))
			continue;
		/* Don't list +H users */
		if (!IsAnOper(sptr) && IsHideOper(acptr))
			continue;

		sendto_one(sptr, ":%s %d %s :\2%s\2 es %s en %s" "%s",
			me.name, RPL_IRCOPS, sptr->name,
			acptr->name,
			find_otype(acptr->umodes),
			acptr->user->server,
			(IsAway(acptr) ? " [Away]" : IsHelpOp(acptr) ? " [Helpop]" : ""));

		if (IsAway(acptr))
			aways++;
		else if (IsSkoAdmin(acptr))
			admins++;
		else
			opers++;

	}

	globs = opers + admins + aways;

	sprintf(buf,
		"Total: \2%d\2 IRCOP%s online - \2%d\2 Admin%s, \2%d\2 Oper%s y \2%d\2 Away%s",
		globs, (globs) > 1 ? "s" : "", admins, admins > 1 ? "s" : "",
		opers, opers > 1 ? "s" : "", aways, aways > 1 ? "s" : "");

	sendto_one(sptr, ":%s %d %s :%s", me.name, RPL_IRCOPS, sptr->name, buf);
	sendto_one(sptr, ":%s %d %s :Fin de /IRCOPS", me.name, RPL_ENDOFIRCOPS, sptr->name);

	return 0;
}
