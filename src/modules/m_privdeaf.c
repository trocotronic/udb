/*
 * usermode +D: makes it so you cannot receive non-channel privmsgs
 * except from opers, U-lines and servers.
 * Just an example of msghooks :P. -- Syzop
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

ModuleHeader MOD_HEADER(m_privdeaf)
  = {
	"m_privdeaf",	/* Name of module */
	"v0.0.2", /* Version */
	"private messages deaf (+D)", /* Short description of module */
	"3.2-b8-1",
	NULL 
    };

long UMODE_PRIVDEAF = 0L;

ModuleInfo PrivdeafModInfo;

static Hook *CheckMsg;

DLLFUNC char *privdeaf_checkmsg(aClient *, aClient *, aClient *, char *, int);

/* This is called on module init, before Server Ready */
DLLFUNC int MOD_INIT(m_privdeaf)(ModuleInfo *modinfo)
{
	/* Add the umode */	
	UmodeAdd(NULL, 'D', UMODE_GLOBAL, NULL, &UMODE_PRIVDEAF);
	/* TODO: test if umode_gget failed? */
	
	/* Hooking */
	bcopy(modinfo,&PrivdeafModInfo,modinfo->size);
	CheckMsg = HookAddPCharEx(PrivdeafModInfo.handle, HOOKTYPE_USERMSG, privdeaf_checkmsg);
	return MOD_SUCCESS;
}

/* Is first run when server is 100% ready */
DLLFUNC int MOD_LOAD(m_privdeaf)(int module_load)
{
	return MOD_SUCCESS;
}


/* Called when module is unloaded */
DLLFUNC int MOD_UNLOAD(m_privdeaf)(int module_unload)
{
	/* Remove umode :( */
	umode_delete('D', UMODE_PRIVDEAF);
	UMODE_PRIVDEAF = 0;
	/* And tha hook :/ */
	HookDel(CheckMsg);
	return MOD_SUCCESS;
}

DLLFUNC char *privdeaf_checkmsg(aClient *cptr, aClient *sptr, aClient *acptr, char *text, int notice)
{
	if ((acptr->umodes & UMODE_PRIVDEAF) && !IsAnOper(sptr) && !IsULine(sptr) && !IsServer(sptr)
#ifdef UDB
	&& acptr != sptr
#endif
	)
#ifdef UDB
	{
		sendto_one(sptr, rpl_str(ERR_USERSILENCED), me.name, sptr->name, acptr->name, " (+D)");
#endif
		return NULL; /* Silently ignored >:) */
#ifdef UDB
	}
#endif	
	else
		return text;
}
