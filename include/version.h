/*
**
** version.h
** UnrealIRCd
** $Id: version.h,v 1.1.1.10 2005-03-21 10:36:21 Trocotronic Exp $
*/
#ifndef __versioninclude
#define __versioninclude 1

/* 
 * Mark of settings
 */
#ifdef DEBUGMODE
#define DEBUGMODESET "+(debug)"
#else
#define DEBUGMODESET ""
#endif
 /**/
#ifdef DEBUG
#define DEBUGSET "(Debug)"
#else
#define DEBUGSET ""
#endif
     /**/
#define COMPILEINFO DEBUGMODESET DEBUGSET
/*
 * Version Unreal3.2.2
 */
#define UnrealProtocol 		2306
#define PATCH1  		"3"
#define PATCH2  		".2"
#define PATCH3  		".3"
#ifdef UDB
#define PATCH4 			"+UDB"
#define PATCH5 			"-3.1"
#define PATCH6			"es"
#else
#define PATCH4  		""
#define PATCH5  		""
#define PATCH6			""
#endif
#define PATCH7  		""
#define PATCH8  		COMPILEINFO
#define PATCH9  		""
/* release header */
#define Rh BASE_VERSION
#define VERSIONONLY		PATCH1 PATCH2 PATCH3 PATCH4 PATCH5 PATCH6 PATCH7
#endif /* __versioninclude */
