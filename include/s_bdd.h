/*
 *   Unreal Internet Relay Chat Daemon, src/s_bdd.c
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
 
#define PRIMERA_LETRA 'a'
#define ULTIMA_LETRA 'z'

#define DB_SIZE 256
#define DB_DIR "database"

#define BDD_BOTS	'b'
#define BDD_CANALES	'c'
#define BDD_BADWORDS	'g'
#define BDD_ILINES	'i'
#define BDD_NICKS	'n'
#define BDD_OPERS	'o'
#define BDD_PRIV	'p'
#define BDD_VHOSTS	'v'
#define BDD_VHOSTS2	'w'

#define BDD_NICKSERV "NickServ"
#define BDD_CHANSERV "ChanServ"
#define BDD_VHOSTSERV "VhostServ"

#define BDD_PREO 0x1
#define BDD_OPER 0x2
#define BDD_DEVEL 0x4
#define BDD_ADMIN 0x8
#define BDD_ROOT 0x10

#define SERS 1
#define REGS 2
#define HASH 3
#define CORR 4
#define RESI 5
#define LEN  6

#define BWD_BLOCK 0x1
#define BWD_MESSAGE 0x2
#define BWD_CHANNEL 0x4
#define BWD_QUIT 0x8

#define HASH_UDB

struct _bdd *busca_registro(char, char *), *busca_serie(char, unsigned long);

typedef struct _bdd udb;

extern char *clave_cifrado;

extern int addreg_file(char, unsigned long, char *, char *);
extern int actualiza_hash(char);
extern int delreg(udb *, int);
extern char *cifranick(char *, char *);

struct _bdd
{
	struct _bdd *prev, *next;
#ifdef HASH_UDB
	struct _bdd *hnext;
#endif
	unsigned long serie;
	char bdd;
	char *index;
	char *value;
};

extern udb *primeradb[DB_SIZE], *ultimadb[DB_SIZE];
extern unsigned MODVAR long hashes[DB_SIZE];
extern unsigned MODVAR long series[DB_SIZE];
extern unsigned MODVAR int registros[DB_SIZE];
extern unsigned MODVAR char corruptas[DB_SIZE];
extern unsigned MODVAR char residentes[DB_SIZE];
extern unsigned int lens[DB_SIZE];
extern aChannel *get_channel(aClient *, char *, int);
extern void set_topic(aClient *, aClient *, aChannel *, char *, int);
#define BorraIpVirtual(x)							\
	do									\
	{									\
		if ((x)->user->virthost)					\
			MyFree((x)->user->virthost);				\
		(x)->user->virthost = NULL;					\
	}while(0)

#define dblen(x) (lens[x] ? lens[x] : 256)
extern void sube_oper(aClient *);
extern char *make_virtualhost(aClient *, char *, char *, int);
extern char *cifra_ip(char *);
