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

#define ircstrdup(x,y) if (x) MyFree(x); if (!y) x = NULL; else x = strdup(y)
#define ircfree(x) if (x) MyFree(x); x = NULL
#define atoul(x) strtoul(x, NULL, 10)
static char    buf[512];

unsigned MODVAR long hashes[DB_SIZE];
unsigned MODVAR long series[DB_SIZE];
unsigned MODVAR int registros[DB_SIZE];
unsigned MODVAR char corruptas[DB_SIZE];
unsigned MODVAR char residentes[DB_SIZE];
unsigned MODVAR int lens[DB_SIZE];

char *clave_cifrado = NULL;
udb *primeradb[DB_SIZE], *ultimadb[DB_SIZE];

/* Rutinas de hash extraídas de hash.c */
/* En fase ALFA */

#ifdef HASH_UDB
udb **udbTable[DB_SIZE];

void clear_hash_udb(char bdd)
{
	int i;
	for (i = 0; i < dblen(bdd); i++)
		udbTable[bdd][i] = NULL;
}
int  add_to_udb_hash_table(char *name, char bdd, udb *registro)
{
	unsigned int  hashv;
	hashv = hash_nick_name(name) % dblen(bdd);
	if (!udbTable[bdd])
	{
		udbTable[bdd] = (udb **)malloc(sizeof(udb *) * dblen(bdd));
		clear_hash_udb(bdd);
	}
	registro->hnext = udbTable[bdd][hashv];
	udbTable[bdd][hashv] = registro;
	return 0;
}
int  del_from_udb_hash_table(char *name, char bdd, udb *registro)
{
	udb *tmp, *prev = NULL;
	unsigned int  hashv;
	hashv = hash_nick_name(name) % dblen(bdd);
	for (tmp = (udb *)udbTable[bdd][hashv]; tmp; tmp = tmp->hnext)
	{
		if (tmp == registro)
		{
			if (prev)
				prev->hnext = tmp->hnext;
			else
				udbTable[bdd][hashv] = tmp->hnext;
			return 1;
		}
		prev = tmp;
	}
	return 0;
}
udb *hash_find_udb(char *name, char bdd, udb *registro)
{
	udb *tmp;
	unsigned int hashv;
	if (!udbTable[bdd])
		return registro;
	hashv = hash_nick_name(name) % dblen(bdd);
	for (tmp = udbTable[bdd][hashv]; tmp; tmp = tmp->hnext)
	{
		if (!strcasecmp(name, tmp->index))
			return tmp;
	}
	return registro;
}
#endif
ConfigItem_badword *busca_word(char *word, ConfigItem_badword **conf)
{
	ConfigItem_badword *badword_ptr;
	for (badword_ptr = *conf; badword_ptr; badword_ptr = (ConfigItem_badword *) badword_ptr->next) 
	{
		if (!strcasecmp(badword_ptr->word, word))
			return badword_ptr;
	}
	return NULL;
}
udb *busca_serie(char bdd, unsigned long serie)
{
	udb *db;
	for (db = primeradb[bdd]; db; db = db->next)
	{
		if (db->serie >= serie)
			return db;
	}
	return NULL;
}
udb *busca_registro(char bdd, char *index)
{
#ifdef HASH_UDB
	if (!index)
		return NULL;
	return hash_find_udb(index, bdd, NULL);
#else
	udb *db;
	if (!index)
		return NULL;
	for (db = primeradb[bdd]; db; db = db->next)
	{
		if (!strcasecmp(db->index, index))
			return db;
	}
	return NULL;
#endif
}
int addword_conf(char *index, int bits, char *reemp, ConfigItem_badword **conf)
{
	ConfigItem_badword *bwd;
	int regflags = 0;
	char *tmp;
	short regex = 0;
#ifdef FAST_BADWORD_REPLACE
	int ast_l = 0, ast_r = 0;
#endif	
	if (!(bwd = busca_word(index, conf)))
		bwd = MyMallocEx(sizeof(ConfigItem_badword));
	regflags = REG_ICASE|REG_EXTENDED;
	bwd->action = BADWORD_REPLACE;
	if (bits & BWD_BLOCK)
	{
		bwd->action = BADWORD_BLOCK;
		regflags |= REG_NOSUB;
	}			
#ifdef FAST_BADWORD_REPLACE
	for (tmp = index; *tmp; tmp++) {
		if ((int)*tmp < 65 || (int)*tmp > 123) {
			if ((index == tmp) && (*tmp == '*')) {
				ast_l = 1; /* Asterisk at the left */
				continue;
			}
			if ((*(tmp + 1) == '\0') && (*tmp == '*')) {
				ast_r = 1; /* Asterisk at the right */
				continue;
			}
			regex = 1;
			break;
		}
	}
	if (regex) {
		bwd->type = BADW_TYPE_REGEX;
		ircstrdup(bwd->word, index);
		regcomp(&bwd->expr, bwd->word, regflags);
	} else {
		char *tmpw;
		bwd->type = BADW_TYPE_FAST;
		bwd->word = tmpw = MyMalloc(strlen(index) - ast_l - ast_r + 1);
		for (tmp = index; *tmp; tmp++)
			if (*tmp != '*')
				*tmpw++ = *tmp;
		*tmpw = '\0';
		if (ast_l)
			bwd->type |= BADW_TYPE_FAST_L;
		if (ast_r)
			bwd->type |= BADW_TYPE_FAST_R;
	}
#else	
	for (tmp = index; *tmp; tmp++) {
		if ((int)*tmp < 65 || (int)*tmp > 123) {
			regex = 1;
			break;
		}
	}
	if (regex) {
		ircstrdup(bwd->word, index);
	}
	else {
		bwd->word = MyMalloc(strlen(index) + strlen(PATTERN) -1);
		ircsprintf(bwd->word, PATTERN, index);
	}
	regcomp(&bwd->expr, bwd->word, regflags);
#endif	
	if (reemp) {
		ircstrdup(bwd->replace, reemp);
	}
	else {
		bwd->replace = NULL;
	}
	AddListItem(bwd, *conf);
	return 0;
}
int delword_conf(char *index, ConfigItem_badword **conf)
{
	ConfigItem_badword *bwd;
	if (!(bwd = busca_word(index, conf)))
		return 0;
	ircfree(bwd->word);
	if (bwd->replace)
		ircfree(bwd->replace);
	regfree(&bwd->expr);
	DelListItem(bwd, *conf);
	MyFree(bwd);
	return 0;
}
int addword(char *index, char *valor)
{
	int bits = 0;
	char *valaux, *reemp;
	valaux = strdup(valor);
	bits = atoi(strtok(valaux,"\t"));
	reemp = strtok(NULL,"\t");
	delword(index);
	if (bits & BWD_MESSAGE)
		addword_conf(index, bits, reemp, &conf_badword_message);
	if (bits & BWD_CHANNEL)
		addword_conf(index, bits, reemp, &conf_badword_channel);
	if (bits & BWD_QUIT)
		addword_conf(index, bits, reemp, &conf_badword_quit);
	return 0;
}
int delword(char *index)
{
	delword_conf(index, &conf_badword_message);
	delword_conf(index, &conf_badword_channel);
	delword_conf(index, &conf_badword_quit);
	return 0;
}
int addchan(char *index, char *valor)
{
	char *valaux, *founder, *modos, *topic;
	aChannel *chptr;
	valaux = strdup(valor);
	founder = strtok(valaux,"\t");
	modos = strtok(NULL,"\t");
	topic = strtok(NULL,"\t");
	chptr = get_channel(NULL, index, CREATE);
	chptr->mode.mode |= MODE_RGSTR;
	if (!BadPtr(modos))
	{
		int pcount, p = 0;
		char pvar[MAXMODEPARAMS][MODEBUFLEN + 3], *parms[7], *modaux;
		modaux = strdup(modos);
		parms[p++] = strtok(modaux, " ");
		if (BadPtr(parms[p-1]))
			goto topic;
		while ((parms[p++] = strtok(NULL, " ")));
		if (!chptr)
			goto topic;
		set_mode(chptr, &me, p, parms, &pcount, pvar, 0);
	}
	topic:
	if (topic)
		set_topic(&me, &me, chptr, topic, 0);
	return 0;
}
int delchan(char *index)
{
	aChannel *chptr;
	chptr = get_channel(NULL, index, !CREATE);
	chptr->mode.mode &= ~MODE_RGSTR;
	if (!loop.ircd_rehashing)
		sendto_channel_butserv(chptr, &me, ":%s MODE %s -r", me.name, chptr->chname);
	if (chptr->users == 0)
		sub1_from_channel(chptr);
	return 0;
}	
int addpriv(char *index, char *valor)
{
	char *id;
	aChannel *chptr;
	chptr = get_channel(NULL, index, CREATE);
	delpriv(index);
	add_banid(&me, chptr, "*!*@*");
	if (!loop.ircd_rehashing)
		sendto_channel_butserv(chptr, &me, ":%s MODE %s +b *!*@*", me.name, chptr->chname);
	for (id = strtok(valor, " "); id; id = strtok(NULL, " "))
	{
		if (!loop.ircd_rehashing)
			sendto_channel_butserv(chptr, &me, ":%s MODE %s +e %s", me.name, chptr->chname, id);
		add_exbanid(&me, chptr, id);
	}
	return 0;
}
int delpriv(char *index)
{
	aChannel *chptr;
	Ban *ban;
	chptr = get_channel(NULL, index, !CREATE);
	del_banid(chptr, "*!*@*");
	if (!loop.ircd_rehashing)
		sendto_channel_butserv(chptr, &me, ":%s MODE %s -b *!*@*", me.name, chptr->chname);
	while (chptr->exlist)
	{
		ban = chptr->exlist;
		chptr->exlist = ban->next;
		if (!loop.ircd_rehashing)
			sendto_channel_butserv(chptr, &me, ":%s MODE %s -e %s", me.name, chptr->chname, ban->banstr);
		MyFree(ban->banstr);
		MyFree(ban->who);
		free_ban(ban);
	}
	return 0;
}
int level_oper_bdd(char *oper)
{
	udb *reg;
	if (!(reg = busca_registro(BDD_OPERS, oper)))
		return 0;
	else
		return atoi(reg->value);
}
int delbdd(char bdd, unsigned long serie)
{
	udb *db, *aux;
	FILE *fp;
	char archivo[128];
#ifdef _WIN32
	ircsprintf(archivo, DB_DIR "\\%c.bdd", bdd);
#else
	ircsprintf(archivo, DB_DIR "/%c.bdd", bdd);
#endif
	if (!(fp = fopen(archivo, "w")))
		return 0;
	series[bdd] = 0L;
	for (db = primeradb[bdd]; db; db = aux)
	{
		aux = db->next;
		if (db->serie < serie)
		{
			series[bdd] = db->serie;
			fprintf(fp, "%09lu %s :%s\n", db->serie, db->index, db->value);
		}
		else
			delreg(db, 0);
	}
	fclose(fp);
	actualiza_hash(bdd);
	return 0;
}
void regenera_claves()
{
	aClient *acptr;
	for (acptr = client; acptr; acptr = acptr->next)
	{
		if (IsClient(acptr))
		{
			if (IsHidden(acptr))
			{
				Debug((DEBUG_ERROR, "Regeneramos ip de %s (%i)", acptr->name, IsHidden(acptr)));
				acptr->user->virthost = make_virtualhost(acptr, acptr->user->realhost, acptr->user->virthost, 0);
			}
			else
				BorraIpVirtual(acptr);
		}
	}
}
int addreg_especial(char bdd, char *index, char *valor)
{
	aClient *acptr;
	if (valor)
	{
		if (bdd == BDD_BADWORDS)
			addword(index, valor);
		else if (bdd == BDD_CANALES)
			addchan(index, valor);
		else if (bdd == BDD_PRIV)
			addpriv(index, valor);
		else if (bdd == BDD_VHOSTS || bdd == BDD_VHOSTS2)
		{
			if (bdd == BDD_VHOSTS && !strcmp(index, "."))
			{
				if (clave_cifrado)
					MyFree(clave_cifrado);
				clave_cifrado = strdup(valor);
				if (!loop.ircd_rehashing)
					regenera_claves();
			}
			else if ((acptr = find_client(index, NULL)))
				if (!loop.ircd_rehashing)
					acptr->user->virthost = make_virtualhost(acptr, acptr->user->realhost, acptr->user->virthost, 1);
		}
		else if (bdd == BDD_OPERS)
		{
			if ((acptr = find_client(index, NULL)) && !IsAnOper(acptr))
				sube_oper(acptr);
		}
	}
	return 0;
}
int addreg(char bdd, unsigned long serie, char *index, char *valor, int add)
{
	udb *db;
	if (series[bdd] >= serie)
		return 0;
	if (corruptas[bdd])
		return 0;
	series[bdd] = serie;
	if ((db = busca_registro(bdd, index)))
	{
		if (BadPtr(valor))
		{
			delreg(db, add);
			if (bdd == BDD_BADWORDS)
				delword(index);
			if (bdd == BDD_CANALES)
				delchan(index);
			if (bdd == BDD_PRIV)
				delpriv(index);
			return 0;
		}
		if (!db->next)
			ultimadb[bdd] = db->prev;
		else
			db->next->prev = db->prev;
		if (!db->prev)
			primeradb[bdd] = db->next;
		else
			db->prev->next = db->next;
		ircstrdup(db->value, valor);
		db->serie = serie;
		db->next = NULL;
		if (!primeradb[bdd])
		{
			db->prev = NULL;
			primeradb[bdd] = db;
		}
		else
		{
			db->prev = ultimadb[bdd];
			ultimadb[bdd]->next = db;
		}
		ultimadb[bdd] = db;
		addreg_especial(bdd, index, valor);
		if (add)
			addreg_file(bdd, serie, index, valor);
		return 0;
	}
	if (BadPtr(valor))
		return 0;
	db = (udb *)malloc(sizeof(udb));
	db->index = strdup(index);
	db->value = strdup(valor);
	db->bdd = bdd;
	db->serie = serie;
	db->next = NULL;
	if (!primeradb[bdd])
	{
		db->prev = NULL;
		primeradb[bdd] = db;
	}
	else
	{
		db->prev = ultimadb[bdd];
		ultimadb[bdd]->next = db;
	}
	ultimadb[bdd] = db;
	registros[bdd]++;
#ifdef HASH_UDB
	add_to_udb_hash_table(index, bdd, db);
#endif	
	if (add)
		addreg_file(bdd, serie, index, valor);
	addreg_especial(bdd, index, valor);
	return 0;
}
int addreg_file(char bdd, unsigned long serie, char *index, char *valor)
{
	FILE *fp;
	char archivo[128];
#ifdef _WIN32
	ircsprintf(archivo, DB_DIR "\\%c.bdd", bdd);
#else
	ircsprintf(archivo, DB_DIR "/%c.bdd", bdd);
#endif	
	if (!(fp = fopen(archivo, "a")))
		return 0;
	fprintf(fp, "%09lu %s :%s\n", serie, index, valor ? valor : "");
	fclose(fp);
	actualiza_hash(bdd);
	return 0;
}
unsigned long obtiene_hash(char bdd)
{
	int fp;
	char *par, bddf[128];
	unsigned long hash = 0L;
	struct stat inode;
#ifdef _WIN32
	ircsprintf(bddf, DB_DIR "\\%c.bdd", bdd);
	if ((fp = open(bddf, O_RDONLY|O_BINARY)) == -1)
#else
	ircsprintf(bddf, DB_DIR "/%c.bdd", bdd);
	if ((fp = open(bddf, O_RDONLY)) == -1)
#endif
		return 0;
	if (fstat(fp, &inode) == -1)
		return 0;
	if (!inode.st_size)
	{
		close(fp);
		return 0;
	}
	par = (char *)malloc(inode.st_size + 1);
	par[inode.st_size] = '\0';
	if (read(fp, par, inode.st_size) == inode.st_size)
		hash = our_crc32(par, strlen(par));
	close(fp);
	MyFree(par);
	return hash;
}
unsigned long lee_hash(char bdd)
{
	FILE *fp;
	char archivo[128], lee[17];
#ifdef _WIN32
	ircsprintf(archivo, DB_DIR "\\hash");
#else
	ircsprintf(archivo, DB_DIR "/hash");
#endif
	if (!(fp = fopen(archivo, "r")))
		return 0L;
	fseek(fp, 16 * (bdd - PRIMERA_LETRA), SEEK_SET);
	bzero(lee, 17);
	fread(lee, 1, 16, fp);
	fclose(fp);
	return atoul(lee);
}
int actualiza_hash(char bdd)
{
	char hashf[128], c;
	FILE *fh;
#ifdef _WIN32
	ircsprintf(hashf, DB_DIR "\\hash");
#else
	ircsprintf(hashf, DB_DIR "/hash");
#endif
	if (!(fh = fopen(hashf, "w")))
		return 0;
	hashes[bdd] = obtiene_hash(bdd);;
	for (c = PRIMERA_LETRA; c <= ULTIMA_LETRA; c++)
		fprintf(fh, "%016lu", hashes[c]);
	fclose(fh);
	return 0;
}
int comprueba_hash(char bdd)
{
	u_long lee, obtiene;
	lee = lee_hash(bdd);
	obtiene = obtiene_hash(bdd);
	if (lee != obtiene)
	{
		Debug((DEBUG_ERROR, "La tabla '%c' está corrupta. (%lu != %lu)",bdd,lee,obtiene));
		sendto_ops("La tabla '%c' está corrupta. (%lu != %lu)",bdd,lee,obtiene);
		delbdd(bdd, 0);
		sendto_serv_butone(NULL,":%s DB * C J 0 %c", me.name, bdd);
		corruptas[bdd] = 1;
		return 1;
	}
	return 0;
}
void libera_memoria_udb(udb *db)
{
	if (db->value)
		MyFree(db->value);
	MyFree(db->index);
	MyFree(db);
}
int delreg(udb *db, int add)
{
	char bdd = db->bdd;
	if (!db->next)
		ultimadb[bdd] = db->prev;
	else
		db->next->prev = db->prev;
	if (!db->prev)
		primeradb[bdd] = db->next;
	else
		db->prev->next = db->next;
	if (add)
		addreg_file(bdd, series[bdd], db->index, "");
	registros[bdd]--;
#ifdef HASH_UDB
	del_from_udb_hash_table(db->index, bdd, db);
#endif
	libera_memoria_udb(db);
	return 0;
}
unsigned long savebdd(char bdd)
{
	udb *db;
	FILE *fp;
	char archivo[128], buf[BUFSIZE];
	unsigned long ini, orig;
#ifdef _WIN32
	ircsprintf(archivo, DB_DIR "\\%c.bdd", bdd);
#else
	ircsprintf(archivo, DB_DIR "/%c.bdd", bdd);
#endif
	if (!(fp = fopen(archivo, "r")))
		return 0;
	ini = ftell(fp);
	fseek(fp, 0L, SEEK_END);
	orig = ftell(fp) - ini;
	fclose(fp);
	if (!(fp = fopen(archivo, "w")))
		return 0;
	for (db = primeradb[bdd]; db; db = db->next)
	{
		buf[0] = '\0';
		ircsprintf(buf, "%09lu %s :%s\n", db->serie, db->index, db->value);
		orig -= strlen(buf);
		fputs(buf, fp);
	}
	fclose(fp);
	actualiza_hash(bdd);
	return orig ? orig - 1 : 0;
}
int loadbdd(char bdd)
{
	int fp;
	struct stat inode;
	char *cont, *item, *no, *valor, *archivo = malloc(sizeof(char) * (strlen(DB_DIR) + 7));
	udb *dbaux, *dbtmp;
	if (comprueba_hash(bdd))
		return 0;
	series[bdd] = 0L;
	registros[bdd] = 0;
#ifdef HASH_UDB
	if (udbTable[bdd])
		MyFree(udbTable[bdd]);
	udbTable[bdd] = NULL;
#endif
	for (dbaux = primeradb[bdd]; dbaux; dbaux = dbtmp)
	{
		dbtmp = dbaux->next;
		libera_memoria_udb(dbaux);
	}
	primeradb[bdd] = ultimadb[bdd] = NULL;
#ifdef _WIN32
	ircsprintf(archivo, DB_DIR "\\%c.bdd", bdd);
	if ((fp = open(archivo, O_RDONLY|O_BINARY|O_CREAT, 0644)) == -1)
#else
	ircsprintf(archivo, DB_DIR "/%c.bdd", bdd);
	if ((fp = open(archivo, O_RDONLY|O_CREAT, 0644)) == -1)
#endif
		return 0;
	if (fstat(fp, &inode) == -1)
		return 0;
	if (!inode.st_size)
	{
		close(fp);
		return 0;
	}
	cont = (char *)malloc(inode.st_size + 1);
	cont[inode.st_size] = '\0';
	if (read(fp, cont, inode.st_size) != inode.st_size)
		return 0;
	close(fp);
	MyFree(archivo);
	while (!BadPtr(cont))
	{
		char *pos;
		pos = strchr(cont, ' ');
		no = (char *)malloc(sizeof(char) * (pos - cont + 1));
		bzero(no, pos - cont + 1);
		strncpy(no, cont, pos - cont);
		cont = pos + 1;
		pos = strchr(cont, ' ');
		item = (char *)malloc(sizeof(char) * (pos - cont + 1));
		bzero(item, pos - cont + 1);
		strncpy(item, cont, pos - cont);
		cont = pos + 1;
		if (!(pos = strchr(cont, '\r')))
			pos = strchr(cont, '\n');
		valor = (char *)malloc(sizeof(char) * (pos - cont + 1));
		bzero(valor, pos - cont + 1);
		strncpy(valor, cont, pos - cont);
		cont = *(pos + 1) == '\n' ? pos + 2 : pos + 1;
		addreg(bdd, atoul(no), item, BadPtr(valor) ? "" : valor + 1, 0);
		MyFree(no);
		MyFree(item);
		MyFree(valor);
	}
	hashes[bdd] = lee_hash(bdd);
	if (registros[bdd])
		sendto_ops("Tabla '%c' R=%09lu", bdd, registros[bdd]);
	return 0;
}
int loadbdds()
{
	char bdd;
#ifdef _WIN32
	mkdir(DB_DIR);
#else
	mkdir(DB_DIR, 0744);
#endif
	sendto_ops("Releyendo Bases de Datos...",NULL);
	for (bdd = PRIMERA_LETRA; bdd <= ULTIMA_LETRA; bdd++)
		loadbdd(bdd);
	return 0;
}
void bdd_init()
{
	char i;
	memset(lens, 0, sizeof(unsigned int) * DB_SIZE);
	memset(residentes, 0, sizeof(unsigned int) * DB_SIZE);
	residentes[BDD_NICKS] = 1;
	residentes[BDD_OPERS] = 1;
	residentes[BDD_VHOSTS] = 1;
	residentes[BDD_ILINES] = 1;
	residentes[BDD_BOTS] = 1;
	residentes[BDD_CANALES] = 1;
	residentes[BDD_VHOSTS2] = 1;
	residentes[BDD_BADWORDS] = 1;
	residentes[BDD_PRIV] = 1;
	/* valores tomados de irc-hispano */
	lens[BDD_NICKS] = 32768;
	lens[BDD_OPERS] = 256;
	lens[BDD_VHOSTS] = 256;
	lens[BDD_ILINES] = 512;
	lens[BDD_BOTS] = 256;
	lens[BDD_CANALES] = 16384;
	lens[BDD_VHOSTS2] = 256;
	lens[BDD_BADWORDS] = 256;
	lens[BDD_PRIV] = 256;
	for (i = PRIMERA_LETRA; i <= ULTIMA_LETRA; i++)
	{
		primeradb[i] = ultimadb[i] = NULL;
		series[i] = hashes[i] = 0L;
		registros[i] = corruptas[i] = 0;
#ifdef HASH_UDB
		udbTable[i] = NULL;
#endif
	}
	loadbdds();
}
CMD_FUNC(m_db)
{
	ConfigItem_link *aconf;
	char hub = 0;
	if (!IsServer(cptr))
		return 0;
	if (!IsUDB(cptr))
		return 0;
	if (parc < 5)
		return 0;
	aconf = cptr->serv->conf;
	if (aconf->hubmask)
		hub = 1;
	switch(*parv[3])
	{
		/*
		 * DB * 0 J serie bdd
		 */
		case 'J':
		{
			char bdd;
			udb *db;
			unsigned long ultimo, cur;
			if (!match(parv[1], me.name))
			{
				if (parc < 6)
					return 0;
				bdd = *parv[5];
				if (bdd < PRIMERA_LETRA || bdd > ULTIMA_LETRA)
					return 0;
				ultimo = atoul(parv[4]);
				if (ultimo > series[bdd] && !hub)
					sendto_one(cptr,":%s DB %s BDD_DESYNCH D %09lu %c", me.name, cptr->name, series[bdd], bdd);
				else if (ultimo < series[bdd])
				{
					/* hay desynch, vamos a mandar el archivo .bdd, resumiéndolo claro */
					FILE *fp;
					char archivo[128], cont1[BUFSIZE], item[BUFSIZE], cont2[BUFSIZE], cont3[BUFSIZE];
					u_long registro;
#ifdef _WIN32
					ircsprintf(archivo, DB_DIR "\\%c.bdd", bdd);
#else
					ircsprintf(archivo, DB_DIR "/%c.bdd", bdd);
#endif
					if ((fp = fopen(archivo, "r")))
					{
						int le;
						while (!feof(fp))
						{
							char *buf, *cur;
							u_long serie;
							buf = malloc(BUFSIZE);
							bzero(buf, BUFSIZE);
							if (!fgets(buf, BUFSIZE, fp))
								break;
							cur = strchr(buf, ' ');
							*cur = '\0';
							serie = atoul(buf);
							cur++;
							if (serie > ultimo)
								sendto_one(cptr,":%s DB %s %s I %09lu %c %s", me.name, parv[0], parv[2], serie, bdd, cur);
							free(buf);
						}
						fclose(fp);
					}
				}
			}
			sendto_serv_butone(cptr,":%s DB %s %s J %s %c",parv[0],parv[1],parv[2],parv[4],*parv[5]);
			/* el comando J es el único que lo propaga el nodo que lo emite
			   todos los demás, los propagan el nodo que lo recibe */
			break;
		}
		
		/*
		 * DB * 0 D serie bdd
		 */
		case 'D':
		{
			char bdd;
			unsigned long serie;
			if (!match(parv[1], me.name))
			{
				if (parc < 6)
					return 0;
				if (hub)
				{
					bdd = *parv[5];
					if (bdd < PRIMERA_LETRA || bdd > ULTIMA_LETRA)
						return 0;
					serie = atoul(parv[4]);
					delbdd(bdd, serie);
					sendto_ops("%s ha borrado la tabla '%c' (R=%09lu)%s",cptr->name, bdd, serie,
						(!strcmp(parv[2],"BDD_DESYNCH") ? " (BDD_DESYNCH)" : ""));
					sendto_one(cptr, ":%s DB %s %s J %09lu %c", me.name, cptr->name, parv[2], serie, bdd);
				}
			}
			sendto_serv_butone(cptr,":%s DB %s %s D %s %c",me.name,parv[1],parv[2],parv[4],*parv[5]);
			break;
		}
		
		/*
		 * DB * 0 O 0 bdd
		 */
		 /*
		  * 14/05/04 Quito este comando por un motivo muy en concreto:
		  * Cuando se aplica O el archivo se borra y se regenera de nuevo, *SÓLO* con los registros.
		  * Entonces, un archivo .bdd también contiene órdenes de borrar un registro (si no hay campo).
		  * Así pues, cuando se linka, se mandan los registros en si y además las órdenes de borrarlos.
		  * 
		  * Si un nodo estuviera en split y se mandara un O en toda la red, los archivos de la red sólo guardarían
		  * sus registros y NO sus órdenes de borrar. Así, cuando conectara el nodo spliteado continuaría con estos registros
		  * "fantasma" puesto que no recibiría las órdenes de borrado.
		  *
		  * Por ahora no se me ocurre ninguna otra alternativa, puesto que tal y como está planteado el protocolo,
		  * este comando resulta inconsistente. Si alguien se le ocurre alguna otra sugerencia, dejadla en el foro de http://www.rallados.net
		  */
		/* case 'O':
		 {
		 	char bdd;
		 	unsigned long serie, bytes = 0L;
			udb *db;
			if (!match(parv[1], me.name))
			{
				if (parc < 6)
					return 0;
				if (hub)
				{
					bdd = *parv[5];
					if (bdd < PRIMERA_LETRA || bdd > ULTIMA_LETRA)
						return 0;
					bytes = savebdd(bdd);
					sendto_ops("%s ha optimizado la tabla '%c'. R=%09lu Bytes ahorrados: %lu", cptr->name, bdd, series[bdd], bytes);
				}
			}
			sendto_serv_butone(cptr,":%s DB %s %s O %s %c",me.name,parv[1],parv[2],parv[4],*parv[5]);
			break;
		}
		*/
		/*
		 * DB * 0 A serie bdd
		 */
		 case 'A':
		 {
		 	char bdd;
		 	if (!match(parv[1], me.name))
			{
				if (parc < 6)
					return 0;
				if (hub)
				{
					bdd = *parv[5];
					if (bdd < PRIMERA_LETRA || bdd > ULTIMA_LETRA)
						return 0;
					if (!strcmp(parv[2],"C"))
						corruptas[bdd] = 0;
					series[bdd] = atoul(parv[4]);
				}
			}
			sendto_serv_butone(cptr,":%s DB %s %s A %s %c",me.name,parv[1],parv[2],parv[4],bdd);
			break;
		}
		
		/*
		 * DB * 0 I serie bdd index :valor
		 */
		case 'I':
		{
			char bdd;
		 	unsigned long serie;
		 	if (!match(parv[1], me.name))
			{
		 		if (parc < 7)
		 			return 0;
				if (hub)
				{
					bdd = *parv[5];
					if (bdd < PRIMERA_LETRA || bdd > ULTIMA_LETRA)
						return 0;
					serie = atoul(parv[4]);
					if (!strcmp(parv[2],"C"))
						corruptas[bdd] = 0;
					else if (!strcmp(parv[2], "E"))
					{
						udb *reg;
						if ((reg = busca_serie(bdd, serie)))
							delreg(reg, 1);
						else
							Debug((DEBUG_ERROR, "no encuentra la serie %lu", serie));
					}
					else
						addreg(bdd, serie, parv[6], parv[7] ? parv[7] : "", 1);
				}
			}
			sendto_serv_butone(cptr,":%s DB %s %s I %s %c %s :%s",me.name,parv[1],parv[2],parv[4],*parv[5],parv[6],parv[7] ? parv[7] : "");
			break;
		}
	}
	return 0;
}

CMD_FUNC(m_ghost)
{
	aClient *acptr;
	udb *reg, *breg;
	char *botname, who[NICKLEN + 2], nick[NICKLEN + 2], quitbuf[TOPICLEN + 1];
   	if (!(breg = busca_registro(BDD_BOTS, BDD_NICKSERV)))
		botname = me.name;
	else
		botname = breg->value;
	if (parc < 2) 
	{
		sendto_one(cptr, ":%s NOTICE %s :*** Sintaxis incorrecta. Formato: GHOST <nick> [clave]", botname, sptr->name);
		return 0;
	}
	strncpyzt(nick, parv[1], NICKLEN + 1);
	acptr = find_client(nick, NULL);
	reg = busca_registro(BDD_NICKS, nick);
	if (!IsRegistered(sptr))
		ircsprintf(who, "%s!", nick);
	else
		strcpy(who, sptr->name);
	if (!reg) 
	{
		sendto_one(cptr, ":%s NOTICE %s :*** El nick %s no está registrado en la base de datos.", botname, sptr->name, nick);
		return 0;
	}
	if (!acptr) 
	{
		sendto_one(cptr, ":%s NOTICE %s :*** El nick %s no se encuentra conectado actualmente.", botname, sptr->name, nick);
		return 0;
     	}
	if (cptr == acptr) 
	{
		sendto_one(cptr, ":%s NOTICE %s :*** No puedes hacer ghost a ti mismo.", botname, sptr->name);
		return 0;
	}
	if (!IsAnOper(sptr) && !IsHelpOp(sptr) && (tipo_de_pass(nick, parv[2]) != 2))
	{
		sendto_one(cptr, ":%s NOTICE %s :*** Contraseña incorrecta.", botname, sptr->name);
		return 0;
	}
	sendto_serv_butone_token(NULL,me.name,MSG_KILL,TOK_KILL,"%s :Comando GHOST utilizado por %s.",acptr->name, who);
	if (MyClient(acptr))
		sendto_one(acptr, ":%s KILL %s :Comando GHOST utilizado por %s.", me.name, acptr->name, who);
	sendto_one(cptr, ":%s NOTICE %s :*** Sesión fantasma del nick %s liberada.", botname, sptr->name, nick);
	ircsprintf(quitbuf, "Killed (Comando GHOST utilizado por %s)", who);
	exit_client(cptr, acptr, &me, quitbuf);
	return 0;
}

CMD_FUNC(m_dbq)
{
	/*
	 * DBQ [server] bdd index
	 */
	udb *cmp;
	char bdd, *index;
	if (!IsClient(sptr)) 
		return 0;
	if (!IsOper(sptr)) 
	{
		sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name, parv[0]);
		return 0;
	}
	if (parc == 4)
	{
		/* server bdd index */
		if (parv[2][1] != '\0')
		{
			sendto_one(cptr, ":%s NOTICE %s :Parámetros incorrectos: Formato: DBQ server tabla  indice", me.name, parv[0]);
			return 0;
		}
		if (!(find_match_server(parv[1]))) 
		{
			sendto_one(sptr, err_str(ERR_NOSUCHSERVER), me.name, sptr->name, parv[1]);
			return 0;
		}
		sendto_serv_butone(cptr,":%s DBQ %s %c %s",parv[0],parv[1],*parv[2],parv[3]);
		if (match(parv[1], me.name))
			return 0;
		bdd = *parv[2];
		index = parv[3];
	}
	else if (parc == 3)
	{
		/* bdd index */
		if (parv[1][1] != '\0')
		{
			sendto_one(cptr, ":%s NOTICE %s :Parámetros incorrectos: Formato: DBQ tabla  indice", me.name, parv[0]);
			return 0;
		}
		bdd = *parv[1];
		index = parv[2];
	}
	else
	{
		sendto_one(cptr, ":%s NOTICE %s :Parámetros incorrectos: Formato: DBQ [server] tabla indice", me.name, parv[0]);
		return 0;
	}
	if (!registros[bdd]) 
	{
		sendto_one(cptr, ":%s NOTICE %s :DBQ ERROR Tabla='%c' Clave='%s' TABLA_NO_RESIDENTE", me.name, parv[0], bdd, index);
		return 0;
	}
	if (!(cmp = busca_registro(bdd, index))) 
	{
		sendto_one(cptr, ":%s NOTICE %s :DBQ ERROR Tabla='%c' Clave='%s' REGISTRO_NO_ENCONTRADO", me.name, parv[0], bdd, index);
		return 0;
	}
    	sendto_one(cptr, ":%s NOTICE %s :DBQ OK Tabla='%c' Clave='%s' Valor='%s'", me.name, parv[0], bdd, cmp->index, cmp->value);
	return 0;
}
/* 2 ok
 * 1 suspendido
 * 0 no reg
 * -1 forbid
 * -2 incorrecto
 * -3 no ha dado pass
 * -4 hay un problema
 */
int tipo_de_pass(char *nick, char *pass)
{
	udb *reg;
	static char realpass[BUFSIZE], *k;
	int sus = 0;
	if (!(reg = busca_registro(BDD_NICKS, nick)))
		return 0; /* no existe */
	if (strchr(reg->value, '*'))
		return -1; /* tiene el nick en forbid, no importa la pass */
	if (!pass)
		return -3;
	bzero(realpass, BUFSIZE);
	strcpy(realpass, reg->value);
	if ((k = strchr(realpass, '+')))
	{
		sus = 1;
		*k = '\0';
	}
	if (*realpass == '.')
	{
		if (atoul(realpass + 1) == our_crc32(pass, strlen(pass)))
		{
			if (sus)
				return 1;  /* suspendido */
			return 2; /* todo ok */
		}
		else
			return -2; /* pass incorrecto */
	}
	else
	{
		if (!strcmp(cifranick(nick, pass), realpass))
		{
			if (sus)
				return 1;  /* suspendido */
			return 2; /* todo ok */
		}
	}
	return -2; /* pass incorrecto */
}
int puede_cambiar_nick_en_bdd(aClient *cptr, aClient *sptr, aClient *acptr, char *parv[], char *nick, char *pass, char nick_used)
{
	int tipo = 1;
	if (!MyConnect(sptr))
		return 1;
	do
	{
		udb *breg;
		char *botname;
		if (sptr == acptr)
			break;
		if (!(breg = busca_registro(BDD_BOTS, BDD_NICKSERV)))
			botname = me.name;
		else
			botname = breg->value;
		if (!(tipo = tipo_de_pass(nick, pass)))
			break;
		if (tipo < 0)
		{
			if (tipo == -1)
				sendto_one(cptr,
					":%s NOTICE %s :*** El nick \002%s\002 está prohibido, no puede ser utilizado.",
					botname, sptr->name, nick);	
			else if (!nick_used)
			{
				if (tipo == -3)
					sendto_one(cptr,
						":%s NOTICE %s :*** El nick %s está Registrado, necesitas contraseña.",
						botname, sptr->name, nick);
				else if (tipo == -2)
					sendto_one(cptr,
						":%s NOTICE %s :*** Contraseña Incorrecta para el nick %s.",
						botname, sptr->name, nick);
				sendto_one(cptr,
					":%s NOTICE %s :*** Utiliza \002/NICK %s%cclave\002 para identificarte.",
					botname, sptr->name, nick, strchr(parv[1], '!') ? '!' : ':');
			}
			sendto_one(sptr, err_str(ERR_NICKNAMEINUSE), me.name,
				BadPtr(parv[0]) ? "*" : parv[0], nick);
			return -1;
		}
		if (nick_used) 
		{
			sendto_one(sptr, err_str(ERR_NICKNAMEINUSE), me.name,
				BadPtr(parv[0]) ? "*" : parv[0], nick);
			return -1;
	     	}
		escape:
		if (tipo == 2)
			sendto_one(cptr, ":%s NOTICE %s :*** Contraseña aceptada. Bienvenid@ a casa ;)", botname, sptr->name);
		else if (tipo == 1)
			sendto_one(cptr, ":%s NOTICE %s :*** Este nick está SUSPENDido", botname, sptr->name);
	} while(0);
	if (nick_used) 
	{
		sendto_one(sptr, err_str(ERR_NICKNAMEINUSE), me.name,
			BadPtr(parv[0]) ? "*" : parv[0], nick);
		return -1;
	}
	return tipo;
}
void set_topic(aClient *cptr, aClient *sptr, aChannel *chptr, char *topic, int send)
{
	char *name, *tnick;
	TS   ttime = 0;
	int  topiclen = strlen(topic);
	int  nicklen = 0;
#ifndef TOPIC_NICK_IS_NUHOST
	nicklen = strlen(sptr->name);
#else
	tnick = make_nick_user_host(sptr->name, sptr->user->username, GetHost(sptr));
	nicklen = strlen(tnick);
#endif
	if (chptr->topic)
		MyFree(chptr->topic);

	if (topiclen > (TOPICLEN))
		topiclen = TOPICLEN;
	if (nicklen > (NICKLEN+USERLEN+HOSTLEN+5))
		nicklen = NICKLEN+USERLEN+HOSTLEN+5;
	chptr->topic = MyMalloc(topiclen + 1);
	strncpyzt(chptr->topic, topic, topiclen + 1);

	if (chptr->topic_nick)
		MyFree(chptr->topic_nick);

	chptr->topic_nick = MyMalloc(nicklen + 1);
#ifndef TOPIC_NICK_IS_NUHOST
	strncpyzt(chptr->topic_nick, sptr->name, nicklen + 1);
#else
	strncpyzt(chptr->topic_nick, tnick, nicklen + 1);
#endif
	chptr->topic_time = TStime();
	if (send)
	{
		sendto_serv_butone_token(cptr, sptr->name, MSG_TOPIC, TOK_TOPIC, "%s %s %lu :%s", chptr->chname, chptr->topic_nick, chptr->topic_time, chptr->topic);
		sendto_channel_butserv(chptr, sptr, ":%s TOPIC %s :%s", sptr->name, chptr->chname, chptr->topic);
	}
}

/* 
 * get_visiblehost
 * Devuelve el host del usuario según los permisos del solicitante
 * (Código del fuente de iRC-Hispano)
 */
char *get_visiblehost(aClient *acptr, aClient *sptr)
{
  if (!IsHidden(acptr) || (sptr && IsShowIp(sptr)) || sptr == acptr)
    return acptr->user->realhost;
  else
  {
    if (BadPtr(acptr->user->virthost))
      acptr->user->virthost = make_virtualhost(acptr, acptr->user->realhost, acptr->user->virthost, 0);
    return acptr->user->virthost;
  }
}
/*
 * make_virtualhost
 * Setea el host virtual del usuario, conforme a la BDD.
 *                                                                
 */
char *cifra_ip(char *ipreal)
{
	static char cifrada[512], clave[13];
	char *p;
	udb *reg;
	int ts = 0;
	unsigned int ourcrc, v[2], k[2], x[2];
	if (!clave_cifrado)
		return "no.hay.clave.de.cifrado";
	ourcrc = our_crc32(ipreal, strlen(ipreal));
	strncpy(clave, clave_cifrado, 12);
	clave[12] = '\0';
	p = cifrada;
	while (1)
  	{
		x[0] = x[1] = 0;
		k[0] = base64toint(clave);
		k[1] = base64toint(clave + 6);
    		v[0] = (k[0] & 0xffff0000) + ts;
    		v[1] = ourcrc;
    		tea(v, k, x);
    		inttobase64(p, x[0], 6);
    		p[6] = '.';
    		inttobase64(p + 7, x[1], 6);
		if (strchr(p, '[') == NULL && strchr(p, ']') == NULL)
			break;
    		else
		{
			if (++ts == 65536)
			{
				strcpy(p, ipreal);
				break;
			}
		}
	}
	return cifrada;
}	
char *make_virtualhost(aClient *acptr, char *viejo, char *nuevo, int mostrar)
{
	char *cifrada, buf[512], *sufix, *x;
	udb *vip, *vh;
	if (!viejo)
		return NULL;
	cifrada = cifra_ip(viejo);
	if (!(vh = busca_registro(BDD_VHOSTS, "..")))
		sufix = "virtual";
	else
		sufix = vh->value;
	if (busca_registro(BDD_NICKS, acptr->name)) /* si acptr está migrado, lleva puesto el +r */
	{
		if ((vip = busca_registro(BDD_VHOSTS, acptr->name))) 
				cifrada = vip->value;
		else if ((vip = busca_registro(BDD_VHOSTS2, acptr->name))) 
		{
			buf[0] = '\0';
			if (!(vh = busca_registro(BDD_VHOSTS2, ".")) || *(vh->value) == '0')
				snprintf(buf, HOSTLEN, "%s.%s", vip->value, sufix);
			else 
				snprintf(buf, HOSTLEN, "%s.%s.%s", cifrada, vip->value, sufix);
			cifrada = buf;
		}
		else
		{
			buf[0] = '\0';
			snprintf(buf, HOSTLEN, "%s.%s", cifrada, sufix);
			cifrada = buf;
		}
	}
	else
	{
		buf[0] = '\0';
		snprintf(buf, HOSTLEN, "%s.%s", cifrada, sufix);
		cifrada = buf;
	}
	if (nuevo)
		MyFree(nuevo);
	x = strdup(cifrada);
	if (MyClient(acptr) && mostrar)
	{
		char *botname;
		udb *reg;
		if (!(reg = busca_registro(BDD_BOTS, BDD_VHOSTSERV)))
			botname = me.name;
		else
			botname = reg->value;
		sendto_one(acptr, ":%s NOTICE %s :*** Protección IP: tu dirección virtual es %s",
			botname, acptr->name, x);
	}
	return x;
}
void sube_oper(aClient *sptr)
{
	int level = level_oper_bdd(sptr->name);
	ConfigItem_oper *aconf;
	if (!level || !IsARegNick(sptr))
		return;
	if (level & BDD_OPER)
		sptr->umodes |= UMODE_HELPOP;
	if (level & BDD_ADMIN)
	{
		sptr->umodes |= (UMODE_NETADMIN | UMODE_OPER);
#ifndef NO_FDLIST
		addto_fdlist(sptr->slot, &oper_fdlist);
#endif
		RunHook2(HOOKTYPE_LOCAL_OPER, sptr, 1);
		IRCstats.operators++;
		if (MyClient(sptr) && IsRegisteredUser(sptr) && (aconf = Find_oper(sptr->name)))
		{
			if (sptr->class)
				sptr->class->clients--;
			sptr->class = aconf->class;
			sptr->class->clients++;
			sptr->oflag = 0;
			if (aconf->swhois) {
				if (sptr->user->swhois)
					MyFree(sptr->user->swhois);
				sptr->user->swhois = MyMalloc(strlen(aconf->swhois) +1);
				strcpy(sptr->user->swhois, aconf->swhois);
				sendto_serv_butone_token(sptr, me.name,
					MSG_SWHOIS, TOK_SWHOIS, "%s :%s", sptr->name, aconf->swhois);
			}
			sptr->oflag = aconf->oflags;
			if (aconf->snomask)
				set_snomask(sptr, aconf->snomask);
			else
				set_snomask(sptr, OPER_SNOMASK);
			if (sptr->user->snomask)
			{
				sptr->user->snomask |= SNO_SNOTICE; /* set +s if needed */
				sptr->umodes |= UMODE_SERVNOTICE;
			}
			/* This is for users who have both 'admin' and 'coadmin' in their conf */
			if (IsCoAdmin(sptr) && IsAdmin(sptr))
			{
				sptr->umodes &= ~UMODE_COADMIN;
				sptr->oflag &= ~OFLAG_COADMIN;
			}
		}
	}
}
#endif
