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
#ifndef _WIN32
#include <dir.h>
#endif

unsigned long registros[DB_SIZE][DB_SIZE];
extern char *clave_cifrado = NULL;
udb *primeradb[DB_SIZE], *ultimadb[DB_SIZE];

/* Rutinas de hash extraídas de hash.c */
/* En fase ALFA */
#ifdef HAS_UDB

static aHashEntry udbTable[DB_SIZE][U_MAX];

void clear_udb_hash_table(void)
{
	memset((char *)udbTable, '\0', sizeof(aHashEntry) * DB_SIZE * U_MAX);
}
int  add_to_udb_hash_table(char *name, char bdd, udb *registro)
{
	unsigned int  hashv;
	hashv = hash_nick_name(name);
	registro->hnext = (udb *)udbTable[bdd][hashv].list;
	udbTable[bdd][hashv].list = (void *)registro;
	udbTable[bdd][hashv].links++;
	udbTable[bdd][hashv].hits++;
	return 0;
}
int  del_from_udb_hash_table(char *name, char bdd, udb *registro)
{
	udb *tmp, *prev = NULL;
	unsigned int  hashv;
	hashv = hash_nick_name(name);
	for (tmp = (udb *)udbTable[bdd][hashv].list; tmp; tmp = tmp->hnext)
	{
		if (tmp == registro)
		{
			if (prev)
				prev->hnext = tmp->hnext;
			else
				udbTable[bdd][hashv].list = (void *)tmp->hnext;
			tmp->hnext = NULL;
			if (udbTable[bdd][hashv].links > 0)
			{
				udbTable[bdd][hashv].links--;
				return 1;
			}
			else
				return -1;
		}
		prev = tmp;
	}
	return 0;
}
udb *hash_find_udb(char *name, char bdd, udb *registro)
{
	udb *tmp;
	aHashEntry *tmp3;
	unsigned int  hashv;
	hashv = hash_nick_name(name);
	tmp3 = &udbTable[bdd][hashv];
	for (tmp = (udb *)tmp3->list; tmp; tmp = tmp->hnext)
		if (smycmp(name, tmp->index) == 0)
		{
			return (tmp);
		}
	return (registro);
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
	return (hash_find_udb(index, bdd, NULL));
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
	valaux = (char *)malloc(sizeof(char) * strlen(valor) + 1);
	strcpy(valaux,valor);
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
	aClient *acptr;
	valaux = (char *)malloc(sizeof(char) * strlen(valor) + 1);
	strcpy(valaux,valor);
	founder = strtok(valaux,"\t");
	modos = strtok(NULL,"\t");
	topic = strtok(NULL,"\t");
	chptr = get_channel(NULL, index, CREATE);
	chptr->mode.mode |= MODE_RGSTR;
	acptr = (aClient *)malloc(sizeof(aClient) + 1);
	SetMe(acptr);
	strncpyzt(acptr->name, me.name, strlen(me.name) + 1);
	if (modos)
	{
		//set_chmodes(modos, &chptr->mode, 0);
		int pcount, p = 0;
		char pvar[MAXMODEPARAMS][MODEBUFLEN + 3], *parms[7], *modaux;
		modaux = malloc(sizeof(char) * strlen(modos) + 1);
		strcpy(modaux, modos);
		parms[p++] = strtok(modaux, " ");
		while ((parms[p] = strtok(NULL, " ")))
			p++;
		set_mode(chptr, acptr, p, parms, &pcount, pvar, 0);
	}
	if (topic)
		set_topic(acptr, acptr, chptr, topic, 0);
	return 0;
}
int delchan(char *index)
{
	aChannel *chptr;
	aClient *acptr;
	acptr = find_server(me.name, NULL);
	SetMe(acptr);
	chptr = get_channel(NULL, index, !CREATE);
	chptr->mode.mode &= ~MODE_RGSTR;
	sendto_serv_butone_token(acptr, me.name, MSG_MODE, TOK_MODE, "%s -r", chptr->chname);
	sendto_channel_butserv(chptr, acptr, ":%s MODE %s -r", me.name, chptr->chname);
	chptr->users++;
	sub1_from_channel(chptr);
	return 0;
}	
int addpriv(char *index, char *valor)
{
	char *id;
	aChannel *chptr;
	aClient *acptr;
	acptr = (aClient *)malloc(sizeof(aClient) + 1);
	SetMe(acptr);
	strncpyzt(acptr->name, me.name, strlen(me.name) + 1);
	chptr = get_channel(NULL, index, CREATE);
	delpriv(index);
	add_banid(acptr, chptr, "*!*@*");
	for (id = strtok(valor, " "); id; id = strtok(NULL, " "))
		add_exbanid(acptr, chptr, id);
	return 0;
}
int delpriv(char *index)
{
	aChannel *chptr;
	Ban *ban;
	chptr = get_channel(NULL, index, !CREATE);
	del_banid(chptr, "*!*@*");
	while (chptr->exlist)
	{
		ban = chptr->exlist;
		chptr->exlist = ban->next;
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
	udb *db;
	FILE *fp;
	char archivo[128];
	sprintf(archivo, DB_DIR "\\%c.bdd", bdd);
	if (!(fp = fopen(archivo, "w")))
		return 0;
	registros[SERS][bdd] = 0L;
	for (db = primeradb[bdd]; db; db = db->next)
	{
		if (db->serie < serie)
		{
			registros[SERS][bdd] = db->serie;
			fprintf(fp, "%09lu %s :%s\n", db->serie, db->index, db->value);
		}
		else
			delreg(db, 0);
	}
	fclose(fp);
	actualiza_hash(bdd);
	return 0;
}
int addreg(char bdd, unsigned long serie, char *index, char *valor, int add)
{
	udb *db;
	if (registros[SERS][bdd] >= serie)
		return 0;
	if (registros[CORR][bdd])
		return 0;
	registros[SERS][bdd] = serie;
	if ((db = busca_registro(bdd, index)))
	{
		if (valor[0] == '\0')
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
		db->value = (char *)realloc(db->value, sizeof(char) * strlen(valor) + 1);
		db->serie = serie;
		strcpy(db->value, valor);
		if (bdd == BDD_BADWORDS)
		{
			if (valor)
				addword(index, valor);
		}	
		if (add)
			addreg_file(bdd, serie, index, valor);
		return 0;
	}
	if (valor[0] == '\0')
		return 0;
	db = (udb *)malloc(sizeof(udb) + 1);
	db->index = (char *)malloc(sizeof(char) * strlen(index) + 1);
	strcpy(db->index, index);
	db->value = (char *)malloc(sizeof(char) * strlen(valor) + 1);
	strcpy(db->value, valor);
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
	registros[REGS][bdd]++;
#ifdef HASH_UDB
	add_to_udb_hash_table(index, bdd, db);
#endif	
	if (bdd == BDD_BADWORDS)
		addword(index, valor);
	if (bdd == BDD_CANALES)
		addchan(index, valor);
	if (bdd == BDD_PRIV)
		addpriv(index, valor);
	if (bdd == BDD_VHOSTS && !strcmp(index, "."))
	{
		if (clave_cifrado)
			clave_cifrado = (char *)realloc(clave_cifrado, sizeof(char) * strlen(valor) + 1);
		else
			clave_cifrado = (char *)malloc(sizeof(char) * strlen(valor) + 1);
		strcpy(clave_cifrado, valor);
	}
	if (add)
		addreg_file(bdd, serie, index, valor);
	return 0;
}
int addreg_file(char bdd, unsigned long serie, char *index, char *valor)
{
	FILE *fp;
	char archivo[128];
	sprintf(archivo, DB_DIR "\\%c.bdd", bdd);
	if (!(fp = fopen(archivo, "a")))
		return 0;
	fprintf(fp, "%09lu %s :%s\n", serie, index, valor ? valor : "");
	fclose(fp);
	actualiza_hash(bdd);
	return 0;
}
unsigned long obtiene_hash(char bdd)
{
	FILE *fp;
	char bddf[128], hashstr[512];
	unsigned long hash = 0L;
	sprintf(bddf, DB_DIR "\\%c.bdd", bdd);
	if (!(fp = fopen(bddf, "r")))
		return 0L;
	while (!feof(fp))
	{
		if (!(fgets(hashstr, 512, fp)))
			break;
		hash ^= our_crc32(hashstr, strlen(hashstr));
	}
	fclose(fp);
	return hash;
}
unsigned long lee_hash(char bdd)
{
	FILE *fp;
	char archivo[128], hashstr[512], data[512], linea = PRIMERA_LETRA;
	int i, j;
	sprintf(archivo, DB_DIR "\\hash");
	if (!(fp = fopen(archivo, "r")))
		return 0L;
	while (!feof(fp))
	{
		bzero(data, 512);
		bzero(hashstr, 512);
		fgets(data, 512, fp);
		for (i = j = 0; i < strlen(data); i++)
		{
			if (data[i] == '\n' || data[i] == '\r')
				continue;
			hashstr[j++] = data[i];
		}
		if (linea == bdd)
			return atol(hashstr);
		linea++;
	}
	fclose(fp);
	return 0L;
}
int actualiza_hash(char bdd)
{
	char hashf[128], c;
	FILE *fh;
	sprintf(hashf, DB_DIR "\\hash");
	if (!(fh = fopen(hashf, "w")))
		return 0;
	registros[HASH][bdd] = obtiene_hash(bdd);
	for (c = PRIMERA_LETRA; c <= ULTIMA_LETRA; c++)
		fprintf(fh, "%lu\n", registros[HASH][c]);
	fclose(fh);
	return 0;
}
int comprueba_hash(char bdd)
{
	if (lee_hash(bdd) != obtiene_hash(bdd))
	{
		sendto_ops("La tabla '%c' está corrupta.",bdd);
		delbdd(bdd, 0);
		sendto_serv_butone(NULL,":%s DB * C J 0 %c", me.name, bdd);
		registros[CORR][bdd] = 1;
	}
	return 0;
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
		addreg_file(bdd, ++registros[SERS][bdd], db->index, "");
	registros[REGS][bdd]--;
	free(busca_registro(bdd, db->index));
#ifdef HASH_UDB
	del_from_udb_hash_table(db->index, bdd, db);
#endif
	return 0;
}
int savebdd(char bdd)
{
	udb *db;
	FILE *fp;
	char archivo[128];
	sprintf(archivo, DB_DIR "\\%c.bdd", bdd);
	if (!(fp = fopen(archivo, "w")))
		return 0;
	for (db = primeradb[bdd]; db; db = db->next)
		fprintf(fp, "%09lu %s :%s\n", db->serie, db->index, db->value);
	fclose(fp);
	return 0;
}
int loadbdds()
{
	char bdd;
	mkdir("database");
	registros[RESI][BDD_NICKS] = 1;
	registros[RESI][BDD_OPERS] = 1;
	registros[RESI][BDD_VHOSTS] = 1;
	registros[RESI][BDD_ILINES] = 1;
	registros[RESI][BDD_BOTS] = 1;
	registros[RESI][BDD_CANALES] = 1;
	registros[RESI][BDD_VHOSTS2] = 1;
	registros[RESI][BDD_BADWORDS] = 1;
	registros[RESI][BDD_PRIV] = 1;
	sendto_ops("Releyendo Bases de Datos...",NULL);
	for (bdd = PRIMERA_LETRA; bdd <= ULTIMA_LETRA; bdd++)
		loadbdd(bdd);
	return 0;
}
int loadbdd(char bdd)
{
	FILE *fp;
	char archivo[128], data[512], *regs[3], buf[BUFSIZE];
	int i, g, h;
	udb *dbaux, *dbtmp;
	registros[REGS][bdd] = registros[SERS][bdd] = registros[HASH][bdd] = 0L;
#ifdef HASH_UDB
	clear_udb_hash_table();
#endif	
	//memset((char *)primeradb, '\0', sizeof(udb) * DB_SIZE);
	for (dbaux = primeradb[bdd]; dbaux; dbaux = dbtmp)
	{
		dbtmp = dbaux->next;
		free(dbaux);
	}
	primeradb[bdd] = ultimadb[bdd] = NULL;
	sprintf(archivo, DB_DIR "\\%c.bdd", bdd);
	if (!(fp = fopen(archivo, "r")))
	{
		if (!(fp = fopen(archivo, "a")))
			return 0;
	}
	while (!feof(fp))
	{
		memset(buf, 0, BUFSIZE);
		if (!fgets(data, 512, fp))
			break;
		for (i = h = g = 0; i < strlen(data); i++)
		{
			if (data[i] == '\n' || data[i] == '\r')
				continue;
			if (data[i] == 0x20 && h < 2)
			{
				regs[h] = (char *)malloc(sizeof(char) * strlen(buf) + 1);
				strcpy(regs[h++], buf);
				memset(buf, 0, BUFSIZE);
				g = 0;
				continue;
			}	
			buf[g++] = data[i];
		}
		regs[h] = (char *)malloc(sizeof(char) * strlen(buf) + 1);
		strcpy(regs[h], buf);
		addreg(bdd, atol(regs[0]), regs[1], !regs[2][0] ? "" : regs[2] + 1, 0);
	}
	registros[HASH][bdd] = lee_hash(bdd);
	comprueba_hash(bdd);
	if (registros[REGS][bdd])
		sendto_ops("Tabla '%c' R=%09lu", bdd, registros[REGS][bdd]);
	fclose(fp);
	return 0;
}

CMD_FUNC(m_db)
{
	ConfigItem_link *aconf;
	short hub = 0;
	
	if (!IsServer(sptr))
		return 0;
	if (!IsUDB(sptr))
		return 0;
	if (parc < 5)
		return 0;
	if (match(parv[1], me.name))
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
			unsigned long ultimo;
			if (parc < 6)
				return 0;
			bdd = *parv[5];
			if (bdd < PRIMERA_LETRA || bdd > ULTIMA_LETRA)
				return 0;
			ultimo = atol(parv[4]);
			if (ultimo > registros[SERS][bdd] && !hub)
				sendto_one(cptr,":%s DB %s BDD_DESYNCH D %09lu %c", me.name, cptr->name, registros[SERS][bdd], bdd);
			else if (ultimo < registros[SERS][bdd])
			{
				for (db = busca_serie(bdd, ultimo + 1); db; db = db->next)
					sendto_one(cptr,":%s DB %s %s I %09lu %c %s :%s", me.name, cptr->name, parv[2], db->serie, bdd, db->index, db->value ? db->value : "");
				if (ultimo == 0)
					sendto_one(cptr,":%s DB %s 0 A %09lu %c", me.name, cptr->name, registros[SERS][bdd], bdd);
			}
			sendto_serv_butone(cptr,":%s DB %s %s J %09lu %c",parv[0],parv[1],parv[2],parv[4],*parv[5]);
			break;
		}
		
		/*
		 * DB * 0 D serie bdd
		 */
		case 'D':
		{
			char bdd;
			unsigned long serie;
			if (parc < 6)
				return 0;
			if (hub)
			{
				bdd = *parv[5];
				if (bdd < PRIMERA_LETRA || bdd > ULTIMA_LETRA)
					return 0;
				serie = atol(parv[4]);
				delbdd(bdd, serie);
				sendto_ops("%s ha borrado la tabla '%c' (R=%09lu)%s",cptr->name, bdd, serie,
					(!strcmp(parv[2],"BDD_DESYNCH") ? " (BDD_DESYNCH)" : ""));
				sendto_one(cptr, ":%s DB %s 0 J %09lu %c", me.name, cptr->name, serie, bdd);
			}
			sendto_serv_butone(cptr,":%s DB %s %s D %09lu %c",parv[0],parv[1],parv[2],parv[4],*parv[5]);
			break;
		}
		
		/*
		 * DB * 0 O 0 bdd
		 */
		 case 'O':
		 {
		 	char bdd;
		 	unsigned long serie, bytes = 0L;
			udb *db;
			if (parc < 6)
				return 0;
			if (hub)
			{
				bdd = *parv[5];
				if (bdd < PRIMERA_LETRA || bdd > ULTIMA_LETRA)
					return 0;
				savebdd(bdd);
				sendto_ops("%s ha optimizado la tabla '%c'. R=%09lu Bytes ahorrados: %lu", cptr->name, bdd, registros[SERS][bdd], bytes);
			}
			sendto_serv_butone(cptr,":%s DB %s %s O %09lu %c",parv[0],parv[1],parv[2],parv[4],*parv[5]);
			break;
		}
		
		/*
		 * DB * 0 A serie bdd
		 */
		 case 'A':
		 {
		 	char bdd;
			if (parc < 6)
				return 0;
			if (hub)
			{
				bdd = *parv[5];
				if (bdd < PRIMERA_LETRA || bdd > ULTIMA_LETRA)
					return 0;
				registros[SERS][bdd] = atol(parv[4]);
			}
			sendto_serv_butone(cptr,":%s DB %s %s A %09lu %c",parv[0],parv[1],parv[2],parv[4],bdd);
			break;
		}
		
		/*
		 * DB * 0 I serie bdd index :valor
		 */
		case 'I':
		{
			char bdd;
		 	unsigned long serie;
		 	if (parc < 7)
		 		return 0;
			if (hub)
			{
				bdd = *parv[5];
				if (bdd < PRIMERA_LETRA || bdd > ULTIMA_LETRA)
					return 0;
				serie = atol(parv[4]);
				if (!strcmp(parv[2],"C"))
					registros[CORR][bdd] = 0;
				addreg(bdd, serie, parv[6], parv[7] ? parv[7] : "", 1);
			}
			sendto_serv_butone(cptr,":%s DB %s %s I %09lu %c %s :%s",parv[0],parv[1],parv[2],parv[4],*parv[5],parv[6],parv[7] ? parv[7] : "");
			break;
		}
	}
	return 0;
}

CMD_FUNC(m_ghost)
{
	aClient *acptr;
	udb *reg, *breg;
	char *botname, who[NICKLEN + 2], nick[NICKLEN + 2], quitbuf[TOPICLEN + 1], *cifrado;
	int comp = 1;
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
	if (parc > 2) 
		cifrado = cifranick(nick, parv[2]);
	else
		cifrado = NULL;
	acptr = find_client(nick, NULL);
	reg = busca_registro(BDD_NICKS, nick);
	if (!IsRegistered(sptr))
	ircsprintf(who, "%s!", nick);
	else
		strcpy(who, sptr->name);
	if (!reg || !reg->value[0]) 
	{
		sendto_one(cptr, ":%s NOTICE %s :*** El nick %s no está registrado en la base de datos.", botname, sptr->name, nick);
		return 0;
	}
	if (cifrado)
		comp = strcmp(reg->value, cifrado);
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
	if (!IsAnOper(sptr) && !IsHelpOp(sptr) && comp) 
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
	if (!registros[RESI][bdd]) 
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
#endif
int puede_cambiar_nick_en_bdd(aClient *cptr, aClient *sptr, char *parv[], char *nick, char *pass, short mismonick, short nick_used, short *suspend, short *clave_ok, long *old_umodes)
{
	*old_umodes = sptr->umodes;
	do
	{
		udb *reg, *breg;
		char *botname, *cifrado, *realpass;
		if (mismonick)
			break;
		if (!(reg = busca_registro(BDD_NICKS, nick)) || !reg->value[0]) 
			break;
		if (!(breg = busca_registro(BDD_BOTS, BDD_NICKSERV)))
			botname = me.name;
		else
			botname = breg->value;
		if (reg->value[strlen(reg->value)-1] == '*') 
		{
			sendto_one(cptr,
				":%s NOTICE %s :*** El nick \002%s\002 está prohibido, no puede ser utilizado.",
				botname, sptr->name, nick);
			sendto_one(sptr, err_str(ERR_NICKNAMEINUSE), me.name,
				BadPtr(parv[0]) ? "*" : parv[0], nick);
			return 0;
		}
		if (reg->value[strlen(reg->value)-1] == '+') 
		{
			realpass = (char *)malloc(sizeof(char)*strlen(reg->value)+1);
			memset(realpass, 0, sizeof(char)*strlen(reg->value));
			strncpy(realpass, reg->value, strlen(reg->value)-1);
			*suspend = 1;
		}
		else
			realpass = reg->value;
		if (sptr->passwd && sptr->passwd[0])
			pass = sptr->passwd;
		cifrado = cifranick(nick, pass);
		if (strcmp(cifrado, realpass))
		{
			if (!nick_used) 
			{
				if (!pass)
					sendto_one(cptr,
						":%s NOTICE %s :*** El nick %s está Registrado, necesitas contraseña.",
						botname, sptr->name, nick);
				else
					sendto_one(cptr,
						":%s NOTICE %s :*** Contraseña Incorrecta para el nick %s.",
						botname, sptr->name, nick);
				sendto_one(cptr,
					":%s NOTICE %s :*** Utiliza \002/NICK %s%cclave\002 para identificarte.",
					botname, sptr->name, nick, strchr(parv[1], '!') ? '!' : ':');
			}
			sendto_one(sptr, err_str(ERR_NICKNAMEINUSE), me.name,
				BadPtr(parv[0]) ? "*" : parv[0], nick);
			return 0;
		}
		if (nick_used) 
		{
			sendto_one(sptr, err_str(ERR_NICKNAMEINUSE), me.name,
				BadPtr(parv[0]) ? "*" : parv[0], nick);
			return 0;
     		}	
		if (!*suspend)
			sendto_one(cptr, ":%s NOTICE %s :*** Contraseña aceptada. Bienvenid@ a casa ;)", botname, sptr->name);
		else
			sendto_one(cptr, ":%s NOTICE %s :*** Este nick está SUSPENDido", botname, sptr->name);
		*clave_ok = 1;
	} while(0);
	if (nick_used) 
	{
		sendto_one(sptr, err_str(ERR_NICKNAMEINUSE), me.name,
			BadPtr(parv[0]) ? "*" : parv[0], nick);
		return 0;
	}
	return 1;
}