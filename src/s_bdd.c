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
#include "channel.h"
#include "numeric.h"
#include <time.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <io.h>
#else
#include <sys/mman.h>
#endif
#include <fcntl.h>
#include "h.h"
#include "res.h"
#include "inet.h"

#ifdef UDB
#include "s_bdd.h"
#ifndef _WIN32
#define O_BINARY 0x0
#endif
Udb *nicks = NULL;
Udb *canales = NULL;
Udb *ips = NULL;
Udb *set = NULL;
u_int BDD_NICKS = 0;
u_int BDD_CHANS = 0;
u_int BDD_IPS = 0;
u_int BDD_SET = 0;
Udb ***hash;
Udb *ultimo = NULL;
int dataver = 0; /* versi�n de la database */
extern char modebuf[BUFSIZE], parabuf[BUFSIZE];
#define ircstrdup(x,y) do{ if (x) MyFree(x); if (!y) x = NULL; else x = strdup(y); }while(0)
#define atoul(x) strtoul(x, NULL, 10)
#define ircfree(x) do { if (x) MyFree(x); x = NULL; } while(0)
#define MAX_HASH 2048
void carga_bloques(void);
static char buf[BUFSIZE];
char bloques[DBMAX];
time_t gmts[DBMAX];
int regs[DBMAX];
aClient *reses[DBMAX]; /* res�menes en curso */
static int BDD_TOTAL = 0;
char *grifo = NULL;
aClient *propaga = NULL;
extern void set_channelmodes(char *, struct ChMode *, int);
#ifdef DEBUGMODE
void printea(Udb *, int);
#endif
void set_dataver(int);
int saca_dataver();
Udb *coge_de_id(int);
extern aCache *find_cache_number(ResRQ *, char *);
extern aCache *add_to_cache(aCache *);
#ifndef IN6ADDRSZ
#define	IN6ADDRSZ	16
#endif
#ifndef INADDRSZ
#define	INADDRSZ	 4
#endif
Udb *alta_bloque(char letra, char *ruta, u_int *id)
{
	int ids = 0;
	Udb *reg;
	if (ultimo)
		ids = ID(ultimo) + 1;
	reg = (Udb *)MyMalloc(sizeof(Udb));
	reg->data_char = (char *)NULL;
	reg->data_long = 0L;
	reg->id = (u_int)letra;
	reg->id |= (ids << 8);
	reg->item = ruta;
	reg->mid = ultimo;
	reg->hsig = reg->up = reg->down = (Udb *)NULL;
	*id = ids;
	ultimo = reg;
	bloques[BDD_TOTAL++] = letra;
	return reg;
}
void vacia_hash(int id)
{
	int i;
	for (i = 0; i < MAX_HASH; i++)
		hash[id][i] = NULL;
}
void alta_hash()
{
	Udb *reg;
	int id;
	hash = (Udb ***)MyMalloc(sizeof(Udb **) * BDD_TOTAL);
	for (reg = ultimo; reg; reg = reg->mid)
	{
		id = ID(reg);
		hash[id] = (Udb **)MyMalloc(sizeof(Udb *) * MAX_HASH);
		vacia_hash(id);
	}
}
#ifndef _WIN32
#define PMAX PATH_MAX 
#else
#define PMAX MAX_PATH
#endif
int actualiza_dataver2()
{
	char *archivos[] = {
		"set.udb" ,
		"nicks.udb" ,
		"canales.udb" ,
		"ips.udb" ,
		NULL
	};
	char *tokens[][32] = {
		{
			"clave_cifrado" , "L" ,
			"sufijo" , "J" ,
			"NickServ" , "N" ,
			"ChanServ" , "C" ,
			"IpServ" , "I" ,
			"clones" , "S" ,
			"quit_ips" , "T" ,
			"quit_clones" , "Q" ,
			NULL
		} ,
		{
			"pass" , "P" ,
			"forbid" , "B" ,
			"vhost" , "V" ,
			"suspendido" , "S" ,
			"oper" , "O" ,
			"desafio" , "D" ,
			"modos" , "M" ,
			"snomasks" , "K" ,
			"swhois" , "W" ,
			NULL
		} ,
		{		
			"fundador" , "F" ,
			"modos" , "M" ,
			"topic" , "T" ,
			"accesos" , "A" ,
			"forbid" , "B" ,
			"suspendido" , "S" ,
			NULL
		} ,
		{
			"clones" , "S" ,
			"nolines" , "E" ,
			NULL
		}
	};
	int vec[][8] = {
		{ 1 } ,
		{ 0 , 1 } ,
		{ 0 , 1 , 0 } ,
		{ 0 , 1 }
	}; 
	FILE *fp, *tmp;
	int i, j, k;
	char *c, *d, buf[8192], f, p1[PMAX], p2[PMAX];
	strncpy(p2, DB_DIR "temporal", sizeof(p2));
	for (i = 0; archivos[i]; i++)
	{
		ircsprintf(p1, "%s%s", DB_DIR, archivos[i]);
		if (!(fp = fopen(p1, "rb")))
			return 1;
		if (!(tmp = fopen(p2, "wb")))
			return 1;
		while (fgets(buf, sizeof(buf), fp))
		{
			c = buf;
			f = 1;
			k = 0;
			while (*c != '\r' && *c != '\n')
			{
				if ((d = strchr(c, ':')) && *(d+1) == ':')
				{
					*d = '\0';
					f = 0;
					if (vec[i][k])
					{
						for (j = 0; tokens[i][j]; j += 2)
						{
							if (!strcmp(tokens[i][j], c))
							{
								fwrite(tokens[i][j+1], 1, strlen(tokens[i][j+1]), tmp);
								f = 1;
								break;
							}
						}
					}
					if (!f)
						fwrite(c, 1, strlen(c), tmp);
					fwrite("::", 1, 2, tmp);
					c = d+2;
					f = 1;
					k++;
				}
				else if (f && (d = strchr(c, ' ')))
				{
					*d = '\0';
					f = 0;
					if (vec[i][k])
					{
						for (j = 0; tokens[i][j]; j += 2)
						{
							if (!strcmp(tokens[i][j], c))
							{
								fwrite(tokens[i][j+1], 1, strlen(tokens[i][j+1]), tmp);
								f = 1;
								break;
							}
						}
					}
					if (!f)
						fwrite(c, 1, strlen(c), tmp);
					f = 0;
					fwrite(" ", 1, 1, tmp);
					c = d+1;
					k++;
				}
				else
				{
					fwrite(c, 1, strlen(c), tmp);
					break;
				}
			}
		}
		fclose(fp);
		fclose(tmp);
		unlink(p1);
		rename(p2, p1);
		unlink(p2);
		actualiza_hash(coge_de_id(i));
	}
	return 0;
}
void bdd_init()
{
	FILE *fh;
	int i;
#ifdef _WIN32
	mkdir(DB_DIR);
#else
	mkdir(DB_DIR, 0744);
#endif
	for (i = 0; i < DBMAX; i++)
		bloques[i] = '\0';
	for (i = 0; i < DBMAX; i++)
		reses[i] = (aClient *)NULL;
	for (i = 0; i < DBMAX; i++)
		regs[i] = 0;
	for (i = 0; i < DBMAX; i++)
		gmts[i] = 0L;
	if (!set)
		set = alta_bloque('S', DB_DIR "set.udb", &BDD_SET);
	if (!nicks)
		nicks = alta_bloque('N', DB_DIR "nicks.udb", &BDD_NICKS);
	if (!canales)
		canales = alta_bloque('C', DB_DIR "canales.udb", &BDD_CHANS);
	if (!ips)
		ips = alta_bloque('I', DB_DIR "ips.udb", &BDD_IPS);
	alta_hash();
	if ((fh = fopen(DB_DIR "crcs", "a")))
		fclose(fh);
	if (!saca_dataver())
	{
		actualiza_dataver2();
		set_dataver(2);
	}
	carga_bloques();
#ifdef DEBUGMODE
	printea(ips, 0);
#endif
}
void cifrado_str(char *origen, char *destino, int len)
{
	int i;
	destino[0] = 0;
	for (i = 0; i < len; i++)
	{
		char tmp[3];
		ircsprintf(tmp, "%02x", origen[i]);
		strcat(destino, tmp);
	}
}
u_long obtiene_hash(Udb *bloq)
{
	int fp;
	char *par;
	u_long hashl = 0L;
	struct stat inode;
	if ((fp = open(bloq->item, O_RDONLY|O_BINARY|O_CREAT, S_IREAD|S_IWRITE)) == -1)
		return 0;
	if (fstat(fp, &inode) == -1)
	{
		close(fp);
		return 0;
	}
	par = MyMalloc(inode.st_size + 1);
	*(par + inode.st_size) = '\0';
	if (read(fp, par, inode.st_size) == inode.st_size)
	{
		char res[16];
		DoMD5(res, par, inode.st_size);
		if (bloq->data_char)
			MyFree(bloq->data_char);
		bloq->data_long = inode.st_size;
		bloq->data_char = MyMalloc(33);
		cifrado_str(res, bloq->data_char, 16);
		hashl = our_crc32(par, inode.st_size);
	}
	close(fp);
	MyFree(par);
	return hashl;
}
u_long lee_hash(int id)
{
	FILE *fp;
	u_long hash = 0L;
	char lee[9];
	if (!(fp = fopen(DB_DIR "crcs", "r")) || fseek(fp, 8 * id, SEEK_SET))
		return 0L;
	bzero(lee, 9);
	fread(lee, 1, 8, fp);
	fclose(fp);
	if (!sscanf(lee, "%X", &hash))
		return 0L;
	return hash;
}
int saca_dataver()
{
	if (!dataver)
	{
		FILE *fp;
		char ver[3];
		if (!(fp = fopen(DB_DIR "crcs", "r")) || fseek(fp, 72, SEEK_SET))
			return 0;
		bzero(ver, 3);
		fread(ver, 1, 2, fp);
		fclose(fp);
		if (!sscanf(ver, "%X", &dataver))
			return 0;
		return dataver;
	}
	return dataver;
}
void set_dataver(int v)
{
	char ver[3];
	FILE *fh;
	bzero(ver, 3);
	if (!(fh = fopen(DB_DIR "crcs", "r+")) || fseek(fh, 72, SEEK_SET))
		return;
	ircsprintf(ver, "%X", v);
	fwrite(ver, 1, 2, fh);
	fclose(fh);
}
int actualiza_hash(Udb *bloque)
{
	char lee[9];
	FILE *fh;
	u_long lo;
	bzero(lee, 9);
	if (!(fh = fopen(DB_DIR "crcs", "r+")) || fseek(fh, 8 * ID(bloque), SEEK_SET))
		return -1;
	lo = obtiene_hash(bloque);
	ircsprintf(lee, "%X", lo);
	fwrite(lee, 1, 8, fh);
	fclose(fh);
	return 0;
}
time_t lee_gmt(int id)
{
	FILE *fp;
	u_long hash = 0L;
	char lee[11];
	if (!(fp = fopen(DB_DIR "crcs", "r")) || fseek(fp, BDD_TOTAL * 8 + 10 * id, SEEK_SET))
		return 0L;
	bzero(lee, 11);
	fread(lee, 1, 10, fp);
	fclose(fp);
	return atoul(lee);
}
int actualiza_gmt(Udb *bloque, time_t gm)
{
	char lee[11];
	FILE *fh;
	time_t hora = gm ? gm : time(0);
	bzero(lee, 11);
	if (!(fh = fopen(DB_DIR "crcs", "r+")) || fseek(fh, BDD_TOTAL * 8 + 10 * ID(bloque), SEEK_SET))
		return -1;
	ircsprintf(lee, "%ul", hora);
	fwrite(lee, 1, 10, fh);
	fclose(fh);
	gmts[ID(bloque)] = hora;
	return 0;
}
/* devuelve el puntero a todo el bloque a partir de su id o letra */
Udb *coge_de_id(int id)
{
	Udb *reg;
	for (reg = ultimo; reg; reg = reg->mid)
	{
		if ((LETRA(reg) == id) || (ID(reg) == id))
			return reg;
	}
	return NULL;
}
/* devuelve su id a partir de una letra */
int coge_de_char(char tipo)
{
	Udb *reg;
	for (reg = ultimo; reg; reg = reg->mid)
	{
		if (LETRA(reg) == tipo)
			return (int)ID(reg);
	}
	return (int)tipo;
}
char coge_de_tipo(int tipo)
{
	Udb *reg;
	for (reg = ultimo; reg; reg = reg->mid)
	{
		if (ID(reg) == tipo)
			return LETRA(reg);
	}
	return (char)tipo;
}
void inserta_registro_en_hash(Udb *registro, int donde, char *clave)
{
	u_int hashv;
	hashv = hash_nick_name(clave) % MAX_HASH;
	registro->hsig = hash[donde][hashv];
	hash[donde][hashv] = registro;
}
int borra_registro_de_hash(Udb *registro, int donde, char *clave)
{
	Udb *aux, *prev = NULL;
	u_int hashv;
	hashv = hash_nick_name(clave) % MAX_HASH;
	for (aux = hash[donde][hashv]; aux; aux = aux->hsig)
	{
		if (aux == registro)
		{
			if (prev)
				prev->hsig = aux->hsig;
			else
				hash[donde][hashv] = aux->hsig;
			return 1;
		}
		prev = aux;
	}
	return 0;
}
/* esta funci�n hace lo mismo que strcasecmp pero soporta la � */
int compara(const char *s1, const char *s2)
{
	const char *ra = s1;
	const char *rb = s2;
	while (((*ra == '�' || *ra == '�') && (*rb == '�' || *rb == '�')) || tolower(*ra) == tolower(*rb)) 
	{
		if (!*ra++)
			return 0;
		else
			++rb;
	}
	return (*ra - *rb);
}
Udb *busca_udb_en_hash(char *clave, int donde, Udb *lugar)
{
	u_int hashv;
	Udb *aux;
	hashv = hash_nick_name(clave) % MAX_HASH;
	for (aux = hash[donde][hashv]; aux; aux = aux->hsig)
	{
		if ((*(clave+1) == '\0' && aux->id == *clave) || !compara(clave, aux->item))
			return aux;
	}
	return lugar;
}
Udb *busca_registro(int tipo, char *clave)
{
	if (!clave)
		return NULL;
	tipo = coge_de_char((char)tipo);
	return busca_udb_en_hash(clave, tipo, NULL);
}
Udb *busca_bloque(char *clave, Udb *bloque)
{
	Udb *aux;
	if (!clave)
		return NULL;
	for (aux = bloque->down; aux; aux = aux->mid)
	{
		if ((*(clave+1) == '\0' && aux->id == *clave) || !compara(clave, aux->item))
			return aux;
	}
	return NULL;
}
Udb *crea_registro(Udb *bloque)
{
	Udb *reg;
	reg = (Udb *)MyMalloc(sizeof(Udb));
	reg->hsig = (Udb *)NULL;
	reg->data_char = reg->item = (char *)NULL;
	reg->data_long = 0L;
	reg->id = 0;
	reg->down = NULL;
	reg->up = bloque;
	reg->mid = bloque->down;
	bloque->down = reg;
	return reg;
}
Udb *da_formato(char *form, Udb *reg)
{
	Udb *root = NULL;
	form[0] = '\0';
	if (reg->up)
		root = da_formato(form, reg->up);
	else
		return reg;
	if (reg->id)
	{
		char *c;
		if ((c = strchr(form, '\0')))
		{
			*c = reg->id;
			*(c+1) = '\0';
		}
	}
	else
		strcat(form, reg->item);
	if (reg->down)
		strcat(form, "::");
	else
	{
		if (reg->data_char)
		{
			strcat(form, " ");
			strcat(form, reg->data_char);
		}
		else if (reg->data_long)
		{
			char tmp[32];
			sprintf(tmp, " %c%lu", CHAR_NUM, reg->data_long);
			strcat(form, tmp);
		}
	}
	return root ? root : reg;
}
int guarda_en_archivo(Udb *reg, int tipo)
{
	char form[BUFSIZE];
	Udb *root;
	FILE *fp;
	form[0] = '\0';
	root = da_formato(form, reg);
	strcat(form, "\n");
	if (!(fp = fopen(root->item, "ab")))
		return -1;
	fputs(form, fp);
	fclose(fp);
	actualiza_hash(root);
	return 0;
}
int guarda_en_archivo_ex(Udb *reg, int tipo)
{
	if (!reg)
		return 0;
	if (reg->mid)
		guarda_en_archivo_ex(reg->mid, tipo);
	if (reg->down)
		guarda_en_archivo_ex(reg->down, tipo);
	else
		guarda_en_archivo(reg, tipo);
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
				acptr->user->virthost = make_virtualhost(acptr, acptr->user->realhost, acptr->user->virthost, 0);
			else
				BorraIpVirtual(acptr);
		}
	}
}
int mira_id(char id, char *tok)
{
	return (id == *tok);
}
void dale_vhost(aClient *sptr)
{
	if (!IsARegNick(sptr))
		return;
	sptr->user->virthost = make_virtualhost(sptr, sptr->user->realhost, sptr->user->virthost, 1);
}
void quitale_vhost(aClient *sptr, Udb *reg)
{
	char *tmp;
	Udb *bloq;
	if (!IsARegNick(sptr))
		return;
	if (!reg && !(reg = busca_registro(BDD_NICKS, sptr->name)))
		return;
	if (!(bloq = busca_bloque(N_VHO_TOK, reg)))
		return;
	tmp = bloq->data_char;
	bloq->data_char = NULL;
	sptr->user->virthost = make_virtualhost(sptr, sptr->user->realhost, sptr->user->virthost, 1);
	bloq->data_char = tmp;
}
void dale_modos(aClient *sptr, Udb *reg, char *modos)
{
	Udb *bloq;
	char *cur;
	if (!reg && !(reg = busca_registro(BDD_NICKS, sptr->name)))
		return;
	if (modos)
		cur = modos;
	else
	{
		if (!(bloq = busca_bloque(N_MOD_TOK, reg)))
			return;
		cur = bloq->data_char;
	}
	while (!BadPtr(cur))
	{
		switch(*cur)
		{
			case 'o':
				if (MyConnect(sptr) && !IsAnOper(sptr))
				{
					sendto_one(sptr, rpl_str(RPL_YOUREOPER), me.name, sptr->name);
					IRCstats.operators++;
#ifndef NO_FDLIST
					addto_fdlist(sptr->slot, &oper_fdlist);
#endif
					RunHook2(HOOKTYPE_LOCAL_OPER, sptr, 1);
				}
				sptr->umodes |= UMODE_OPER;
				break;
			case 'h':
				sptr->umodes |= UMODE_HELPOP;
				if (MyConnect(sptr))
					sptr->oflag |= OFLAG_HELPOP;
				break;
			case 'a':
				sptr->umodes |= UMODE_SADMIN;
				if (MyConnect(sptr))
					sptr->oflag |= OFLAG_SADMIN;
				break;
			case 'A':
				sptr->umodes |= UMODE_ADMIN;
				if (MyConnect(sptr))
					sptr->oflag |= OFLAG_ADMIN;
				break;
			case 'O':
				sptr->umodes |= UMODE_LOCOP;
				break;
			case 'k':
				sptr->umodes |= UMODE_SERVICES;
				if (MyConnect(sptr))
					sptr->oflag |= OFLAG_OVERRIDE;
				break;
			case 'N':
				sptr->umodes |= UMODE_NETADMIN;
				if (MyConnect(sptr))
					sptr->oflag |= OFLAG_NETADMIN;
				break;
			case 'C':
				sptr->umodes |= UMODE_COADMIN;
				if (MyConnect(sptr))
					sptr->oflag |= OFLAG_COADMIN;
				break;
			case 'W':
				sptr->umodes |= UMODE_WHOIS;
				if (MyConnect(sptr))
					sptr->oflag |= OFLAG_WHOIS;
				break;
			case 'q':
				sptr->umodes |= UMODE_KIX;
				break;
			case 'H':
				if (!IsHideOper(sptr) && IsOper(sptr))
					IRCstats.operators--;
				sptr->umodes |= UMODE_HIDEOPER;
				break;
			case 'X':
				sptr->umodes |= UMODE_SHOWIP;
				break;
			case 'B':
				sptr->umodes |= UMODE_BOT;
				break;
		}
		cur++;
	}
}
void quitale_modos(aClient *sptr, Udb *reg, char *modos)
{
	Udb *bloq;
	char *cur;
	if (!reg && !(reg = busca_registro(BDD_NICKS, sptr->name)))
		return;
	if (modos)
		cur = modos;
	else
	{
		if (!(bloq = busca_bloque(N_MOD_TOK, reg)))
			return;
		cur = bloq->data_char;
	}
	while (!BadPtr(cur))
	{
		switch(*cur)
		{
			case 'o':
				if (MyConnect(sptr) && IsAnOper(sptr))
				{
#ifndef NO_FDLIST
					delfrom_fdlist(sptr->slot, &oper_fdlist);
#endif
					sptr->oflag = 0;
					IRCstats.operators--;
					VERIFY_OPERCOUNT(sptr, "quitale_modos");
					remove_oper_snomasks(sptr);
					RunHook2(HOOKTYPE_LOCAL_OPER, sptr, 0);
				}
				sptr->umodes &= ~UMODE_OPER;
				break;
			case 'h':
				sptr->umodes &= ~UMODE_HELPOP;
				if (MyConnect(sptr))
					sptr->oflag &= ~OFLAG_HELPOP;
				break;
			case 'a':
				sptr->umodes &= ~UMODE_SADMIN;
				if (MyConnect(sptr))
					sptr->oflag &= ~OFLAG_SADMIN;
				break;
			case 'A':
				sptr->umodes &= ~UMODE_ADMIN;
				if (MyConnect(sptr))
					sptr->oflag &= ~OFLAG_ADMIN;
				break;
			case 'O':
				sptr->umodes &= ~UMODE_LOCOP;
				break;
			case 'k':
				sptr->umodes &= ~UMODE_SERVICES;
				if (MyConnect(sptr))
					sptr->oflag &= ~OFLAG_OVERRIDE;
				break;
			case 'N':
				sptr->umodes &= ~UMODE_NETADMIN;
				if (MyConnect(sptr))
					sptr->oflag &= ~OFLAG_NETADMIN;
				break;
			case 'C':
				sptr->umodes &= ~UMODE_COADMIN;
				if (MyConnect(sptr))
					sptr->oflag &= ~OFLAG_COADMIN;
				break;
			case 'W':
				sptr->umodes &= ~UMODE_WHOIS;
				if (MyConnect(sptr))
					sptr->oflag &= ~OFLAG_WHOIS;
				break;
			case 'q':
				sptr->umodes &= ~UMODE_KIX;
				break;
			case 'H':
				if (IsHideOper(sptr) && IsOper(sptr))
					IRCstats.operators++;
				sptr->umodes &= ~UMODE_HIDEOPER;
				break;
			case 'X':
				sptr->umodes &= ~UMODE_SHOWIP;
				break;
			case 'B':
				sptr->umodes &= ~UMODE_BOT;
				break;
		}
		cur++;
	}
}
void dale_oper(aClient *sptr, Udb *reg)
{
	Udb *bloq;
	if (!reg && !(reg = busca_registro(BDD_NICKS, sptr->name)))
		return;
	if ((bloq = busca_bloque(N_OPE_TOK, reg)))
	{
		u_long nivel = bloq->data_long;
		if (nivel & BDD_OPER)
			dale_modos(sptr, reg, "h");
		if (nivel & BDD_ADMIN)
		{
			dale_modos(sptr, reg, "oa");
			if (MyConnect(sptr))
				sptr->oflag |= (OFLAG_NADMIN | OFLAG_ISGLOBAL | OFLAG_ZLINE);
		}
		if (nivel & BDD_ROOT)
		{
			dale_modos(sptr, reg, "oN");
			if (MyConnect(sptr))
				sptr->oflag |= (OFLAG_NADMIN | OFLAG_ISGLOBAL | OFLAG_ZLINE | OFLAG_DIE | OFLAG_RESTART | OFLAG_ADDLINE);
		}
	}
}
void quitale_oper(aClient *sptr, Udb *reg)
{
	Udb *bloq;
	if (!reg && !(reg = busca_registro(BDD_NICKS, sptr->name)))
		return;
	if ((bloq = busca_bloque(N_OPE_TOK, reg)))
	{
		u_long nivel = bloq->data_long;
		if (nivel & BDD_OPER)
			quitale_modos(sptr, reg, "h");
		if (nivel & BDD_ADMIN)
		{
			quitale_modos(sptr, reg, "oa");
			if (MyConnect(sptr))
				sptr->oflag &= ~(OFLAG_NADMIN | OFLAG_TKL | OFLAG_GZL | OFLAG_OVERRIDE | OFLAG_ZLINE);
		}
		
		if (nivel & BDD_ROOT)
		{
			quitale_modos(sptr, reg, "oN");
			if (MyConnect(sptr))
				sptr->oflag &= ~(OFLAG_DIE | OFLAG_RESTART | OFLAG_ADDLINE);
		}
	}
}
void dale_swhois(aClient *sptr, Udb *reg)
{
	Udb *bloq;
	if (!reg && !(reg = busca_registro(BDD_NICKS, sptr->name)))
		return;
	if ((bloq = busca_bloque(N_SWO_TOK, reg)))
		ircstrdup(sptr->user->swhois, bloq->data_char);
}
void quitale_swhois(aClient *sptr, Udb *reg)
{
	Udb *bloq;
	if (!reg && !(reg = busca_registro(BDD_NICKS, sptr->name)))
		return;
	if ((bloq = busca_bloque(N_SWO_TOK, reg)))
	{
		MyFree(sptr->user->swhois);
		sptr->user->swhois = NULL;
	}
}
void dale_snomasks(aClient *sptr, Udb *reg)
{
	Udb *bloq;
	if (!MyConnect(sptr) || (!reg && !(reg = busca_registro(BDD_NICKS, sptr->name))))
		return;
	if ((bloq = busca_bloque(N_SNO_TOK, reg)))
	{
		set_snomask(sptr, bloq->data_char);
		if (sptr->user->snomask)
		{
			sptr->user->snomask |= SNO_SNOTICE;
			sptr->umodes |= UMODE_SERVNOTICE;
		}
	}
}
void quitale_snomasks(aClient *sptr, Udb *reg)
{
	Udb *bloq;
	if (MyConnect(sptr) || (!reg && !(reg = busca_registro(BDD_NICKS, sptr->name))))
		return;
	if ((bloq = busca_bloque(N_SNO_TOK, reg)))
	{
		buf[0] = '-';
		strcpy(&buf[1], bloq->data_char);
		set_snomask(sptr, buf);
	}
}
void dale_cosas(int pass, aClient *sptr, Udb *reg)
{
	Udb *bloq;
	u_long viejos;
	if (!reg && !(reg = busca_registro(BDD_NICKS, sptr->name)))
		return;
	viejos = sptr->umodes;
	if (pass == 2)
	{
		sptr->umodes |= UMODE_REGNICK;
		dale_modos(sptr, reg, NULL);
		dale_oper(sptr, reg);
		if (MyClient(sptr))
		{
			dale_swhois(sptr, reg);
			dale_snomasks(sptr, reg);
		}
	}
	else if (pass == 1)
		sptr->umodes |= UMODE_SUSPEND;
	if (MyClient(sptr))
		send_umode(sptr->from, sptr, viejos, SEND_UMODES, buf);
}
void quitale_cosas(aClient *sptr, Udb *reg)
{
	Udb *bloq;
	u_long viejos;
	if (!reg && !(reg = busca_registro(BDD_NICKS, sptr->name)))
		return;
	viejos = sptr->umodes;
	sptr->umodes &= ~(UMODE_REGNICK | UMODE_SUSPEND);
	quitale_modos(sptr, reg, NULL);
	quitale_oper(sptr, reg);
	if (MyClient(sptr))
	{
		quitale_swhois(sptr, reg);
		quitale_snomasks(sptr, reg);
		send_umode(sptr->from, sptr, viejos, SEND_UMODES, buf);
	}
}
void quitale_dns(char *ip)
{
	struct in_addr addr;
	aCache *cp;
#ifdef INET6
	inet_pton(AF_INET6, ip, (struct in_addr *)&addr);
#else
	inet_pton(AF_INET, ip, (struct in_addr *)&addr);
#endif
	if ((cp = find_cache_number(NULL, (char *) &addr)))
		rem_cache(cp);
}
void quitale_exc(char *ip)
{
	ConfigItem_except *aux, *sig;
	ircsprintf(buf, "*@%s", ip);
	for (aux = conf_except; aux; aux = sig)
	{
		sig = (ConfigItem_except *)aux->next;
		if (!strcmp(aux->mask, buf))
		{
			ircfree(aux->mask);
			if (aux->netmask)
				MyFree(aux->netmask);
			DelListItem(aux, conf_except);
			MyFree(aux);
		}
	}
}
void quitale_ips(char *item)
{
	quitale_dns(item);
	quitale_exc(item);
}
void inserta_registro_especial(int tipo, Udb *reg, char nuevo)
{
	if (loop.ircd_rehashing && tipo != BDD_IPS) /* si estamos refrescando, no tocamos nada */
		return;
	if (tipo == BDD_CHANS)
	{
		aChannel *chptr;
		Udb *root = reg;
		char *botnick = chan_nick(1), *botmask = chan_mask(1);
		while (*root->item != '#')
		{
			if (!(root = root->up))
				return;
		}
		buf[0] = '+';
		buf[1] = '\0';
		chptr = get_channel(&me, root->item, CREATE);
		if (!(chptr->mode.mode & MODE_RGSTR))
		{
			chptr->mode.mode |= MODE_RGSTR;
			strcat(buf, "r");
		}
		if (mira_id(reg->id, C_MOD_TOK) || !strcmp(reg->item, C_MOD))
		{
			char *modos = reg->data_char;
			struct ChMode store;
			if (*modos == '+')
				modos++;
			memset(&store, 0, sizeof(struct ChMode));
			set_channelmodes(modos, &store, 0);
			if (nuevo) /* a�adimos modos */
				chptr->mode.mode |= store.mode;
			else /* es relectura de la bdd, borramos lo que pueda tener */
			{
				chptr->mode.mode = store.mode;
				bzero(chptr->mode.key, sizeof(chptr->mode.key));
				bzero(chptr->mode.link, sizeof(chptr->mode.link));
				chptr->mode.limit = 0;
#ifdef NEWCHFLOODPROT
				if (chptr->mode.floodprot)
				{
					MyFree(chptr->mode.floodprot);
					chptr->mode.floodprot = NULL;
				}
#endif
#ifdef EXTCMODE
				chptr->mode.extmode = 0;
#endif
			}
			chptr->mode.mode |= MODE_RGSTR;
#ifdef NEWCHFLOODPROT
			if (store.floodprot.per)
			{
				chptr->mode.floodprot = MyMalloc(sizeof(ChanFloodProt));
				memcpy(chptr->mode.floodprot, &store.floodprot, sizeof(ChanFloodProt));
			}
#else
			chptr->mode.kmode = store.kmode;
			chptr->mode.per = store.per;
			chptr->mode.msgs = store.msgs;
#endif
#ifdef EXTCMODE
			if (store.extmodes)
			{
				int i;
				chptr->mode.extmode = store.extmodes;
				for (i = 0; i <= Channelmode_highest; i++)
				{
					if (!Channelmode_Table[i].flag || !Channelmode_Table[i].paracount)
						continue;
					if (chptr->mode.extmode & Channelmode_Table[i].mode)
					{
						CmodeParam *p;
						p = Channelmode_Table[i].put_param(NULL, store.extparams[i]);
						AddListItem(p, chptr->mode.extmodeparam);
					}
				}
			}
#endif
			strcat(buf, *modos == '+' ? modos+1 : modos);
		}
		else if (mira_id(reg->id, C_TOP_TOK) || !strcmp(reg->item, C_TOP))
		{
			int topiclen = strlen(reg->data_char);
			int nicklen;
			nicklen = strlen(botnick);
			if (topiclen > (TOPICLEN))
				topiclen = TOPICLEN;
			if (chptr->topic)
				MyFree(chptr->topic);
			chptr->topic = MyMalloc(topiclen + 1);
			strncpyzt(chptr->topic, reg->data_char, topiclen + 1);
			chptr->topic_time = TStime();
			if (chptr->topic_nick)
				MyFree(chptr->topic_nick);
			chptr->topic_nick = MyMalloc(nicklen + 1);
			strncpyzt(chptr->topic_nick, botnick, nicklen + 1);
			if (chptr->members)
				sendto_channel_butserv(chptr, &me, ":%s TOPIC %s :%s", botmask, chptr->chname, chptr->topic);
		}
		if (!chptr->creationtime)
			chptr->creationtime = TStime();
		if (buf[1] && chptr->members)
			sendto_channel_butserv(chptr, &me, ":%s MODE %s %s", botmask, chptr->chname, buf);
	}
	else if (tipo == BDD_SET)
	{
		if (mira_id(reg->id, S_CLA_TOK) || !strcmp(reg->item, S_CLA) || mira_id(reg->id, S_SUF_TOK) || !strcmp(reg->item, S_SUF))
			regenera_claves();
	}
	else if (tipo == BDD_NICKS)
	{
		aClient *sptr = NULL;
		Udb *root = reg;
		u_long viejos;
		while (root)
		{
			if ((sptr = find_client(root->item, NULL)))
				break;
			root = root->up;
		}
		if (!sptr)
			return;
		viejos = sptr->umodes;
		sptr->umodes |= UMODE_REGNICK;
		if (mira_id(reg->id, N_VHO_TOK) || !strcmp(reg->item, N_VHO))
			dale_vhost(sptr);
		else if (mira_id(reg->id, N_MOD_TOK) || !strcmp(reg->item, N_MOD))
			dale_modos(sptr, reg, reg->data_char);
		else if (mira_id(reg->id, N_SNO_TOK) || !strcmp(reg->item, N_SNO))
			dale_snomasks(sptr, reg->up);
		else if (mira_id(reg->id, N_OPE_TOK) || !strcmp(reg->item, N_OPE))
			dale_oper(sptr, reg->up);
		else if (mira_id(reg->id, N_SWO_TOK) || !strcmp(reg->item, N_SWO))
			dale_swhois(sptr, reg->up);
		else if (mira_id(reg->id, N_SUS_TOK) || !strcmp(reg->item, N_SUS))
		{
			quitale_cosas(sptr, reg->up);
			sptr->umodes |= UMODE_SUSPEND;
		}
		if (MyClient(sptr) && IsPerson(sptr))
			send_umode(sptr->from, sptr, viejos, SEND_UMODES, buf);
	}
	else if (tipo == BDD_IPS)
	{
		if (mira_id(reg->id, I_NOL_TOK) || !strcmp(reg->item, I_NOL))
		{
			char *c;
			ircsprintf(buf, "*@%s", reg->up->item);
			for (c = reg->data_char; !BadPtr(c); c++)
			{
				switch(*c)
				{
					case 'G':
						create_tkl_except(buf, "gline");
						break;
					case 'Z':
						create_tkl_except(buf, "gzline");
						break;
					case 'Q':
						create_tkl_except(buf, "gqline");
						create_tkl_except(buf, "qline");
						break;
					case 'S':
						create_tkl_except(buf, "shun");
						break;
#ifdef THROTTLING
					case 'T':
					{
						ConfigItem_except *ca;
						struct irc_netmask tmp;
						ca = MyMallocEx(sizeof(ConfigItem_except));
						ca->mask = strdup(buf);
						tmp.type = parse_netmask(ca->mask, &tmp);
						if (tmp.type != HM_HOST)
						{
							ca->netmask = MyMallocEx(sizeof(struct irc_netmask));
							bcopy(&tmp, ca->netmask, sizeof(struct irc_netmask));
						}
						ca->flag.type = CONF_EXCEPT_THROTTLE;
						AddListItem(ca, conf_except);
					}
#endif
				}
			}
		}
		else if (!loop.ircd_rehashing && (mira_id(reg->id, I_HOS_TOK) || !strcmp(reg->item, I_HOS)))
		{
			aCache *cp;
			struct hostent *hp;
			struct in_addr addr;
			char a = 1;
#ifdef INET6
			inet_pton(AF_INET6, reg->up->item, (struct in_addr *)&addr);
#else
			inet_pton(AF_INET, reg->up->item, (struct in_addr *)&addr);
#endif
			if ((cp = find_cache_number(NULL, (char *) &addr)))
			{
				 /* actualizamos el stuff */
				MyFree(cp->he.h_name);
				MyFree(cp->he.h_addr_list[0]);
				MyFree(cp->he.h_addr_list);
				MyFree(cp->he.h_aliases);
				a = 0;
			}
			else
			{
				cp = (aCache *)MyMalloc(sizeof(aCache));
				bzero((char *)cp, sizeof(aCache));
			}
			hp = &cp->he;
			hp->h_addr_list = (char **)MyMalloc(sizeof(char *) * 2);
			bzero((char *)hp->h_addr_list, sizeof(char *) * 2);
			hp->h_addr_list[0] = (char *)MyMalloc(sizeof(struct IN_ADDR));
			bzero(hp->h_addr_list[0], sizeof(struct IN_ADDR));
			hp->h_aliases = (char **)MyMalloc(sizeof(char *));
			hp->h_aliases[0] = NULL;
#ifdef INET6
			hp->h_addrtype = AF_INET6;
			hp->h_length = 6;
			memcpy(hp->h_addr_list[0], &addr, IN6ADDRSZ);
#else
			hp->h_addrtype = AF_INET;
			hp->h_length = 4;
			memcpy(hp->h_addr_list[0], &addr, INADDRSZ);
#endif
			hp->h_name = strdup(reg->data_char);
			//inet_aton(reg->up->item, (struct in_addr *)hp->h_addr_list[0]);
			hp->h_addr_list[1] = NULL;
			if (a)
			{
				cp->ttl = 31536000; /* 1 a�o */
				cp->expireat = TStime() + cp->ttl;
				add_to_cache(cp);
			}
		}	
	}	
}
void borra_registro_especial(int tipo, Udb *reg)
{
	Udb *bloq = NULL;
	if (loop.ircd_rehashing) /* si estamos refrescando, no tocamos nada */
		return;
	if (tipo == BDD_CHANS)
	{
		aChannel *chptr;
		Udb *root = reg;
		while (*root->item != '#')
		{
			if (!(root = root->up))
				return;
		}
		if (!(chptr = get_channel(&me, root->item, !CREATE)))
			return;
		if ((mira_id(reg->id, C_MOD_TOK) || !strcmp(C_MOD, reg->item)) || (*reg->item == '#' && (bloq = busca_bloque(C_MOD_TOK, reg))))
		{
#ifdef EXTCMODE
			extcmode_free_paramlist(chptr->mode.extmodeparam);
			chptr->mode.extmodeparam = NULL;
#endif
#ifdef NEWCHFLOODPROT
			chanfloodtimer_stopchantimers(chptr);
			if (chptr->mode.floodprot)
				MyFree(chptr->mode.floodprot);
			chptr->mode.floodprot = NULL;
#endif
#ifdef JOINTHROTTLE
			cmodej_delchannelentries(chptr);
#endif
		}
		if ((mira_id(reg->id, C_TOP_TOK)|| !strcmp(C_TOP, reg->item)) || (*reg->item == '#' && (bloq = busca_bloque(C_TOP_TOK, reg))))
		{
			if (chptr->topic)
			{
				MyFree(chptr->topic);
				chptr->topic = NULL;
				chptr->topic_time = 0;
			}
		}
		if (*reg->item == '#')
		{
			chptr->mode.mode &= ~MODE_RGSTR;
			if (!chptr->members) /* si hay gente no tocamos nada */
				sub1_from_channel(chptr);
		}
	}
	else if (tipo == BDD_NICKS)
	{
		aClient *sptr = NULL;
		Udb *root = reg;
		while (root)
		{
			if ((sptr = find_client(root->item, NULL)))
				break;
			root = root->up;
		}
		if (!sptr)
			return;
		if ((mira_id(reg->id, N_VHO_TOK) || !strcmp(N_VHO, reg->item)))
			quitale_vhost(sptr, reg->up);
		else if ((mira_id(reg->id, N_SNO_TOK) || !strcmp(N_SNO, reg->item)))
			quitale_snomasks(sptr, reg);
		else if ((mira_id(reg->id, N_OPE_TOK) || !strcmp(N_OPE, reg->item)))
			quitale_oper(sptr, reg);
		else if ((mira_id(reg->id, N_MOD_TOK) || !strcmp(N_MOD, reg->item)))
			quitale_modos(sptr, reg, NULL);
		else if ((mira_id(reg->id, N_SWO_TOK) || !strcmp(N_SWO, reg->item)))
			quitale_swhois(sptr, reg);
		else if (!strcasecmp(sptr->name, reg->item))
			quitale_cosas(sptr, reg);
	}
	else if (tipo == BDD_IPS)
	{
		if ((mira_id(reg->id, I_HOS_TOK) || !strcmp(I_HOS, reg->item)))
			quitale_dns(reg->up->item);
		else if ((mira_id(reg->id, I_NOL_TOK) || !strcmp(I_NOL, reg->item)))
			quitale_exc(reg->up->item);
		else if (!reg->up->up)
			quitale_ips(reg->item);
	}
}
#ifdef DEBUGMODE
void printea(Udb *bloq, int escapes)
{
	int i;
	char tabs[32];
	tabs[0] = '\0';
	for (i = 0; i < escapes; i++)
		strcat(tabs, "\t");
	if (bloq->id)
		tabs[escapes] = bloq->id;
	if (bloq->data_char)
		debug(2, "%s%s \"%s\"%s", tabs, bloq->item,  bloq->data_char, bloq->down ? " {" : ";");
	else if (bloq->data_long)
		debug(2, "%s%s *%lu%s", tabs, bloq->item,  bloq->data_long, bloq->down ? " {" : ";");
	else
		debug(2, "%s%s %s", tabs, bloq->item, bloq->down ? " {" : ";");
	if (bloq->down)
	{
		printea(bloq->down, ++escapes);
		escapes--;
		debug(2, "%s};", tabs);
	}
	if (bloq->mid)
		printea(bloq->mid, escapes);
}
#endif
void libera_memoria_udb(int tipo, Udb *reg)
{
	if (reg->down)
	{
		//borra_registro_de_hash(reg->down, tipo, reg->down->item);
		libera_memoria_udb(tipo, reg->down);
	}
	if (reg->mid)
	{
		//borra_registro_de_hash(reg->mid, tipo, reg->mid->item);
		libera_memoria_udb(tipo, reg->mid);
	}
	borra_registro_de_hash(reg, tipo, reg->item);
	if (reg->data_char)
		MyFree(reg->data_char);
	if (reg->item)
		MyFree(reg->item);
	MyFree(reg);
}
void borra_registro(int tipo, Udb *reg, int archivo)
{
	Udb *aux, *down, *prev = NULL, *up;
	if (!(up = reg->up)) /* estamos arriba de todo */
		return;
	tipo = coge_de_char(tipo);
	borra_registro_de_hash(reg, tipo, reg->item);
	borra_registro_especial(tipo, reg);
	if (reg->data_char)
		MyFree(reg->data_char);
	reg->data_char = NULL;
	reg->data_long = 0L;
	down = reg->down;
	reg->down = NULL;
	if (archivo)
		guarda_en_archivo(reg, tipo);
	for (aux = up->down; aux; aux = aux->mid)
	{
		if (aux == reg)
		{
			if (prev)
				prev->mid = aux->mid;
			else
				up->down = aux->mid;
			break;
		}
		prev = aux;
	}
	reg->mid = NULL;
	reg->down = down;
	if (!reg->up->up)
		regs[tipo]--;
	libera_memoria_udb(tipo, reg);
	if (!up->down)
		borra_registro(tipo, up, archivo);
}	
Udb *inserta_registro(int tipo, Udb *bloque, char *item, char *data_char, u_long data_long, int archivo)
{
	Udb *reg;
	if (!bloque || !item)
		return NULL;
	tipo = coge_de_char(tipo);
	if (!(reg = busca_bloque(item, bloque)))
	{
		reg = crea_registro(bloque);
		if (!bloque->up)
			regs[tipo]++;
		if (*(item+1) == '\0')
		{
			reg->id = *item;
			reg->item = strdup("");
		}
		else
			reg->item = strdup(item);
		inserta_registro_en_hash(reg, tipo, item);
	}
	else
	{
		if ((data_char && reg->data_char && !strcmp(reg->data_char, data_char)) || (data_long == reg->data_long && data_long))
			return NULL;
	}
	if (reg->data_char)
		MyFree(reg->data_char);
	reg->data_char = NULL;
	if (data_char)
		reg->data_char = strdup(data_char);
	reg->data_long = data_long;
	if (archivo && (data_char || data_long))
		guarda_en_archivo(reg, tipo);
	inserta_registro_especial(tipo, reg, archivo);
	return reg;
}
DLLFUNC int level_oper_bdd(char *oper)
{
	Udb *reg;
	if ((reg = busca_registro(BDD_NICKS, oper)))
	{
		Udb *aux;
		if ((aux = busca_bloque(N_OPE_TOK, reg)))
			return aux->data_long;
	}
	return 0;
}
char *cifra_ip(char *ipreal)
{
	static char cifrada[512];
	char *p, *clavec = NULL, clave[13];
	int ts = 0;
	Udb *bloq;
	unsigned int ourcrc, v[2], k[2], x[2];
	bzero(clave, sizeof(clave));
	bzero(cifrada, sizeof(cifrada));
	ourcrc = our_crc32(ipreal, strlen(ipreal));
	if ((bloq = busca_registro(BDD_SET, S_CLA_TOK)))
		clavec = bloq->data_char;
	else
		clavec = CLOAK_KEYCRC;
	strncpy(clave, clavec, 12);
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
				strncpy(p, ipreal, sizeof(cifrada));
				break;
			}
		}
	}
	return cifrada;
}	
char *make_virtualhost(aClient *acptr, char *real, char *virtual, int mostrar)
{
	Udb *reg, *bloq;
	char x[HOSTLEN+1], *suf = NULL;
	if (!real)
		return NULL;
	if ((reg = busca_registro(BDD_SET, S_SUF_TOK)))
		suf = reg->data_char;
	else
		suf = "virtual";
	if (IsARegNick(acptr) && (reg = busca_registro(BDD_NICKS, acptr->name)) && (bloq = busca_bloque(N_VHO_TOK, reg)) && !BadPtr(bloq->data_char))
		strncpyzt(x, bloq->data_char, HOSTLEN);
	else
		snprintf(x, HOSTLEN, "%s.%s", cifra_ip(real), suf);
	if (MyClient(acptr) && mostrar && IsHidden(acptr) && virtual && strcmp(virtual, x))
	{
		char *botname;
		if (!(reg = busca_registro(BDD_SET, S_IPS_TOK)))
			botname = me.name;
		else
			botname = reg->data_char;
		sendto_one(acptr, ":%s NOTICE %s :*** Protecci�n IP: tu direcci�n virtual es %s",
			botname, acptr->name, x);
	}
	if (virtual)
		MyFree(virtual);
	return strdup(x);
}
void parsea_linea(int tipo, char *cur, int archivo)
{
	char *ds, *cop, *sp;
	Udb *bloq;
	bloq = coge_de_id(tipo);
	cop = cur = strdup(cur);
	while ((ds = strchr(cur, ':')))
	{
		if (*(ds + 1) == ':')
		{
			*ds++ = '\0';
			if ((sp = strchr(cur, ' ')))
				*sp++ = '\0';
			if (*cur)
				bloq = inserta_registro(tipo, bloq, cur, sp, 0, archivo);
		}
		else /* ya no son :: */
			break;
		cur = ++ds;
	}
	if ((ds = strchr(cur, ' ')))
	{
		*ds++ = '\0';
		if (BadPtr(ds))
			goto borra;
		if (*ds == CHAR_NUM)
			inserta_registro(tipo, bloq, cur, NULL, atoul(++ds), archivo);
		else
			inserta_registro(tipo, bloq, cur, ds, 0, archivo);
	}
	else
	{
		borra:
		if ((bloq = busca_bloque(cur, bloq)))
			borra_registro(tipo, bloq, archivo);
	}
	MyFree(cop);
}
void carga_bloque(int tipo)
{
	Udb *root;
	u_long lee, obtiene, trunca = 0L, bytes = 0L;
	char bloque, linea[BUFSIZE], *c;
	FILE *fp;
	bloque = coge_de_tipo(tipo);
	root = coge_de_id(tipo);
	if ((lee = lee_hash(tipo)) != (obtiene = obtiene_hash(root)))
	{
		sendto_ops("El bloque %c est� corrupto (%lu != %lu)", bloque, lee, obtiene);
		if ((fp = fopen(root->item, "wb")))
		{
			fclose(fp);
			actualiza_hash(root);
		}
		if (Servers && !IsMe(Servers->value.cptr))
			sendto_one(Servers->value.cptr, ":%s DB %s RES %c 0", me.name, Servers->value.cptr->name, bloque);
		return;
	}
	gmts[tipo] = lee_gmt(tipo);
	if ((fp = fopen(root->item, "rb")))
	{
		while (fgets(linea, sizeof(linea), fp))
		{
			if ((c = strchr(linea, '\r')))
				*c = '\0';
			if ((c = strchr(linea, '\n')))
				*c ='\0';
			else
			{
				trunca = bytes;
				break;
			}
			bytes += strlen(linea) + 1;
			parsea_linea(tipo, linea, 0);
			bzero(linea, sizeof(linea));
		}
		fclose(fp);
	}
	if (trunca)
		trunca_bloque(&me, &me, root, trunca);
}
void descarga_bloque(int tipo)
{
	Udb *aux, *sig, *bloq;
	bloq = coge_de_id(tipo);
	for (aux = bloq->down; aux; aux = sig)
	{
		sig = aux->mid;
		borra_registro(tipo, aux, 0);
	}
	bloq->data_long = 0L;
	vacia_hash(tipo);
}
void carga_bloques()
{
	int i;
	for (i = 0; i < BDD_TOTAL; i++)
		descarga_bloque(i);
	sendto_ops("Releyendo Bases de Datos...");
	for (i = 0; i < BDD_TOTAL; i++)
		carga_bloque(i);
}
int trunca_bloque(aClient *cptr, aClient *sptr, Udb *bloq, u_long bytes)
{
	FILE *fp;
	char *contenido = NULL, bdd;
	bdd = LETRA(bloq);
	if ((fp = fopen(bloq->item, "rb")))
	{
		contenido = MyMalloc(bytes);
		if (fread(contenido, 1, bytes, fp) != bytes)
		{
			fclose(fp);
			sendto_one(cptr, ":%s DB %s ERR DRP %i %c fread", me.name, sptr->name, E_UDB_FATAL, bdd);
			MyFree(contenido);
			return 1;
		}
		fclose(fp);
		if ((fp = fopen(bloq->item, "wb")))
		{
			int id;
			id = coge_de_char(bdd);
			if (fwrite(contenido, 1, bytes, fp) != bytes)
			{
				fclose(fp);
				sendto_one(cptr, ":%s DB %s ERR DRP %i %c fwrite", me.name, sptr->name, E_UDB_FATAL, bdd);
				MyFree(contenido);
				return 1;
			}
			fclose(fp);
			actualiza_hash(bloq);
			descarga_bloque(id);
			carga_bloque(id);
		}
		else
		{
			sendto_one(":%s DB %s ERR DRP %i %c fopen(wb)", me.name, sptr->name, E_UDB_FATAL, bdd);
			MyFree(contenido);
			return 1;
		}
		MyFree(contenido);
	}
	else
	{
		sendto_one(cptr, ":%s DB %s ERR DRP %i %c fopen(rb)", me.name, sptr->name, E_UDB_FATAL, bdd);
		return 1;
	}
	return 0;
}
int optimiza(Udb *bloq)
{
	FILE *fp;
	int id = ID(bloq);
	if ((fp = fopen(bloq->item, "wb")))
		fclose(fp);
	guarda_en_archivo_ex(bloq->down, id);
	actualiza_hash(bloq);
	/* De momento, lo comento porque no creo que sea necesario remapear toda el bloque. En memoria, no hay registros superfluos */
	//descarga_bloque(id);
	//carga_bloque(id);
	return 0;
}
/* comandos
 * 
 * INF: da informaci�n (su md5) si no coinciden, se piden res�menes
 * RES: resumen de la base de datos. se utiliza para solicitar un resumen o para solicitar al otro nodo que resuma 
 *	 el nodo que tenga mas registros, es el que manda los que le faltan al otro
 * INS: insertar registro. este comando solo puede emitirlo un hub. si no es asi, no se propaga
 * DEL: borra un registro. lo mismo, solo desde hubs
 * ERR: hay un error
 * DRP: trunca una db
 * OPT: optimiza una db
 * FDR: fin del resumen
 * eso es todo amigos 
 */
 
CMD_FUNC(m_db)
{
	if (!IsServer(cptr))
		return 0;
	if (!IsUDB(cptr))
		return 0;
	if (parc < 5)
	{
		sendto_one(cptr, ":%s DB %s ERR 0 %i", me.name, sptr->name, E_UDB_PARAMS);
		return 1;
	}
	/* DB * INF <bdd> <md5> <ts de la �ltima optimizaci�n>*/
	if (!strcasecmp(parv[2], "INF"))
	{
		if (!match(parv[1], me.name))
		{
			Udb *bloq;
			time_t gm;
			if (!strchr(bloques, *parv[3]))
			{
				sendto_one(cptr, ":%s DB %s ERR RES %i %c", me.name, sptr->name, E_UDB_NODB, *parv[3]);
				return 1;
			}
			bloq = coge_de_id(*parv[3]);
			gm = atoul(parv[5]);
			if (strcmp(parv[4], bloq->data_char))
			{
				if (gm > gmts[ID(bloq)])
				{
					trunca_bloque(cptr, sptr, bloq, 0);
					sendto_one(cptr, ":%s DB %s RES %c 0", me.name, parv[0], *parv[3]);
					reses[ID(bloq)] = sptr; /* esperamos su res */
					actualiza_gmt(bloq, gm);
					if (++(sptr->serv->flags.bloqs) == BDD_TOTAL)
						sendto_one(cptr, ":%s %s", me.name, (IsToken(cptr) ? TOK_EOS : MSG_EOS));
				}
				else if (gm == gmts[ID(bloq)])
					sendto_one(cptr, ":%s DB %s RES %c %lu", me.name, parv[0], *parv[3], bloq->data_long);
				/* si es menor, el otro nodo vaciar� su db y nos mandar� un RES, ser� cuando empecemos el resumen. abremos terminado nuestro burst */
			}
			else
			{
				if (++(sptr->serv->flags.bloqs) == BDD_TOTAL)
					sendto_one(cptr, ":%s %s", me.name, (IsToken(cptr) ? TOK_EOS : MSG_EOS));
			}
		}
		/* pasamos el comando puesto que no es necesario que sea hub */
		sendto_serv_butone(cptr, ":%s DB %s INF %c %s %s", parv[0], parv[1], *parv[3], parv[4], parv[5]);
	}
	/* DB * RES <bdd> <btyes> */
	else if (!strcasecmp(parv[2], "RES"))
	{
		if (!match(parv[1], me.name))
		{
			/* el nodo nos pide resumen, siempre se lo damos en caso que sea menor */
			u_long bytes;
			Udb *bloq;
			if (!strchr(bloques, *parv[3]))
			{
				sendto_one(cptr, ":%s DB %s ERR RES %i %c", me.name, sptr->name, E_UDB_NODB, *parv[3]);
				return 1;
			}
			bloq = coge_de_id(*parv[3]);
			if (reses[ID(bloq)])
			{
				sendto_one(cptr, ":%s DB %s ERR RES %i %c", me.name, sptr->name, E_UDB_RPROG, *parv[3]);
				return 1;
			}
			bytes = atoul(parv[4]);
			if (bytes < bloq->data_long) /* tiene menos, se los mandamos */
			{
				FILE *fp;
				if ((fp = fopen(bloq->item, "rb")))
				{
					char linea[512], *d;
					fseek(fp, bytes, SEEK_SET);
					while (!feof(fp))
					{
						bzero(linea, 512);
						if (!fgets(linea, 512, fp))
							break;
						if ((d = strchr(linea, '\r')))
							*d = '\0';
						if ((d = strchr(linea, '\n')))
							*d = '\0';
						if (strchr(linea, ' '))
							sendto_one(cptr, ":%s DB * INS %lu %c::%s", me.name, bytes, *parv[3], linea);
						else
							sendto_one(cptr, ":%s DB * DEL %lu %c::%s", me.name, bytes, *parv[3], linea);
						bytes = ftell(fp);
					}
					fclose(fp);
					sendto_one(cptr, ":%s DB %s FDR %c 0", me.name, sptr->name, *parv[3]);
				}
			}
			else if (!bytes && !bloq->data_long) /* muy raras veces se daba */
				sendto_one(cptr, ":%s DB %s FDR %c 0", me.name, sptr->name, *parv[3]);
			else
				reses[ID(bloq)] = sptr; /* esperamos su res */
			if (++(sptr->serv->flags.bloqs) == BDD_TOTAL)
					sendto_one(cptr, ":%s %s", me.name, (IsToken(cptr) ? TOK_EOS : MSG_EOS));
		}		
		sendto_serv_butone(cptr, ":%s DB %s RES %c %s", parv[0], parv[1], *parv[3], parv[4]);
	}
	/* DB * INS <offset> <bdd>::a::b::...::item valor */
	else if (!strcasecmp(parv[2], "INS"))
	{
		if (!strcmp(sptr->name, parv[0]) && !cptr->serv->conf->hubmask) /* el nodo emisor no es hub, paramos */
		{
			sendto_one(cptr, ":%s DB %s ERR INS %i", me.name, sptr->name, E_UDB_NOHUB);
			return 0;
		}
		if (!match(parv[1], me.name))
		{
			char buf[1024], tipo, *r = parv[4];
			u_long bytes;
			Udb *bloq;
			tipo = *r;
			if (parc < 6)
			{
				sendto_one(cptr, ":%s DB %s ERR INS %i", me.name, sptr->name, E_UDB_PARAMS);
				return 1;
			}
			if (!strchr(bloques, tipo))
			{
				sendto_one(cptr, ":%s DB %s ERR INS %i %c", me.name, sptr->name, E_UDB_NODB, tipo);
				return 1;
			}
			bytes = atoul(parv[3]);
			bloq = coge_de_id(tipo);
			if (reses[ID(bloq)])
			{
				if (reses[ID(bloq)] != sptr)
				{
					sendto_one(cptr, ":%s DB %s ERR INS %i %c", me.name, sptr->name, E_UDB_RPROG, tipo);
					return 1;
				}
			}
			else
			{
				if (propaga != sptr)
				{
					sendto_one(cptr, ":%s DB %s ERR INS %i %s", me.name, sptr->name, E_UDB_FBSRV, grifo);
					return 1;
				}
			}
			if (bytes != bloq->data_long)
			{
				sendto_one(cptr, ":%s DB %s ERR INS %i %c %lu", me.name, sptr->name, E_UDB_LEN, tipo, bloq->data_long);
				/* a partir de este punto el servidor que recibe esta instrucci�n debe truncar su bloque con el valor recibido
				   y propagar el truncado por la red, obviamente en el otro sentido. 
				   Si el nodo que lo ha enviado es un LEAF propagar� un DRP pero que no llegar� a ning�n sitio porque no tiene servidores
				   en el otro sentido. Si es un HUB, tendr� v�a libre para propagar el DRP. 
				   A efectos, ser�a lo mismo que el nodo receptor mandara un DRP, pero as� se ahorra una l�nea ;) */
				return 1;
			}
			r += 3;
			ircsprintf(buf, "%s %s", r, parv[5]);
			parsea_linea(tipo, buf, 1);
			if (reses[ID(bloq)] == sptr) /* estamos en un resumen, hay que repropagar los registros */
			{
				sendto_serv_butone(cptr, ":%s DB %s INS %s %s %s", propaga->name, parv[1], parv[3], parv[4], parv[5]);
				return 0;
			}
		}
		sendto_serv_butone(cptr, ":%s DB %s INS %s %s %s", parv[0], parv[1], parv[3], parv[4], parv[5]);
	}
	/* DB * DEL <offset> <bdd>::a::b::...::item */
	else if (!strcasecmp(parv[2], "DEL"))
	{
		if (!strcmp(sptr->name, parv[0]) && !cptr->serv->conf->hubmask)
		{
			sendto_one(cptr, ":%s DB %s ERR DEL %i", me.name, sptr->name, E_UDB_NOHUB);
			return 0;
		}
		if (!match(parv[1], me.name))
		{
			char tipo, *r = parv[4];
			u_long bytes;
			Udb *bloq;
			tipo = *r;
			if (!strchr(bloques, tipo))
			{
				sendto_one(cptr, ":%s DB %s ERR DEL %i %c", me.name, sptr->name, E_UDB_NODB, tipo);
				return 1;
			}
			bytes = atoul(parv[3]);
			bloq = coge_de_id(tipo);
			if (reses[ID(bloq)])
			{
				if (reses[ID(bloq)] != sptr)
				{
					sendto_one(cptr, ":%s DB %s ERR DEL %i %c", me.name, sptr->name, E_UDB_RPROG, tipo);
					return 1;
				}
			}
			else
			{
				if (propaga != sptr)
				{
					sendto_one(cptr, ":%s DB %s ERR DEL %i %s", me.name, sptr->name, E_UDB_FBSRV, grifo);
					return 1;
				}
			}
			if (bytes != bloq->data_long)
			{
				sendto_one(cptr, ":%s DB %s ERR DEL %i %c %lu", me.name, sptr->name, E_UDB_LEN, tipo, bloq->data_long);
				return 1;
			}
			r += 3;
			parsea_linea(tipo, r, 1);
			if (reses[ID(bloq)] == sptr) /* estamos en un res */
			{
				sendto_serv_butone(cptr, ":%s DB %s DEL %s %s", propaga->name, parv[1], parv[3], parv[4]);
				return 0;
			}
		}
		sendto_serv_butone(cptr, ":%s DB %s DEL %s %s", parv[0], parv[1], parv[3], parv[4]);
	}
	/* DB * DRP <bdd> <byte> */
	else if (!strcasecmp(parv[2], "DRP"))
	{
		if (!strcmp(sptr->name, parv[0]) && !cptr->serv->conf->hubmask)
		{
			sendto_one(cptr, ":%s DB %s ERR DRP %i", me.name, sptr->name, E_UDB_NOHUB);
			return 0;
		}
		if (!match(parv[1], me.name))
		{
			u_long bytes;
			Udb *bloq;
			if (!strchr(bloques, *parv[3]))
			{
				sendto_one(cptr, ":%s DB %s ERR DRP %i %c", me.name, sptr->name, E_UDB_NODB, *parv[3]);
				return 1;
			}
			bloq = coge_de_id(*parv[3]);
			if (reses[ID(bloq)] != sptr)
			{
				sendto_one(cptr, ":%s DB %s ERR INS %i %c", me.name, sptr->name, E_UDB_RPROG, *parv[3]);
				return 1;
			}
			bytes = atoul(parv[4]);
			if (bytes > bloq->data_long)
			{
				sendto_one(cptr, ":%s DB %s ERR DRP %i %c %lu", me.name, sptr->name, E_UDB_LEN, *parv[3], bloq->data_long);
				return 1;
			}
			trunca_bloque(cptr, sptr, bloq, bytes);
		}
		sendto_serv_butone(cptr, ":%s DB %s DRP %s %s", parv[0], parv[1], parv[3], parv[4]);
	}
	/* DB <nodo-emisor> ERR <comando-error> <errno> <params> */
	else if (!strcmp(parv[2], "ERR")) /* tratamiento de errores */
	{
		int error = 0;
		if (!match(parv[1], me.name))
		{
			error = atoi(parv[4]);
			switch (error)
			{
				case E_UDB_LEN:
				{
					Udb *bloq;
					u_long bytes;
					char *cb;
					bloq = coge_de_id(*parv[5]);
					cb = strchr(parv[5], ' ') + 1; /* esto siempre debe cumplirse, si no a cascar */
					bytes = atoul(cb);
					trunca_bloque(cptr, sptr, bloq, bytes);
					/* somos nosotros quienes mandamos el DRP, quienes deshacemos el cambio! */
					sendto_serv_butone(cptr, ":%s DB %s DRP %c %s", me.name, parv[1], *parv[5], cb);
					break;
				}
			}
			/* una vez hemos terminado, retornamos puesto que estos comandos s�lo van dirigidos a un nodo */
			return 1;
		}
		sendto_serv_butone(cptr, ":%s DB %s ERR %s %s %s", parv[0], parv[1], parv[3], parv[4], parv[5]);
	}
	/* DB * OPT <bdd> <hora>*/
	else if (!strcmp(parv[2], "OPT"))
	{
		Udb *bloq;
		if (!strcmp(sptr->name, parv[0]) && !cptr->serv->conf->hubmask)
		{
			sendto_one(cptr, ":%s DB %s ERR OPT %i", me.name, sptr->name, E_UDB_NOHUB);
			return 0;
		}
		if (!strchr(bloques, *parv[3]))
		{
			sendto_one(cptr, ":%s DB %s ERR OPT %i %c", me.name, sptr->name, E_UDB_NODB, *parv[3]);
			return 1;
		}
		bloq = coge_de_id(*parv[3]);
		optimiza(bloq);
		actualiza_gmt(bloq, atoul(parv[4]));
		sendto_serv_butone(cptr, ":%s DB %s OPT %s %s", parv[0], parv[1], parv[3], parv[4]);
	}
	/* DB * FDR <bdd> <NULL> */
	else if (!strcmp(parv[2], "FDR"))
	{
		if (!match(parv[1], me.name))
		{
			Udb *bloq;
			if (!strchr(bloques, *parv[3]))
			{
				sendto_one(cptr, ":%s DB %s ERR FDR %i %c", me.name, sptr->name, E_UDB_NODB, *parv[3]);
				return 1;
			}
			bloq = coge_de_id(*parv[3]);
			if (reses[ID(bloq)] != sptr)
			{
				sendto_one(cptr, ":%s DB %s ERR FDR %i %c", me.name, sptr->name, E_UDB_NORES, *parv[3]);
				return 1;
			}
			reses[ID(bloq)] = NULL;
		}
	}
	return 0;
}
/* 2 ok
 * 1 suspendido
 * 0 no reg
 * -1 forbid
 * -2 incorrecto
 * -3 no ha dado pass
 */
int tipo_de_pass(char *nick, char *pass, Udb *reg)
{
	Udb *bloq, *cha;
	anAuthStruct *as;
	int tipo = AUTHTYPE_PLAINTEXT;
	char *frb, *pas, *des, *sus, bdd;
	if (*nick == '#')
	{
		frb = C_FOR_TOK;
		pas = C_PAS_TOK;
		des = C_DES_TOK;
		sus = C_SUS_TOK;
		bdd = BDD_CHANS;
	}
	else
	{
		frb = N_FOR_TOK;
		pas = N_PAS_TOK;
		des = N_DES_TOK;
		sus = N_SUS_TOK;
		bdd = BDD_NICKS;
	}
	if (!reg && !(reg = busca_registro(bdd, nick)))
		return 0; /* no existe */
	if (busca_bloque(frb, reg))
		return -1; /* tiene el nick en forbid, no importa la pass */
	if (!(bloq = busca_bloque(pas, reg)))
		return 0; /* no existe */
	if (!pass)
		return -3;
	bzero(buf, sizeof(buf));
	if ((cha = busca_bloque(des, reg)))
	{
		int len = 0;
		char *bpass, buf2[22];
		if ((tipo = Auth_FindType(cha->data_char)) == -1)
			return 0; /* si el desafio no es correcto, el nick no existe */
		bpass = bloq->data_char;
		bzero(buf2, sizeof(buf2));
		switch(tipo)
		{
#ifdef AUTHENABLE_MD5
			case AUTHTYPE_MD5:
				if (*bpass != '$')
					len = 17;
				break;
#endif
#ifdef AUTHENABLE_SHA1
			case AUTHTYPE_SHA1:
				if (*bpass != '$')
					len = 21;
				break;
#endif
#ifdef AUTHENABLE_RIPEMD160
			case AUTHTYPE_RIPEMD160:
				if (*bpass != '$')
					len = 21;
				break;
#endif
		}
		if (len)
		{
			char tmp[3];
			int i;
			for (i = 0; i < len; i++)
			{
				ircsprintf(tmp, "%c%c", *bpass, *(bpass + 1));
				buf2[i] = (char)strtol(tmp, NULL, 16);
				bpass += 2;
			}
			b64_encode(buf2, len - 1, buf, sizeof(buf));
		}
		else
			strcpy(buf, bpass);
	}
	else
		strcpy(buf, bloq->data_char);
	as = (anAuthStruct *) MyMalloc(sizeof(anAuthStruct));
	as->type = tipo;
	as->data = strdup(buf);
	if (Auth_Check(&me, as, pass) == 2) /* ok */
	{
		Auth_DeleteAuthStruct(as);
		if (busca_bloque(sus, reg))
			return 1;
		return 2;
	}
	Auth_DeleteAuthStruct(as);
	return -2;
}
CMD_FUNC(m_ghost)
{
	aClient *acptr;
	Udb *reg, *breg;
	char *botname, who[NICKLEN + 2], nick[NICKLEN + 2], quitbuf[TOPICLEN + 1];
	int val;
   	if (!(breg = busca_registro(BDD_SET, S_NIC_TOK)))
		botname = me.name;
	else
		botname = breg->data_char;
	if (MyConnect(sptr) && sptr->user && !IsAnOper(sptr))
	{
		if ((sptr->user->flood.udb_c >= pases) && 
		    (TStime() - sptr->user->flood.udb_t < intervalo))
		{
			sendto_one(sptr, ":%s NOTICE %s :*** Demasiadas contrase�as incorrectas. No puedes utilizar este comando hasta %i segundos.", botname, sptr->name, (int)(intervalo - (TStime() - sptr->user->flood.udb_t)));
			return 0;
		}
	}
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
		strncpy(who, sptr->name, NICKLEN);
	if (!reg) 
	{
		sendto_one(cptr, ":%s NOTICE %s :*** El nick %s no est� registrado en la base de datos.", botname, sptr->name, nick);
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
	val = tipo_de_pass(nick, parv[2], reg);
	if (val < 0)
	{
		if (MyConnect(sptr) && sptr->user && !IsAnOper(sptr))
		{
			if ((sptr->user->flood.udb_c >= pases) && 
			    (TStime() - sptr->user->flood.udb_t < intervalo))
			{
				sendto_one(sptr, ":%s 339 %s :Demasiadas contrase�as incorrectas. No puedes utilizar este comando hasta %i segundos.", me.name, sptr->name, (int)(intervalo - (TStime() - sptr->user->flood.udb_t)));
				return 0;
			}
		}
		else
			sendto_one(cptr, ":%s NOTICE %s :*** Contrase�a incorrecta.", botname, sptr->name);
		return 0;
	}
	else if (val == 1)
	{
		sendto_one(cptr, ":%s NOTICE %s :*** No puedes aplicar ghost sobre un nick suspendido.", botname, sptr->name);
		return 0;
	}
	sendto_serv_butone_token(NULL, me.name, MSG_KILL, TOK_KILL, "%s :Comando GHOST utilizado por %s.", acptr->name, who);
	if (MyClient(acptr))
		sendto_one(acptr, ":%s KILL %s :Comando GHOST utilizado por %s.", me.name, acptr->name, who);
	sendto_one(cptr, ":%s NOTICE %s :*** Sesi�n fantasma del nick %s liberada.", botname, sptr->name, nick);
	ircsprintf(quitbuf, "Killed (Comando GHOST utilizado por %s)", who);
	return exit_client(cptr, acptr, &me, quitbuf);
}
CMD_FUNC(m_dbq)
{
	char *cur, *pos, *ds;
	Udb *bloq;
	if (!IsClient(sptr)) 
		return 0;
	if (!IsOper(sptr)) 
	{
		sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name, parv[0]);
		return 0;
	}
	if (parc < 2)
	{
		sendto_one(sptr, ":%s 339 %s :Par�metros insuficientes. Sintaxis: /dbq [servidor] <bloque>.", me.name, sptr->name);
		return 0;
	}
	if (parc == 3)
	{
		if (!(find_match_server(parv[1]))) 
		{
			sendto_one(sptr, err_str(ERR_NOSUCHSERVER), me.name, sptr->name, parv[1]);
			return 0;
		}
		sendto_serv_butone(cptr, ":%s DBQ %s %s", parv[0], parv[1], parv[2]);
		if (match(parv[1], me.name))
			return 0;
		parv[1] = parv[2];
	}
	pos = cur = strdup(parv[1]);
	if (!(bloq = coge_de_id(*pos)))
	{
		sendto_one(sptr, ":%s 339 %s :La base de datos %c no existe.", me.name, sptr->name, *pos);
		return 0;
	}
	if (*(++cur) != '\0')
	{
		if (*cur++ != ':' || *cur++ != ':' || *cur == '\0')
		{
			sendto_one(sptr, ":%s 339 %s :Formato de bloque incorrecto.", me.name, sptr->name);
			return 1;
		}
		
		while ((ds = strchr(cur, ':')))
		{
			if (*(ds + 1) == ':')
			{
				*ds++ = '\0';
				if (!(bloq = busca_bloque(cur, bloq)))
					goto nobloq;
			}
			else
				break;
			cur = ++ds;
		}
		if (!(bloq = busca_bloque(cur, bloq)))
		{
			nobloq:
			sendto_one(sptr, ":%s 339 %s :No se encuentra el bloque %s.", me.name, sptr->name, cur);
		}
		else
		{
			if (bloq->data_long)
				sendto_one(sptr, ":%s 339 %s :DBQ %s %lu", me.name, sptr->name, parv[1], bloq->data_long);
			else if (bloq->data_char)
				sendto_one(sptr, ":%s 339 %s :DBQ %s %s", me.name, sptr->name, parv[1], bloq->data_char);
			else
			{
				Udb *aux;
				for (aux = bloq->down; aux; aux = aux->mid)
				{
					if (aux->data_long)
						sendto_one(sptr, ":%s 339 %s :DBQ %s::%c %lu", me.name, sptr->name, parv[1], aux->id, aux->data_long);
					else if (aux->data_char)
						sendto_one(sptr, ":%s 339 %s :DBQ %s::%c %s", me.name, sptr->name, parv[1], aux->id, aux->data_char);
					else
						sendto_one(sptr, ":%s 339 %s :DBQ %s::%c (no tiene datos)", me.name, sptr->name, parv[1], aux->id);
				}
			}
		}
	}
	else
	{
		int id = ID(bloq);
		sendto_one(sptr, ":%s 339 %s :%i %i %lu %s %lu %X", me.name, sptr->name, id, regs[id], bloq->data_long, bloq->data_char, lee_gmt(id), lee_hash(id));
	} 
	MyFree(pos);
	return 0;
}
DLLFUNC char *get_visiblehost(aClient *acptr, aClient *sptr)
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
/* devuelve el aClient de ChanServ si est� online o no. si est� forzar en 1 lo devuelve indistintamente */
aClient *chan_client()
{
	char *b, botnick[NICKLEN+1];
	aClient *cptr;
	Udb *chanserv;
	if ((chanserv = busca_registro(BDD_SET, S_CHA_TOK)))
		strncpy(botnick, chanserv->data_char, sizeof(botnick));
	else
		strncpy(botnick, me.name, sizeof(botnick));
	if ((b = strchr(botnick, '!')))
		*b = '\0';
	if ((cptr = find_client(botnick, NULL)))
		return cptr;
	return &me;
}
char *chan_nick(int forzar)
{
	aClient *cptr;
	if ((cptr = chan_client()))
	{
		if (forzar)
		{
			if (!IsMe(cptr))
				return cptr->name;
			else
			{
				static char botnick[NICKLEN+1];
				char *b;
				Udb *chanserv;
				if ((chanserv = busca_registro(BDD_SET, S_CHA_TOK)))
				{
					strncpy(botnick, chanserv->data_char, sizeof(botnick));
					if ((b = strchr(botnick, '!')))
						*b = '\0';
					return botnick;
				}
			}
		}
		else
			return cptr->name;
	}
	return me.name;
}
char *chan_mask(int forzar)
{
	aClient *cptr;
	if ((cptr = chan_client()) && IsPerson(cptr))
	{
		static char ret[NICKLEN+1+USERLEN+1+HOSTLEN+1];
		ircsprintf(ret, "%s!%s@%s", cptr->name, cptr->username, GetHost(cptr));
		return ret;
	}
	else if (forzar)
	{
		Udb *chanserv;
		if ((chanserv = busca_registro(BDD_SET, S_CHA_TOK)))
			return chanserv->data_char;
	}
	return me.name;
}

#endif
