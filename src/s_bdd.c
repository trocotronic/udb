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
 *
 * $Id: s_bdd.c,v 1.1.1.17 2006-11-01 00:06:43 Trocotronic Exp $
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
#ifdef ZIP_LINKS
int zDeflate(FILE *, FILE *, int);
int zInflate(FILE *, FILE *);
#endif

Udb *UDB_NICKS = NULL, *UDB_CANALES = NULL, *UDB_IPS = NULL, *UDB_SET = NULL;
Udb ***hash;
UDBloq *ultimo = NULL;
UDBloq *N = NULL, *C= NULL, *S = NULL, *I = NULL;
int dataver = 0; /* versi�n de la database */
FILE *fcrc = NULL;
extern char modebuf[BUFSIZE], parabuf[BUFSIZE];
#define ircstrdup(x,y) do{ if (x) MyFree(x); if (!y) x = NULL; else x = strdup(y); }while(0)
#define atoul(x) strtoul(x, NULL, 10)
#define ircfree(x) do { if (x) MyFree(x); x = NULL; } while(0)
#define MAX_HASH 2048
void CargaBloques(void);
static char buf[BUFSIZE];
static int BDD_TOTAL = 0;
char *grifo = NULL;
aClient *propaga = NULL;
static Udb *globdes = NULL;

extern void set_channelmodes(char *, struct ChMode *, int);
#ifdef DEBUGMODE
void printea(Udb *, int);
#endif
void SetDataVer(u_int);
int CogeDataVer();
UDBloq *CogeDeId(u_int);
extern char *unrealdns_findcache_byaddr(struct IN_ADDR *);
extern DNSCache *unrealdns_findcache_byaddr_dns(struct IN_ADDR *);
extern void unrealdns_addtocache(char *, void *, int);
extern void unrealdns_removecacherecord(DNSCache *);
UDBloq *AltaBloque(char letra, char *ruta, Udb **dest)
{
	int id = 0;
	UDBloq *reg;
	if (ultimo)
		id = ultimo->id + 1;
	reg = (UDBloq *)MyMalloc(sizeof(UDBloq));
	reg->arbol = (Udb *)MyMalloc(sizeof(Udb));
	reg->arbol->id = id;
	reg->arbol->up = NULL;
	reg->arbol->down = NULL;
	reg->arbol->mid = NULL;
	reg->arbol->hsig = NULL;
	reg->crc32 = 0L;
	reg->id = id;
	reg->lof = 0L;
	reg->letra = letra;
	reg->path = ruta;
	reg->regs = 0;
	reg->gmt = 0L;
	reg->res = NULL;
	*dest = reg->arbol;
	reg->sig = ultimo;
	ultimo = reg;
	BDD_TOTAL++;
	return reg;
}
void VaciaHash(int id)
{
	int i;
	for (i = 0; i < MAX_HASH; i++)
		hash[id][i] = NULL;
}
void AltaHash()
{
	UDBloq *reg;
	int id;
	hash = (Udb ***)MyMalloc(sizeof(Udb **) * BDD_TOTAL);
	for (reg = ultimo; reg; reg = reg->sig)
	{
		id = reg->id;
		hash[id] = (Udb **)MyMalloc(sizeof(Udb *) * MAX_HASH);
		VaciaHash(id);
	}
}
#ifndef _WIN32
#define PMAX PATH_MAX 
#else
#define PMAX MAX_PATH
#endif
/* tokeniza los 4 bloques */
int ActualizaDataVer2()
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
		fflush(tmp);
		fclose(fp);
		fclose(tmp);
		unlink(p1);
		rename(p2, p1);
		unlink(p2);
		ActualizaHash(CogeDeId(i));
	}
	return 0;
}
/* quita el registro de devel y desplaza los que hubiere */
int ActualizaDataVer3()
{
	FILE *fp, *tmp;
	char *c, buf[8192];
	if (!(fp = fopen(DB_DIR "nicks.udb", "rb")))
		return 1;
	if (!(tmp = fopen(DB_DIR "temporal", "wb")))
		return 1;
	while (fgets(buf, sizeof(buf), fp))
	{
		if ((c = strchr(buf, ' ')))
		{
			if (*(c-2) == ':' && *(c-1) == *(N_OPE_TOK)) /* lo tenemos! */
			{
				int val;
				sscanf(c, " %*c%i\n", &val);
				if (val & 0x1)
					val &= ~0x1;
				if (val & 0x2)
				{
					val &= ~0x2;
					val |= 0x1;
				}
				if (val & 0x4)
					val &= ~0x4;
				if (val & 0x8)
				{
					val &= ~0x8;
					val |= 0x2;
				}
				if (val & 0x10)
				{
					val &= ~0x10;
					val |= 0x4;
				}
				*c = '\0';
				ircsprintf(buf, "%s %c%i\n", buf, CHAR_NUM, val);
			}
			fwrite(buf, 1, strlen(buf), tmp);
		}
	}
	fflush(tmp);
	fclose(fp);
	fclose(tmp);
	unlink(DB_DIR "nicks.udb");
	rename(DB_DIR "temporal", DB_DIR "nicks.udb");
	unlink(DB_DIR "temporal");
	ActualizaHash(N);
	return 0;
}
int ActualizaDataVer4()
{
	ActualizaHash(N);
	ActualizaHash(C);
	ActualizaHash(I);
	ActualizaHash(S);
	return 0;
}
void IniciaUDB()
{
	FILE *fh;
	int ver;
#ifdef _WIN32
	mkdir(DB_DIR);
	mkdir(DB_DIR_BCK);
#else
	mkdir(DB_DIR, 0744);
	mkdir(DB_DIR_BCK, 0744);
#endif
	if (!S)
		S = AltaBloque('S', DB_DIR "set.udb", &UDB_SET);
	if (!N)
		N = AltaBloque('N', DB_DIR "nicks.udb", &UDB_NICKS);
	if (!C)
		C = AltaBloque('C', DB_DIR "canales.udb", &UDB_CANALES);
	if (!I)
		I = AltaBloque('I', DB_DIR "ips.udb", &UDB_IPS);
	AltaHash();
	if ((fh = fopen(DB_DIR "crcs", "ab")))
	{
		fclose(fh);
		fcrc = fopen(DB_DIR "crcs", "r+b");
	}
	switch ((ver = CogeDataVer()))
	{
		case 0:
		case 1:
			ActualizaDataVer2();
		case 2:
			ActualizaDataVer3();
		case 3:
			ActualizaDataVer4();
	}
	SetDataVer(4);
	CargaBloques();
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
u_long ObtieneHash(UDBloq *bloq)
{
	int fp;
	char *par;
	struct stat inode;
	if ((fp = open(bloq->path, O_RDONLY|O_BINARY|O_CREAT, S_IREAD|S_IWRITE)) == -1)
		return 0L;
	if (fstat(fp, &inode) == -1)
	{
		close(fp);
		return 0L;
	}
	par = MyMalloc(inode.st_size + 1);
	*(par + inode.st_size) = '\0';
	if (read(fp, par, inode.st_size) == inode.st_size)
	{
		bloq->lof = inode.st_size;
		bloq->crc32 = our_crc32(par, inode.st_size);
	}
	close(fp);
	MyFree(par);
	return bloq->crc32;
}
u_long CogeHash(u_int id)
{
	u_long hash = 0;
	char lee[9];
	if (fseek(fcrc, 8 * id, SEEK_SET))
		return 0L;
	bzero(lee, 9);
	fread(lee, 1, 8, fcrc);
	if (!sscanf(lee, "%lX", &hash))
		return 0L;
	return hash;
}
int CogeDataVer()
{
	if (!dataver)
	{
		char ver[3];
		if (fseek(fcrc, 72, SEEK_SET))
			return 0;
		bzero(ver, 3);
		fread(ver, 1, 2, fcrc);
		if (!sscanf(ver, "%X", &dataver))
			return 0;
		return dataver;
	}
	return dataver;
}
void SetDataVer(u_int v)
{
	char ver[3];
	bzero(ver, 3);
	if (fseek(fcrc, 72, SEEK_SET))
		return;
	ircsprintf(ver, "%X", v);
	fwrite(ver, 1, 2, fcrc);
	fflush(fcrc);
}
int ActualizaHash(UDBloq *bloq)
{
	char lee[9];
	u_long lo;
	bzero(lee, 9);
	if (fseek(fcrc, 8 * bloq->id, SEEK_SET))
		return -1;
	lo = ObtieneHash(bloq);
	ircsprintf(lee, "%lX", lo);
	fwrite(lee, 1, 8, fcrc);
	fflush(fcrc);
	return 0;
}
time_t LeeGMT(u_int id)
{
	char lee[11];
	if (fseek(fcrc, BDD_TOTAL * 8 + 10 * id, SEEK_SET))
		return 0L;
	bzero(lee, 11);
	fread(lee, 1, 10, fcrc);
	return atoul(lee);
}
int ActualizaGMT(UDBloq *bloq, time_t gm)
{
	char lee[11];
	time_t hora = gm ? gm : time(0);
	bzero(lee, 11);
	if (fseek(fcrc, BDD_TOTAL * 8 + 10 * bloq->id, SEEK_SET))
		return -1;
	ircsprintf(lee, "%lu", hora);
	fwrite(lee, 1, 10, fcrc);
	fflush(fcrc);
	bloq->gmt = gm;
	return 0;
}
/* devuelve el puntero a todo el bloque a partir de su id o letra */
UDBloq *CogeDeId(u_int id)
{
	UDBloq *reg;
	for (reg = ultimo; reg; reg = reg->sig)
	{
		if (reg->letra == id || reg->id == id)
			return reg;
	}
	return NULL;
}
void InsertaRegistroEnHash(Udb *registro, u_int donde, char *clave)
{
	u_int hashv;
	hashv = hash_nick_name(clave) % MAX_HASH;
	registro->hsig = hash[donde][hashv];
	hash[donde][hashv] = registro;
}
int BorraRegistroDeHash(Udb *registro, u_int donde, char *clave)
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
/*
int complow(char a1, char b1)
{
	char a2, b2, a3, b3;
	a2 = a1+32;
	b2 = b1+32;
	a3 = a1-32;
	b3 = b1-32;
	if (a1 == b1)
		return 0;
	else if (a1 == b2)
		return 0;
	else if (a1 == b3)
		return 0;
	else if (a2 == b1)
		return 0;
	else if (a2 == b2)
		return 0;
	else if (a2 == b3)
		return 0;
	else if (a3 == b1)
		return 0;
	else if (a3 == b2)
		return 0;
	else if (a3 == b3)
		return 0;
	return b1-a1;
}
	
///* esta funci�n hace lo mismo que strcasecmp pero soporta la � 
int compara(char *ra, char *rb)
{
	if (!ra || !rb)
		return 1;
	while (!complow(*ra, *rb) || tolower(*ra) == tolower(*rb)) 
	{
		if (!*ra++)
			return 0;
		else
			++rb;
	}
	return (*ra - *rb);
}
*/
/* 
 * efect�a una b�squeda en hash 
 * esta funci�n debe llamarse cuando se busca un registro superior (nicks, canales, ips o sets). as� nos ahorramos la b�squeda 
 * binaria y podemos localizar r�pidamente el registro en cuesti�n.
 * si hay dos bloques repetidos es un problema. por ejemplo, que un nick se llame 'P' y tenga la opci�n 'P'. 
 * en este caso, devolver�a el �ltimo insertado: 'P' de pass, no del nick.
 * por esa raz�n se adjunta el bloque superior: no puede haber dos bloques id�nticos en el mismo nivel.
*/
Udb *BuscaBloque(char *clave, Udb *sup)
{
	u_int hashv;
	Udb *aux;
	if (!clave)
		return NULL;
	hashv = hash_nick_name(clave) % MAX_HASH;
	for (aux = hash[sup->id][hashv]; aux; aux = aux->hsig)
	{
		//if ((*(clave+1) == '\0' && !complow(aux->id, *clave)) || !compara(clave, aux->item))
		if (aux->up == sup && !strcasecmp(clave, aux->item))
			return aux;
	}
	return NULL;
}
Udb *CreaRegistro(Udb *bloque)
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
Udb *DaFormato(char *form, Udb *reg)
{
	Udb *root = NULL;
	form[0] = '\0';
	if (reg->up)
		root = DaFormato(form, reg->up);
	else
		return reg;
	if (!BadPtr(reg->item))
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
int GuardaEnArchivo(Udb *reg, u_int tipo)
{
	char form[BUFSIZE];
	UDBloq *bloq;
	FILE *fp;
	bloq = CogeDeId(tipo);
	form[0] = '\0';
	DaFormato(form, reg);
	strcat(form, "\n");
	if (!(fp = fopen(bloq->path, "ab")))
		return -1;
	fputs(form, fp);
	fclose(fp);
	ActualizaHash(bloq);
	return 0;
}
int GuardaEnArchivoInv(Udb *reg, u_int tipo)
{
	if (!reg)
		return 0;
	if (reg->mid)
		GuardaEnArchivoInv(reg->mid, tipo);
	if (reg->down)
		GuardaEnArchivoInv(reg->down, tipo);
	else
		GuardaEnArchivo(reg, tipo);
	return 0;
}
void RegeneraClaves()
{
	aClient *acptr;
	for (acptr = client; acptr; acptr = acptr->next)
	{
		if (IsClient(acptr))
		{
			if (IsHidden(acptr))
				acptr->user->virthost = MakeVirtualHost(acptr, acptr->user->realhost, acptr->user->virthost, 0);
			else
				BorraIpVirtual(acptr);
		}
	}
}
/*int mira_id(char id, char *tok)
{
	return (id == *tok);
}*/
void DaleVhost(aClient *sptr)
{
	if (!IsARegNick(sptr))
		return;
	sptr->user->virthost = MakeVirtualHost(sptr, sptr->user->realhost, sptr->user->virthost, 1);
}
void QuitaleVhost(aClient *sptr, Udb *reg)
{
	char *tmp = NULL;
	Udb *bloq = NULL;
	if (!IsARegNick(sptr))
		return;
	if (!reg)
		reg = BuscaBloque(sptr->name, UDB_NICKS);
	if ((bloq = BuscaBloque(N_VHO_TOK, reg)))
	{
		tmp = bloq->data_char;
		bloq->data_char = NULL;
	}
	sptr->user->virthost = MakeVirtualHost(sptr, sptr->user->realhost, sptr->user->virthost, 1);
	if (tmp) /* si tmp, bloq */
		bloq->data_char = tmp;
}
void DaleModos(aClient *sptr, Udb *reg, char *modos)
{
	Udb *bloq;
	char *cur;
	if (!reg && !(reg = BuscaBloque(sptr->name, UDB_NICKS)))
		return;
	if (modos)
		cur = modos;
	else
	{
		if (!(bloq = BuscaBloque(N_MOD_TOK, reg)))
			return;
		cur = bloq->data_char;
	}
	while (!BadPtr(cur))
	{
		switch(*cur)
		{
			case 'o':
				if (MyClient(sptr) && !IsOper(sptr))
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
				if (MyClient(sptr))
					sptr->oflag |= OFLAG_HELPOP;
				break;
			case 'a':
				sptr->umodes |= UMODE_SADMIN;
				if (MyClient(sptr))
					sptr->oflag |= OFLAG_SADMIN;
				break;
			case 'A':
				sptr->umodes |= UMODE_ADMIN;
				if (MyClient(sptr))
					sptr->oflag |= OFLAG_ADMIN;
				break;
			case 'O':
				sptr->umodes |= UMODE_LOCOP;
				break;
			case 'k':
				sptr->umodes |= UMODE_SERVICES;
				if (MyClient(sptr))
					sptr->oflag |= OFLAG_OVERRIDE;
				break;
			case 'N':
				sptr->umodes |= UMODE_NETADMIN;
				if (MyClient(sptr))
					sptr->oflag |= OFLAG_NETADMIN;
				break;
			case 'C':
				sptr->umodes |= UMODE_COADMIN;
				if (MyClient(sptr))
					sptr->oflag |= OFLAG_COADMIN;
				break;
			case 'W':
				sptr->umodes |= UMODE_WHOIS;
				if (MyClient(sptr))
					sptr->oflag |= OFLAG_WHOIS;
				break;
			case 'q':
				sptr->umodes |= UMODE_KIX;
				break;
			case 'H':
				if (!IsHideOper(sptr) && IsOper(sptr) && MyClient(sptr))
				{
					VERIFY_OPERCOUNT(sptr, "DaleModos H");
					IRCstats.operators--;
				}
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
void QuitaleModos(aClient *sptr, Udb *reg, char *modos)
{
	Udb *bloq;
	char *cur;
	if (!reg && !(reg = BuscaBloque(sptr->name, UDB_NICKS)))
		return;
	if (modos)
		cur = modos;
	else
	{
		if (!(bloq = BuscaBloque(N_MOD_TOK, reg)))
			return;
		cur = bloq->data_char;
	}
	while (!BadPtr(cur))
	{
		switch(*cur)
		{
			case 'o':
				if (MyClient(sptr) && IsOper(sptr))
				{
#ifndef NO_FDLIST
					delfrom_fdlist(sptr->slot, &oper_fdlist);
#endif
					sptr->oflag = 0;
					IRCstats.operators--;
					VERIFY_OPERCOUNT(sptr, "QuitaleModos o");
					remove_oper_snomasks(sptr);
					RunHook2(HOOKTYPE_LOCAL_OPER, sptr, 0);
				}
				sptr->umodes &= ~UMODE_OPER;
				break;
			case 'h':
				sptr->umodes &= ~UMODE_HELPOP;
				if (MyClient(sptr))
					sptr->oflag &= ~OFLAG_HELPOP;
				break;
			case 'a':
				sptr->umodes &= ~UMODE_SADMIN;
				if (MyClient(sptr))
					sptr->oflag &= ~OFLAG_SADMIN;
				break;
			case 'A':
				sptr->umodes &= ~UMODE_ADMIN;
				if (MyClient(sptr))
					sptr->oflag &= ~OFLAG_ADMIN;
				break;
			case 'O':
				sptr->umodes &= ~UMODE_LOCOP;
				break;
			case 'k':
				sptr->umodes &= ~UMODE_SERVICES;
				if (MyClient(sptr))
					sptr->oflag &= ~OFLAG_OVERRIDE;
				break;
			case 'N':
				sptr->umodes &= ~UMODE_NETADMIN;
				if (MyClient(sptr))
					sptr->oflag &= ~OFLAG_NETADMIN;
				break;
			case 'C':
				sptr->umodes &= ~UMODE_COADMIN;
				if (MyClient(sptr))
					sptr->oflag &= ~OFLAG_COADMIN;
				break;
			case 'W':
				sptr->umodes &= ~UMODE_WHOIS;
				if (MyClient(sptr))
					sptr->oflag &= ~OFLAG_WHOIS;
				break;
			case 'q':
				sptr->umodes &= ~UMODE_KIX;
				break;
			case 'H':
				if (IsHideOper(sptr) && IsOper(sptr) && MyClient(sptr))
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
void DaleOper(aClient *sptr, Udb *reg)
{
	Udb *bloq;
	if (!reg && !(reg = BuscaBloque(sptr->name, UDB_NICKS)))
		return;
	if ((bloq = BuscaBloque(N_OPE_TOK, reg)))
	{
		u_long nivel = bloq->data_long;
		if (nivel & BDD_OPER)
		{
			DaleModos(sptr, reg, "h");
			if (MyClient(sptr))
				sptr->oflag |= OFLAG_HELPOP;
		}
		if (nivel & BDD_ADMIN)
		{
			DaleModos(sptr, reg, "oa");
			if (MyClient(sptr))
				sptr->oflag |= (OFLAG_NADMIN | OFLAG_ISGLOBAL | OFLAG_ZLINE);
		}
		if (nivel & BDD_ROOT)
		{
			DaleModos(sptr, reg, "oN");
			if (MyClient(sptr))
				sptr->oflag |= (OFLAG_NADMIN | OFLAG_ISGLOBAL | OFLAG_ZLINE | OFLAG_DIE | OFLAG_RESTART | OFLAG_ADDLINE);
		}
	}
}
void QuitaleOper(aClient *sptr, Udb *reg)
{
	Udb *bloq;
	if (!reg && !(reg = BuscaBloque(sptr->name, UDB_NICKS)))
		return;
	if ((bloq = BuscaBloque(N_OPE_TOK, reg)))
	{
		u_long nivel = bloq->data_long;
		if (nivel & BDD_OPER)
		{
			QuitaleModos(sptr, reg, "h");
			if (MyClient(sptr))
				sptr->oflag &= ~OFLAG_HELPOP;
		}
		if (nivel & BDD_ADMIN)
		{
			QuitaleModos(sptr, reg, "oa");
			if (MyClient(sptr))
				sptr->oflag &= ~(OFLAG_NADMIN | OFLAG_NADMIN | OFLAG_ZLINE);
		}
		
		if (nivel & BDD_ROOT)
		{
			QuitaleModos(sptr, reg, "oN");
			if (MyClient(sptr))
				sptr->oflag &= ~(OFLAG_NADMIN | OFLAG_ISGLOBAL | OFLAG_ZLINE | OFLAG_DIE | OFLAG_RESTART | OFLAG_ADDLINE);
		}
	}
}
void DaleSwhois(aClient *sptr, Udb *reg)
{
	Udb *bloq;
	if (!reg && !(reg = BuscaBloque(sptr->name, UDB_NICKS)))
		return;
	if ((bloq = BuscaBloque(N_SWO_TOK, reg)) && !BadPtr(bloq->data_char))
		ircstrdup(sptr->user->swhois, bloq->data_char);
}
void QuitaleSwhois(aClient *sptr, Udb *reg)
{
	Udb *bloq;
	if (!reg && !(reg = BuscaBloque(sptr->name, UDB_NICKS)))
		return;
	if ((bloq = BuscaBloque(N_SWO_TOK, reg)))
	{
		MyFree(sptr->user->swhois);
		sptr->user->swhois = NULL;
	}
}
void DaleSnomasks(aClient *sptr, Udb *reg)
{
	Udb *bloq;
	if (!MyClient(sptr) || (!reg && !(reg = BuscaBloque(sptr->name, UDB_NICKS))))
		return;
	if ((bloq = BuscaBloque(N_SNO_TOK, reg)) && !BadPtr(bloq->data_char))
	{
		set_snomask(sptr, bloq->data_char);
		if (sptr->user->snomask)
		{
			sptr->user->snomask |= SNO_SNOTICE;
			sptr->umodes |= UMODE_SERVNOTICE;
		}
	}
}
void QuitaleSnomasks(aClient *sptr, Udb *reg)
{
	Udb *bloq;
	if (MyClient(sptr) || (!reg && !(reg = BuscaBloque(sptr->name, UDB_NICKS))))
		return;
	if ((bloq = BuscaBloque(N_SNO_TOK, reg)) && !BadPtr(bloq->data_char))
	{
		buf[0] = '-';
		strcpy(&buf[1], bloq->data_char);
		set_snomask(sptr, buf);
	}
}
void DaleCosas(int pass, aClient *sptr, Udb *reg, char *umodebuf)
{
	Udb *bloq;
	u_long viejos = 0L;
	if (!reg && !(reg = BuscaBloque(sptr->name, UDB_NICKS)))
		return;
	viejos = sptr->umodes;
	if (pass == 2)
	{
		sptr->umodes |= UMODE_REGNICK;
		DaleModos(sptr, reg, NULL);
		DaleOper(sptr, reg);
		if (MyClient(sptr) && IsPerson(sptr))
		{
			DaleSwhois(sptr, reg);
			DaleSnomasks(sptr, reg);
		}
	}
	else if (pass == 1)
		sptr->umodes |= UMODE_SUSPEND;
	if (MyClient(sptr))
	{
		send_umode(sptr->from, sptr, viejos, SEND_UMODES|UMODE_SERVNOTICE,  umodebuf ? umodebuf : buf);
		//sendto_serv_butone_token_opt(&me, OPT_NOT_PMODE | OPT_UMODE2, sptr->name, MSG_UMODE2, TOK_UMODE2, "%s", umodebuf);
		//sendto_serv_butone_token_opt(&me, OPT_NOT_PMODE | OPT_NOT_UMODE2, sptr->name, MSG_MODE, TOK_MODE, "%s %s", sptr->name, umodebuf);
	}
}
void QuitaleCosas(aClient *sptr, Udb *reg)
{
	Udb *bloq;
	u_long viejos;
	char umodebuf[128]; /* hay de sobras */
	if (!reg && !(reg = BuscaBloque(sptr->name, UDB_NICKS)))
		return;
	viejos = sptr->umodes;
	sptr->umodes &= ~(UMODE_REGNICK | UMODE_SUSPEND);
	QuitaleModos(sptr, reg, NULL);
	QuitaleOper(sptr, reg);
	if (MyClient(sptr))
	{
		QuitaleSwhois(sptr, reg);
		QuitaleSnomasks(sptr, reg);
		send_umode(sptr->from, sptr, viejos, SEND_UMODES|UMODE_SERVNOTICE, umodebuf);
		//sendto_serv_butone_token_opt(&me, OPT_NOT_PMODE | OPT_UMODE2, sptr->name, MSG_UMODE2, TOK_UMODE2, "%s", umodebuf);
		//sendto_serv_butone_token_opt(&me, OPT_NOT_PMODE | OPT_NOT_UMODE2, sptr->name, MSG_MODE, TOK_MODE, "%s %s", sptr->name, umodebuf);
	}
}
void QuitaleDns(char *ip)
{
	struct IN_ADDR addr;
	DNSCache *cp;
#ifdef INET6
	inet_pton(AF_INET6, ip, (struct IN_ADDR *)&addr);
#else
	inet_pton(AF_INET, ip, (struct IN_ADDR *)&addr);
#endif
	if ((cp = unrealdns_findcache_byaddr_dns(&addr)))
		unrealdns_removecacherecord(cp);
}
void QuitaleExc(char *ip)
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
void QuitaleIps(char *item)
{
	QuitaleDns(item);
	QuitaleExc(item);
}
void InsertaRegistroEspecial(u_int tipo, Udb *reg, int nuevo)
{
	if (loop.ircd_rehashing && tipo != I->id && tipo != S->id) /* si estamos refrescando, no tocamos nada */
		return;
	if (tipo == C->id)
	{
		aChannel *chptr;
		Udb *root = reg;
		char *botnick = ChanNick(1), *botmask = ChanMask(1);
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
		//if (mira_id(reg->id, C_MOD_TOK) || !strcmp(reg->item, C_MOD))
		if (!strcmp(reg->item, C_MOD_TOK))
		{
			char *modos = reg->data_char;
			struct ChMode store;
			if (BadPtr(modos))
				return;
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
		//else if (mira_id(reg->id, C_TOP_TOK) || !strcmp(reg->item, C_TOP))
		else if (!strcmp(reg->item, C_TOP_TOK))
		{
			int topiclen;
			int nicklen;
			char *tmp;
			if (BadPtr(reg->data_char))
				return;
			topiclen = strlen(reg->data_char);
			nicklen = strlen(botnick);
			if (topiclen > (TOPICLEN))
				topiclen = TOPICLEN;
			tmp = MyMalloc(topiclen + 1);
			strncpyzt(tmp, reg->data_char, topiclen + 1);
			if (!chptr->topic || strcmp(tmp, chptr->topic))
			{
				if (chptr->topic)
					MyFree(chptr->topic);
				chptr->topic = MyMalloc(topiclen + 1);
				chptr->topic_time = TStime();
				if (chptr->topic_nick)
					MyFree(chptr->topic_nick);
				strncpyzt(chptr->topic, reg->data_char, topiclen + 1);
				chptr->topic_nick = MyMalloc(nicklen + 1);
				strncpyzt(chptr->topic_nick, botnick, nicklen + 1);
				if (chptr->members)
					sendto_channel_butserv(chptr, &me, ":%s TOPIC %s :%s", botmask, chptr->chname, chptr->topic);
			}
			MyFree(tmp);
		}
		if (!chptr->creationtime)
			chptr->creationtime = TStime();
		if (buf[1] && chptr->members)
			sendto_channel_butserv(chptr, &me, ":%s MODE %s %s", botmask, chptr->chname, buf);
	}
	else if (tipo == S->id)
	{
		//if (!loop.ircd_rehashing && (mira_id(reg->id, S_CLA_TOK) || !strcmp(reg->item, S_CLA) || mira_id(reg->id, S_SUF_TOK) || !strcmp(reg->item, S_SUF)))
		if (!loop.ircd_rehashing && (!strcmp(reg->item, S_CLA_TOK) || !strcmp(reg->item, S_SUF_TOK)))
			RegeneraClaves();
		//else if (mira_id(reg->id, S_DES_TOK) || !strcmp(reg->item, S_DES))
		else if (!strcmp(reg->item, S_DES_TOK))
			globdes = reg;
	}
	else if (tipo == N->id)
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
		//if (mira_id(reg->id, N_VHO_TOK) || !strcmp(reg->item, N_VHO))
		if (!strcmp(reg->item, N_VHO_TOK))
			DaleVhost(sptr);
		//else if (mira_id(reg->id, N_MOD_TOK) || !strcmp(reg->item, N_MOD))
		else if (!strcmp(reg->item, N_MOD_TOK))
			DaleModos(sptr, reg, reg->data_char);
		//else if (mira_id(reg->id, N_SNO_TOK) || !strcmp(reg->item, N_SNO))
		else if (!strcmp(reg->item, N_SNO_TOK))
			DaleSnomasks(sptr, reg->up);
		//else if (mira_id(reg->id, N_OPE_TOK) || !strcmp(reg->item, N_OPE))
		else if (!strcmp(reg->item, N_OPE_TOK))
			DaleOper(sptr, reg->up);
		//else if (mira_id(reg->id, N_SWO_TOK) || !strcmp(reg->item, N_SWO))
		else if (!strcmp(reg->item, N_SWO_TOK))
			DaleSwhois(sptr, reg->up);
		//else if (mira_id(reg->id, N_SUS_TOK) || !strcmp(reg->item, N_SUS))
		else if (!strcmp(reg->item, N_SUS_TOK))
		{
			QuitaleCosas(sptr, reg->up);
			sptr->umodes |= UMODE_SUSPEND;
		}
		if (MyClient(sptr) && IsPerson(sptr))
		{
			char umodebuf[128];
			send_umode(sptr->from, sptr, viejos, SEND_UMODES, umodebuf);
			//sendto_serv_butone_token_opt(&me, OPT_NOT_PMODE | OPT_UMODE2, sptr->name, MSG_UMODE2, TOK_UMODE2, "%s", umodebuf);
			//sendto_serv_butone_token_opt(&me, OPT_NOT_PMODE | OPT_NOT_UMODE2, sptr->name, MSG_MODE, TOK_MODE, "%s %s", sptr->name, umodebuf);
		}
	}
	else if (tipo == I->id)
	{
		//if (mira_id(reg->id, I_NOL_TOK) || !strcmp(reg->item, I_NOL))
		if (!strcmp(reg->item, I_NOL_TOK))
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
		//else if (!loop.ircd_rehashing && (mira_id(reg->id, I_HOS_TOK) || !strcmp(reg->item, I_HOS)))
		else if (!loop.ircd_rehashing && !strcmp(reg->item, I_HOS_TOK))
		{
			DNSCache *cp;
			struct IN_ADDR addr;
#ifdef INET6
			inet_pton(AF_INET6, reg->up->item, (struct IN_ADDR *)&addr);
#else
			inet_pton(AF_INET, reg->up->item, (struct IN_ADDR *)&addr);
#endif
			if ((cp = unrealdns_findcache_byaddr_dns(&addr)))
				unrealdns_removecacherecord(cp);
			unrealdns_addtocache(reg->data_char, &addr, sizeof(&addr));
			if ((cp = unrealdns_findcache_byaddr_dns(&addr))) /* si no lo encuentra, algo pasa */
				cp->expires = TStime() + 31536000;
		}
	}	
}
void BorraRegistroEspecial(int tipo, Udb *reg)
{
	Udb *bloq = NULL;
	if (loop.ircd_rehashing) /* si estamos refrescando, no tocamos nada */
		return;
	if (tipo == C->id)
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
		//if ((mira_id(reg->id, C_MOD_TOK) || !strcmp(C_MOD, reg->item)) || (*reg->item == '#' && (bloq = BuscaBloque(C_MOD_TOK, reg))))
		if (!strcmp(C_MOD_TOK, reg->item) || (*reg->item == '#' && (bloq = BuscaBloque(C_MOD_TOK, reg))))
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
		//if ((mira_id(reg->id, C_TOP_TOK)|| !strcmp(C_TOP, reg->item)) || (*reg->item == '#' && (bloq = BuscaBloque(C_TOP_TOK, reg))))
		if (!strcmp(C_TOP_TOK, reg->item) || (*reg->item == '#' && (bloq = BuscaBloque(C_TOP_TOK, reg))))
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
	else if (tipo == N->id)
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
		//if ((mira_id(reg->id, N_VHO_TOK) || !strcmp(N_VHO, reg->item)))
		if (!strcmp(reg->item, N_VHO_TOK))
			QuitaleVhost(sptr, reg->up);
		//else if ((mira_id(reg->id, N_SNO_TOK) || !strcmp(N_SNO, reg->item)))
		else if (!strcmp(reg->item, N_SNO_TOK))
			QuitaleSnomasks(sptr, reg);
		//else if ((mira_id(reg->id, N_OPE_TOK) || !strcmp(N_OPE, reg->item)))
		else if (!strcmp(reg->item, N_OPE_TOK))
			QuitaleOper(sptr, reg);
		//else if ((mira_id(reg->id, N_MOD_TOK) || !strcmp(N_MOD, reg->item)))
		else if (!strcmp(reg->item, N_MOD_TOK))
			QuitaleModos(sptr, reg, NULL);
		//else if ((mira_id(reg->id, N_SWO_TOK) || !strcmp(N_SWO, reg->item)))
		else if (!strcmp(reg->item, N_SWO_TOK))
			QuitaleSwhois(sptr, reg);
		//else if (mira_id(reg->id, N_SUS_TOK) || !strcmp(reg->item, N_SUS))
		else if (!strcmp(reg->item, N_SUS_TOK))
		{
			u_long viejos = sptr->umodes;
			sptr->umodes &= ~UMODE_SUSPEND;
			if (MyClient(sptr) && IsPerson(sptr))
			{
				char umodebuf[128];
				send_umode(sptr->from, sptr, viejos, SEND_UMODES, umodebuf);
				//sendto_serv_butone_token_opt(&me, OPT_NOT_PMODE | OPT_UMODE2, sptr->name, MSG_UMODE2, TOK_UMODE2, "%s", umodebuf);
				//sendto_serv_butone_token_opt(&me, OPT_NOT_PMODE | OPT_NOT_UMODE2, sptr->name, MSG_MODE, TOK_MODE, "%s %s", sptr->name, umodebuf);
			}
		}
		else if (!strcasecmp(sptr->name, reg->item))
			QuitaleCosas(sptr, reg);
		
	}
	else if (tipo == I->id)
	{
		//if ((mira_id(reg->id, I_HOS_TOK) || !strcmp(I_HOS, reg->item)))
		if (!strcmp(reg->item, I_HOS_TOK))
			QuitaleDns(reg->up->item);
		//else if ((mira_id(reg->id, I_NOL_TOK) || !strcmp(I_NOL, reg->item)))
		else if (!strcmp(reg->item, I_NOL_TOK))
			QuitaleExc(reg->up->item);
		else if (!reg->up->up)
			QuitaleIps(reg->item);
	}
	else if (tipo == S->id)
	{
		//if (mira_id(reg->id, S_DES_TOK) || !strcmp(reg->item, S_DES))
		if (!strcmp(reg->item, S_DES_TOK))
			globdes = NULL;
	}
}
void printea(Udb *bloq, int escapes)
{
	int i;
	char tabs[32];
	tabs[0] = '\0';
	for (i = 0; i < escapes; i++)
		strcat(tabs, "\t");
//	if (bloq->id)
//		tabs[escapes] = bloq->id;
	if (bloq->data_char)
		sendto_ops("%s%s \"%s\"%s", tabs, bloq->item,  bloq->data_char, bloq->down ? " {" : ";");
	else if (bloq->data_long)
		sendto_ops("%s%s *%lu%s", tabs, bloq->item,  bloq->data_long, bloq->down ? " {" : ";");
	else
		sendto_ops("%s%s %s", tabs, bloq->item, bloq->down ? " {" : ";");
	if (bloq->down)
	{
		printea(bloq->down, ++escapes);
		escapes--;
		sendto_ops("%s};", tabs);
	}
	if (bloq->mid)
		printea(bloq->mid, escapes);
}
void LiberaMemoriaUdb(u_int tipo, Udb *reg)
{
	if (reg->down)
	{
		BorraRegistroDeHash(reg->down, tipo, reg->down->item);
		LiberaMemoriaUdb(tipo, reg->down);
	}
	if (reg->mid)
	{
		BorraRegistroDeHash(reg->mid, tipo, reg->mid->item);
		LiberaMemoriaUdb(tipo, reg->mid);
	}
	//BorraRegistroDeHash(reg, tipo, reg->item);
	if (reg->data_char)
		MyFree(reg->data_char);
	if (reg->item)
		MyFree(reg->item);
	MyFree(reg);
}
/* Devuelve NULL si hay error. Si no, devuelve el superior */
Udb *BorraRegistro(u_int tipo, Udb *reg, int archivo)
{
	Udb *aux, *down, *prev = NULL, *up;
	if (!(up = reg->up)) /* estamos arriba de todo */
		return NULL;
	BorraRegistroDeHash(reg, tipo, reg->item);
	BorraRegistroEspecial(tipo, reg);
	if (reg->data_char)
		MyFree(reg->data_char);
	reg->data_char = NULL;
	reg->data_long = 0L;
	down = reg->down;
	reg->down = NULL;
	if (archivo)
		GuardaEnArchivo(reg, tipo);
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
	{
		UDBloq *root = CogeDeId(tipo);
		root->regs--;
	}
	LiberaMemoriaUdb(tipo, reg);
	if (!up->down && up->up)
		up = BorraRegistro(tipo, up, archivo);
	return up;
}	
Udb *InsertaRegistro(u_int tipo, Udb *bloque, char *item, char *data_char, u_long data_long, int archivo)
{
	Udb *reg;
	if (!bloque || !item)
		return NULL;
	if (!(reg = BuscaBloque(item, bloque)))
	{
		reg = CreaRegistro(bloque);
		if (!bloque->up)
		{
			UDBloq *root = CogeDeId(tipo);
			root->regs++;
		}
		reg->id = bloque->id;
		/*if (*(item+1) == '\0')
		{
			reg->id = *item;
			reg->item = strdup("");
		}
		else*/
			reg->item = strdup(item);
		InsertaRegistroEnHash(reg, tipo, item);
	}
	else
	{
		if ((!BadPtr(data_char) && !BadPtr(reg->data_char) && !strcmp(reg->data_char, data_char)) || (data_long == reg->data_long && data_long))
			return NULL;
	}
	if (reg->data_char)
		MyFree(reg->data_char);
	reg->data_char = NULL;
	if (data_char)
		reg->data_char = strdup(data_char);
	reg->data_long = data_long;
	if (archivo && (data_char || data_long))
		GuardaEnArchivo(reg, tipo);
	InsertaRegistroEspecial(tipo, reg, archivo);
	return reg;
}
DLLFUNC u_int LevelOperUdb(char *oper)
{
	Udb *reg;
	if ((reg = BuscaBloque(oper, UDB_NICKS)))
	{
		Udb *aux;
		if ((aux = BuscaBloque(N_OPE_TOK, reg)))
			return (u_int)aux->data_long;
	}
	return 0;
}
char *CifraIp(char *ipreal)
{
	static char cifrada[512];
	char *p, *clavec = NULL, clave[13];
	int ts = 0;
	Udb *bloq;
	unsigned int ourcrc, v[2], k[2], x[2];
	bzero(clave, sizeof(clave));
	bzero(cifrada, sizeof(cifrada));
	ourcrc = our_crc32(ipreal, strlen(ipreal));
	if ((bloq = BuscaBloque(S_CLA_TOK, UDB_SET)) && !BadPtr(bloq->data_char))
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
char *MakeVirtualHost(aClient *acptr, char *real, char *virt, int mostrar)
{
	Udb *reg, *bloq;
	char *x, *suf = NULL;
	if (!real)
		return NULL;
	if ((reg = BuscaBloque(S_SUF_TOK, UDB_SET)) && !BadPtr(reg->data_char))
		suf = reg->data_char;
	else
		suf = "virtual";
	if (BadPtr(acptr->user->cloakedhost))
		snprintf(acptr->user->cloakedhost, HOSTLEN, "%s.%s", CifraIp(real), suf);
	if (IsARegNick(acptr) && (reg = BuscaBloque(acptr->name, UDB_NICKS)) && (bloq = BuscaBloque(N_VHO_TOK, reg)) && !BadPtr(bloq->data_char))
	{
		x = bloq->data_char;
		acptr->umodes |= UMODE_SETHOST;
	}
	else
	{
		x = acptr->user->cloakedhost;
		acptr->umodes &= ~UMODE_SETHOST;
	}
	if (MyClient(acptr) && mostrar && IsHidden(acptr) && (!virt || strcmp(virt, x)))
	{
		char *botname;
		if ((reg = BuscaBloque(S_IPS_TOK, UDB_SET)) && !BadPtr(reg->data_char))
			botname = reg->data_char;
		else
			botname = me.name;
		sendto_one(acptr, ":%s NOTICE %s :*** Protecci�n IP: tu direcci�n virtual es %s", botname, acptr->name, x);		
	}
	if (virt)
		MyFree(virt);
	return strdup(x);
}
/* 0 ok, 1 error (no se ha insertado/borrado) */
int ParseaLinea(u_int tipo, char *cur, int archivo)
{
	char *ds, *cop, *sp = NULL;
	Udb *bloq;
	UDBloq *root;
	root = CogeDeId(tipo);
	cop = cur = strdup(cur);
	bloq = root->arbol;
	sp = strchr(cur, ' ');
	while ((ds = strchr(cur, ':')))
	{
		if (sp && sp < ds)
			break;
		if (*(ds + 1) == ':')
		{
			*ds++ = '\0';
			if (*cur)
				bloq = InsertaRegistro(tipo, bloq, cur, NULL, 0, archivo);
		}
		else /* ya no son :: */
			break;
		cur = ++ds;
	}
	if (sp)
	{
		*sp++ = '\0';
		if (BadPtr(sp))
			goto borra;
		if (*sp == CHAR_NUM)
			bloq = InsertaRegistro(tipo, bloq, cur, NULL, atoul(++sp), archivo);
		else
			bloq = InsertaRegistro(tipo, bloq, cur, sp, 0, archivo);
	}
	else
	{
		borra:
		if ((bloq = BuscaBloque(cur, bloq)))
			bloq = BorraRegistro(tipo, bloq, archivo);
	}
	MyFree(cop);
	if (bloq)
		return 0;
	return 1;
}
void CargaBloque(u_int tipo)
{
	UDBloq *root;
	u_long lee, obtiene, trunca = 0L, bytes = 0L;
	char linea[BUFSIZE], *c;
	FILE *fp;
	root = CogeDeId(tipo);
	lee = CogeHash(tipo);
	obtiene = ObtieneHash(root);
	if (lee != obtiene)
	{
		sendto_ops("El bloque %c est� corrupto (%lu != %lu)", root->letra, lee, obtiene);
		if ((fp = fopen(root->path, "wb")))
		{
			fclose(fp);
			ActualizaHash(root);
		}
		if (Servers && !IsMe(Servers->value.cptr))
			sendto_one(Servers->value.cptr, ":%s DB %s RES %c 0", me.name, Servers->value.cptr->name, root->letra);
		return;
	}
	root->gmt = LeeGMT(tipo);
	if ((fp = fopen(root->path, "rb")))
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
			ParseaLinea(tipo, linea, 0);
			bzero(linea, sizeof(linea));
		}
		fclose(fp);
	}
	if (trunca)
		TruncaBloque(&me, &me, root, trunca);
}
void DescargaBloque(u_int tipo)
{
	Udb *aux, *sig;
	UDBloq *root;
	root = CogeDeId(tipo);
	for (aux = root->arbol->down; aux; aux = sig)
	{
		sig = aux->mid;
		BorraRegistro(tipo, aux, 0);
	}
	root->lof = 0L;
	root->regs = 0;
	VaciaHash(tipo);
}
void CargaBloques()
{
	u_int i;
	for (i = 0; i < BDD_TOTAL; i++)
		DescargaBloque(i);
	sendto_ops("Releyendo Bases de Datos...");
	for (i = 0; i < BDD_TOTAL; i++)
		CargaBloque(i);
}
int TruncaBloque(aClient *cptr, aClient *sptr, UDBloq *bloq, u_long bytes)
{
	FILE *fp;
	char *contenido = NULL;
	if ((fp = fopen(bloq->path, "rb")))
	{
		if (bytes)
		{
			contenido = MyMalloc(bytes);
			if (fread(contenido, 1, bytes, fp) != bytes)
			{
				fclose(fp);
				sendto_one(cptr, ":%s DB %s ERR DRP %i %c fread", me.name, sptr->name, E_UDB_FATAL, bloq->letra);
				ircfree(contenido);
				return 1;
			}
		}
		fclose(fp);
		if ((fp = fopen(bloq->path, "wb")))
		{
			if (bytes && fwrite(contenido, 1, bytes, fp) != bytes)
			{
				fclose(fp);
				sendto_one(cptr, ":%s DB %s ERR DRP %i %c fwrite", me.name, sptr->name, E_UDB_FATAL, bloq->letra);
				ircfree(contenido);
				return 1;
			}
			fflush(fp);
			fclose(fp);
			ActualizaHash(bloq);
			DescargaBloque(bloq->id);
			CargaBloque(bloq->id);
		}
		else
		{
			sendto_one(":%s DB %s ERR DRP %i %c fopen(wb)", me.name, sptr->name, E_UDB_NOOPEN, bloq->letra);
			ircfree(contenido);
			return 1;
		}
		ircfree(contenido);
	}
	else
	{
		sendto_one(cptr, ":%s DB %s ERR DRP %i %c fopen(rb)", me.name, sptr->name, E_UDB_NOOPEN, bloq->letra);
		return 1;
	}
	return 0;
}
int OptimizaBloque(UDBloq *bloq)
{
	FILE *fp;
	if (!(fp = fopen(bloq->path, "wb")))
		return 1;
	fclose(fp);
	GuardaEnArchivoInv(bloq->arbol->down, bloq->id);
	ActualizaHash(bloq);
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
 * BCK: hace una copia de una db
 * RST: restaura una copia de una db
 * FHO: fija el tiempo de optimizaci�n
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
			UDBloq *bloq;
			time_t gm;
			u_long crc32;
			if (!(bloq = CogeDeId(*parv[3])))
			{
				sendto_one(cptr, ":%s DB %s ERR RES %i %c", me.name, sptr->name, E_UDB_NODB, *parv[3]);
				return 1;
			}
			gm = atoul(parv[5]);
			sscanf(parv[4], "%lX", &crc32);
			if (crc32 != bloq->crc32)
			{
				if (gm > bloq->gmt)
				{
					TruncaBloque(cptr, sptr, bloq, 0);
					sendto_serv_butone(cptr, ":%s DB * DRP %c 0", parv[0], *parv[3]); /* mandamos en sentido contrario, como si fuera el propio servidor */
					sendto_one(cptr, ":%s DB %s RES %c 0", me.name, parv[0], *parv[3]);
					bloq->res = sptr; /* esperamos su res */
					ActualizaGMT(bloq, gm);
					if (++(sptr->serv->flags.bloqs) == BDD_TOTAL)
						sendto_one(cptr, ":%s %s", me.name, (IsToken(cptr) ? TOK_EOS : MSG_EOS));
				}
				else if (gm == bloq->gmt)
				{
					sendto_one(cptr, ":%s DB %s RES %c %lu", me.name, parv[0], *parv[3], bloq->lof);
					bloq->res = sptr; /* de momento no sabemos si somos los que tenemos menos */
				}
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
			UDBloq *bloq;
			if (!(bloq = CogeDeId(*parv[3])))
			{
				sendto_one(cptr, ":%s DB %s ERR RES %i %c", me.name, sptr->name, E_UDB_NODB, *parv[3]);
				return 1;
			}
			if (bloq->res && bloq->res != sptr)
			{
				sendto_one(cptr, ":%s DB %s ERR RES %i %c", me.name, sptr->name, E_UDB_RPROG, *parv[3]);
				return 1;
			}
			bytes = atoul(parv[4]);
			if (bytes <= bloq->lof) /* tiene menos o los mismos, se los mandamos */
			{
				FILE *fp;
				if ((fp = fopen(bloq->path, "rb")))
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
				}
				else
					sendto_one(cptr, ":%s DB %s ERR RES %i %c", me.name, sptr->name, E_UDB_NOOPEN, *parv[3]);
				sendto_one(cptr, ":%s DB %s FDR %c 0", me.name, sptr->name, *parv[3]);
				bloq->res = NULL; /* OJO! ya hemos terminado, si no se queda esperando */
			}
			 /* esto ya no hace falta */
			//else if (!bytes && !bloq->data_long) /* muy raras veces se daba */
			//	sendto_one(cptr, ":%s DB %s FDR %c 0", me.name, sptr->name, *parv[3]);
			//else /* se comenta porque tal vez no sea rec�proco. en tal caso, se esperan ->res cuando se env�an RES */
			//	bloq->res = sptr; /* esperamos su res */
			if (++(sptr->serv->flags.bloqs) == BDD_TOTAL)
					sendto_one(cptr, ":%s %s", me.name, (IsToken(cptr) ? TOK_EOS : MSG_EOS));
		}
		sendto_serv_butone(cptr, ":%s DB %s RES %c %s", parv[0], parv[1], *parv[3], parv[4]);
	}
	/* DB * INS <offset> <bdd>::a::b::...::item valor */
	else if (!strcasecmp(parv[2], "INS"))
	{
		if (!strcmp(cptr->name, parv[0]) && !cptr->serv->conf->hubmask) /* el nodo emisor no es hub, paramos */
		{
			sendto_one(cptr, ":%s DB %s ERR INS %i", me.name, sptr->name, E_UDB_NOHUB);
			return 0;
		}
		if (!match(parv[1], me.name))
		{
			char buf[1024], *r = parv[4];
			u_long bytes;
			UDBloq *bloq;
			if (parc < 6)
			{
				sendto_one(cptr, ":%s DB %s ERR INS %i", me.name, sptr->name, E_UDB_PARAMS);
				return 1;
			}
			if (!(bloq = CogeDeId(*r)))
			{
				sendto_one(cptr, ":%s DB %s ERR INS %i %c", me.name, sptr->name, E_UDB_NODB, *r);
				return 1;
			}
			bytes = atoul(parv[3]);
			if (bloq->res)
			{
				if (bloq->res != sptr)
				{
					sendto_one(cptr, ":%s DB %s ERR INS %i %c", me.name, sptr->name, E_UDB_RPROG, *r);
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
			if (bytes != bloq->lof)
			{
				sendto_one(cptr, ":%s DB %s ERR INS %i %c %lu", me.name, sptr->name, E_UDB_LEN, *r, bloq->lof);
				/* a partir de este punto el servidor que recibe esta instrucci�n debe truncar su bloque con el valor recibido
				   y propagar el truncado por la red, obviamente en el otro sentido. 
				   Si el nodo que lo ha enviado es un LEAF propagar� un DRP pero que no llegar� a ning�n sitio porque no tiene servidores
				   en el otro sentido. Si es un HUB, tendr� v�a libre para propagar el DRP. 
				   A efectos, ser�a lo mismo que el nodo receptor mandara un DRP, pero as� se ahorra una l�nea ;) */
				return 1;
			}
			r += 3;
			ircsprintf(buf, "%s %s", r, parv[5]);
			if (ParseaLinea(bloq->id, buf, 1))
			{
				sendto_one(cptr, ":%s DB %s ERR INS %i", me.name, sptr->name, E_UDB_REP);
				return 1;
			}
			if (bloq->res == sptr) /* estamos en un resumen, hay que repropagar los registros */
			{
				sendto_serv_butone(cptr, ":%s DB %s INS %s %s %s", propaga->name, parv[1], parv[3], parv[4], parv[5]);
				return 0;
			}
		}
		sendto_serv_butone(cptr, ":%s DB %s INS %s %s %s", parv[0], parv[1], parv[3], parv[4], parv[5]); /* parv[0] siempre es propaga */
	}
	/* DB * DEL <offset> <bdd>::a::b::...::item */
	else if (!strcasecmp(parv[2], "DEL"))
	{
		if (!strcmp(cptr->name, parv[0]) && !cptr->serv->conf->hubmask)
		{
			sendto_one(cptr, ":%s DB %s ERR DEL %i", me.name, sptr->name, E_UDB_NOHUB);
			return 0;
		}
		if (!match(parv[1], me.name))
		{
			char *r = parv[4];
			u_long bytes;
			UDBloq *bloq;
			if (!(bloq = CogeDeId(*r)))
			{
				sendto_one(cptr, ":%s DB %s ERR DEL %i %c", me.name, sptr->name, E_UDB_NODB, *r);
				return 1;
			}
			bytes = atoul(parv[3]);
			if (bloq->res)
			{
				if (bloq->res != sptr)
				{
					sendto_one(cptr, ":%s DB %s ERR DEL %i %c", me.name, sptr->name, E_UDB_RPROG, *r);
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
			if (bytes != bloq->lof)
			{
				sendto_one(cptr, ":%s DB %s ERR DEL %i %c %lu", me.name, sptr->name, E_UDB_LEN, *r, bloq->lof);
				return 1;
			}
			r += 3;
			if (ParseaLinea(bloq->id, r, 1))
			{
				sendto_one(cptr, ":%s DB %s ERR DEL %i", me.name, sptr->name, E_UDB_REP);
				return 1;
			}
			if (bloq->res == sptr) /* estamos en un res */
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
		if (!strcmp(cptr->name, parv[0]) && !cptr->serv->conf->hubmask)
		{
			sendto_one(cptr, ":%s DB %s ERR DRP %i", me.name, sptr->name, E_UDB_NOHUB);
			return 0;
		}
		if (!match(parv[1], me.name))
		{
			u_long bytes;
			UDBloq *bloq;
			if (!(bloq = CogeDeId(*parv[3])))
			{
				sendto_one(cptr, ":%s DB %s ERR DRP %i %c", me.name, sptr->name, E_UDB_NODB, *parv[3]);
				return 1;
			}
			if (bloq->res && bloq->res != sptr)
			{
				sendto_one(cptr, ":%s DB %s ERR DRP %i %c", me.name, sptr->name, E_UDB_RPROG, *parv[3]);
				return 1;
			}
			bytes = atoul(parv[4]);
			if (bytes > bloq->lof)
			{
				sendto_one(cptr, ":%s DB %s ERR DRP %i %c %lu", me.name, sptr->name, E_UDB_LEN, *parv[3], bloq->lof);
				return 1;
			}
			TruncaBloque(cptr, sptr, bloq, bytes);
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
					UDBloq *bloq;
					u_long bytes;
					char *cb;
					bloq = CogeDeId(*parv[5]);
					cb = strchr(parv[5], ' ') + 1; /* esto siempre debe cumplirse, si no a cascar */
					bytes = atoul(cb);
					TruncaBloque(cptr, sptr, bloq, bytes);
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
		UDBloq *bloq;
		if (!strcmp(cptr->name, parv[0]) && !cptr->serv->conf->hubmask)
		{
			sendto_one(cptr, ":%s DB %s ERR OPT %i", me.name, sptr->name, E_UDB_NOHUB);
			return 0;
		}
		if (!(bloq = CogeDeId(*parv[3])))
		{
			sendto_one(cptr, ":%s DB %s ERR OPT %i %c", me.name, sptr->name, E_UDB_NODB, *parv[3]);
			return 1;
		}
		OptimizaBloque(bloq);
		ActualizaGMT(bloq, atoul(parv[4]));
		sendto_serv_butone(cptr, ":%s DB %s OPT %s %s", parv[0], parv[1], parv[3], parv[4]);
	}
	/* DB * FDR <bdd> <NULL> */
	else if (!strcmp(parv[2], "FDR"))
	{
		if (!match(parv[1], me.name))
		{
			UDBloq *bloq;
			if (!(bloq = CogeDeId(*parv[3])))
			{
				sendto_one(cptr, ":%s DB %s ERR FDR %i %c", me.name, sptr->name, E_UDB_NODB, *parv[3]);
				return 1;
			}
			if (bloq->res != sptr)
			{
				sendto_one(cptr, ":%s DB %s ERR FDR %i %c", me.name, sptr->name, E_UDB_NORES, *parv[3]);
				return 1;
			}
			bloq->res = NULL;
		}
		sendto_serv_butone(cptr, ":%s DB %s FDR %s %s", parv[0], parv[1], parv[3], parv[4]);
	}
	/* DB * BCK <bdd> <nombre> */
	else if (!strcmp(parv[2], "BCK"))
	{
		UDBloq *bloq;
		FILE *fp1, *fp2;
		char tmp[BUFSIZE];
		if (!(bloq = CogeDeId(*parv[3])))
		{
			sendto_one(cptr, ":%s DB %s ERR BCK %i %c", me.name, sptr->name, E_UDB_NODB, *parv[3]);
			return 1;
		}
		ircsprintf(tmp, DB_DIR_BCK "%c%s.bck.udb", *parv[3], parv[4]);
		if ((fp1 = fopen(bloq->path, "rb")))
		{
			if ((fp2 = fopen(tmp, "wb")))
			{
#ifdef ZIP_LINKS
				if (zDeflate(fp1, fp2, Z_DEFAULT_COMPRESSION) != Z_OK)
					sendto_one(cptr, ":%s DB %s ERR BCK %i %c zDeflate", me.name, sptr->name, E_UDB_FATAL, *parv[3]);
#else
				size_t leidos;
				while ((leidos = fread(tmp, 1, BUFSIZE, fp1)))
					fwrite(tmp, 1, leidos, fp2);
#endif
				fclose(fp2);
			}
			else
				sendto_one(cptr, ":%s DB %s ERR BCK %i %c", me.name, sptr->name, E_UDB_NOOPEN, *parv[3]);
			fclose(fp1);
		}
		else
			sendto_one(cptr, ":%s DB %s ERR BCK %i %c", me.name, sptr->name, E_UDB_NOOPEN, *parv[3]);
		sendto_serv_butone(cptr, ":%s DB %s BCK %c %s", parv[0], parv[1], *parv[3], parv[4]);
	}
	/* DB * RST <bdd> <nombre> <hora> */
	else if (!strcmp(parv[2], "RST"))
	{
		UDBloq *bloq;
		FILE *fp1, *fp2;
		char tmp[BUFSIZE];
		if (!(bloq = CogeDeId(*parv[3])))
		{
			sendto_one(cptr, ":%s DB %s ERR RST %i %c", me.name, sptr->name, E_UDB_NODB, *parv[3]);
			return 1;
		}
		ActualizaGMT(bloq, atoul(parv[5]));
		ircsprintf(tmp, DB_DIR_BCK "%c%s.bck.udb", *parv[3], parv[4]);
		if ((fp1 = fopen(tmp, "rb")))
		{
			if ((fp2 = fopen(bloq->path, "wb")))
			{
#ifdef ZIP_LINKS
				if (zInflate(fp1, fp2) != Z_OK)
					sendto_one(cptr, ":%s DB %s ERR RST %i %c zInflate", me.name, sptr->name, E_UDB_FATAL, *parv[3]);
#else
				size_t leidos;
				while ((leidos = fread(tmp, 1, BUFSIZE, fp1)))
					fwrite(tmp, 1, leidos, fp2);
#endif
				fclose(fp2);
			}
			fclose(fp1);
			ActualizaHash(bloq);
			/* loop.ircd_rehashing = 1; hay que rehacer los cambios */
			DescargaBloque(bloq->id);
			CargaBloque(bloq->id);
			//loop.ircd_rehashing = 0;
			sendto_serv_butone(cptr, ":%s DB %s RST %c %s %s", parv[0], parv[1], *parv[3], parv[4], parv[5]);
		}
		else
		{
			TruncaBloque(cptr, sptr, bloq, 0);
			sendto_serv_butone(cptr, ":%s DB * DRP %c 0", parv[0], *parv[3]);
			sendto_serv_butone(cptr, ":%s DB * FHO %c %s", parv[0], *parv[3], parv[5]);
			sendto_one(cptr, ":%s DB %s RES %c 0", me.name, parv[0], *parv[3]);
			bloq->res = sptr;
		}
	}
	/* DB * FHO <bdd> <hora> */
	else if (!strcmp(parv[2], "FHO"))
	{
		UDBloq *bloq;
		if (!(bloq = CogeDeId(*parv[3])))
		{
			sendto_one(cptr, ":%s DB %s ERR FHO %i %c", me.name, sptr->name, E_UDB_NODB, *parv[3]);
			return 1;
		}
		ActualizaGMT(bloq, atoul(parv[4]));
		sendto_serv_butone(cptr, ":%s DB * FHO %c %s", parv[0], *parv[3], parv[4]);
	}
	return 0;
}
/* 2 ok
 * 1 suspendido
 * 0 no reg
 * -1 forbid
 * -2 incorrecto
 * -3 no ha dado pass
 * -4 ip no autorizada
 */
int TipoDePass(char *nick, char *pass, Udb *reg, aClient *cptr)
{
	Udb *bloq = NULL, *cha = NULL;
	anAuthStruct *as = NULL;
	int tipo = AUTHTYPE_PLAINTEXT;
	char *frb = NULL, *pas = NULL, *des = NULL, *sus = NULL, *all = NULL;
	Udb *bdd = NULL;
	if (*nick == '#')
	{
		frb = C_FOR_TOK;
		pas = C_PAS_TOK;
		des = C_DES_TOK;
		sus = C_SUS_TOK;
		bdd = UDB_CANALES;
	}
	else
	{
		frb = N_FOR_TOK;
		pas = N_PAS_TOK;
		des = N_DES_TOK;
		sus = N_SUS_TOK;
		all = N_ALL_TOK;
		bdd = UDB_NICKS;
	}
	if (!reg && !(reg = BuscaBloque(nick, bdd)))
		return 0; /* no existe */
	if (BuscaBloque(frb, reg))
		return -1; /* tiene el nick en forbid, no importa la pass */
	if (!(bloq = BuscaBloque(pas, reg)) || BadPtr(bloq->data_char))
		return 0; /* no existe */
	if (!pass)
		return -3;
	if (all && (cha = BuscaBloque(all, reg)) && !BadPtr(cha->data_char))
	{
		struct irc_netmask tmp;
		tmp.type = parse_netmask(cha->data_char, &tmp);
		if (!match_ip(cptr->ip, NULL, NULL, &tmp))
			return -4;
	}
	bzero(buf, sizeof(buf));
	if (!(cha = BuscaBloque(des, reg)) || BadPtr(cha->data_char))
		cha = globdes;
	if (cha && !BadPtr(cha->data_char))
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
		if (BuscaBloque(sus, reg))
			return 1;
		return 2;
	}
	Auth_DeleteAuthStruct(as);
	return -2;
}
CMD_FUNC(m_ghost)
{
	aClient *acptr = NULL;
	Udb *reg = NULL, *breg = NULL;
	char *botname = NULL, who[NICKLEN + 2], nick[NICKLEN + 2], quitbuf[TOPICLEN + 1];
	int val = 0;
	bzero(who, sizeof(who));
   	if ((breg = BuscaBloque(S_NIC_TOK, UDB_SET)) && !BadPtr(breg->data_char))
		botname = breg->data_char;
	else
		botname = me.name;
	if (MyClient(sptr) && sptr->user && !IsAnOper(sptr))
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
	reg = BuscaBloque(nick, UDB_NICKS);
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
	val = TipoDePass(nick, parv[2], reg, cptr);
	if (val < 0)
	{
		if (MyClient(sptr) && sptr->user && !IsAnOper(sptr))
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
	char *cur = NULL, *pos = NULL, *ds = NULL;
	Udb *bloq = NULL;
	UDBloq *root = NULL;
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
		if (strcmp(me.name, parv[1])) /* solo propagamos si el servidor no es exactamente el nuestro */
			sendto_serv_butone(cptr, ":%s DBQ %s %s", parv[0], parv[1], parv[2]);
		if (match(parv[1], me.name))
			return 0;
		parv[1] = parv[2];
	}
	pos = cur = strdup(parv[1]);
	if (!(root = CogeDeId(*pos)))
	{
		sendto_one(sptr, ":%s 339 %s :El bloque %c no existe.", me.name, sptr->name, *pos);
		return 0;
	}
	bloq = root->arbol;
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
				if (!(bloq = BuscaBloque(cur, bloq)))
					goto nobloq;
			}
			else
				break;
			cur = ++ds;
		}
		if (!(bloq = BuscaBloque(cur, bloq)))
		{
			nobloq:
			sendto_one(sptr, ":%s 339 %s :No se encuentra el bloque %s.", me.name, sptr->name, cur);
		}
		else
		{
			if (bloq->data_long)
				sendto_one(sptr, ":%s 339 %s :DBQ %s %lu", me.name, sptr->name, parv[1], bloq->data_long);
			else if (!BadPtr(bloq->data_char))
				sendto_one(sptr, ":%s 339 %s :DBQ %s %s", me.name, sptr->name, parv[1], bloq->data_char);
			else
			{
				Udb *aux;
				for (aux = bloq->down; aux; aux = aux->mid)
				{
					if (aux->data_long)
						sendto_one(sptr, ":%s 339 %s :DBQ %s::%s %lu", me.name, sptr->name, parv[1], aux->item, aux->data_long);
					else if (!BadPtr(aux->data_char))
						sendto_one(sptr, ":%s 339 %s :DBQ %s::%s %s", me.name, sptr->name, parv[1], aux->item, aux->data_char);
					else
						sendto_one(sptr, ":%s 339 %s :DBQ %s::%s (no tiene datos)", me.name, sptr->name, parv[1], aux->item);
				}
			}
		}
	}
	else
		sendto_one(sptr, ":%s 339 %s :%i %i %lu %lu %lX %s", me.name, sptr->name, root->id, root->regs, root->lof, root->gmt, root->crc32, root->res ? "*" : "");
	MyFree(pos);
	return 0;
}
DLLFUNC char *GetVisibleHost(aClient *acptr, aClient *sptr)
{
	if (!IsHidden(acptr) || (sptr && IsShowIp(sptr)) || sptr == acptr)
		return acptr->user->realhost;
	else
	{
		if (BadPtr(acptr->user->virthost))
			acptr->user->virthost = MakeVirtualHost(acptr, acptr->user->realhost, acptr->user->virthost, 0);
		return acptr->user->virthost;
	}
}
/* devuelve el aClient de ChanServ si est� online o no. si est� forzar en 1 lo devuelve indistintamente */
aClient *ChanClient()
{
	char *b, botnick[NICKLEN+1];
	aClient *cptr = NULL;
	Udb *chanserv = NULL;
	bzero(botnick, sizeof(botnick));
	if ((chanserv = BuscaBloque(S_CHA_TOK, UDB_SET)) && !BadPtr(chanserv->data_char))
		strncpy(botnick, chanserv->data_char, sizeof(botnick));
	else
		strncpy(botnick, me.name, sizeof(botnick));
	if ((b = strchr(botnick, '!')))
		*b = '\0';
	if ((cptr = find_client(botnick, NULL)))
		return cptr;
	return &me;
}
char *ChanNick(int forzar)
{
	aClient *cptr = NULL;
	if ((cptr = ChanClient()))
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
				if ((chanserv = BuscaBloque(S_CHA_TOK, UDB_SET)) && !BadPtr(chanserv->data_char))
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
char *ChanMask(int forzar)
{
	aClient *cptr = NULL;
	if ((cptr = ChanClient()) && IsPerson(cptr))
	{
		static char ret[NICKLEN+1+USERLEN+1+HOSTLEN+1];
		ircsprintf(ret, "%s!%s@%s", cptr->name, cptr->username, GetHost(cptr));
		return ret;
	}
	else if (forzar)
	{
		Udb *chanserv;
		if ((chanserv = BuscaBloque(S_CHA_TOK, UDB_SET)) && !BadPtr(chanserv->data_char))
			return chanserv->data_char;
	}
	return me.name;
}
#ifdef ZIP_LINKS
/* rutinas de www.zlib.net */
#define CHUNK 16384
int zDeflate(FILE *source, FILE *dest, int level)
{
    int ret, flush;
    unsigned have;
    z_stream strm;
    unsigned char in[CHUNK];
    unsigned char out[CHUNK];

    /* allocate deflate state */
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    ret = deflateInit(&strm, level);
    if (ret != Z_OK)
        return ret;

    /* compress until end of file */
    do {
        strm.avail_in = fread(in, 1, CHUNK, source);
        if (ferror(source)) {
            (void)deflateEnd(&strm);
            return Z_ERRNO;
        }
        flush = feof(source) ? Z_FINISH : Z_NO_FLUSH;
        strm.next_in = in;

        /* run deflate() on input until output buffer not full, finish
           compression if all of source has been read in */
        do {
            strm.avail_out = CHUNK;
            strm.next_out = out;
            ret = deflate(&strm, flush);    /* no bad return value */
            have = CHUNK - strm.avail_out;
            if (fwrite(out, 1, have, dest) != have || ferror(dest)) {
                (void)deflateEnd(&strm);
                return Z_ERRNO;
            }
        } while (strm.avail_out == 0);

        /* done when last data in file processed */
    } while (flush != Z_FINISH);

    /* clean up and return */
    (void)deflateEnd(&strm);
    return Z_OK;
}
int zInflate(FILE *source, FILE *dest)
{
    int ret;
    unsigned have;
    z_stream strm;
    unsigned char in[CHUNK];
    unsigned char out[CHUNK];

    /* allocate inflate state */
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    strm.avail_in = 0;
    strm.next_in = Z_NULL;
    ret = inflateInit(&strm);
    if (ret != Z_OK)
        return ret;

    /* decompress until deflate stream ends or end of file */
    do {
        strm.avail_in = fread(in, 1, CHUNK, source);
        if (ferror(source)) {
            (void)inflateEnd(&strm);
            return Z_ERRNO;
        }
        if (strm.avail_in == 0)
            break;
        strm.next_in = in;

        /* run inflate() on input until output buffer not full */
        do {
            strm.avail_out = CHUNK;
            strm.next_out = out;
            ret = inflate(&strm, Z_NO_FLUSH);
            switch (ret) {
            case Z_NEED_DICT:
                ret = Z_DATA_ERROR;     /* and fall through */
            case Z_DATA_ERROR:
            case Z_MEM_ERROR:
                (void)inflateEnd(&strm);
                return ret;
            }
            have = CHUNK - strm.avail_out;
            if (fwrite(out, 1, have, dest) != have || ferror(dest)) {
                (void)inflateEnd(&strm);
                return Z_ERRNO;
            }
        } while (strm.avail_out == 0);

        /* done when inflate() says it's done */
    } while (ret != Z_STREAM_END);

    /* clean up and return */
    (void)inflateEnd(&strm);
    return ret == Z_STREAM_END ? Z_OK : Z_DATA_ERROR;
}
#endif
#endif
