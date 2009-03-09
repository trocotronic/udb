/*
 *   Unreal Internet Relay Chat Daemon, src/udb.c
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
 * $Id: udb.c,v 1.1.2.14 2008/04/26 14:48:52 Trocotronic Exp $
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
#include "udb.h"
#ifndef _WIN32
#define O_BINARY 0x0
#else
#define read _read
#define write _write
#define open _open
#define close _close
#define fsync _commit
#define ftruncate _chsize
#endif

/*
 * ----------------------------------------------------------------
 * | u_int id | u_int ver | u_long hash | time_t gmt | ...data... |
 * ----------------------------------------------------------------
 */
#define INI_ID 0
#define INI_VER (INI_ID + sizeof(u_int))
#define INI_HASH (INI_VER + sizeof(u_int))
#define INI_GMT (INI_HASH + sizeof(u_long))
#define INI_DATA (INI_GMT + sizeof(time_t))
#define ircstrdup(x,y) do{ if (x) MyFree(x); if (!y) x = NULL; else x = strdup(y); }while(0)
#define atoul(x) strtoul(x, NULL, 10)
#define ircfree(x) do { if (x) MyFree(x); x = NULL; } while(0)
#define MAX_HASH 2048

Udb *UDB_NICKS = NULL, *UDB_CANALES = NULL, *UDB_IPS = NULL, *UDB_SET = NULL, *UDB_LINKS = NULL, *UDB_LINES = NULL;
#ifdef UDB_HASH
Udb ***hash;
#endif
UDBloq *ultimo = NULL;
UDBloq *N = NULL, *C = NULL, *S = NULL, *I = NULL, *L = NULL, *K = NULL;
extern char modebuf[BUFSIZE], parabuf[BUFSIZE];
void CargaBloques(void);
static char buf[BUFSIZE];
static int BDD_TOTAL = 0;
char *grifo = NULL;
aClient *propaga = NULL;
static Udb *globdes = NULL;
int pases = 3, intervalo = 60;
char *pfxs = NULL;
char PF_VOICE, PF_HALF, PF_OP, PF_ADMIN, PF_OWN;

#ifdef DEBUGMODE
void printea(Udb *, int);
#endif
int SetDataVer(u_int);
int CogeDataVer();
UDBloq *CogeDeId(u_int);
Udb *BorraRegistro(u_int, Udb *, int);
int ActualizaDataVer2(), ActualizaDataVer3(), ActualizaDataVer4();
#ifdef ZIP_LINKS
int zDeflate(int , FILE *, int);
int zInflate(FILE * , FILE *);
#endif

extern char *unrealdns_findcache_byaddr(struct IN_ADDR *);
extern DNSCache *unrealdns_findcache_byaddr_dns(struct IN_ADDR *);
extern void unrealdns_addtocache(char *, void *, int);
extern void unrealdns_removecacherecord(DNSCache *);
extern aClient *find_server_quick_straight(char *);
extern void set_channelmodes(char *, struct ChMode *, int);
void PonPfxs();

UDBloq *AltaBloque(char letra, char *ruta, Udb **dest)
{
	u_int id = 0;
	UDBloq *reg;
	if (ultimo)
		id = ultimo->id + 1;
	reg = (UDBloq *)MyMalloc(sizeof(UDBloq));
	reg->arbol = (Udb *)MyMalloc(sizeof(Udb));
	reg->arbol->id = id;
	reg->arbol->up = NULL;
	reg->arbol->down = NULL;
	reg->arbol->mid = NULL;
#ifdef UDB_HASH
	reg->arbol->hsig = NULL;
#endif
	reg->arbol->item = NULL;
	reg->arbol->data_char = NULL;
	reg->arbol->data_long = 0L;
	reg->crc32 = 0L;
	reg->id = id;
	reg->lof = 0L;
	reg->letra = letra;
	reg->path = ruta;
	reg->regs = 0;
	reg->gmt = 0L;
	reg->res = NULL;
	reg->ver = 0;
	*dest = reg->arbol;
	reg->sig = ultimo;
	ultimo = reg;
	BDD_TOTAL++;
	return reg;
}
#ifdef UDB_HASH
void VaciaHash(int id)
{
	int i;
	for (i = 0; i < MAX_HASH; i++)
		hash[id][i] = NULL;
}
void AltaHash()
{
	UDBloq *reg;
	u_int id;
	hash = (Udb ***)MyMalloc(sizeof(Udb **) * BDD_TOTAL);
	for (reg = ultimo; reg; reg = reg->sig)
	{
		id = reg->id;
		hash[id] = (Udb **)MyMalloc(sizeof(Udb *) * MAX_HASH);
		VaciaHash(id);
	}
}
#endif
#ifndef _WIN32
#define PMAX PATH_MAX
#else
#define PMAX MAX_PATH
#endif
int IniciaUDB()
{
	int dataver;
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
	if (!L)
		L = AltaBloque('L', DB_DIR "links.udb", &UDB_LINKS);
	if (!K)
		K = AltaBloque('K', DB_DIR "lines.udb", &UDB_LINES);
#ifdef UDB_HASH
	AltaHash();
#endif
	/* compatibilidad */
	switch ((dataver = CogeDataVer()))
	{
		case 0:
		case 1:
			ActualizaDataVer2();
		case 2:
			ActualizaDataVer3();
		case 3:
			ActualizaDataVer4();
	}
	CargaBloques();
	SetDataVer(5);
	if (!pfxs)
	{
		ircstrdup(pfxs, "~&@%+");
		PonPfxs();
	}
	return 1;
}
u_long ObtieneHash(UDBloq *bloq)
{
	char *par;
	struct stat inode;
	u_long crc32 = 0L;
	size_t t;
	if (fstat(bloq->fd, &inode) < 0)
		return 0L;
	t = inode.st_size - INI_DATA;
	if (t <= 0)
		return 0L;
	par = MyMalloc(t);
	lseek(bloq->fd, INI_DATA, SEEK_SET);
	if (read(bloq->fd, par, t) == t)
		crc32 = our_crc32(par, t);
	MyFree(par);
	return crc32;
}
int ActualizaHash(UDBloq *bloq)
{
	struct stat inode;
	bloq->crc32 = ObtieneHash(bloq);
	if (lseek(bloq->fd, INI_HASH, SEEK_SET) < 0)
		return 0;
	if (write(bloq->fd, &bloq->crc32, sizeof(bloq->crc32)) < 0)
		return 0;
	fsync(bloq->fd);
	if (fstat(bloq->fd, &inode) < 0)
		return 0;
	bloq->lof = inode.st_size - INI_DATA;
	return 1;
}
int CogeDataVer()
{
	FILE *fcrc;
	int dataver;
	if ((fcrc = fopen(DB_DIR "crcs", "r+b")))
	{
		char ver[3];
		if (fseek(fcrc, 72, SEEK_SET))
		{
			fclose(fcrc);
			return 0;
		}
		bzero(ver, 3);
		fread(ver, 1, 2, fcrc);
		fclose(fcrc);
		unlink(DB_DIR "crcs");
		if (!sscanf(ver, "%X", &dataver))
			return 0;
		return dataver;
	}
	return -1;
}
int SetDataVer(u_int v)
{
	UDBloq *bloq;
	for (bloq = ultimo; bloq; bloq = bloq->sig)
	{
		lseek(bloq->fd, INI_VER, SEEK_SET);
		if (write(bloq->fd, &v, sizeof(v)) < 0)
			return 0;
		fsync(bloq->fd);
	}
	return 1;
}
int ActualizaGMT(UDBloq *bloq, time_t gm)
{
	time_t hora = gm ? gm : time(0);
	lseek(bloq->fd, INI_GMT, SEEK_SET);
	if (write(bloq->fd, &hora, sizeof(hora)) < 0)
		return 0;
	fsync(bloq->fd);
	bloq->gmt = hora;
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
#ifdef UDB_HASH
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
#endif
Udb *BuscaBloque(char *clave, Udb *sup)
{
	Udb *aux;
#ifdef UDB_HASH
	u_int hashv;
	if (!clave)
		return NULL;
	hashv = hash_nick_name(clave) % MAX_HASH;
	for (aux = hash[sup->id][hashv]; aux; aux = aux->hsig)
	{
		//if ((*(clave+1) == '\0' && !complow(aux->id, *clave)) || !compara(clave, aux->item))
		if (aux->up == sup && !strcasecmp(clave, aux->item))
			return aux;
	}
#else
	if (!clave)
		return NULL;
	for (aux = sup->down; aux; aux = aux->mid)
	{
		if (!BadPtr(aux->item) && !strcasecmp(clave, aux->item))
			return aux;
	}
#endif
	return NULL;
}
Udb *CreaRegistro(Udb *bloque)
{
	Udb *reg;
	reg = (Udb *)MyMalloc(sizeof(Udb));
#ifdef UDB_HASH
	reg->hsig = (Udb *)NULL;
#endif
	reg->data_char = reg->item = (char *)NULL;
	reg->data_long = 0L;
	reg->id = 0;
	reg->down = NULL;
	reg->up = bloque;
	reg->b64 = 0;
	reg->mid = bloque->down;
	bloque->down = reg;
	return reg;
}
Udb *DaFormato(char *form, Udb *reg, size_t t)
{
	Udb *root = NULL;
	form[0] = '\0';
	if (reg->up)
		root = DaFormato(form, reg->up, t);
	else
		return reg;
	if (!BadPtr(reg->item))
	{
		if (reg->b64)
		{
			char tmp[BUFSIZE];
			b64_encode(reg->item, strlen(reg->item), &tmp[1], BUFSIZE-1);
			tmp[0] = CHAR_B64;
			strlcat(form, tmp, t);
		}
		else
			strlcat(form, reg->item, t);
	}
	if (reg->down)
		strlcat(form, "::", t);
	else
	{
		if (reg->data_char)
		{
			strlcat(form, " ", t);
			if (*reg->data_char == CHAR_NUM)
				strlcat(form, "\\", t);
			strlcat(form, reg->data_char, t);
		}
		else if (reg->data_long)
		{
			char tmp[32];
			sprintf(tmp, " %c%lu", CHAR_NUM, reg->data_long);
			strlcat(form, tmp, t);
		}
	}
	return root ? root : reg;
}
int GuardaEnArchivo(Udb *reg, u_int tipo)
{
	char form[BUFSIZE];
	UDBloq *bloq;
	if (!(bloq = CogeDeId(tipo)))
		return 0;
	form[0] = '\0';
	DaFormato(form, reg, sizeof(form));
	strlcat(form, "\n", sizeof(form));
	lseek(bloq->fd, 0, SEEK_END);
	if (write(bloq->fd, form, sizeof(char) * strlen(form)) < 0)
		return 0;
	return 1;
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
int FijaCabecera(UDBloq *bloq)
{
	int fd;
	char path[BUFSIZE];
	size_t len = 0;
	u_long hash = 0L, gmt = 0L;
	u_int ver = 1;
	ircsprintf(path, "%s.tmp", bloq->path);
	if ((fd = open(path, O_CREAT | O_BINARY | O_RDWR, 0600)) < 0)
		return 0;
	if (write(fd, &bloq->id, sizeof(bloq->id)) < 0)
		return 0;
	if (write(fd, &ver, sizeof(ver)) < 0)
		return 0;
	if (write(fd, &hash, sizeof(hash)) < 0)
		return 0;
	if (write(fd, &gmt, sizeof(gmt)) < 0)
		return 0;
	lseek(bloq->fd, 0, SEEK_SET);
	while ((len = read(bloq->fd, buf, sizeof(buf))) > 0)
		write(fd, buf, len);
	fsync(bloq->fd);
	close(bloq->fd);
	close(fd);
	if (unlink(bloq->path) < 0)
		return 0;
	if (rename(path, bloq->path) < 0)
		return 0;
	if ((bloq->fd = open(bloq->path, O_CREAT | O_BINARY | O_RDWR, 0600)) < 0)
		return 0;
	ActualizaHash(bloq);
	return 1;
}
int CargaCabecera(UDBloq *bloq)
{
	u_int id;
	struct stat inode;
	if ((bloq->fd = open(bloq->path, O_CREAT | O_BINARY | O_RDWR, 0600)) < 0)
		return 0;
	if (read(bloq->fd, &id, sizeof(id)) < 0)
		return 0;
	if (id != bloq->id && !FijaCabecera(bloq))
		return 0;
	lseek(bloq->fd, INI_VER, SEEK_SET);
	if (read(bloq->fd, &bloq->ver, sizeof(bloq->ver)) < 0)
		return 0;
	if (read(bloq->fd, &bloq->crc32, sizeof(bloq->crc32)) < 0)
		return 0;
	if (read(bloq->fd, &bloq->gmt, sizeof(bloq->gmt)) < 0)
		return 0;
	if (fstat(bloq->fd, &inode) < 0)
		return 0;
	bloq->lof = inode.st_size - INI_DATA;
	return 1;
}
int CargaBloque(u_int tipo)
{
	UDBloq *bloq;
	u_long obtiene, bytes = 0L;
	char linea[BUFSIZE], c;
	int i = 0;
	if (!(bloq = CogeDeId(tipo)))
	{
		ircsprintf(buf, "Ha sido imposible cargar el bloque %i", tipo);
		sendto_ops(buf);
/*
		if (!loop.ircd_rehashing)
#ifdef _WIN32
			MessageBox(NULL, buf, "Archivo corrupto", MB_OK);
#else
			fprintf(stderr, buf);
#endif
*/
		return 0;
	}
	CargaCabecera(bloq);
	obtiene = ObtieneHash(bloq);
	if (bloq->crc32 != obtiene)
	{
		ircsprintf(buf, "El bloque %c está corrupto (%lu != %lu)", bloq->letra, bloq->crc32, obtiene);
		sendto_ops(buf);
/*
		if (!loop.ircd_rehashing)
#ifdef _WIN32
			MessageBox(NULL, buf, "Archivo corrupto", MB_OK);
#else
			fprintf(stderr, buf);
#endif
*/
		ftruncate(bloq->fd, INI_DATA);
		ActualizaHash(bloq);
		if (Servers && !IsMe(Servers->value.cptr))
			sendto_one(Servers->value.cptr, ":%s DB %s RES %c 0", me.name, Servers->value.cptr->name, bloq->letra);
		return 0;
	}
	lseek(bloq->fd, INI_DATA, SEEK_SET);
	while (read(bloq->fd, &c, sizeof(c)) > 0)
	{
		if (c == '\r' || c == '\n')
		{
			linea[i] = '\0';
			bytes += strlen(linea) + 1;
			ParseaLinea(bloq, linea, 0);
			i = 0;
		}
		else
			linea[i++] = c;
	}
	if (i)
		TruncaBloque(bloq, bytes);
	return 1;
}
void DescargaBloque(u_int tipo)
{
	Udb *aux, *sig;
	UDBloq *root;
	if (!(root = CogeDeId(tipo)))
		return;
	for (aux = root->arbol->down; aux; aux = sig)
	{
		sig = aux->mid;
		BorraRegistro(tipo, aux, 0);
	}
	root->lof = 0L;
	root->regs = 0;
#ifdef UDB_HASH
	VaciaHash(tipo);
#endif
	close(root->fd);
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
int TruncaBloque(UDBloq *bloq, u_long bytes)
{
	if (ftruncate(bloq->fd, INI_DATA + bytes) < 0)
		return 0;
	ActualizaHash(bloq);
	DescargaBloque(bloq->id);
	CargaBloque(bloq->id);
	return 1;
}
int OptimizaBloque(UDBloq *bloq)
{
	if (ftruncate(bloq->fd, INI_DATA) < 0)
		return 0;
	GuardaEnArchivoInv(bloq->arbol->down, bloq->id);
	ActualizaHash(bloq);
	return 1;
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
			{
				if (acptr->user->virthost)
					MyFree(acptr->user->virthost);
				acptr->user->virthost = NULL;
			}
		}
	}
}
/*int mira_id(char id, char *tok)
{
	return (id == *tok);
}*/
void DaleVhost(aClient *sptr)
{
	if (!IsARegNick(sptr) || !sptr->user)
		return;
	sptr->user->virthost = MakeVirtualHost(sptr, sptr->user->realhost, sptr->user->virthost, 1);
}
void QuitaleVhost(aClient *sptr, Udb *reg, Udb *bloq)
{
	char *tmp = NULL;
	if (!IsARegNick(sptr))
		return;
	if (!bloq)
	{
		if (!reg && !(reg = BuscaBloque(sptr->name, UDB_NICKS)))
			return;
		if (!(bloq = BuscaBloque(N_VHO, reg)))
			return;
	}
	tmp = bloq->data_char;
	bloq->data_char = NULL;
	sptr->user->virthost = MakeVirtualHost(sptr, sptr->user->realhost, sptr->user->virthost, 1);
	bloq->data_char = tmp;
}
void DaleModos(aClient *sptr, Udb *reg, Udb *bloq, char *modos)
{
	char *cur;
	if (modos)
		cur = modos;
	else
	{
		if (!bloq)
		{
			if (!reg && !(reg = BuscaBloque(sptr->name, UDB_NICKS)))
				return;
			if (!(bloq = BuscaBloque(N_MOD, reg)))
				return;
		}
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
void QuitaleModos(aClient *sptr, Udb *reg, Udb *bloq, char *modos)
{
	char *cur;
	if (modos)
		cur = modos;
	else
	{
		if (!bloq)
		{
			if (!reg && !(reg = BuscaBloque(sptr->name, UDB_NICKS)))
				return;
		 	if (!(bloq = BuscaBloque(N_MOD, reg)))
				return;
		}
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
void DaleOper(aClient *sptr, Udb *reg, Udb *bloq)
{
	u_long nivel;
	if (!bloq)
	{
		if (!reg && !(reg = BuscaBloque(sptr->name, UDB_NICKS)))
			return;
		if (!(bloq = BuscaBloque(N_OPE, reg)))
			return;
	}
	nivel = bloq->data_long;
	if (nivel & BDD_OPER)
	{
		DaleModos(sptr, reg, NULL, "h");
		if (MyClient(sptr))
			sptr->oflag |= OFLAG_HELPOP;
	}
	if (nivel & BDD_ADMIN)
	{
		DaleModos(sptr, reg, NULL, "oa");
		if (MyClient(sptr))
			sptr->oflag |= (OFLAG_NADMIN | OFLAG_ISGLOBAL | OFLAG_ZLINE);
	}
	if (nivel & BDD_ROOT)
	{
		DaleModos(sptr, reg, NULL, "oN");
		if (MyClient(sptr))
			sptr->oflag |= (OFLAG_NADMIN | OFLAG_ISGLOBAL | OFLAG_ZLINE | OFLAG_DIE | OFLAG_RESTART | OFLAG_ADDLINE);
	}
}
void QuitaleOper(aClient *sptr, Udb *reg, Udb *bloq)
{
	u_long nivel;
	if (!bloq)
	{
		if (!reg && !(reg = BuscaBloque(sptr->name, UDB_NICKS)))
			return;
		if (!(bloq = BuscaBloque(N_OPE, reg)))
			return;
	}
	nivel = bloq->data_long;
	if (nivel & BDD_OPER)
	{
		QuitaleModos(sptr, reg, NULL, "h");
		if (MyClient(sptr))
			sptr->oflag &= ~OFLAG_HELPOP;
	}
	if (nivel & BDD_ADMIN)
	{
		QuitaleModos(sptr, reg, NULL, "oa");
		if (MyClient(sptr))
			sptr->oflag &= ~(OFLAG_NADMIN | OFLAG_NADMIN | OFLAG_ZLINE);
	}
	if (nivel & BDD_ROOT)
	{
		QuitaleModos(sptr, reg, NULL, "oN");
		if (MyClient(sptr))
			sptr->oflag &= ~(OFLAG_NADMIN | OFLAG_ISGLOBAL | OFLAG_ZLINE | OFLAG_DIE | OFLAG_RESTART | OFLAG_ADDLINE);
	}
}
void DaleSwhois(aClient *sptr, Udb *reg, Udb *bloq)
{
	if (!bloq)
	{
		if (!reg && !(reg = BuscaBloque(sptr->name, UDB_NICKS)))
			return;
		if (!(bloq = BuscaBloque(N_SWO, reg)))
			return;
	}
	ircstrdup(sptr->user->swhois, bloq->data_char);
}
void QuitaleSwhois(aClient *sptr, Udb *reg, Udb *bloq)
{
	if (!bloq)
	{
		if (!reg && !(reg = BuscaBloque(sptr->name, UDB_NICKS)))
			return;
		if (!(bloq = BuscaBloque(N_SWO, reg)))
			return;
	}
	MyFree(sptr->user->swhois);
	sptr->user->swhois = NULL;
}
void DaleSnomasks(aClient *sptr, Udb *reg, Udb *bloq)
{
	if (!MyClient(sptr))
		return;
	if (!bloq)
	{
		if (!reg && !(reg = BuscaBloque(sptr->name, UDB_NICKS)))
			return;
		if (!(bloq = BuscaBloque(N_SNO, reg)))
			return;
	}
	set_snomask(sptr, bloq->data_char);
	if (sptr->user->snomask)
	{
		sptr->user->snomask |= SNO_SNOTICE;
		sptr->umodes |= UMODE_SERVNOTICE;
	}
}
void QuitaleSnomasks(aClient *sptr, Udb *reg, Udb *bloq)
{
	if (MyClient(sptr))
		return;
	if (!bloq)
	{
		if (!reg && !(reg = BuscaBloque(sptr->name, UDB_NICKS)))
			return;
		if (!(bloq = BuscaBloque(N_SNO, reg)))
			return;
	}
	buf[0] = '-';
	strcpy(&buf[1], bloq->data_char);
	set_snomask(sptr, buf);
}
/* mira los servidores linkados localmente y si uno es debug, le manda la linea */
void EnviaADebugs(aClient *sptr, int comando, char *param)
{
	int i;
	aClient *acptr;
	Udb *reg, *bloq;
	if (BadPtr(param))
		return;
	for (i = LastSlot; i >= 0; i--)
	{
		if ((acptr = local[i]) && IsServer(acptr) && MyConnect(acptr) && (acptr != sptr))
		{
			if ((reg = BuscaBloque(acptr->name, UDB_LINKS)) && (bloq = BuscaBloque(L_OPT, reg)) && (bloq->data_long & L_OPT_DEBG))
			{
				switch(comando)
				{
					case 1:
						if (!SupportUMODE2(acptr))
							sendto_one(acptr, ":%s MODE %s :%s", sptr->name, sptr->name, param);
						else
							sendto_one(acptr, ":%s %s %s", sptr->name, (IsToken(acptr) ? TOK_UMODE2 : MSG_UMODE2), param);
						break;
					case 2:
						sendto_one(acptr, ":%s %s %s", sptr->name, (IsToken(acptr) ? TOK_SETHOST : MSG_SETHOST), param);
						break;
				}
			}
		}
	}
}
void DaleCosas(int pass, aClient *sptr, Udb *reg, char *umodebuf)
{
	u_long viejos = 0L;
	if (!reg && !(reg = BuscaBloque(sptr->name, UDB_NICKS)))
		return;
	viejos = sptr->umodes;
	if (pass == 2)
	{
		sptr->umodes |= UMODE_REGNICK;
		DaleModos(sptr, reg, NULL, NULL);
		DaleOper(sptr, reg, NULL);
		if (MyClient(sptr) && IsPerson(sptr))
		{
			DaleSwhois(sptr, reg, NULL);
			DaleSnomasks(sptr, reg, NULL);
		}
		if (BuscaBloque(N_VHO, reg))
			sptr->umodes |= UMODE_SETHOST;
	}
	else if (pass == 1)
		sptr->umodes |= UMODE_SUSPEND;
	if (!umodebuf)
		umodebuf = buf;
	send_umode(MyClient(sptr) ? sptr->from : NULL, sptr, viejos, SEND_UMODES|UMODE_SERVNOTICE, umodebuf);
	if (sptr->from)
		EnviaADebugs(sptr, 1, umodebuf);
}
void QuitaleCosas(aClient *sptr, Udb *reg)
{
	Udb *bloq;
	u_long viejos;
	char umodebuf[128]; /* hay de sobras */
	if (!reg && !(reg = BuscaBloque(sptr->name, UDB_NICKS)))
		return;
	viejos = sptr->umodes;
	sptr->umodes &= ~(UMODE_REGNICK | UMODE_SUSPEND | UMODE_SETHOST);
	QuitaleModos(sptr, reg, NULL, NULL);
	QuitaleOper(sptr, reg, NULL);
	if (MyClient(sptr))
	{
		QuitaleSwhois(sptr, reg, NULL);
		QuitaleSnomasks(sptr, reg, NULL);
	}
	send_umode(MyClient(sptr) ? sptr->from : NULL, sptr, viejos, SEND_UMODES|UMODE_SERVNOTICE, umodebuf);
	if (sptr->from)
		EnviaADebugs(sptr, 1, umodebuf);
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
int InsertaRegistroEspecial(u_int tipo, Udb *reg, int nuevo)
{
	if (loop.ircd_rehashing && tipo != I->id && tipo != S->id) /* si estamos refrescando, no tocamos nada */
		return 1;
	if (tipo == C->id)
	{
		aChannel *chptr;
		Udb *root = reg;
		char *botnick = BotNick(S_CHA, 1), *botmask = BotMask(S_CHA, 1);
		while (root->item && *root->item != '#')
		{
			if (!(root = root->up))
				return 0;
		}
		if (!root->item)
			return 0;
		buf[0] = '+';
		buf[1] = '\0';
		chptr = get_channel(&me, root->item, CREATE);
		if (!(chptr->mode.mode & MODE_RGSTR))
		{
			chptr->mode.mode |= MODE_RGSTR;
			strcat(buf, "r");
		}
		if (!strcmp(reg->item, C_MOD))
		{
			char *modos = reg->data_char;
			struct ChMode store;
			if (BadPtr(modos))
				return 0;
			if (*modos == '+')
				modos++;
			memset(&store, 0, sizeof(struct ChMode));
			set_channelmodes(modos, &store, 0);
			if (nuevo) /* añadimos modos */
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
		else if (!strcmp(reg->item, C_TOP))
		{
			int topiclen;
			int nicklen;
			char *tmp;
			if (BadPtr(reg->data_char))
				return 0;
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
				if (chptr->users)
					sendto_channel_butserv(chptr, &me, ":%s TOPIC %s :%s", botmask, chptr->chname, chptr->topic);
			}
			MyFree(tmp);
		}
		if (!chptr->creationtime)
			chptr->creationtime = TStime();
		if (buf[1] && chptr->users)
			sendto_channel_butserv(chptr, &me, ":%s MODE %s %s", botmask, chptr->chname, buf);
	}
	else if (tipo == S->id)
	{
		if (!loop.ircd_rehashing  && !strcmp(reg->item, S_CLA) || !strcmp(reg->item, S_SUF))
			RegeneraClaves();
		else if (!strcmp(reg->item, S_DES))
			globdes = reg;
		else if (!strcmp(reg->item, S_FLO))
			config_parse_flood(reg->data_char, &pases, &intervalo);
		else if (!strcmp(reg->item, S_PRE))
		{
			ircstrdup(pfxs, reg->data_char);
			PonPfxs();
		}
	}
	else if (tipo == N->id)
	{
		aClient *sptr = NULL;
		Udb *root = reg;
		u_long viejos;
		char umodebuf[128];
		while (root)
		{
			if (!root->up->up)
				break;
			root = root->up;
		}
		if (!(sptr = find_client(root->item, NULL)))
			return 1; /* si no está online da igual */
		viejos = sptr->umodes;
		sptr->umodes |= UMODE_REGNICK;
		if (!strcmp(reg->item, N_VHO))
			DaleVhost(sptr);
		else if (!strcmp(reg->item, N_MOD))
			DaleModos(sptr, NULL, reg, NULL);
		else if (!strcmp(reg->item, N_SNO))
			DaleSnomasks(sptr, NULL, reg);
		else if (!strcmp(reg->item, N_OPE))
			DaleOper(sptr, NULL, reg);
		else if (!strcmp(reg->item, N_SWO))
			DaleSwhois(sptr, NULL, reg);
		else if (!strcmp(reg->item, N_SUS))
		{
			QuitaleCosas(sptr, reg->up);
			sptr->umodes |= UMODE_SUSPEND;
		}
		send_umode(MyClient(sptr) && IsPerson(sptr) ? sptr->from : NULL, sptr, viejos, SEND_UMODES, umodebuf);
		if (sptr->from)
			EnviaADebugs(sptr, 1, umodebuf);
	}
	else if (tipo == I->id)
	{
		/* es necesario regenerarlo después de un rehash porque se borra */
		if (!strcmp(reg->item, I_NOL))
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
		else if (!loop.ircd_rehashing && !strcmp(reg->item, I_HOS))
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
	else if (tipo == L->id)
	{
		aClient *sptr = NULL;
		if (!strcmp(reg->item, L_OPT) && (reg->data_long & L_OPT_PROP))
		{
			if (grifo && strcasecmp(reg->up->item, grifo))
				return 0;
			ircstrdup(grifo, reg->up->item);
			if ((sptr = find_server_quick_straight(grifo)))
				propaga = sptr;
		}
	}
	else if (tipo == K->id)
	{
		if (!strcmp(reg->item, K_RAZ)) /* entra la razón, ejecutamos la *line */
		{
			int type;
			aTKline *tk;
			if (*reg->up->up->item == 'F')
			{
				Udb *acc, *tip, *tklt;
				unsigned long dur = 0L;
				if ((acc = BuscaBloque(K_ACC, reg->up)) && (tip = BuscaBloque(K_TIP, reg->up)))
				{
					tklt = BuscaBloque(K_TKL, reg->up);
					tk = tkl_add_line(TKL_SPAMF|TKL_GLOBAL, tip->data_char, acc->data_char, reg->up->item, me.name, 0, 0, tklt ? tklt->data_long : 0, unreal_encodespace(reg->data_char));
				}
			}
			else
			{
				//char tip = (*reg->up->up->item == 'G' ? 'K' : *reg->up->up->item);
				char tip = *reg->up->up->item;
				for (tk = tklines[tkl_hash(tip)]; tk; tk = tk->next)
		 		{
			  		if (!strcmp(tk->hostmask, reg->up->item) && !strcmp(tk->usermask, "*"))
				  	{
				  		ircstrdup(tk->reason, reg->data_char);
				  		return 1;
				  	}
				}
				if (*reg->up->up->item == 'G')
					type = TKL_KILL|TKL_GLOBAL;
				else if (*reg->up->up->item == 'Z')
					type = TKL_ZAP|TKL_GLOBAL;
				else if (*reg->up->up->item == 'S')
					type = TKL_SHUN|TKL_GLOBAL;
				if (*reg->up->up->item == 'Q')
					tk = tkl_add_line(TKL_NICK|TKL_GLOBAL, "H", reg->up->item, reg->data_char, me.name, 0, 0, 0, NULL);
				else
					tk = tkl_add_line(type, "*", reg->up->item, reg->data_char, me.name, 0, 0, 0, NULL);
				loop.do_bancheck = 1;
			}
		}
	}
	return 1;
}
void BorraRegistroEspecial(u_int tipo, Udb *reg)
{
	Udb *bloq = NULL;
	if (loop.ircd_rehashing) /* si estamos refrescando, no tocamos nada */
		return;
	if (tipo == C->id)
	{
		aChannel *chptr;
		Udb *root = reg;
		while (root->item && *root->item != '#')
		{
			if (!(root = root->up))
				return;
		}
		if (!(chptr = get_channel(&me, root->item, !CREATE)))
			return;
/*		if (!strcmp(C_MOD, reg->item) || (*reg->item == '#' && (bloq = BuscaBloque(C_MOD, reg))))
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
		if (!strcmp(C_TOP, reg->item) || (*reg->item == '#' && (bloq = BuscaBloque(C_TOP, reg))))
		{
			if (chptr->topic)
			{
				MyFree(chptr->topic);
				chptr->topic = NULL;
				chptr->topic_time = 0;
			}
		}*/
		if (*reg->item == '#')
		{
			chptr->mode.mode &= ~MODE_RGSTR;
			if (!chptr->users) /* si hay gente no tocamos nada */
				sub1_from_channel(chptr);
			else
				sendto_channel_butserv(chptr, &me, ":%s MODE %s -r", BotMask(S_CHA, 1), chptr->chname);
		}
	}
	else if (tipo == N->id)
	{
		aClient *sptr = NULL;
		Udb *root = reg;
		char umodebuf[128];
		while (root)
		{
			if ((sptr = find_client(root->item, NULL)))
				break;
			root = root->up;
		}
		if (!sptr)
			return;
		if (!strcmp(reg->item, N_VHO))
			QuitaleVhost(sptr, NULL, reg);
		else if (!strcmp(reg->item, N_SNO))
			QuitaleSnomasks(sptr, NULL, reg);
		else if (!strcmp(reg->item, N_OPE))
			QuitaleOper(sptr, NULL, reg);
		else if (!strcmp(reg->item, N_MOD))
			QuitaleModos(sptr, NULL, reg, NULL);
		else if (!strcmp(reg->item, N_SWO))
			QuitaleSwhois(sptr, NULL, reg);
		else if (!strcmp(reg->item, N_SUS))
		{
			u_long viejos = sptr->umodes;
			sptr->umodes &= ~UMODE_SUSPEND;
			send_umode(MyClient(sptr) && IsPerson(sptr) ? sptr->from : NULL, sptr, viejos, SEND_UMODES, umodebuf);
			if (sptr->from)
				EnviaADebugs(sptr, 1, umodebuf);
		}
		else if (!strcasecmp(sptr->name, reg->item))
			QuitaleCosas(sptr, reg);

	}
	else if (tipo == I->id)
	{
		if (!strcmp(reg->item, I_HOS))
			QuitaleDns(reg->up->item);
		else if (!strcmp(reg->item, I_NOL))
			QuitaleExc(reg->up->item);
		else if (!reg->up->up)
			QuitaleIps(reg->item);
	}
	else if (tipo == S->id)
	{
		if (!strcmp(reg->item, S_DES))
			globdes = NULL;
		else if (!strcmp(reg->item, S_FLO))
			intervalo = pases = 0;
		else if (!strcmp(reg->item, S_PRE))
		{
			ircstrdup(pfxs, "~&@%+");
			PonPfxs();
		}
	}
	else if (tipo == L->id)
	{
		if (!strcmp(reg->item, L_OPT) && !(reg->data_long & L_OPT_PROP))
		{
			ircfree(grifo);
			propaga = NULL;
		}
	}
	else if (tipo == K->id)
	{
		aTKline *tk, *sig;
		int m = 0;
		if (!reg->up->up) /* un subloque */ /* NO CAMBIAR DE ORDEN O PETARA */
		{
			Udb *tmp;
			for (tmp = reg->down; tmp; tmp = tmp->mid)
			{
				//char tip = (*reg->item == 'G' ? 'K' : *reg->item);
				char tip = *reg->item;
				m = 0;
				for (tk = tklines[tkl_hash(tip)]; tk; tk = sig)
				{
					sig = tk->next;
					if (*reg->item == 'F' && !stricmp(tk->reason, tmp->item))
						m = 1;
					else if (*reg->item == 'Q' && !stricmp(tk->hostmask, tmp->item))
						m = 1;
					else if (!stricmp(tk->hostmask, tmp->item) && !strcmp(tk->usermask, "*"))
						m = 1;
					if (m)
					{
						if (*reg->item == 'S')
							tkl_check_local_remove_shun(tk);
						tkl_del_line(tk);
						break;
					}
				}
			}
		}
		else if (!reg->up->up->up) /* un registro */
		{
			//char tip = (*reg->up->item == 'G' ? 'K' : *reg->up->item);
			char tip = *reg->up->item;
			for (tk = tklines[tkl_hash(tip)]; tk; tk = tk->next)
			{
				if (*reg->up->item == 'F' && !stricmp(tk->reason, reg->item))
					m = 1;
				else if (*reg->up->item == 'Q' && !stricmp(tk->hostmask, reg->item))
					m = 1;
				else if (!stricmp(tk->hostmask, reg->item) && !strcmp(tk->usermask, "*"))
					m = 1;
				if (m)
				{
					if (*reg->up->item == 'S')
						tkl_check_local_remove_shun(tk);
					tkl_del_line(tk);
					break;
				}
			}
		}
	}
}
void PonPfxs()
{
	Isupport *ispp;
	if (!pfxs)
		ircstrdup(pfxs, "~&@%+");
	if (pfxs[0] != '\0')
	{
		PF_OWN = pfxs[0];
		if (pfxs[1] != '\0')
		{
			PF_ADMIN = pfxs[1];
			if (pfxs[2] != '\0')
			{
				PF_OP = pfxs[2];
				if (pfxs[3] != '\0')
				{
					PF_HALF = pfxs[3];
					if (pfxs[4] != '\0')
						PF_VOICE = pfxs[4];
				}
			}
		}
	}
	if ((ispp = IsupportFind("STATUSMSG")))
		IsupportSetValue(ispp, pfxs);
	if ((ispp = IsupportFind("PREFIX")))
	{
		ircsprintf(buf, "(qaohv)%s", pfxs);
		IsupportSetValue(ispp, buf);
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
#ifdef UDB_HASH
		BorraRegistroDeHash(reg->down, tipo, reg->down->item);
#endif
		LiberaMemoriaUdb(tipo, reg->down);
	}
	if (reg->mid)
	{
#ifdef UDB_HASH
		BorraRegistroDeHash(reg->mid, tipo, reg->mid->item);
#endif
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
	UDBloq *bloq;
	if (!(up = reg->up)) /* estamos arriba de todo */
		return NULL;
#ifdef UDB_HASH
	BorraRegistroDeHash(reg, tipo, reg->item);
#endif
	BorraRegistroEspecial(tipo, reg);
	if (reg->data_char)
		MyFree(reg->data_char);
	reg->data_char = NULL;
	reg->data_long = 0L;
	down = reg->down;
	reg->down = NULL;
	bloq = CogeDeId(tipo);
	if (archivo)
	{
		GuardaEnArchivo(reg, tipo);
		ActualizaHash(bloq);
	}
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
	if (!reg->up->up && bloq)
		bloq->regs--;
	LiberaMemoriaUdb(tipo, reg);
	if (!up->down && up->up)
		up = BorraRegistro(tipo, up, archivo);
	return up;
}
Udb *InsertaRegistro(u_int tipo, Udb *bloque, char *item, char *data_char, u_long data_long, int archivo)
{
	Udb *reg;
	UDBloq *bloq;
	if (!bloque || !item)
		return NULL;
	bloq = CogeDeId(tipo);
	if (!(reg = BuscaBloque(item, bloque)))
	{
		reg = CreaRegistro(bloque);
		if (!bloque->up && bloq)
			bloq->regs++;
		reg->id = bloque->id;
		/*if (*(item+1) == '\0')
		{
			reg->id = *item;
			reg->item = strdup("");
		}
		else*/
			reg->item = strdup(item);
#ifdef UDB_HASH
		InsertaRegistroEnHash(reg, tipo, item);
#endif
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
	{
		GuardaEnArchivo(reg, tipo);
		ActualizaHash(bloq);
	}
	if (!InsertaRegistroEspecial(tipo, reg, archivo))
	{
		BorraRegistro(tipo, reg, archivo);
		return NULL;
	}
	return reg;
}
/* 0 ok, 1 error (no se ha insertado/borrado) */
int ParseaLinea(UDBloq *root, char *cur, int archivo)
{
	char *ds, *cop, *sp = NULL;
	Udb *bloq;
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
			{
				if (*cur == CHAR_B64)
				{
					char tmp[BUFSIZE];
					b64_decode(cur+1, tmp, BUFSIZE);
					bloq = InsertaRegistro(bloq->id, bloq, tmp, NULL, 0, archivo);
					bloq->b64 = 1;
				}
				else
					bloq = InsertaRegistro(bloq->id, bloq, cur, NULL, 0, archivo);
			}
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
		if (*sp == '\\' && *(sp+1) == CHAR_NUM)
			bloq = InsertaRegistro(bloq->id, bloq, cur, sp+1, 0, archivo);
		else if (*sp == CHAR_NUM)
			bloq = InsertaRegistro(bloq->id, bloq, cur, NULL, atoul(++sp), archivo);
		else
			bloq = InsertaRegistro(bloq->id, bloq, cur, sp, 0, archivo);
	}
	else
	{
		borra:
		if (*cur == CHAR_B64)
		{
			char tmp[BUFSIZE];
			b64_decode(cur+1, tmp, BUFSIZE);
			if ((bloq = BuscaBloque(tmp, bloq)))
				bloq = BorraRegistro(bloq->id, bloq, archivo);
		}
		else
		{
			if ((bloq = BuscaBloque(cur, bloq)))
				bloq = BorraRegistro(bloq->id, bloq, archivo);
		}
	}
	MyFree(cop);
	if (bloq)
		return 0;
	return 1;
}
int BuscaOpt(int opt, Udb *reg)
{
	Udb *bloq;
	if (reg && (bloq = BuscaBloque(C_OPT, reg)) && (bloq->data_long & opt))
		return (bloq->data_long & opt);
	return 0x0;
}
DLLFUNC u_int LevelOperUdb(char *oper)
{
	Udb *reg;
	if ((reg = BuscaBloque(oper, UDB_NICKS)))
	{
		Udb *aux;
		if ((aux = BuscaBloque(N_OPE, reg)))
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
	if ((bloq = BuscaBloque(S_CLA, UDB_SET)) && !BadPtr(bloq->data_char))
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
	if ((reg = BuscaBloque(S_SUF, UDB_SET)) && !BadPtr(reg->data_char))
		suf = reg->data_char;
	else
		suf = "virtual";
	if (BadPtr(acptr->user->cloakedhost))
		snprintf(acptr->user->cloakedhost, HOSTLEN, "%s.%s", CifraIp(real), suf);
	if (IsARegNick(acptr) && (reg = BuscaBloque(acptr->name, UDB_NICKS)) && (bloq = BuscaBloque(N_VHO, reg)) && !BadPtr(bloq->data_char))
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
		if ((reg = BuscaBloque(S_IPS, UDB_SET)) && !BadPtr(reg->data_char))
			botname = reg->data_char;
		else
			botname = me.name;
		sendto_one(acptr, ":%s NOTICE %s :*** Protección IP: tu dirección virtual es %s", botname, acptr->name, x);
		EnviaADebugs(acptr, 2, x);
	}
	if (virt)
		MyFree(virt);
	return strdup(x);
}

/* comandos
 *
 * INF: da información (su md5) si no coinciden, se piden resúmenes
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
 * FHO: fija el tiempo de optimización
 * eso es todo amigos
 */

CMD_FUNC(m_db)
{
	int mascara;
	if (!IsServer(cptr))
		return 0;
	if (!IsUDB(cptr))
		return 0;
	if (parc < 5)
	{
		sendto_one(cptr, ":%s DB %s ERR 0 %i 0", me.name, sptr->name, E_UDB_PARAMS);
		return 1;
	}
	mascara = (strchr(parv[1], '?') || strchr(parv[1], '*')) ? 1 : 0;
	/* DB * INF <bdd> <md5> <ts de la última optimización>*/
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
					TruncaBloque(bloq, 0);
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
				/* si es menor, el otro nodo vaciará su db y nos mandará un RES, será cuando empecemos el resumen. abremos terminado nuestro burst */
			}
			else
			{
				if (++(sptr->serv->flags.bloqs) == BDD_TOTAL)
					sendto_one(cptr, ":%s %s", me.name, (IsToken(cptr) ? TOK_EOS : MSG_EOS));
			}
			if (!mascara)
				return 0;
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
				char c, linea[BUFSIZE];
				int i = 0;
				lseek(bloq->fd, INI_DATA + bytes, SEEK_SET);
				while (read(bloq->fd, &c, sizeof(c)) > 0)
				{
					if (c == '\r' || c == '\n')
					{
						linea[i] = '\0';
						if (strchr(linea, ' '))
							sendto_one(cptr, ":%s DB * INS %lu %c::%s", me.name, bytes, *parv[3], linea);
						else
							sendto_one(cptr, ":%s DB * DEL %lu %c::%s", me.name, bytes, *parv[3], linea);
						bytes += strlen(linea) + 1;
						i = 0;
					}
					else
						linea[i++] = c;
				}
				sendto_one(cptr, ":%s DB %s FDR %c 0", me.name, sptr->name, *parv[3]);
				bloq->res = NULL; /* OJO! ya hemos terminado, si no se queda esperando */
			}
			 /* esto ya no hace falta */
			//else if (!bytes && !bloq->data_long) /* muy raras veces se daba */
			//	sendto_one(cptr, ":%s DB %s FDR %c 0", me.name, sptr->name, *parv[3]);
			//else /* se comenta porque tal vez no sea recíproco. en tal caso, se esperan ->res cuando se envían RES */
			//	bloq->res = sptr; /* esperamos su res */
			if (++(sptr->serv->flags.bloqs) == BDD_TOTAL)
					sendto_one(cptr, ":%s %s", me.name, (IsToken(cptr) ? TOK_EOS : MSG_EOS));
			if (!mascara)
				return 0;
		}
		sendto_serv_butone(cptr, ":%s DB %s RES %c %s", parv[0], parv[1], *parv[3], parv[4]);
	}
	/* DB * INS <offset> <bdd>::a::b::...::item valor */
	else if (!strcasecmp(parv[2], "INS"))
	{
		if (!strcmp(cptr->name, parv[0]) && !cptr->serv->conf->hubmask) /* el nodo emisor no es hub, paramos */
		{
			sendto_one(cptr, ":%s DB %s ERR INS %i %c", me.name, sptr->name, E_UDB_NOHUB, *parv[4]);
			return 0;
		}
		if (!match(parv[1], me.name))
		{
			char buf[1024], *r = parv[4];
			u_long bytes;
			UDBloq *bloq;
			if (parc < 6)
			{
				sendto_one(cptr, ":%s DB %s ERR INS %i %c", me.name, sptr->name, E_UDB_PARAMS, *r);
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
				if (propaga && propaga != sptr)
				{
					sendto_one(cptr, ":%s DB %s ERR INS %i %s", me.name, sptr->name, E_UDB_FBSRV, grifo);
					return 1;
				}
			}
			if (bytes != bloq->lof)
			{
				sendto_one(cptr, ":%s DB %s ERR INS %i %c %lu", me.name, sptr->name, E_UDB_LEN, *r, bloq->lof);
				/* a partir de este punto el servidor que recibe esta instrucción debe truncar su bloque con el valor recibido
				   y propagar el truncado por la red, obviamente en el otro sentido.
				   Si el nodo que lo ha enviado es un LEAF propagará un DRP pero que no llegará a ningún sitio porque no tiene servidores
				   en el otro sentido. Si es un HUB, tendrá vía libre para propagar el DRP.
				   A efectos, sería lo mismo que el nodo receptor mandara un DRP, pero así se ahorra una línea ;) */
				return 1;
			}
			r += 3;
			ircsprintf(buf, "%s %s", r, parv[5]);
			if (bloq->res == sptr)
			{
				strcat(buf, "\n");
				lseek(bloq->fd, 0, SEEK_END);
				if (write(bloq->fd, buf, sizeof(char) * strlen(buf)) < 0)
					return 0;
				ActualizaHash(bloq);
			}
			else
			{
				if (ParseaLinea(bloq, buf, 1))
				{
					sendto_one(cptr, ":%s DB %s ERR INS %i %c", me.name, sptr->name, E_UDB_REP, *parv[4]);
					return 1;
				}
			}
			if (propaga && bloq->res == sptr) /* estamos en un resumen, hay que repropagar los registros */
			{
				sendto_serv_butone(cptr, ":%s DB %s INS %s %s %s", propaga->name, parv[1], parv[3], parv[4], parv[5]);
				return 0;
			}
			if (!mascara)
				return 0;
		}
		sendto_serv_butone(cptr, ":%s DB %s INS %s %s %s", parv[0], parv[1], parv[3], parv[4], parv[5]); /* parv[0] siempre es propaga */
	}
	/* DB * DEL <offset> <bdd>::a::b::...::item */
	else if (!strcasecmp(parv[2], "DEL"))
	{
		if (!strcmp(cptr->name, parv[0]) && !cptr->serv->conf->hubmask)
		{
			sendto_one(cptr, ":%s DB %s ERR DEL %i %c", me.name, sptr->name, E_UDB_NOHUB, *parv[4]);
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
				if (propaga && propaga != sptr)
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
			strcpy(buf,r);
			if (bloq->res == sptr)
			{
				strcat(buf, "\n");
				lseek(bloq->fd, 0, SEEK_END);
				if (write(bloq->fd, buf, sizeof(char) * strlen(buf)) < 0)
					return 0;
				ActualizaHash(bloq);
			}
			else
			{
				if (ParseaLinea(bloq, r, 1))
				{
					sendto_one(cptr, ":%s DB %s ERR DEL %i %c", me.name, sptr->name, E_UDB_REP, *parv[4]);
					return 1;
				}
			}
			if (propaga && bloq->res == sptr) /* estamos en un res */
			{
				sendto_serv_butone(cptr, ":%s DB %s DEL %s %s", propaga->name, parv[1], parv[3], parv[4]);
				return 0;
			}
			if (!mascara)
				return 0;
		}
		sendto_serv_butone(cptr, ":%s DB %s DEL %s %s", parv[0], parv[1], parv[3], parv[4]);
	}
	/* DB * DRP <bdd> <byte> */
	else if (!strcasecmp(parv[2], "DRP"))
	{
		if (!strcmp(cptr->name, parv[0]) && !cptr->serv->conf->hubmask)
		{
			sendto_one(cptr, ":%s DB %s ERR DRP %i %c", me.name, sptr->name, E_UDB_NOHUB, *parv[3]);
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
			TruncaBloque(bloq, bytes);
			if (!mascara)
				return 0;
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
					if (!(bloq = CogeDeId(*parv[5])))
					{
						sendto_one(cptr, ":%s DB %s ERR E_UDB_LEN %i %c", me.name, sptr->name, E_UDB_NODB, *parv[5]);
						return 1;
					}
					cb = strchr(parv[5], ' ') + 1; /* esto siempre debe cumplirse, si no a cascar */
					bytes = atoul(cb);
					TruncaBloque(bloq, bytes);
					/* somos nosotros quienes mandamos el DRP, quienes deshacemos el cambio! */
					sendto_serv_butone(cptr, ":%s DB %s DRP %c %s", me.name, parv[0], *parv[5], cb);
					break;
				}
			}
			if (!mascara)
				return 0;
		}
		sendto_serv_butone(cptr, ":%s DB %s ERR %s %s %s", parv[0], parv[1], parv[3], parv[4], parv[5]);
	}
	/* DB * OPT <bdd> <hora>*/
	else if (!strcmp(parv[2], "OPT"))
	{
		UDBloq *bloq;
		if (!strcmp(cptr->name, parv[0]) && !cptr->serv->conf->hubmask)
		{
			sendto_one(cptr, ":%s DB %s ERR OPT %i %c", me.name, sptr->name, E_UDB_NOHUB, *parv[3]);
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
			if (bloq->res == sptr)
			{
				DescargaBloque(bloq->id);
				CargaBloque(bloq->id);
				bloq->res = NULL;
			}
			if (!mascara)
				return 0;
		}
		sendto_serv_butone(cptr, ":%s DB %s FDR %s %s", parv[0], parv[1], parv[3], parv[4]);
	}
	/* DB * BCK <bdd> <nombre> */
	else if (!strcmp(parv[2], "BCK"))
	{
		UDBloq *bloq;
		FILE *fp2;
		char tmp[BUFSIZE];
		if (!(bloq = CogeDeId(*parv[3])))
		{
			sendto_one(cptr, ":%s DB %s ERR BCK %i %c", me.name, sptr->name, E_UDB_NODB, *parv[3]);
			return 1;
		}
		ircsprintf(tmp, DB_DIR_BCK "%c%s.bck.udb", *parv[3], parv[4]);
		lseek(bloq->fd, 0, SEEK_SET);
		if ((fp2 = fopen(tmp, "wb")))
		{
#ifdef ZIP_LINKS
			if (zDeflate(bloq->fd, fp2, Z_DEFAULT_COMPRESSION) != Z_OK)
				sendto_one(cptr, ":%s DB %s ERR BCK %i %c zDeflate", me.name, sptr->name, E_UDB_FATAL, *parv[3]);
#else
			size_t leidos;
			while ((leidos = read(bloq->fd, tmp, sizeof(tmp))))
				fwrite(tmp, 1, leidos, fp2);
#endif
			fclose(fp2);
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
			close(bloq->fd);
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
			/* loop.ircd_rehashing = 1; hay que rehacer los cambios */
			DescargaBloque(bloq->id);
			CargaBloque(bloq->id);
			//loop.ircd_rehashing = 0;
			sendto_serv_butone(cptr, ":%s DB %s RST %c %s %s", parv[0], parv[1], *parv[3], parv[4], parv[5]);
		}
		else
		{
			TruncaBloque(bloq, 0);
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
		frb = C_FOR;
		pas = C_PAS;
		des = C_DES;
		sus = C_SUS;
		bdd = UDB_CANALES;
	}
	else
	{
		frb = N_FOR;
		pas = N_PAS;
		des = N_DES;
		sus = N_SUS;
		all = N_ALL;
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
   	if ((breg = BuscaBloque(S_NIC, UDB_SET)) && !BadPtr(breg->data_char))
		botname = breg->data_char;
	else
		botname = me.name;
	if (MyClient(sptr) && sptr->user && !IsAnOper(sptr))
	{
		if ((sptr->user->flood.udb_c >= pases) &&
		    (TStime() - sptr->user->flood.udb_t < intervalo))
		{
			sendto_one(sptr, ":%s NOTICE %s :*** Demasiadas contraseñas incorrectas. No puedes utilizar este comando hasta %i segundos.", botname, sptr->name, (int)(intervalo - (TStime() - sptr->user->flood.udb_t)));
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
	val = TipoDePass(nick, parv[2], reg, cptr);
	if (val < 0)
	{
		if (MyClient(sptr) && sptr->user && !IsAnOper(sptr))
		{
			if ((sptr->user->flood.udb_c >= pases) &&
			    (TStime() - sptr->user->flood.udb_t < intervalo))
			{
				sendto_one(sptr, ":%s 339 %s :Demasiadas contraseñas incorrectas. No puedes utilizar este comando hasta %i segundos.", me.name, sptr->name, (int)(intervalo - (TStime() - sptr->user->flood.udb_t)));
				return 0;
			}
		}
		else
			sendto_one(cptr, ":%s NOTICE %s :*** Contraseña incorrecta.", botname, sptr->name);
		return 0;
	}
	else if (val == 1)
	{
		sendto_one(cptr, ":%s NOTICE %s :*** No puedes aplicar ghost sobre un nick suspendido.", botname, sptr->name);
		return 0;
	}
	ircstp->is_kill++;
	sendto_serv_butone_token(NULL, me.name, MSG_KILL, TOK_KILL, "%s :Comando GHOST utilizado por %s.", acptr->name, who);
	if (MyClient(acptr))
		sendto_one(acptr, ":%s KILL %s :Comando GHOST utilizado por %s.", me.name, acptr->name, who);
	sendto_one(cptr, ":%s NOTICE %s :*** Sesión fantasma del nick %s liberada.", botname, sptr->name, nick);
	ircsprintf(quitbuf, "Killed (Comando GHOST utilizado por %s)", who);
	acptr->flags |= FLAGS_KILLED;
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
		sendto_one(sptr, ":%s 339 %s :Parámetros insuficientes. Sintaxis: /dbq [servidor] <bloque>.", me.name, sptr->name);
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
					else if (aux->down)
						sendto_one(sptr, ":%s 339 %s :DBQ %s::%s (tiene subbloques)", me.name, sptr->name, parv[1], aux->item);
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
/* devuelve el aClient del BotServ si está online o no. si está forzar en 1 lo devuelve indistintamente */
aClient *BotClient(char *bloq)
{
	char *b, botnick[NICKLEN+1];
	aClient *cptr = NULL;
	Udb *botserv = NULL;
	bzero(botnick, sizeof(botnick));
	if ((botserv = BuscaBloque(bloq, UDB_SET)) && !BadPtr(botserv->data_char))
		strncpy(botnick, botserv->data_char, sizeof(botnick));
	else
		strncpy(botnick, me.name, sizeof(botnick));
	if ((b = strchr(botnick, '!')))
		*b = '\0';
	if ((cptr = find_client(botnick, NULL)))
		return cptr;
	return &me;
}
char *BotNick(char *bloq, int forzar)
{
	aClient *cptr = NULL;
	if ((cptr = BotClient(bloq)))
	{
		if (forzar)
		{
			if (!IsMe(cptr))
				return cptr->name;
			else
			{
				static char botnick[NICKLEN+1];
				char *b;
				Udb *botserv;
				if ((botserv = BuscaBloque(bloq, UDB_SET)) && !BadPtr(botserv->data_char))
				{
					strncpy(botnick, botserv->data_char, sizeof(botnick));
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
char *BotMask(char *bloq, int forzar)
{
	aClient *cptr = NULL;
	if ((cptr = BotClient(bloq)) && IsPerson(cptr))
	{
		static char ret[NICKLEN+1+USERLEN+1+HOSTLEN+1];
		ircsprintf(ret, "%s!%s@%s", cptr->name, cptr->username, GetHost(cptr));
		return ret;
	}
	else if (forzar)
	{
		Udb *botserv;
		if ((botserv = BuscaBloque(bloq, UDB_SET)) && !BadPtr(botserv->data_char))
			return botserv->data_char;
	}
	return me.name;
}
#ifdef ZIP_LINKS
/* rutinas de www.zlib.net */
#define CHUNK 16384
int zDeflate(int source, FILE *dest, int level)
{
	int ret, flush;
	unsigned have;
	z_stream strm;
	unsigned char in[CHUNK];
	unsigned char out[CHUNK];
	strm.zalloc = Z_NULL;
	strm.zfree = Z_NULL;
	strm.opaque = Z_NULL;
	ret = deflateInit(&strm, level);
	if (ret != Z_OK)
		return ret;
	/* compress until end of file */
	lseek(source, 0, SEEK_SET);
	do
	{
		ret = read(source, in, CHUNK);
		if (ret < 0)
		{
			(void)deflateEnd(&strm);
			return Z_ERRNO;
		}
		flush = (ret == 0 ? Z_FINISH : Z_NO_FLUSH);
		strm.avail_in = ret;
		strm.next_in = in;
		/* run deflate() on input until output buffer not full, finish
		compression if all of source has been read in */
		do
		{
			strm.avail_out = CHUNK;
			strm.next_out = out;
			ret = deflate(&strm, flush);    /* no bad return value */
			have = CHUNK - strm.avail_out;
			if (fwrite(out, 1, have, dest) != have || ferror(dest))
			{
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
	strm.zalloc = Z_NULL;
	strm.zfree = Z_NULL;
	strm.opaque = Z_NULL;
	strm.avail_in = 0;
	strm.next_in = Z_NULL;
	ret = inflateInit(&strm);
	if (ret != Z_OK)
		return ret;
	/* decompress until deflate stream ends or end of file */
	do
	{
		strm.avail_in = fread(in, 1, CHUNK, source);
		if (ferror(source))
		{
			(void)inflateEnd(&strm);
			return Z_ERRNO;
		}
		if (strm.avail_in == 0)
			break;
		strm.next_in = in;
		/* run inflate() on input until output buffer not full */
		do
		{
			strm.avail_out = CHUNK;
			strm.next_out = out;
			ret = inflate(&strm, Z_NO_FLUSH);
			switch (ret)
			{
				case Z_NEED_DICT:
					ret = Z_DATA_ERROR;     /* and fall through */
				case Z_DATA_ERROR:
				case Z_MEM_ERROR:
					(void)inflateEnd(&strm);
					return ret;
			}
			have = CHUNK - strm.avail_out;
			if (fwrite(out, 1, have, dest) != have || ferror(dest))
			{
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
		//ActualizaHash(CogeDeId(i));
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
			if (*(c-2) == ':' && *(c-1) == *(N_OPE)) /* lo tenemos! */
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
	//ActualizaHash(N);
	return 0;
}
int ActualizaDataVer4()
{
	//ActualizaHash(N);
	//ActualizaHash(C);
	//ActualizaHash(I);
	//ActualizaHash(S);
	return 0;
}
#endif
