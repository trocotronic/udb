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

#ifdef UDB
#include "s_bdd.h"
#ifndef _WIN32
#define O_BINARY 0x0
#endif
DLLFUNC Udb *nicks = NULL;
DLLFUNC Udb *canales = NULL;
DLLFUNC Udb *ips = NULL;
DLLFUNC Udb *set = NULL;
DLLFUNC u_int BDD_NICKS, BDD_CHANS, BDD_IPS, BDD_SET;
Udb ***hash;
Udb *ultimo = NULL;
extern char modebuf[BUFSIZE], parabuf[BUFSIZE];
#define da_Udb(x) do{ x = (Udb *)MyMalloc(sizeof(Udb)); bzero(x, sizeof(Udb)); }while(0)
#define ircstrdup(x,y) do{ if (x) MyFree(x); if (!y) x = NULL; else x = strdup(y); }while(0)
#define atoul(x) strtoul(x, NULL, 10)
void carga_bloques(void);
static char buf[BUFSIZE];
char *chan_nick();
static char bloques[128];
static int BDD_TOTAL = 0;
void alta_bloque(char letra, char *ruta, Udb **reg, u_int *id)
{
	static u_int ids = 0;
	da_Udb(*reg);
	(*reg)->id |= (u_int)letra;
	(*reg)->id |= (ids << 8);
	(*reg)->item = ruta;
	(*reg)->mid = ultimo;
	*id = ids;
	ultimo = *reg;
	bloques[BDD_TOTAL++] = letra;
	ids++;
}
void alta_hash()
{
	Udb *reg;
	hash = (Udb ***)MyMalloc(sizeof(Udb **) * BDD_TOTAL);
	for (reg = ultimo; reg; reg = reg->mid)
	{
		hash[(reg->id >> 8)] = (Udb **)MyMalloc(sizeof(Udb *) * 2048);
		bzero(hash[(reg->id >> 8)], sizeof(Udb *) * 2048);
	}
}
void bdd_init()
{
	FILE *fh;
#ifdef _WIN32
	mkdir(DB_DIR);
#else
	mkdir(DB_DIR, 0744);
#endif
	bzero(bloques, sizeof(bloques));
	if (!nicks)
		alta_bloque('N', DB_DIR "nicks.udb", &nicks, &BDD_NICKS);
	if (!canales)
		alta_bloque('C', DB_DIR "canales.udb", &canales, &BDD_CHANS);
	if (!ips)
		alta_bloque('I', DB_DIR "ips.udb", &ips, &BDD_IPS);
	if (!set)
		alta_bloque('S', DB_DIR "set.udb", &set, &BDD_SET);
	alta_hash();
	if ((fh = fopen(DB_DIR "crcs", "a")))
		fclose(fh);
	carga_bloques();
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
	par[inode.st_size] = '\0';
	if (read(fp, par, inode.st_size) == inode.st_size)
	{
		MD5_CTX hash;
		char res[512];
		MD5_Init(&hash);
		MD5_Update(&hash, par, inode.st_size);
		MD5_Final(res, &hash);
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
	if (!(fp = fopen(DB_DIR "crcs", "r")))
		return 0L;
	fseek(fp, 8 * id, SEEK_SET);
	bzero(lee, 9);
	fread(lee, 1, 8, fp);
	fclose(fp);
	if (!sscanf(lee, "%X", &hash))
		return 0L;
	return hash;
}
int actualiza_hash(Udb *bloque)
{
	char lee[9];
	FILE *fh;
	u_long lo;
	bzero(lee, 9);
	if (!(fh = fopen(DB_DIR "crcs", "r+")))
		return -1;
	lo = obtiene_hash(bloque);
	fseek(fh, 8 * (bloque->id >> 8), SEEK_SET);
	ircsprintf(lee, "%X", lo);
	fwrite(lee, 1, 8, fh);
	fclose(fh);
	return 0;
}
/* devuelve el puntero a todo el bloque a partir de su id o letra */
Udb *coge_de_id(int id)
{
	Udb *reg;
	for (reg = ultimo; reg; reg = reg->mid)
	{
		if (((reg->id & 0xFF) == id) || ((reg->id >> 8) == id))
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
		if ((reg->id & 0xFF) == tipo)
			return (reg->id >> 8);
	}
	return tipo;
}
char coge_de_tipo(int tipo)
{
	Udb *reg;
	for (reg = ultimo; reg; reg = reg->mid)
	{
		if ((reg->id >> 8) == tipo)
			return (reg->id & 0xFF);
	}
	return tipo;
}
void inserta_registro_en_hash(Udb *registro, int donde, char *clave)
{
	u_int hashv;
	hashv = hash_nick_name(clave) % 2048;
	registro->hsig = hash[donde][hashv];
	hash[donde][hashv] = registro;
}
int borra_registro_de_hash(Udb *registro, int donde, char *clave)
{
	Udb *aux, *prev = NULL;
	u_int hashv;
	hashv = hash_nick_name(clave) % 2048;
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
Udb *busca_udb_en_hash(char *clave, int donde, Udb *lugar)
{
	u_int hashv;
	Udb *aux;
	hashv = hash_nick_name(clave) % 2048;
	for (aux = hash[donde][hashv]; aux; aux = aux->hsig)
	{
		if (!strcasecmp(clave, aux->item))
			return aux;
	}
	return lugar;
}
Udb *busca_registro(int tipo, char *clave)
{
	if (!clave)
		return NULL;
	tipo = coge_de_char(tipo);
	return busca_udb_en_hash(clave, tipo, NULL);
}
Udb *busca_bloque(char *clave, Udb *bloque)
{
	Udb *aux;
	if (!clave)
		return NULL;
	for (aux = bloque->down; aux; aux = aux->mid)
	{
		if (!strcasecmp(clave, aux->item))
			return aux;
	}
	return NULL;
}
Udb *crea_registro(Udb *bloque)
{
	Udb *reg;
	da_Udb(reg);
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
			sprintf(tmp, "%c%lu", CHAR_NUM, reg->data_long);
			strcat(form, " ");
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
	actualiza_hash(coge_de_id(tipo));
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
void inserta_registro_especial(int tipo, Udb *reg)
{
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
		chptr = get_channel(&me, root->item, CREATE);
		chptr->mode.mode |= MODE_RGSTR;
		if (!strcmp(reg->item, "modos"))
		{
			struct ChMode store;
			memset(&store, 0, sizeof(store));
			set_channelmodes(reg->data_char, &store, 0);
			chptr->mode.mode |= store.mode;
			if (chptr->mode.mode & MODE_FLOODLIMIT)
			{
#ifdef NEWCHFLOODPROT
				if (!chptr->mode.floodprot)
					chptr->mode.floodprot = MyMalloc(sizeof(ChanFloodProt));
				memcpy(chptr->mode.floodprot, &store.floodprot, sizeof(ChanFloodProt));
#else
				chptr->mode.msgs = store.mode.msgs;
				chptr->mode.per = store.mode.per;
				chptr->mode.kmode = store.mode.kmode;
#endif
			}
#ifdef  EXTCMODE
			chptr->mode.extmode = store.extmodes;
#endif
			if (chptr->members)
				sendto_channel_butserv(chptr, &me, ":%s MODE %s +%s", chan_nick(), chptr->chname, reg->data_char);
		}
		else if (!strcmp(reg->item, "topic"))
		{
			int topiclen = strlen(reg->data_char);
			int nicklen = strlen(me.name);
			if (topiclen > (TOPICLEN))
				topiclen = TOPICLEN;
			chptr->topic = MyMalloc(topiclen + 1);
			strncpyzt(chptr->topic, reg->data_char, topiclen + 1);
			chptr->topic_time = TStime();
			chptr->topic_nick = MyMalloc(nicklen + 1);
			strncpyzt(chptr->topic_nick, me.name, nicklen + 1);
			if (chptr->members)
				sendto_channel_butserv(chptr, &me, ":%s TOPIC %s :%s", chan_nick(), chptr->chname, chptr->topic);
		}
	}
	else if (tipo == BDD_SET)
	{
		if (!strcmp(reg->item, "clave_cifrado") || !strcmp(reg->item, "sufijo"))
			regenera_claves();
	}
	else if (tipo == BDD_NICKS)
	{
		if (!strcmp(reg->item, "vhost"))
		{
			aClient *acptr;
			if ((acptr = find_client(reg->up->item, NULL)) && IsARegNick(acptr))
				acptr->user->virthost = make_virtualhost(acptr, acptr->user->realhost, acptr->user->virthost, 1);
		}
	}
}
void borra_registro_especial(int tipo, Udb *reg)
{
	if (loop.ircd_rehashing) /* si estamos refrescando, no tocamos nada */
		return;
	if (tipo == BDD_CHANS)
	{
		aChannel *chptr;
		Udb *bloq = NULL, *root = reg;
		while (*root->item != '#')
		{
			if (!(root = root->up))
				return;
		}
		chptr = get_channel(&me, root->item, !CREATE);
		if (!strcmp("modos", reg->item) || (*reg->item == '#' && (bloq = busca_bloque("modos", reg))))
		{
			char *modos = (bloq ? bloq->data_char : reg->data_char);
			aCtab *tab;
			while (*modos != '\0')
			{
				switch (*modos)
				{
					case 'f':
					{
#ifdef NEWCHFLOODPROT
						MyFree(chptr->mode.floodprot);
						chptr->mode.floodprot = NULL;
						chanfloodtimer_stopchantimers(chptr);
#else
						chptr->mode.msgs = chptr->mode.per = chptr->mode.kmode = 0;
#endif
						break;
					}
					default:
						for (tab = &cFlagTab[0]; tab->mode; tab++)
						{
							if (tab->flag == *modos)
							{
								chptr->mode.mode &= ~tab->mode;
								break;
							}
						}
				}
				modos++;
			}
			bloq = NULL;
		}
		if (*reg->item == '#')
		{
			chptr->mode.mode &= ~MODE_RGSTR;
			if (!chptr->members) /* si hay gente no tocamos nada */
				sub1_from_channel(chptr);
		}
	}
}
#ifdef DEBUGMODE
void printea(Udb *bloq, int escapes)
{
	int i;
	buf[0] = 0;
	for (i = 0; i < escapes; i++)
		debug(2, "\t");
	debug(2, bloq->item);
	if (bloq->data_char)
		debug(2, " %s", bloq->data_char);
	debug(2, "\r\n");
	if (bloq->down)
		printea(bloq->down, ++escapes);
	if (bloq->mid)
		printea(bloq->mid, escapes);
	return;
}
#endif
void libera_memoria_udb(int tipo, Udb *reg)
{
	if (reg->down)
	{
		borra_registro_de_hash(reg->down, tipo, reg->down->item);
		libera_memoria_udb(tipo, reg->down);
	}
	if (reg->mid)
	{
		borra_registro_de_hash(reg->mid, tipo, reg->mid->item);
		libera_memoria_udb(tipo, reg->mid);
	}
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
	aux = coge_de_id(tipo);
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
	if (!reg->sig)
		aux->sig = reg->prev;
	else
		reg->sig->prev = reg->prev;
	if (!reg->prev)
		aux->prev = reg->sig;
	else
		reg->prev->sig = reg->sig;
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
		reg->item = strdup(item);
		inserta_registro_en_hash(reg, tipo, item);
	}
	else
	{
		if (data_char && reg->data_char && !strcmp(reg->data_char, data_char))
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
	inserta_registro_especial(tipo, reg);
	return reg;
}
DLLFUNC int level_oper_bdd(char *oper)
{
	Udb *reg;
	if ((reg = busca_registro(BDD_NICKS, oper)))
	{
		Udb *aux;
		if ((aux = busca_bloque("oper", reg)))
			return aux->data_long;
	}
	return 0;
}
char *cifra_ip(char *ipreal)
{
	static char cifrada[512], clave[13];
	char *p, *clavec;
	int ts = 0;
	Udb *bloq;
	unsigned int ourcrc, v[2], k[2], x[2];
	bzero(clave, 13);
	bzero(cifrada, 512);
	ourcrc = our_crc32(ipreal, strlen(ipreal));
	if ((bloq = busca_registro(BDD_SET, "clave_cifrado")))
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
				strcpy(p, ipreal);
				break;
			}
		}
	}
	return cifrada;
}	
char *make_virtualhost(aClient *acptr, char *viejo, char *nuevo, int mostrar)
{
	Udb *reg, *bloq;
	char x[HOSTLEN+1], *suf;
	if (!viejo)
		return NULL;
	if ((reg = busca_registro(BDD_SET, "sufijo")))
		suf = reg->data_char;
	else
		suf = "virtual";
	if (IsARegNick(acptr) && (reg = busca_registro(BDD_NICKS, acptr->name)) && (bloq = busca_bloque("vhost", reg)))
		strncpyzt(x, bloq->data_char, HOSTLEN);
	else
		snprintf(x, HOSTLEN, "%s.%s", cifra_ip(viejo), suf);
	if (nuevo)
		MyFree(nuevo);
	if (MyClient(acptr) && mostrar)
	{
		char *botname;
		if (!(reg = busca_registro(BDD_SET, "IpServ")))
			botname = me.name;
		else
			botname = reg->data_char;
		sendto_one(acptr, ":%s NOTICE %s :*** Protección IP: tu dirección virtual es %s",
			botname, acptr->name, x);
	}
	return strdup(x);
}
void parsea_linea(int tipo, char *cur, int archivo)
{
	char *ds, *cop, *sp;
	Udb *bloq;
	int ins = 0;
	bloq = coge_de_id(tipo);
	cop = cur = strdup(cur);
	while ((ds = strchr(cur, ':')))
	{
		if (*(ds + 1) == ':')
		{
			*ds++ = '\0';
			if ((sp = strchr(cur, ' ')))
				*sp = '\0';
			bloq = inserta_registro(tipo, bloq, cur, sp, 0, archivo);
		}
		else /* ya no son :: */
			break;
		cur = ++ds;
	}
	if ((ds = strchr(cur, ' ')))
	{
		*ds++ = '\0';
		if (*ds == CHAR_NUM)
			inserta_registro(tipo, bloq, cur, NULL, atoul(++ds), archivo);
		else
			inserta_registro(tipo, bloq, cur, ds, 0, archivo);
	}
	else
	{
		if ((bloq = busca_bloque(cur, bloq)))
			borra_registro(tipo, bloq, archivo);
	}
	MyFree(cop);
}
void carga_bloque(int tipo)
{
	char *cur, *ds, *p;
	Udb *root;
	u_long lee, obtiene;
	char bloque;
	int len, fd;
#ifdef _WIN32
	HANDLE mapa, archivo;
#else
	struct stat sb;
#endif
	bloque = coge_de_tipo(tipo);
	root = coge_de_id(tipo);
	if ((lee = lee_hash(root->id >> 8)) != (obtiene = obtiene_hash(root)))
	{
		sendto_ops("El bloque %c está corrupto (%lu != %lu)", bloque, lee, obtiene);
		if ((fd = open(root->item, O_WRONLY|O_TRUNC)))
		{
			close(fd);
			actualiza_hash(root);
		}
		if (Servers && !IsMe(Servers->value.cptr))
			sendto_one(Servers->value.cptr, ":%s DB %s RES %c 0", me.name, Servers->value.cptr->name, bloque);
		return;
	}
#ifdef _WIN32
	if ((archivo = CreateFile(root->item, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE)
#else
	if ((fd = open(root->item, O_RDONLY)) == -1)
#endif
		return;
#ifdef _WIN32
	len = GetFileSize(archivo, NULL);
	if (!(mapa = CreateFileMapping(archivo, NULL, PAGE_READWRITE, 0, len, NULL)))
		return;
	p = cur = MapViewOfFile(mapa, FILE_MAP_COPY, 0, 0, 0);
	if (!p)
		return;
#else
	if (fstat(fd, &sb) == -1)
		return;
	len = sb.st_size;
	p = cur = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
#endif
	while (cur < (p + len))
	{
		if ((ds = strchr(cur, '\r')))
			*ds = '\0';
		if ((ds = strchr(cur, '\n')))
			*ds = '\0';
		parsea_linea(tipo, cur, 0);
		cur = ++ds;
	}
#ifdef _WIN32
	UnmapViewOfFile(p);
	CloseHandle(mapa);
	CloseHandle(archivo);
#else
	munmap(p, len);
	close(fd);
#endif
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
/* comandos
 * 
 * INF: da información (su md5) si no coinciden, se piden resúmenes
 * RES: resumen de la base de datos. se utiliza para solicitar un resumen o para solicitar al otro nodo que resuma 
 *	 el nodo que tenga mas registros, es el que manda los que le faltan al otro
 * INS: insertar registro. este comando solo puede emitirlo un hub. si no es asi, no se propaga
 * DEL: borra un registro. lo mismo, solo desde hubs
 * ERR: hay un error
 * DRP: trunca una db
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
	/* DB * INF <bdd> <md5> */
	if (!strcasecmp(parv[2], "INF"))
	{
		if (!match(parv[1], me.name))
		{
			Udb *bloq;
			if (!strchr(bloques, *parv[3]))
			{
				sendto_one(cptr, ":%s DB %s ERR RES %i %c", me.name, sptr->name, E_UDB_NODB, *parv[3]);
				return 1;
			}
			bloq = coge_de_id(*parv[3]);
			if (strcmp(parv[4], bloq->data_char))
				sendto_one(cptr, ":%s DB %s RES %c %lu", me.name, parv[0], *parv[3], bloq->data_long);
			else
			{
				if (++(sptr->serv->flags.bloqs) == BDD_TOTAL)
					sendto_one(cptr, ":%s %s", me.name, (IsToken(cptr) ? TOK_EOS : MSG_EOS));
			}
		}
		/* pasamos el comando puesto que no es necesario que sea hub */
		sendto_serv_butone(cptr, ":%s DB %s INF %c %s", parv[0], parv[1], *parv[3], parv[4]);
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
				}
			}
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
			if (bytes != bloq->data_long)
			{
				sendto_one(cptr, ":%s DB %s ERR INS %i %c %lu", me.name, sptr->name, E_UDB_LEN, tipo, bloq->data_long);
				return 1;
			}
			r += 3;
			ircsprintf(buf, "%s %s", r, parv[5]);
			parsea_linea(tipo, buf, 1);
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
			if (bytes != bloq->data_long)
			{
				sendto_one(cptr, ":%s DB %s ERR DEL %i %c %lu", me.name, sptr->name, E_UDB_LEN, tipo, bloq->data_long);
				return 1;
			}
			r += 3;
			parsea_linea(tipo, r, 1);
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
			FILE *fp;
			Udb *bloq;
			char *contenido = NULL;
			u_long bytes;
			if (!strchr(bloques, *parv[3]))
			{
				sendto_one(cptr, ":%s DB %s ERR DRP %i %c", me.name, sptr->name, E_UDB_NODB, *parv[3]);
				return 1;
			}
			bloq = coge_de_id(*parv[3]);
			bytes = atoul(parv[4]);
			if (bytes > bloq->data_long)
			{
				sendto_one(cptr, ":%s DB %s ERR DRP %i %c", me.name, sptr->name, E_UDB_LEN, *parv[3]);
				return 1;
			}
			if ((fp = fopen(bloq->item, "rb")))
			{
				contenido = MyMalloc(bytes);
				if (fread(contenido, 1, bytes, fp) != bytes)
				{
					fclose(fp);
					sendto_one(cptr, ":%s DB %s ERR DRP %i %c fread", me.name, sptr->name, E_UDB_FATAL, *parv[3]);
					return 1;
				}
				fclose(fp);
				if ((fp = fopen(bloq->item, "wb")))
				{
					int id;
					id = coge_de_char(*parv[3]);
					if (fwrite(contenido, 1, bytes, fp) != bytes)
					{
						fclose(fp);
						sendto_one(cptr, ":%s DB %s ERR DRP %i %c fwrite", me.name, sptr->name, E_UDB_FATAL, *parv[3]);
						return 1;
					}
					fclose(fp);
					actualiza_hash(bloq);
					descarga_bloque(id);
					carga_bloque(id);
				}
				else
				{
					sendto_one(cptr, ":%s DB %s ERR DRP %i %c fopen(wb)", me.name, sptr->name, E_UDB_FATAL, *parv[3]);
					return 1;
				}
				if (contenido)
					MyFree(contenido);
			}
			else
			{
				sendto_one(cptr, ":%s DB %s ERR DRP %i %c fopen(rb)", me.name, sptr->name, E_UDB_FATAL, *parv[3]);
				return 1;
			}
		}
		sendto_serv_butone(cptr, ":%s DB %s DRP %s %s", parv[0], parv[1], parv[3], parv[4]);
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
int tipo_de_pass(char *nick, char *pass)
{
	Udb *reg, *bloq, *cha;
	anAuthStruct *as;
	int tipo = AUTHTYPE_PLAINTEXT;
	if (!(reg = busca_registro(BDD_NICKS, nick)))
		return 0; /* no existe */
	if (busca_bloque("forbid", reg))
		return -1; /* tiene el nick en forbid, no importa la pass */
	if (!(bloq = busca_bloque("pass", reg)))
		return 0; /* no existe */
	if (!pass)
		return -3;
	bzero(buf, sizeof(buf));
	if ((cha = busca_bloque("desafio", reg)))
	{
		int len;
		char *bpass, buf2[22];
		if ((tipo = Auth_FindType(cha->data_char)) == -1)
			return 0; /* si el desafio no es correcto, el nick no existe */
		bpass = bloq->data_char;
		bzero(buf2, sizeof(buf2));
		switch(tipo)
		{
#ifdef AUTHENABLE_MD5
			case AUTHTYPE_MD5:
				len = 17;
				break;
#endif
#ifdef AUTHENABLE_SHA1
			case AUTHTYPE_SHA1:
				len = 21;
				break;
#endif
#ifdef AUTHENABLE_RIPEMD160
			case AUTHTYPE_RIPEMD160:
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
		strcpy(buf, pass);
	as = (anAuthStruct *) MyMalloc(sizeof(anAuthStruct));
	as->type = tipo;
	as->data = strdup(buf);
	if (Auth_Check(&me, as, pass) == 2) /* ok */
	{
		Auth_DeleteAuthStruct(as);
		if (busca_bloque("suspendido", reg))
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
   	if (!(breg = busca_registro(BDD_SET, "NickServ")))
		botname = me.name;
	else
		botname = breg->data_char;
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
	val = tipo_de_pass(nick, parv[2]);
	if (!IsAnOper(sptr) && !IsHelpOp(sptr))
	{
		if (val < 0)
		{
			sendto_one(cptr, ":%s NOTICE %s :*** Contraseña incorrecta.", botname, sptr->name);
			return 0;
		}
		else if (val == 1)
		{
			sendto_one(cptr, ":%s NOTICE %s :*** No puedes aplicar ghost sobre un nick suspendido.", botname, sptr->name);
			return 0;
		}
	}
	sendto_serv_butone_token(NULL, me.name, MSG_KILL, TOK_KILL, "%s :Comando GHOST utilizado por %s.", acptr->name, who);
	if (MyClient(acptr))
		sendto_one(acptr, ":%s KILL %s :Comando GHOST utilizado por %s.", me.name, acptr->name, who);
	sendto_one(cptr, ":%s NOTICE %s :*** Sesión fantasma del nick %s liberada.", botname, sptr->name, nick);
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
		sendto_one(sptr, ":%s NOTICE %s :Parámetros insuficientes. Sintaxis: /dbq [servidor] <bloque>.", me.name, sptr->name);
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
		sendto_one(sptr, ":%s NOTICE %s :La base de datos %c no existe.", me.name, sptr->name, *pos);
		return 0;
	}
	cur += 3;
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
		sendto_one(sptr, ":%s NOTICE %s :No se encuentra el bloque %s.", me.name, sptr->name, cur);
	}
	else
	{
		if (bloq->data_long)
			sendto_one(sptr, ":%s NOTICE %s :DBQ %s %lu", me.name, sptr->name, parv[1], bloq->data_long);
		else
			sendto_one(sptr, ":%s NOTICE %s :DBQ %s %s", me.name, sptr->name, parv[1], bloq->data_char);
	}
	MyFree(pos);
	return 0;
}
int puede_cambiar_nick_en_bdd(aClient *cptr, aClient *sptr, aClient *acptr, char *parv[], char *nick, char *pass, char nick_used)
{
	int tipo = 1;
	if (!MyConnect(sptr))
		return 1;
	do
	{
		Udb *breg;
		char *botname;
		if (sptr == acptr)
			break;
		if (!(tipo = tipo_de_pass(nick, pass)))
			break;
		if (!(breg = busca_registro(BDD_SET, "NickServ")))
			botname = me.name;
		else
			botname = breg->data_char;
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
void dale_cosas(int val, aClient *sptr)
{
	if (val > 0)
	{
		if (val == 2)
		{
			Udb *reg, *bloq;
			sptr->umodes |= UMODE_REGNICK;
			reg = busca_registro(BDD_NICKS, sptr->name);
			if ((bloq = busca_bloque("modos", reg)))
			{
				char *cur = bloq->data_char;
				while (!BadPtr(cur))
				{
					switch(*cur)
					{
						case 'o':
							if (!IsAnOper(sptr))
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
							sptr->oflag |= OFLAG_HELPOP;
							break;
						case 'a':
							sptr->umodes |= UMODE_SADMIN;
							sptr->oflag |= OFLAG_SADMIN;
							break;
						case 'A':
							sptr->umodes |= UMODE_ADMIN;
							sptr->oflag |= OFLAG_ADMIN;
							break;
						case 'O':
							sptr->umodes |= UMODE_LOCOP;
							break;
						case 'k':
							sptr->umodes |= UMODE_SERVICES;
							sptr->oflag |= OFLAG_OVERRIDE;
							break;
						case 'N':
							sptr->umodes |= UMODE_NETADMIN;
							sptr->oflag |= OFLAG_NETADMIN;
							break;
						case 'C':
							sptr->umodes |= UMODE_COADMIN;
							sptr->oflag |= OFLAG_COADMIN;
							break;
						case 'W':
							sptr->umodes |= UMODE_WHOIS;
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
					}
					cur++;
				}
			}
			if ((bloq = busca_bloque("oper", reg)))
			{
				u_long nivel = bloq->data_long;
				if (nivel & BDD_OPER)
				{
					sptr->umodes |= UMODE_HELPOP;
					sptr->oflag |= OFLAG_HELPOP;
				}
				if (nivel & BDD_ADMIN || nivel & BDD_ROOT)
				{
					sptr->umodes |= (UMODE_OPER | UMODE_NETADMIN);
					if (!IsAnOper(sptr))
					{
						sendto_one(sptr, rpl_str(RPL_YOUREOPER), me.name, sptr->name);
						IRCstats.operators++;
#ifndef NO_FDLIST
						addto_fdlist(sptr->slot, &oper_fdlist);
#endif
						RunHook2(HOOKTYPE_LOCAL_OPER, sptr, 1);
					}
					if (nivel & BDD_ROOT)
						sptr->oflag |= (OFLAG_NADMIN | OFLAG_DIE | OFLAG_RESTART | OFLAG_TKL | OFLAG_GZL | OFLAG_OVERRIDE | OFLAG_ADDLINE | OFLAG_ZLINE);
				}
			}
			if (IsClient(sptr))
			{
				if ((bloq = busca_bloque("snomasks", reg)))
					set_snomask(sptr, bloq->data_char);
				if ((bloq = busca_bloque("swhois", reg)))
					ircstrdup(sptr->user->swhois, bloq->data_char);
			}
		}
		else if (val == 1)
			sptr->umodes |= UMODE_SUSPEND;
	}
}
char *chan_mask()
{
	char botnick[NICKLEN+1+USERLEN+1+HOSTLEN+1];
	Udb *chanserv;
	char *desde, *b;
	if ((chanserv = busca_registro(BDD_SET, "ChanServ")))
		strcpy(botnick, chanserv->data_char);
	else
		strcpy(botnick, me.name);
	if ((b = strchr(botnick, '!')))
		*b = 0;
	if (!find_client(botnick, NULL) || !chanserv) /* no está online */
		desde = me.name;
	else
		desde = chanserv->data_char;
	return desde;
}
char *chan_nick()
{
	static char botnick[NICKLEN+1+USERLEN+1+HOSTLEN+1];
	Udb *chanserv;
	char *desde, *b;
	if ((chanserv = busca_registro(BDD_SET, "ChanServ")))
		strcpy(botnick, chanserv->data_char);
	else
		strcpy(botnick, me.name);
	if ((b = strchr(botnick, '!')))
		*b = 0;
	if (!find_client(botnick, NULL) || !chanserv) /* no está online */
		desde = me.name;
	else
		desde = botnick;
	return desde;
}

#endif
