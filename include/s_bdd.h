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

#ifdef _WIN32
#define DB_DIR "database\\"
#else
#define DB_DIR "database/"
#endif
typedef struct _udb Udb;
struct _udb
{
	char *item; /* si queremos darle un nombre */
	int id; /* si queremos darle una id */
	char *data_char; /* su valor char */
	u_long data_long; /* su valor numérico */
	struct _udb *prev, *sig, *hsig, *up, *mid, *down; /* punteros enlazados bla bla bla */
	/* 
	   para los bloques root (nicks, canales, ips y set) los punteros apuntan:
	   - prev al primer registro
	   - sig al ultimo registro
	   - hsig a NULL
	   - up a NULL
	   - mid al siguiente bloque root
	   - down al ultimo registro introducido
	   - data_char al total MD5 de su archivo
	   - item al path del archivo
	   - id contiene dos numeros de 16 bits: los 8 bits altos contienen su id, y los 8 bits bajos, su letra.
	   */
};
/* bloques actuales */
#ifdef MODULE_COMPILE
extern MODVAR Udb *nicks, *canales, *ips, *set;
#else
DLLFUNC extern MODVAR Udb *nicks, *canales, *ips, *set;
#endif

#ifdef MODULE_COMPILE
extern MODVAR u_int BDD_NICKS, BDD_CHANS, BDD_IPS, BDD_SET;
#else
DLLFUNC extern MODVAR u_int BDD_NICKS, BDD_CHANS, BDD_IPS, BDD_SET;
#endif

DLLFUNC extern char *make_virtualhost(aClient *, char *, char *, int);
DLLFUNC extern Udb *busca_registro(int, char *), *busca_bloque(char *, Udb *);
DLLFUNC extern int level_oper_bdd(char *);
DLLFUNC char *get_visiblehost(aClient *, aClient *);
DLLFUNC extern char *chan_nick();
DLLFUNC extern char *chan_mask();
#define BorraIpVirtual(x)							\
	do									\
	{									\
		if ((x)->user->virthost)					\
			MyFree((x)->user->virthost);			\
		(x)->user->virthost = NULL;					\
	}while(0)

#define BDD_PREO 0x1
#define BDD_OPER 0x2
#define BDD_DEVEL 0x4
#define BDD_ADMIN 0x8
#define BDD_ROOT 0x10

#define CHAR_NUM '*' /* caracter para indicar que se trata de un entero largo */

/*
 * Vamos a explicar un poco los bloques de cada bloque principal.
 * Los nicks tienen los siguientes subbloques:
 * - N::<nick>::pass <contraseña> -> contiene la contraseña del nick
 * - N::<nick>::vhost <vhost> -> su host virtual
 * - N::<nick>::forbid <motivo> -> razón de su prohibición (si este bloque está presente no se permite su uso)
 * - N::<nick>::suspendido <motivo> -> razón de su suspenso (si este bloque está presente recibe el flag +S)
 * - N::<nick>::oper *<bits> -> flags de operador (preoper, oper, devel, etc.). Es un número:
 *		BDD_PREO 0x1
 *		BDD_OPER 0x2
 *		BDD_DEVEL 0x4
 *		BDD_ADMIN 0x8
 *		BDD_ROOT 0x10
 * 	- BDD_OPER: recibe automáticamente el flag +h
 *	- BDD_ADMIN: recibe automáticamente los flags +oN
 *	- BDD_ROOT: además del +oN, recibe todos los privilegios (/rehash, /restart, etc.)
 * - N::<nick>::desafio <metodo> -> metodo de cifrado de la contraseña. Métodos que acepta:
 * 		{"plain"|"crypt"|"md5"|"sha1"|"sslclientcert"|"ripemd160"}
 * - N::<nick>::modos <modos> -> contiene los modos de operador que puede utilizar:
 *		ohaAOkNCWqHX
 * - N::<nick>:snomasks <snomask> -> contiene las snomask de operador que puede utilizar:
 *		cfFjveGnNqS
 * - N::<nick>::swhois <whois> -> contiene su swhois
 * Todos estos campos se dan en el momento que el usuario se identifica correcamente con /nick nick:pass
 *
 * Los canales tienen los siguientes subbloques:
 * - C::<#canal>::fundador <nick> -> nick del fundador
 * - C::<#canal>::modos <modos> -> modos del canal
 * - C::<#canal>::topic <topic> -> topic del canal
 * - C::<#canal>::accesos::<usuario> NULL -> es un subloque que contiene los nicks de las personas que pueden entrar. Si este bloque está presente
 *	sólo podrán entrar en el canal los nicks que figuren en sus subloques.
 *	- C::<#canal>::accesos::Trocotronic NULL -> Sólo Trocotronic, con el modo +r, podrá entrar en el canal.
 * - C::<#canal>::forbid <motivo> -> #canal prohibido
 * - C::<#canal>::suspendido * -> no da +oq al fundador
 *
 * Las ips tienen los siguiente subbloques
 * - I::<ip> *<nº clones> -> nº de clones que se permiten desde esa ip
 *
 * El bloque set es un unibloque, que contiene todas las características de la red a nivel global.
 * - S::clave_cifrado <clave alfanumérica> -> la clave de cifrado a usar para encriptar el host de los usuarios
 * - S::sufijo <sufijo> -> sufijo para las ip virtuales
 * - S::NickServ <nick!user@host> -> máscara de NickServ
 * - S::ChanServ <nick!user@host> -> máscara de ChanServ
 * - S::IpServ <nick!user@host> -> máscara de IpServ
 * - S::clones *<nº clones> -> número de clones permitidos en la red
 * - S::quit_ips <mensaje quit> -> mensaje que se muestra si esta conexión sobrepasa su capacidad otorgada
 * - S::quit_clones <mensaje quit> -> mensaje que se muestra si se rebasa los clones permitidos
 */

#define E_UDB_NODB 1
#define E_UDB_LEN 2
#define E_UDB_NOHUB 3
#define E_UDB_PARAMS 4
#define E_UDB_NOOPEN 5
#define E_UDB_FATAL 6
