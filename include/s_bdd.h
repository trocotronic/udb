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
 * $Id: s_bdd.h,v 1.1.1.14 2007-03-20 19:34:25 Trocotronic Exp $
 */

/* CONFIGURACI�N DEL SISTEMA INTERNO UDB */
/* !!! NO TOCAR SI NO SE SABE REALMENTE QU� EST� MODIFICANDO !!! */
#define UDB_HASH
#define UDB_TOK
/* FIN DE CONFIGURACI�N */

/* --- NO TOCAR NADA A PARTIR DE AQU� --- */
#ifdef _WIN32
#define DB_DIR "database\\"
#define DB_DIR_BCK DB_DIR "backup\\"
#else
#define DB_DIR "database/"
#define DB_DIR_BCK DB_DIR "backup/"
#endif
#define UDB_VER "UDB3.5.1"
typedef struct _udb Udb;
typedef struct _bloque UDBloq;
struct _udb
{
	char *item;
	u_int id;
	char *data_char;
	u_long data_long;
#ifdef UDB_HASH
	struct _udb *hsig;
#endif
	struct _udb *up, *mid, *down;
};
struct _bloque
{
	Udb *arbol;
	struct _bloque *sig;
	u_long crc32;
	char *path;
	u_int id;
	u_long lof;
	time_t gmt;
	aClient *res;
	u_int regs;
	char letra;
	u_int ver;
	int fd;
};
/* bloques actuales */
#if !defined(MODULE_COMPILE) && defined(_WIN32)
#define DLLEXP __declspec(dllexport)
#else
#define DLLEXP
#endif
DLLEXP extern MODVAR UDBloq *N;
DLLEXP extern MODVAR UDBloq *C;
DLLEXP extern MODVAR UDBloq *S;
DLLEXP extern MODVAR UDBloq *I;
DLLEXP extern MODVAR UDBloq *L;
DLLEXP extern MODVAR UDBloq *ultimo;
DLLEXP extern MODVAR Udb *UDB_NICKS;
DLLEXP extern MODVAR Udb *UDB_CANALES;
DLLEXP extern MODVAR Udb *UDB_IPS;
DLLEXP extern MODVAR Udb *UDB_SET;
DLLEXP extern MODVAR Udb *UDB_LINKS;
DLLEXP extern MODVAR char *grifo;
DLLEXP extern MODVAR int pases;
DLLEXP extern MODVAR int intervalo;
DLLEXP extern MODVAR aClient *propaga;

DLLFUNC extern char *MakeVirtualHost(aClient *, char *, char *, int);
DLLFUNC extern Udb *BuscaBloque(char *, Udb *);
DLLFUNC extern u_int LevelOperUdb(char *);
DLLFUNC char *GetVisibleHost(aClient *, aClient *);
DLLFUNC extern char *ChanNick(int);
DLLFUNC extern char *ChanMask(int);
DLLFUNC extern aClient *ChanClient();
DLLFUNC extern void DaleCosas(int, aClient *, Udb *, char *);
DLLFUNC extern void QuitaleCosas(aClient *, Udb *);
DLLFUNC extern int TipoDePass(char *, char *, Udb *, aClient *);
DLLFUNC extern int BuscaOpt(int, Udb *);

#define BDD_OPER 0x1
#define BDD_ADMIN 0x2
#define BDD_ROOT 0x4

#define CHAR_NUM '*' /* caracter para indicar que se trata de un entero largo */

/*
 * Vamos a explicar un poco los bloques de cada bloque principal.
 * Los nicks tienen los siguientes subbloques:
 * - N::<nick>::pass <contrase�a> -> contiene la contrase�a del nick
 * - N::<nick>::vhost <vhost> -> su host virtual
 * - N::<nick>::forbid <motivo> -> raz�n de su prohibici�n (si este bloque est� presente no se permite su uso)
 * - N::<nick>::suspendido <motivo> -> raz�n de su suspenso (si este bloque est� presente recibe el flag +S)
 * - N::<nick>::oper *<bits> -> flags de operador (preoper, oper, devel, etc.). Es un n�mero:
 *		BDD_OPER 0x1
 *		BDD_ADMIN 0x2
 *		BDD_ROOT 0x4
 * 	- BDD_OPER: recibe autom�ticamente el flag +h
 *	- BDD_ADMIN: recibe autom�ticamente los flags +oa privilegios de administraci�n
 *	- BDD_ROOT: recibe +oN y privilegios de servidor (/rehash, /restart, etc.)
 * - N::<nick>::desafio <metodo> -> metodo de cifrado de la contrase�a. M�todos que acepta:
 * 		{"plain"|"crypt"|"md5"|"sha1"|"sslclientcert"|"ripemd160"}
 * 		Si no se especifica, se usar� el que haya en el bloque S::desafio
 * - N::<nick>::modos <modos> -> contiene los modos de operador que puede utilizar:
 *		ohaAOkNCWqHX
 * - N::<nick>:snomasks <snomask> -> contiene las snomask de operador que puede utilizar:
 *		cfFjveGnNqS
 * - N::<nick>::swhois <whois> -> contiene su swhois
 * - N::<nick>::acceso <ip> -> acceso s�lo a esta ip (CIDR para un rango de ips)
 * Todos estos campos se dan en el momento que el usuario se identifica correcamente con /nick nick:pass
 *
 * Los canales tienen los siguientes subbloques:
 * - C::<#canal>::fundador <nick> -> nick del fundador
 * - C::<#canal>::modos <modos> -> modos del canal
 * - C::<#canal>::topic <topic> -> topic del canal
 * - C::<#canal>::accesos::<usuario> NULL -> es un subloque que contiene los nicks de las personas que pueden entrar. Si este bloque est� presente
 *	s�lo podr�n entrar en el canal los nicks que figuren en sus subloques.
 *	- C::<#canal>::accesos::Trocotronic NULL -> S�lo Trocotronic, con el modo +r, podr� entrar en el canal.
 * - C::<#canal>::forbid <motivo> -> #canal prohibido
 * - C::<#canal>::suspendido NULL -> no da +oq al fundador, el canal no est� en +r
 * - C::<#canal>::pass <contrase�a> -> Contrase�a del canal para darse +ao. Se usa /join # pass o /invite nick # pass
 * - C::<#canal>::desafio <desafio> -> Desaf�o de la contrase�a del canal
 * - C::<#canal>::opciones *<opts> -> Fija distintas opciones para el canal.
 * 		- C_OPT_PBAN 0x1 -> Si figura este flag, hay protecci�n de bans: s�lo el autor de los bans puede quitarlo (excepto founder y opers).
 *		- C_OPT_RMOD 0x2 -> Si figura este flag, los modos que haya en canal estar�n bloqueados, no se podr�n cambiar (excepto founder).
 *
 * Las ips tienen los siguiente subbloques
 * - I::<ip|host>::clones *<n� clones> -> n� de clones que se permiten desde esa ip
 * - I::<ip|host>::nolines GZQST -> *Lines que se salta: G Glines, Z Zlines, Q QLines, S Shuns y T Throttling
 * - I::<ip>::host <host> -> Host al que resuelve dicha ip
 *
 * El bloque set es un unibloque, que contiene todas las caracter�sticas de la red a nivel global.
 * - S::clave_cifrado <clave alfanum�rica> -> la clave de cifrado a usar para encriptar el host de los usuarios
 * - S::sufijo <sufijo> -> sufijo para las ip virtuales
 * - S::NickServ <nick!user@host> -> m�scara de NickServ
 * - S::ChanServ <nick!user@host> -> m�scara de ChanServ
 * - S::IpServ <nick!user@host> -> m�scara de IpServ
 * - S::clones *<n� clones> -> n�mero de clones permitidos en la red
 * - S::quit_ips <mensaje quit> -> mensaje que se muestra si esta conexi�n sobrepasa su capacidad otorgada
 * - S::quit_clones <mensaje quit> -> mensaje que se muestra si se rebasa los clones permitidos
 * - S::desafio <metodo> -> Desaf�o global con el que se cifran las contrase�as
 * - S::flood <v>:<s> -> Si el usuario intenta m�s de <v> veces durante <s> segundos una contrase�a incorrecta, es bloqueado.
 *
 * Los servidores tienen los siguientes subbloques:
 * - L::<servidor>::opciones *<opts> -> Fija distintas opciones para este link
 *    	- L_OPT_DEBG 0x1 -> Establece este servidor como debug. Recibe todos los cambio de usuarios UDB (modo +r por ejemplo).
 *    	- L_OPT_PROP 0x2 -> Establece este servidor como propagador. Es el �nico servidor que puede propagar datos por la red. S�lo puede haber UNO.
 *			ATENCI�N: Si se propaga esta opci�n y ya hay otro link propagador, el bloque entero se borrar�!
 *    	- L_OPT_CLNT 0x4 -> Permite la conexi�n de clientes en el caso de que sea un servidor no-UDB leaf y que a su vez est� configurado como uline.
 */

#define E_UDB_NODB 1 /* no existe bloque */
#define E_UDB_LEN 2 /* no corresponde offset */
#define E_UDB_NOHUB 3 /* no es hub */
#define E_UDB_PARAMS 4 /* faltan par�metros */
#define E_UDB_NOOPEN 5 /* no puede abrir */
#define E_UDB_FATAL 6 /* algo raro pasa */
#define E_UDB_RPROG 7 /* resumen en progreso */
#define E_UDB_NORES 8 /* no hab�a mandado resumen */
#define E_UDB_FBSRV 9 /* servidor prohibido */
#define E_UDB_REP 10 /* dato repetido */

#ifdef UDB_TOK
#define C_FUN "F"	/* fundador */
#define C_MOD "M"	/* modos */
#define C_TOP "T"	/* topic */
#define C_ACC "A"	/* acceso */
#define C_FOR "B"	/* forbid */
#define C_SUS "S"	/* suspendido */
#define C_PAS "P"	/* pass */
#define C_DES "D"	/* desafio */
#define C_OPT "O"	/* opciones */
#define N_ALL "A"	/* acceso */
#define N_PAS "P"	/* pass */
#define N_VHO "V"	/* vhost */
#define N_FOR "B"	/* forbid */
#define N_SUS "S"	/* suspendido */
#define N_OPE "O"	/* oper */
#define N_DES "D"	/* desafio */
#define N_MOD "M"	/* modos */
#define N_SNO "K"	/* snomasks */
#define N_SWO "W"	/* swhois */
#define I_CLO "S"	/* n� clones */
#define I_NOL "E"	/* nolines */
#define I_HOS "H"	/* host reverso */
#define S_CLA "L"	/* clave de cifrado */
#define S_SUF "J"	/* sufijo */
#define S_NIC "N"	/* nickserv */
#define S_CHA "C"	/* chanserv */
#define S_IPS "I"	/* ipserv */
#define S_CLO "S"	/* n� clones global */
#define S_QIP "T"	/* quit por ip */
#define S_QCL "Q"	/* quit por clones */
#define S_DES "D"	/* desafio global */
#define S_FLO "F"	/* pass-flood */
#define L_OPT "O"	/* opciones */
#else
#define C_FUN "fundador"
#define C_MOD "modos"
#define C_TOP "topic"
#define C_ACC "accesos"
#define C_FOR "forbid"
#define C_SUS "suspendido"
#define C_PAS "pass"
#define C_DES "desafio"
#define C_OPT "opciones"
#define N_ALL "acceso"
#define N_PAS "pass"
#define N_VHO "vhost"
#define N_FOR "forbid"
#define N_SUS "suspendido"
#define N_OPE "oper"
#define N_DES "desafio"
#define N_MOD "modos"
#define N_SNO "snomasks"
#define N_SWO "swhois"
#define I_CLO "clones"
#define I_NOL "nolines"
#define I_HOS "host"
#define S_CLA "clave_cifrado"
#define S_SUF "sufijo"
#define S_NIC "NickServ"
#define S_CHA "ChanServ"
#define S_IPS "IpServ"
#define S_CLO "clones"
#define S_QIP "quit_ips"
#define S_QCL "quit_clones"
#define S_DES "desafio"
#define S_FLO "flood"
#define L_OPT "opciones"
#endif

#define C_OPT_PBAN 0x1
#define C_OPT_RMOD 0x2

#define L_OPT_DEBG 0x1
#define L_OPT_PROP 0x2
#define L_OPT_CLNT 0x4
