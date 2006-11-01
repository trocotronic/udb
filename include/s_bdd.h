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
 * $Id: s_bdd.h,v 1.1.1.12 2006-11-01 00:06:42 Trocotronic Exp $
 */

#ifdef _WIN32
#define DB_DIR "database\\"
#define DB_DIR_BCK DB_DIR "backup\\"
#else
#define DB_DIR "database/"
#define DB_DIR_BCK DB_DIR "backup/"
#endif
#define DBMAX 64 /* hay de sobras */
#define UDB_VER "UDB3.4"
typedef struct _udb Udb;
typedef struct _bloque UDBloq;
struct _udb
{
	char *item; /* si queremos darle un nombre */
	u_int id; /* si queremos darle una id */
	char *data_char; /* su valor char */
	u_long data_long; /* su valor num�rico */
	struct _udb *hsig, *up, *mid, *down; /* punteros enlazados bla bla bla */
	/* 
	   para los bloques root (nicks, canales, ips y set) los punteros apuntan:
	   - hsig a NULL
	   - up a NULL
	   - mid al siguiente bloque root
	   - down al ultimo registro introducido
	   - data_char al total MD5 de su archivo
	   - item al path del archivo
	   - id contiene id
	   - data_long contiene el tama�o en bytes del archivo
	   */
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
DLLEXP extern MODVAR UDBloq *ultimo;
DLLEXP extern MODVAR Udb *UDB_NICKS;
DLLEXP extern MODVAR Udb *UDB_CANALES;
DLLEXP extern MODVAR Udb *UDB_IPS;
DLLEXP extern MODVAR Udb *UDB_SET;
DLLEXP extern MODVAR char *grifo;

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
DLLEXP extern MODVAR int pases;
DLLEXP extern MODVAR int intervalo;
DLLEXP extern MODVAR aClient *propaga;

#define BorraIpVirtual(x)							\
	do									\
	{									\
		if ((x)->user->virthost)					\
			MyFree((x)->user->virthost);				\
		(x)->user->virthost = NULL;					\
	}while(0)

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
 * - N::<nick>::A <ip> -> acceso s�lo a esta ip (CIDR para un rango de ips)
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
 * 		- BDD_C_OPT_PBAN 0x1 -> Si figura esta bit, hay protecci�n de bans: s�lo el autor de los bans puede quitarlo (excepto founder y opers).
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

#define C_FUN "fundador"
#define C_FUN_TOK "F"
#define C_MOD "modos"
#define C_MOD_TOK "M"
#define C_TOP "topic"
#define C_TOP_TOK "T"
#define C_ACC "accesos"
#define C_ACC_TOK "A"
#define C_FOR "forbid"
#define C_FOR_TOK "B"
#define C_SUS "suspendido"
#define C_SUS_TOK "S"
#define C_PAS "pass"
#define C_PAS_TOK "P"
#define C_DES "desafio"
#define C_DES_TOK "D"
#define C_OPT "opciones"
#define C_OPT_TOK "O"
#define N_ALL "acceso"
#define N_ALL_TOK "A"
#define N_PAS "pass"
#define N_PAS_TOK "P"
#define N_VHO "vhost"
#define N_VHO_TOK "V"
#define N_FOR "forbid"
#define N_FOR_TOK "B"
#define N_SUS "suspendido"
#define N_SUS_TOK "S"
#define N_OPE "oper"
#define N_OPE_TOK "O"
#define N_DES "desafio"
#define N_DES_TOK "D"
#define N_MOD "modos"
#define N_MOD_TOK "M"
#define N_SNO "snomasks"
#define N_SNO_TOK "K"
#define N_SWO "swhois"
#define N_SWO_TOK "W"
#define I_CLO "clones"
#define I_CLO_TOK "S"
#define I_NOL "nolines"
#define I_NOL_TOK "E"
#define I_HOS "host"
#define I_HOS_TOK "H"
#define S_CLA "clave_cifrado"
#define S_CLA_TOK "L"
#define S_SUF "sufijo"
#define S_SUF_TOK "J"
#define S_NIC "NickServ"
#define S_NIC_TOK "N"
#define S_CHA "ChanServ"
#define S_CHA_TOK "C"
#define S_IPS "IpServ"
#define S_IPS_TOK "I"
#define S_CLO "clones"
#define S_CLO_TOK "S"
#define S_QIP "quit_ips"
#define S_QIP_TOK "T"
#define S_QCL "quit_clones"
#define S_QCL_TOK "Q"
#define S_DES "desafio"
#define S_DES_TOK "D"

#define BDD_C_OPT_PBAN 0x1
#define BDD_C_OPT_RMOD 0x2
