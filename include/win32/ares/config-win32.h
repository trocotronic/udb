#ifndef __ARES_CONFIG_WIN32_H
#define __ARES_CONFIG_WIN32_H

/* $Id: config-win32.h,v 1.1.2.2 2008/12/19 16:17:04 syzop Exp $ */

/* Copyright (C) 2004 - 2008 by Daniel Stenberg et al
 *
 * Permission to use, copy, modify, and distribute this software and its
 * documentation for any purpose and without fee is hereby granted, provided
 * that the above copyright notice appear in all copies and that both that
 * copyright notice and this permission notice appear in supporting
 * documentation, and that the name of M.I.T. not be used in advertising or
 * publicity pertaining to distribution of the software without specific,
 * written prior permission.  M.I.T. makes no representations about the
 * suitability of this software for any purpose.  It is provided "as is"
 * without express or implied warranty.
 */

/* ================================================================ */
/*    ares/config-win32.h - Hand crafted config file for Windows    */
/* ================================================================ */

/* ---------------------------------------------------------------- */
/*                          HEADER FILES                            */
/* ---------------------------------------------------------------- */

/* Define if you have the <getopt.h> header file.  */
#if defined(__MINGW32__)
#define HAVE_GETOPT_H 1
#endif

/* Define if you have the <signal.h> header file. */
#define HAVE_SIGNAL_H 1

/* Define if you have the <sys/time.h> header file */
/* #define HAVE_SYS_TIME_H 1 */

/* Define if you have the <time.h> header file.  */
#define HAVE_TIME_H 1

/* Define if you have the <process.h> header file.  */
#define HAVE_PROCESS_H 1

/* Define if you have the <unistd.h> header file.  */
#if defined(__MINGW32__) || defined(__WATCOMC__) || defined(__LCC__) || \
    defined(__POCC__)
#define HAVE_UNISTD_H 1
#endif

/* Define if you have the <windows.h> header file.  */
#define HAVE_WINDOWS_H 1

/* Define if you have the <winsock.h> header file.  */
#define HAVE_WINSOCK_H 1

/* Define if you have the <winsock2.h> header file.  */
//#define HAVE_WINSOCK2_H 1

/* Define if you have the <ws2tcpip.h> header file.  */
//#define HAVE_WS2TCPIP_H 1

/* ---------------------------------------------------------------- */
/*                        OTHER HEADER INFO                         */
/* ---------------------------------------------------------------- */

/* Define if sig_atomic_t is an available typedef. */
#define HAVE_SIG_ATOMIC_T 1

/* Define if you have the ANSI C header files.  */
#define STDC_HEADERS 1

/* Define if you can safely include both <sys/time.h> and <time.h>.  */
/* #define TIME_WITH_SYS_TIME 1 */

/* ---------------------------------------------------------------- */
/*                             FUNCTIONS                            */
/* ---------------------------------------------------------------- */

/* Define if you have the ioctlsocket function. */
#define HAVE_IOCTLSOCKET 1

/* Define if you have a working ioctlsocket FIONBIO function. */
#define HAVE_IOCTLSOCKET_FIONBIO 1

/* Define if you have the strcasecmp function. */
/* #define HAVE_STRCASECMP 1 */

/* Define if you have the strdup function. */
#define HAVE_STRDUP 1

/* Define if you have the stricmp function. */
#define HAVE_STRICMP 1

/* Define if you have the strncasecmp function. */
/* #define HAVE_STRNCASECMP 1 */

/* Define if you have the strnicmp function. */
#define HAVE_STRNICMP 1

/* Define if you have the gethostname function.  */
#define HAVE_GETHOSTNAME 1

/* Define if you have the recv function. */
#define HAVE_RECV 1

/* Define to the type of arg 1 for recv. */
#define RECV_TYPE_ARG1 SOCKET

/* Define to the type of arg 2 for recv. */
#define RECV_TYPE_ARG2 char *

/* Define to the type of arg 3 for recv. */
#define RECV_TYPE_ARG3 int

/* Define to the type of arg 4 for recv. */
#define RECV_TYPE_ARG4 int

/* Define to the function return type for recv. */
#define RECV_TYPE_RETV int

/* Define if you have the recvfrom function. */
#define HAVE_RECVFROM 1

/* Define to the type of arg 1 for recvfrom. */
#define RECVFROM_TYPE_ARG1 SOCKET

/* Define to the type pointed by arg 2 for recvfrom. */
#define RECVFROM_TYPE_ARG2 char

/* Define to the type of arg 3 for recvfrom. */
#define RECVFROM_TYPE_ARG3 int

/* Define to the type of arg 4 for recvfrom. */
#define RECVFROM_TYPE_ARG4 int

/* Define to the type pointed by arg 5 for recvfrom. */
#define RECVFROM_TYPE_ARG5 struct sockaddr

/* Define to the type pointed by arg 6 for recvfrom. */
#define RECVFROM_TYPE_ARG6 int

/* Define to the function return type for recvfrom. */
#define RECVFROM_TYPE_RETV int

/* Define if you have the send function. */
#define HAVE_SEND 1

/* Define to the type of arg 1 for send. */
#define SEND_TYPE_ARG1 SOCKET

/* Define to the type qualifier of arg 2 for send. */
#define SEND_QUAL_ARG2 const

/* Define to the type of arg 2 for send. */
#define SEND_TYPE_ARG2 char *

/* Define to the type of arg 3 for send. */
#define SEND_TYPE_ARG3 int

/* Define to the type of arg 4 for send. */
#define SEND_TYPE_ARG4 int

/* Define to the function return type for send. */
#define SEND_TYPE_RETV int

/* Specifics for the Watt-32 tcp/ip stack */
#ifdef WATT32
  #define SOCKET              int
  #define NS_INADDRSZ         4
  #define HAVE_ARPA_NAMESER_H 1
  #define HAVE_ARPA_INET_H    1
  #define HAVE_NETDB_H        1
  #define HAVE_NETINET_IN_H   1
  #define HAVE_SYS_SOCKET_H   1
  #define HAVE_NETINET_TCP_H  1
  #define HAVE_AF_INET6       1
  #define HAVE_PF_INET6       1
  #define HAVE_STRUCT_IN6_ADDR     1
  #define HAVE_STRUCT_SOCKADDR_IN6 1
  #undef HAVE_WINSOCK_H
  #undef HAVE_WINSOCK2_H
  #undef HAVE_WS2TCPIP_H
#endif

/* ---------------------------------------------------------------- */
/*                       TYPEDEF REPLACEMENTS                       */
/* ---------------------------------------------------------------- */

/* Define this if in_addr_t is not an available 'typedefed' type */
#define in_addr_t unsigned long

/* Define as the return type of signal handlers (int or void).  */
#define RETSIGTYPE void

/* Define ssize_t if it is not an available 'typedefed' type */
#if (defined(__WATCOMC__) && (__WATCOMC__ >= 1240)) || defined(__POCC__)
#elif defined(_WIN64)
#define ssize_t __int64
#else
#define ssize_t int
#endif

/* ---------------------------------------------------------------- */
/*                          STRUCT RELATED                          */
/* ---------------------------------------------------------------- */

/* Define this if you have struct addrinfo */
#define HAVE_STRUCT_ADDRINFO 1

/* Define this if you have struct sockaddr_storage */
#define HAVE_STRUCT_SOCKADDR_STORAGE 1

/* Define this if you have struct timeval */
#define HAVE_STRUCT_TIMEVAL 1

/* ---------------------------------------------------------------- */
/*                        COMPILER SPECIFIC                         */
/* ---------------------------------------------------------------- */

/* Define to avoid VS2005 complaining about portable C functions */
#if defined(_MSC_VER) && (_MSC_VER >= 1400)
#define _CRT_SECURE_NO_DEPRECATE 1
#define _CRT_NONSTDC_NO_DEPRECATE 1
#endif

/* VS2008 does not support Windows build targets prior to WinXP, */
/* so, if no build target has been defined we will target WinXP. */
#if defined(_MSC_VER) && (_MSC_VER >= 1500)
#  ifndef _WIN32_WINNT
#    define _WIN32_WINNT 0x0501
#  endif
#  ifndef WINVER
#    define WINVER 0x0501
#  endif
#  if (_WIN32_WINNT < 0x0501) || (WINVER < 0x0501)
#    error VS2008 does not support Windows build targets prior to WinXP
#  endif
#endif

/* Availability of freeaddrinfo, getaddrinfo and getnameinfo functions is quite */
/* convoluted, compiler dependant and in some cases even build target dependat. */
#if defined(HAVE_WS2TCPIP_H)
#  if defined(_WIN32_WINNT) && (_WIN32_WINNT >= 0x0501)
#    define HAVE_FREEADDRINFO 1
#    define HAVE_GETADDRINFO  1
#    define HAVE_GETNAMEINFO  1
#  elif defined(_MSC_VER) && (_MSC_VER >= 1200)
#    define HAVE_FREEADDRINFO 1
#    define HAVE_GETADDRINFO  1
#    define HAVE_GETNAMEINFO  1
#  endif
#endif

/* ---------------------------------------------------------------- */
/*                         IPV6 COMPATIBILITY                       */
/* ---------------------------------------------------------------- */

/* Define this if you have address family AF_INET6 */
#ifdef HAVE_WINSOCK2_H
#define HAVE_AF_INET6 1
#endif

/* Define this if you have protocol family PF_INET6 */
#ifdef HAVE_WINSOCK2_H
#define HAVE_PF_INET6 1
#endif

/* Define this if you have struct in6_addr */
#ifdef HAVE_WS2TCPIP_H
#define HAVE_STRUCT_IN6_ADDR 1
#endif

/* Define this if you have struct sockaddr_in6 */
#ifdef HAVE_WS2TCPIP_H
#define HAVE_STRUCT_SOCKADDR_IN6 1
#endif

/* Define this if you have sockaddr_in6 with scopeid */
#ifdef HAVE_WS2TCPIP_H
#define HAVE_SOCKADDR_IN6_SIN6_SCOPE_ID 1
#endif


#endif  /* __ARES_CONFIG_WIN32_H */
