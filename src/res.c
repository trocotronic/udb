/************************************************************************
 *   IRC - Internet Relay Chat, ircd/res.c
 *   Copyright (C) 1992 Darren Reed
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

#include "struct.h"
#include "common.h"
#include "sys.h"
#include "res.h"
#include "numeric.h"
#include "h.h"
#include "proto.h"
#include <signal.h>
#ifndef _WIN32
#include <sys/time.h>
#include <sys/socket.h>
#endif
#include "nameser.h"
#include "resolv.h"
#include "inet.h"
#include "threads.h"
#include <string.h>
#ifndef CLEAN_COMPILE
static char rcsid[] = "@(#)$Id: res.c,v 1.1.1.2 2004-02-18 18:24:12 Trocotronic Exp $";
#endif
#if 0
#undef	DEBUG	/* because there is a lot of debug code in here :-) */
#endif
#define HE(x) (&((x)->he))
static char hostbuf[HOSTLEN + 1 + 100];	/* +100 for INET6 */
static char dot[] = ".";
static int incache = 0;
static CacheTable hashtable[ARES_CACSIZE];
static aCache *cachetop = NULL;
static ResRQ *last, *first;

static void rem_cache(aCache *);
static void rem_request(ResRQ *);
static int do_query_name(Link *, char *, ResRQ *);
static int do_query_number(Link *, struct IN_ADDR *, ResRQ *);
static void resend_query(ResRQ *);
static int proc_answer(ResRQ *, HEADER *, char *, char *);
static int query_name(char *, int, int, ResRQ *);
static aCache *make_cache(ResRQ *), *rem_list(aCache *);
static aCache *find_cache_name(char *);
static aCache *find_cache_number(ResRQ *, char *);
static int add_request(ResRQ *);
static ResRQ *make_request(Link *);
static int send_res_msg(char *, int, int);
static ResRQ *find_id(int);
static int hash_number(unsigned char *);
static void update_list(ResRQ *, aCache *);
static int hash_name(char *);
static int bad_hostname(char *, int);
#define CLI_HASH_VALUE local[tcc % 256]

extern TS nextexpire;

static struct cacheinfo {
	int  ca_adds;
	int  ca_dels;
	int  ca_expires;
	int  ca_lookups;
	int  ca_na_hits;
	int  ca_nu_hits;
	int  ca_updates;
} cainfo;

static char *global_timeout_list = NOTINIT;

static struct resinfo {
	int  re_errors;
	int  re_nu_look;
	int  re_na_look;
	int  re_replies;
	int  re_requests;
	int  re_resends;
	int  re_sent;
	int  re_timeouts;
	int  re_shortttl;
	int  re_unkrep;
} reinfo;

int init_resolver(int op)
{
	int  ret = 0;

	if (op & RES_INITLIST)
	{
		bzero((char *)&reinfo, sizeof(reinfo));
		first = last = NULL;
	}
	if (op & RES_CALLINIT)
	{
		ret = ircd_res_init();
		if (!ircd_res.nscount)
		{
			ircd_res.nscount = 1;
			Debug((DEBUG_DNS, "Setting nameserver to be %s",
				NAME_SERVER));
#ifdef INET6
			/* still IPv4 */
			ircd_res.nsaddr_list[0].sin_addr.s_addr =
			    inet_pton(AF_INET, NAME_SERVER,
			    &ircd_res.nsaddr_list[0].sin_addr.s_addr);
#else
			ircd_res.nsaddr_list[0].sin_addr.s_addr =
			    inet_addr(NAME_SERVER);
#endif
		}
	}

	if (op & RES_INITSOCK)
	{
		int  on = 0;

#ifdef INET6
		/* still IPv4 */
		ret = resfd = socket(AF_INET, SOCK_DGRAM, 0);
#else
		ret = resfd = socket(AF_INET, SOCK_DGRAM, 0);
#endif
		(void)setsockopt(ret, SOL_SOCKET, SO_BROADCAST, &on, on);
	}
#ifdef DEBUGMODE
	if (op & RES_INITDEBG)
		ircd_res.options |= RES_DEBUG;
#endif
	if (op & RES_INITCACH)
	{
		bzero((char *)&cainfo, sizeof(cainfo));
		bzero((char *)hashtable, sizeof(hashtable));
	}
	if (op == 0)
		ret = resfd;
	return ret;
}

static int add_request(ResRQ *new)
{
	if (!new)
		return -1;
	if (!first)
		first = last = new;
	else
	{
		last->next = new;
		last = new;
	}
	new->next = NULL;
	reinfo.re_requests++;
	return 0;
}

/*
 * remove a request from the list. This must also free any memory that has
 * been allocated for temporary storage of DNS results.
 */
static void rem_request(ResRQ *old)
{
	ResRQ **rptr, *r2ptr = NULL;
	int  i;
	char *s;

	if (!old)
		return;

	for (rptr = &first; *rptr; r2ptr = *rptr, rptr = &(*rptr)->next)
		if (*rptr == old)
		{
			*rptr = old->next;
			if (last == old)
				last = r2ptr;
			break;
		}
#ifdef	DEBUGMODE
	Debug((DEBUG_INFO, "rem_request:Remove %#x at %#x %#x", old, *rptr, r2ptr));
#endif
	r2ptr = old;
	if (r2ptr->he.h_name)
		MyFree(r2ptr->he.h_name);
	for (i = 0; i < MAXALIASES; i++)
		if ((s = r2ptr->he.h_aliases[i]))
			MyFree(s);
	if (r2ptr->name)
		MyFree(r2ptr->name);
	MyFree(r2ptr);
	return;
}

/*
 * Create a DNS request record for the server.
 */
static ResRQ *make_request(Link *lp)
{
	ResRQ *nreq;

	nreq = (ResRQ *)MyMalloc(sizeof(ResRQ));
	bzero((char *)nreq, sizeof(ResRQ));
	nreq->next = NULL;	/* where NULL is non-zero ;) */
	nreq->sentat = TStime();
	nreq->retries = HOST_RETRIES;
	nreq->resend = 1;
	nreq->srch = -1;
	if (lp)
		bcopy((char *)lp, (char *)&nreq->cinfo, sizeof(Link));
	else
		bzero((char *)&nreq->cinfo, sizeof(Link));
	nreq->timeout = HOST_TIMEOUT;	/* start at 4 and exponential inc. */
	nreq->he.h_addrtype = AFINET;
	nreq->he.h_name = NULL;
	nreq->he.h_aliases[0] = NULL;
	(void)add_request(nreq);
	return nreq;
}

/*
 * Remove queries from the list which have been there too long without
 * being resolved.
 */
time_t timeout_query_list(time_t now)
{
	ResRQ *rptr, *r2ptr;
	time_t next = 0, tout;
	aClient *cptr;

	Debug((DEBUG_DNS, "timeout_query_list at %s", myctime(now)));
	for (rptr = first; rptr; rptr = r2ptr)
	{
		r2ptr = rptr->next;
		tout = rptr->sentat + rptr->timeout;
		if (now >= tout)
		{
			if (--rptr->retries <= 0)
			{
#ifdef DEBUGMODE
				Debug((DEBUG_ERROR, "timeout %x now %d cptr %x",
				    rptr, now, rptr->cinfo.value.cptr));
#endif
				reinfo.re_timeouts++;
				cptr = rptr->cinfo.value.cptr;
				switch (rptr->cinfo.flags)
				{
				  case ASYNC_CLIENT:
					  if (SHOWCONNECTINFO && !cptr->serv)
						  sendto_one(cptr, "%s", REPORT_FAIL_DNS);
					  ClearDNS(cptr);
                      if (!DoingAuth(cptr))
						  SetAccess(cptr);
					  break;
				  case ASYNC_CONNECT:
					  sendto_ops("Host %s unknown", rptr->name);
					  break;
				}
				rem_request(rptr);
				continue;
			}
			else
			{
				rptr->sentat = now;
				rptr->timeout += rptr->timeout;
				resend_query(rptr);
				tout = now + rptr->timeout;
#ifdef DEBUGMODE
				Debug((DEBUG_INFO, "r %x now %d retry %d c %x",
				    rptr, now, rptr->retries,
				    rptr->cinfo.value.cptr));
#endif
			}
		}
		if (!next || tout < next)
			next = tout;
	}
	return (next > now) ? next : (now + AR_TTL);
}

/*
 * del_queries - called by the server to cleanup outstanding queries for
 * which there no longer exist clients or conf lines.
 */
void del_queries(char *cp)
{
	ResRQ *rptr, *r2ptr;

	for (rptr = first; rptr; rptr = r2ptr)
	{
		r2ptr = rptr->next;
		if (cp == rptr->cinfo.value.cp)
			rem_request(rptr);
	}
}

/*
 * sends msg to all nameservers found in the "ircd_res" structure.
 * This should reflect /etc/resolv.conf. We will get responses
 * which arent needed but is easier than checking to see if nameserver
 * isnt present. Returns number of messages successfully sent to
 * nameservers or -1 if no successful sends.
 */
static int send_res_msg(char *msg, int len, int rcount)
{
#ifdef DEBUGMODE
	char debbuffer[50];
	int j;
#endif

	int  i;
	int  sent = 0, max;

	if (!msg)
		return -1;

	max = MIN(ircd_res.nscount, rcount);
	if (ircd_res.options & RES_PRIMARY)
		max = 1;
	if (!max)
		max = 1;

#ifdef DEBUGMODE
	Debug((DEBUG_DNS, "send_res_msg: Dumping packet contents"));
	*debbuffer = '\0';
	j = 0;
	for (i = 0; i < len; i++)
	{
		debbuffer[j] = msg[i] > 32 ? msg[i] : '.';
		j++;
		if (j == 32)
		{
			debbuffer[j] = '\0';
			Debug((DEBUG_DNS, "- %s", debbuffer));
			j = 0;				
		}
	}
	if (j > 0)
	{
		debbuffer[j] = '\0';
		Debug((DEBUG_DNS, "- %s", debbuffer));
	}
#endif


	for (i = 0; i < max; i++)
	{
		Debug((DEBUG_DNS, "Sending to nameserver %i",
			i));
#ifdef INET6
		/* still IPv4 */
		ircd_res.nsaddr_list[i].sin_family = AF_INET;
#else
		ircd_res.nsaddr_list[i].sin_family = AF_INET;
#endif
#ifdef INET6
		if (sendto(resfd, msg, len, 0,
		    (struct sockaddr *)&(ircd_res.nsaddr_list[i]),
		    sizeof(struct sockaddr)) == len)
#else
		if (sendto(resfd, msg, len, 0,
		    (struct sockaddr *)&(ircd_res.nsaddr_list[i]),
		    sizeof(struct sockaddr)) == len)
#endif

		{
			Debug((DEBUG_DNS, "send_res_msg, errno = %s",strerror(ERRNO)));
			reinfo.re_sent++;
			sent++;
		}
		else
			Debug((DEBUG_ERROR, "s_r_m:sendto: %d on %d",
			    ERRNO, resfd));
	}

	return (sent) ? sent : -1;
}

/*
 * find a dns request id (id is determined by dn_mkquery)
 */
static ResRQ *find_id(int id)
{
	ResRQ *rptr;

	for (rptr = first; rptr; rptr = rptr->next)
		if (rptr->id == id)
			break;
	return rptr;
}

struct hostent *gethost_byname(char *name, Link *lp)
{
	aCache *cp;

	reinfo.re_na_look++;
	if ((cp = find_cache_name(name)))
		return (struct hostent *)&(cp->he);
	if (!lp)
		return NULL;
	(void)do_query_name(lp, name, NULL);
	return NULL;
}

struct hostent *gethost_byaddr(char *addr, Link *lp)
{
	aCache *cp;

	reinfo.re_nu_look++;
	if ((cp = find_cache_number(NULL, addr)))
		return (struct hostent *)&(cp->he);
	if (!lp)
		return NULL;
	(void)do_query_number(lp, (struct IN_ADDR *)addr, NULL);
	return NULL;
}

static int do_query_name(Link *lp, char *name, ResRQ *rptr)
{
	char hname[HOSTLEN + 1];
	int  len;

	strncpyzt(hname, name, sizeof(hname));
	len = strlen(hname);

	if (rptr && !index(hname, '.') && ircd_res.options & RES_DEFNAMES)
	{
		(void)strncat(hname, dot, sizeof(hname) - len - 1);
		len++;
		(void)strncat(hname, ircd_res.defdname,
		    sizeof(hname) - len - 1);
	}

	/*
	 * Store the name passed as the one to lookup and generate other host
	 * names to pass onto the nameserver(s) for lookups.
	 */
	if (!rptr)
	{
		rptr = make_request(lp);
#ifdef INET6
		rptr->type = T_ANY; /* Was T_AAAA: now using T_ANY so we fetch both A and AAAA -- Syzop */
#else
		rptr->type = T_A;
#endif
		rptr->name = (char *)MyMalloc(strlen(name) + 1);
		(void)strcpy(rptr->name, name);
	}
	Debug((DEBUG_DNS, "do_query_name(): %s ", hname));
#ifdef INET6
	return (query_name(hname, C_IN, T_ANY, rptr)); /* Was T_AAAA: now using T_ANY so we fetch both A and AAAA -- Syzop */
#else
	return (query_name(hname, C_IN, T_A, rptr));
#endif
}

/*
 * Use this to do reverse IP# lookups.
 */
static int do_query_number(Link *lp, struct IN_ADDR *numb, ResRQ *rptr)
{
	char ipbuf[128];
	u_char *cp;
#ifdef INET6
	cp = (u_char *)&numb->s6_addr;
	if (cp[0] == 0 && cp[1] == 0 && cp[2] == 0 && cp[3] == 0 && cp[4] == 0
	    && cp[5] == 0 && cp[6] == 0 && cp[7] == 0 && cp[8] == 0
	    && cp[9] == 0 && ((cp[10] == 0 && cp[11] == 0) || (cp[10] == 0xff
	    && cp[11] == 0xff)))
	{
		(void)ircsprintf(ipbuf, "%u.%u.%u.%u.in-addr.arpa.",
		    (u_int)(cp[15]), (u_int)(cp[14]),
		    (u_int)(cp[13]), (u_int)(cp[12]));
	}
	else
	{
		(void)ircsprintf(ipbuf,
		    "%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.ip6.%s.",
		    (u_int)(cp[15] & 0xf), (u_int)(cp[15] >> 4),
		    (u_int)(cp[14] & 0xf), (u_int)(cp[14] >> 4),
		    (u_int)(cp[13] & 0xf), (u_int)(cp[13] >> 4),
		    (u_int)(cp[12] & 0xf), (u_int)(cp[12] >> 4),
		    (u_int)(cp[11] & 0xf), (u_int)(cp[11] >> 4),
		    (u_int)(cp[10] & 0xf), (u_int)(cp[10] >> 4),
		    (u_int)(cp[9] & 0xf), (u_int)(cp[9] >> 4),
		    (u_int)(cp[8] & 0xf), (u_int)(cp[8] >> 4),
		    (u_int)(cp[7] & 0xf), (u_int)(cp[7] >> 4),
		    (u_int)(cp[6] & 0xf), (u_int)(cp[6] >> 4),
		    (u_int)(cp[5] & 0xf), (u_int)(cp[5] >> 4),
		    (u_int)(cp[4] & 0xf), (u_int)(cp[4] >> 4),
		    (u_int)(cp[3] & 0xf), (u_int)(cp[3] >> 4),
		    (u_int)(cp[2] & 0xf), (u_int)(cp[2] >> 4),
		    (u_int)(cp[1] & 0xf), (u_int)(cp[1] >> 4),
		    (u_int)(cp[0] & 0xf), (u_int)(cp[0] >> 4),
#ifdef SIXBONE_HACK
		    (cp[0] == 0x3f && cp[1] == 0xfe) ? "int" : "arpa"
#else
		    "arpa"
#endif
		    );
	}
#else
	cp = (u_char *)&numb->s_addr;
	(void)ircsprintf(ipbuf, "%u.%u.%u.%u.in-addr.arpa.",
	    (u_int)(cp[3]), (u_int)(cp[2]), (u_int)(cp[1]), (u_int)(cp[0]));
#endif
	Debug((DEBUG_DNS, "do_query_number: built %s rptr = %lx",
		ipbuf, rptr));

	if (!rptr)
	{
		rptr = make_request(lp);
		rptr->type = T_PTR;
#ifdef INET6
		bcopy(numb->s6_addr, rptr->addr.s6_addr, IN6ADDRSZ);
		bcopy((char *)numb->s6_addr,
		    (char *)&rptr->he.h_addr, sizeof(struct in6_addr));
#else
		rptr->addr.s_addr = numb->s_addr;
		bcopy((char *)&numb->s_addr,
		    (char *)&rptr->he.h_addr, sizeof(struct in_addr));
#endif
		rptr->he.h_length = sizeof(struct IN_ADDR);
	}
	return (query_name(ipbuf, C_IN, T_PTR, rptr));
}

/*
 * generate a query based on class, type and name.
 */
static int query_name(char *name, int class, int type, ResRQ *rptr)
{
	struct timeval tv;
	char buf[MAXPACKET];
	int  r, s;
	HEADER *hptr;

	bzero(buf, sizeof(buf));
	r = ircd_res_mkquery(QUERY, name, class, type, NULL, 0, NULL, (u_char *)buf, sizeof(buf));
	if (r <= 0)
	{
		Debug((DEBUG_DNS, "query_name: NO_RECOVERY"));
		SET_ERRNO(NO_RECOVERY);
		return r;
	}
	hptr = (HEADER *) buf;
	do
	{
		hptr->id = htons(getrandom16());
	} while (find_id(ntohs(hptr->id)));
	/* The above loop takes care of preventing requests with duplicate id's. -- Syzop */

	rptr->id = ntohs(hptr->id);
	rptr->sends++;
	s = send_res_msg(buf, r, rptr->sends);
	if (s == -1)
	{
		Debug((DEBUG_DNS, "query_name: TRY_AGAIN"));
		SET_ERRNO(TRY_AGAIN);
		return -1;
	}
	else
		rptr->sent += s;
	return 0;
}

static void resend_query(ResRQ *rptr)
{
	if (rptr->resend == 0)
		return;
	reinfo.re_resends++;
	switch (rptr->type)
	{
	  case T_PTR:
		  (void)do_query_number(NULL, &rptr->addr, rptr);
		  break;
#ifdef INET6
	  case T_AAAA:
#endif
	  case T_A:
		  (void)do_query_name(NULL, rptr->name, rptr);
		  break;
	  default:
		  break;
	}
	return;
}

/*
 * process name server reply.
 */
static int proc_answer(ResRQ *rptr, HEADER *hptr, char *buf, char *eob)
{
	char *cp, **alias;
	struct hent *hp;
	int  class, type, dlen, len, ans = 0, ansa = 0, n;
	struct IN_ADDR dr, *adr;

	cp = buf + sizeof(HEADER);
	hp = (struct hent *)&(rptr->he);
	adr = &hp->h_addr;
#ifdef INET6
	while (adr->s6_addr[0] | adr->s6_addr[1] | adr->s6_addr[2] |
	    adr->s6_addr[3])
#else
	while (adr->s_addr)
#endif
		adr++;
	alias = hp->h_aliases;
	while (*alias)
		alias++;
#if SOLARIS_2 && !defined(__GNUC__)	/* brain damaged compiler it seems */
	for (; hptr->qdcount > 0; hptr->qdcount--)
#else
	while (hptr->qdcount-- > 0)
#endif
		if ((n = __ircd_dn_skipname((u_char *)cp, (u_char *)eob)) == -1)
			break;
		else
			cp += (n + QFIXEDSZ);
	/*
	 * proccess each answer sent to us blech.
	 */
	while (hptr->ancount-- > 0 && cp && cp < eob)
	{
		n = ircd_dn_expand((u_char *)buf, (u_char *)eob, (u_char *)cp,
		    hostbuf, sizeof(hostbuf));
		if (n <= 0)
			break;

		cp += n;
		type = (int)ircd_getshort((u_char *)cp);
		cp += 2;	/* INT16SZ */
		class = (int)ircd_getshort((u_char *)cp);
		cp += 2;	/* INT16SZ */
		rptr->ttl = ircd_getlong((u_char *)cp);
		cp += 4;	/* INT32SZ */
		dlen = (int)ircd_getshort((u_char *)cp);
		cp += 2;	/* INT16SZ */
		rptr->type = type;

		/* name server never returns with trailing '.' */
		if (!index(hostbuf, '.') && (ircd_res.options & RES_DEFNAMES))
		{
			(void)strlcat(hostbuf, dot, sizeof hostbuf);
			(void)strlcat(hostbuf, ircd_res.defdname, sizeof hostbuf);
		}
		len = strlen(hostbuf);

		switch (type)
		{
#ifdef INET6
		  case T_AAAA:
#endif
		  case T_A:
#ifdef INET6
			  if (dlen != ((type == T_AAAA) ? sizeof(dr) :
			      sizeof(struct in_addr)))
#else
			  if (dlen != sizeof(dr))
#endif
			  {
				  Debug((DEBUG_DNS,
				      "Bad IP length (%d) returned for %s",
				      dlen, hostbuf));
				  return -2;
			  }
			if (ansa >= MAXADDRS - 1)
			{
				cp += dlen;
				break;
			}
			  hp->h_length = dlen;
			  if (ans == 1)
				  hp->h_addrtype = (class == C_IN) ?
				      AFINET : AF_UNSPEC;
#ifdef INET6

			if (type == T_AAAA)
				bcopy(cp, (char *)&dr, dlen);
			else {
				/* ugly hack */
				memset(dr.s6_addr, 0, 10);
				dr.s6_addr[10] = dr.s6_addr[11] = 0xff;
				memcpy(dr.s6_addr+12, cp, 4);
			}
			bcopy(dr.s6_addr, adr->s6_addr, IN6ADDRSZ);
#else
			bcopy(cp, (char *)&dr, dlen);
			adr->s_addr = dr.s_addr;
#endif
#ifdef INET6
			Debug((DEBUG_INFO,"got ip # %s for %s",
			       inet_ntop(AF_INET6, (char *)adr, mydummy,
					 MYDUMMY_SIZE),
			       hostbuf));
#else
			Debug((DEBUG_INFO,"got ip # %s for %s",
			       inetntoa((char *)adr),
			       hostbuf));
#endif
			if (!hp->h_name && len < HOSTLEN)
			    {
				hp->h_name =(char *)MyMalloc(len+1);
				(void)strlcpy(hp->h_name, hostbuf, len+1);
			    }
			  ans++;
			  ansa++;
			  adr++;
			  cp += dlen;
			  break;
		  case T_PTR:
			  if ((n = ircd_dn_expand((u_char *)buf, (u_char *)eob,
			      (u_char *)cp, hostbuf, sizeof(hostbuf))) < 0)
			  {
				  cp = NULL;
				  break;
			  }
			  cp += n;
			  len = strlen(hostbuf);
			  Debug((DEBUG_INFO, "got host %s (%d vs %d)",
			      hostbuf, len, strlen(hostbuf)));
			  if (bad_hostname(hostbuf, len))
				  return -1;
			  /*
			   * copy the returned hostname into the host name
			   * or alias field if there is a known hostname
			   * already.
			   */
			  if (hp->h_name)
			  {
				  Debug((DEBUG_INFO, "duplicate PTR ignored"));
			  }
			  else
			  {
				  hp->h_name = (char *)MyMalloc(len + 1);
				  (void)strlcpy(hp->h_name, hostbuf, len +1);
			  }
			  ans++;
			  break;
		  case T_CNAME:
			  cp += dlen;
			  Debug((DEBUG_INFO, "got cname %s", hostbuf));
			  if (bad_hostname(hostbuf, len))
				  return -1;	/* a break would be enough here */
			  if (alias >= &(hp->h_aliases[MAXALIASES - 1]))
				  break;
			  *alias = (char *)MyMalloc(len + 1);
			  (void)strlcpy(*alias++, hostbuf, len+1);
			  *alias = NULL;
			  ans++;
			  break;
		  default:
			  cp += dlen;
#ifdef DEBUGMODE
			  Debug((DEBUG_INFO, "proc_answer: type:%d for:%s",
			      type, hostbuf));
#endif
			  break;
		}
	}
	return ans;
}
/*
 * read a dns reply from the nameserver and process it.
 */
struct hostent *get_res(char *lp)
{
	static char buf[sizeof(HEADER) + MAXPACKET];
	HEADER *hptr;
#ifdef INET6
	struct sockaddr_in sin;
#else
	struct sockaddr_in sin;
#endif
	int  rc, a, max;
	SOCK_LEN_TYPE len = sizeof(sin);

	ResRQ	*rptr = NULL;
	aCache	*cp = NULL;
#ifndef _WIN32
	(void)alarm((unsigned)4);
#endif
#ifdef INET6
	rc = recvfrom(resfd, buf, sizeof(buf), 0, (struct sockaddr *)&sin,
	    &len);
#else
	rc = recvfrom(resfd, buf, sizeof(buf), 0, (struct sockaddr *)&sin,
	    &len);
#endif
#ifndef _WIN32
	(void)alarm((unsigned)0);
#endif
	if (rc <= sizeof(HEADER))
		goto getres_err;
	/*
	 * convert DNS reply reader from Network byte order to CPU byte order.
	 */
	hptr = (HEADER *) buf;
	hptr->id = ntohs(hptr->id);
	hptr->ancount = ntohs(hptr->ancount);
	hptr->qdcount = ntohs(hptr->qdcount);
	hptr->nscount = ntohs(hptr->nscount);
	hptr->arcount = ntohs(hptr->arcount);
#ifdef	DEBUGMODE
	Debug((DEBUG_NOTICE, "get_res:id = %d rcode = %d ancount = %d",
	    hptr->id, hptr->rcode, hptr->ancount));
#endif
	reinfo.re_replies++;
	/*
	 * response for an id which we have already received an answer for
	 * just ignore this response.
	 */
	rptr = find_id(hptr->id);
	if (!rptr)
		goto getres_err;
	/*
	 * check against possibly fake replies
	 */
	max = MIN(ircd_res.nscount, rptr->sends);
	if (!max)
		max = 1;

	for (a = 0; a < max; a++)
#ifdef INET6
		if (!ircd_res.nsaddr_list[a].sin_addr.s_addr ||
		    !bcmp((char *)&sin.sin_addr,
		    (char *)&ircd_res.nsaddr_list[a].sin_addr,
		    sizeof(struct in_addr)))
#else
		if (!ircd_res.nsaddr_list[a].sin_addr.s_addr ||
		    !bcmp((char *)&sin.sin_addr,
		    (char *)&ircd_res.nsaddr_list[a].sin_addr,
		    sizeof(struct in_addr)))
#endif
			break;
	if (a == max)
	{
		reinfo.re_unkrep++;
		goto getres_err;
	}

	if ((hptr->rcode != NOERROR) || (hptr->ancount == 0))
	{
		switch (hptr->rcode)
		{
		  case NXDOMAIN:
			  SET_ERRNO(TRY_AGAIN);
			  break;
		  case SERVFAIL:
			  SET_ERRNO(TRY_AGAIN);
			  break;
		  case NOERROR:
			  SET_ERRNO(NO_DATA);
			  break;
		  case FORMERR:
		  case NOTIMP:
		  case REFUSED:
		  default:
			  SET_ERRNO(NO_RECOVERY);
			  break;
		}
		reinfo.re_errors++;
		/*
		   ** If a bad error was returned, we stop here and dont send
		   ** send any more (no retries granted).
		 */
		if (ERRNO != TRY_AGAIN)
		{
			Debug((DEBUG_DNS, "Fatal DNS error %d for %d",
			    ERRNO, hptr->rcode));
			rptr->resend = 0;
			rptr->retries = 0;
		}
		goto getres_err;
	}
	a = proc_answer(rptr, hptr, buf, buf + rc);
	if (a == -1)
	{
		sendto_snomask(SNO_JUNK, "Bad hostname returned from %s for %s",
		    inet_ntoa(sin.sin_addr),
		    Inet_ia2p((struct IN_ADDR *)&rptr->he.h_addr));
		Debug((DEBUG_DNS, "Bad hostname returned from %s for %s",
		    inet_ntoa(sin.sin_addr),
		    Inet_ia2p((struct IN_ADDR *)&rptr->he.h_addr)));
	}
#ifdef DEBUGMODE
	Debug((DEBUG_INFO, "get_res:Proc answer = %d", a));
#endif
	if (a > 0 && rptr->type == T_PTR)
	{
		struct hostent *hp2 = NULL;

		if (BadPtr(rptr->he.h_name))	/* Kludge!      960907/Vesa */
			goto getres_err;

		Debug((DEBUG_DNS, "relookup %s <-> %s",
		    rptr->he.h_name, 
		    Inet_ia2p((struct IN_ADDR *)&rptr->he.h_addr)));
		/*
		 * Lookup the 'authoritive' name that we were given for the
		 * ip#.  By using this call rather than regenerating the
		 * type we automatically gain the use of the cache with no
		 * extra kludges.
		 */
		if ((hp2 = gethost_byname(rptr->he.h_name, &rptr->cinfo)))
			if (lp)
				bcopy((char *)&rptr->cinfo, lp, sizeof(Link));
		/*
		 * If name wasn't found, a request has been queued and it will
		 * be the last one queued.  This is rather nasty way to keep
		 * a host alias with the query. -avalon
		 */
		if (!hp2 && rptr->he.h_aliases[0])
			for (a = 0; rptr->he.h_aliases[a]; a++)
			{
				Debug((DEBUG_DNS, "Copied CNAME %s for %s",
				    rptr->he.h_aliases[a], rptr->he.h_name));
				last->he.h_aliases[a] = rptr->he.h_aliases[a];
				rptr->he.h_aliases[a] = NULL;
			}

		rem_request(rptr);
		return hp2;
	}

	if (a > 0)
	{
		if (lp)
			bcopy((char *)&rptr->cinfo, lp, sizeof(Link));
		cp = make_cache(rptr);
#ifdef	DEBUGMODE
		Debug((DEBUG_INFO, "get_res:cp=%#x rptr=%#x (made)", cp, rptr));
#endif

		rem_request(rptr);
	}
	else if (!rptr->sent)
		rem_request(rptr);
	return cp ? (struct hostent *)&cp->he : NULL;

      getres_err:
	/*
	 * Reprocess an error if the nameserver didnt tell us to "TRY_AGAIN".
	 */
	if (rptr)
	{
		if (ERRNO != TRY_AGAIN)
		{
			/*
			 * If we havent tried with the default domain and its
			 * set, then give it a try next.
			 */
			if (ircd_res.options & RES_DEFNAMES
			    && ++rptr->srch == 0)
			{
				rptr->retries = ircd_res.retry;
				rptr->sends = 0;
				rptr->resend = 1;
#ifdef INET6
/* Comment out this ifdef to get names like ::ffff:a.b.c.d */
				if (rptr->type == T_AAAA)
					query_name(rptr->name, C_IN, T_A, rptr);
				Debug((DEBUG_DNS,
				    "getres_err: didn't work with T_AAAA, now also trying with T_A for %s",
				    rptr->name));
#endif
				resend_query(rptr);
			}
			else
			{
#ifdef INET6
/* Comment out this ifdef to get names like ::ffff:a.b.c.d */
				if (rptr->type == T_AAAA)
					query_name(rptr->name, C_IN, T_A, rptr);
				Debug((DEBUG_DNS,
				    "getres_err: didn't work with T_AAAA, now also trying with T_A for %s",
				    rptr->name));
#endif
				resend_query(rptr);
			}
		}
		else if (lp)
			bcopy((char *)&rptr->cinfo, lp, sizeof(Link));
	}
	return (struct hostent *)NULL;
}

static int hash_number(u_char *ip)
{
	u_int hashv = 0;

	/* could use loop but slower */
	hashv += (int)*ip++;
	hashv += hashv + (int)*ip++;
	hashv += hashv + (int)*ip++;
#ifdef INET6
	hashv += hashv + (int)*ip++;
	hashv += hashv + (int)*ip++;
	hashv += hashv + (int)*ip++;
	hashv += hashv + (int)*ip++;
	hashv += hashv + (int)*ip++;
	hashv += hashv + (int)*ip++;
	hashv += hashv + (int)*ip++;
	hashv += hashv + (int)*ip++;
	hashv += hashv + (int)*ip++;
	hashv += hashv + (int)*ip++;
	hashv += hashv + (int)*ip++;
	hashv += hashv + (int)*ip++;
#endif
	hashv += hashv + (int)*ip;
	hashv %= ARES_CACSIZE;
	return (hashv);
}

static int hash_name(char *name)
{
	u_int hashv = 0;

	for (; *name && *name != '.'; name++)
		hashv += *name;
	hashv %= ARES_CACSIZE;
	return (hashv);
}

/*
** Add a new cache item to the queue and hash table.
*/
static aCache *add_to_cache(aCache *ocp)
{
	aCache *cp = NULL;
	int  hashv;

#ifdef DEBUGMODE
	Debug((DEBUG_INFO,
	    "add_to_cache:ocp %#x he %#x name %#x addrl %#x 0 %#x",
	    ocp, HE(ocp), HE(ocp)->h_name, HE(ocp)->h_addr_list,
	    HE(ocp)->h_addr_list[0]));
#endif
	ocp->list_next = cachetop;
	cachetop = ocp;

	hashv = hash_name(HE(ocp)->h_name);
	ocp->hname_next = hashtable[hashv].name_list;
	hashtable[hashv].name_list = ocp;

	hashv = hash_number((u_char *)HE(ocp)->h_addr);
	ocp->hnum_next = hashtable[hashv].num_list;
	hashtable[hashv].num_list = ocp;

#ifdef	DEBUGMODE
#ifdef INET6
	Debug((DEBUG_INFO, "add_to_cache:added %s[%08x%08x%08x%08x] cache %#x.",
	    ocp->he.h_name,
	    ((struct in6_addr *)HE(ocp)->h_addr_list)->s6_addr[0],
	    ((struct in6_addr *)HE(ocp)->h_addr_list)->s6_addr[1],
	    ((struct in6_addr *)HE(ocp)->h_addr_list)->s6_addr[2],
	    ((struct in6_addr *)HE(ocp)->h_addr_list)->s6_addr[3], ocp));
#else
	Debug((DEBUG_INFO, "add_to_cache:added %s[%08x] cache %#x.",
	    HE(ocp)->h_name, HE(ocp)->h_addr_list[0], ocp));
#endif
	Debug((DEBUG_INFO,
	    "add_to_cache:h1 %d h2 %x lnext %#x namnext %#x numnext %#x",
	    hash_name(HE(ocp)->h_name), hashv, ocp->list_next,
	    ocp->hname_next, ocp->hnum_next));
#endif

	/*
	 * LRU deletion of excessive cache entries.
	 */
	if (++incache > MAXCACHED)
	{
		for (cp = cachetop; cp->list_next; cp = cp->list_next)
			;
		rem_cache(cp);
	}
	cainfo.ca_adds++;

	return ocp;
}

/*
** update_list does not alter the cache structure passed. It is assumed that
** it already contains the correct expire time, if it is a new entry. Old
** entries have the expirey time updated.
*/
static void update_list(ResRQ *rptr, aCache *cachep)
{
	aCache **cpp, *cp = cachep;
	char *s, *t, **base;
	int  i, j;
	int  addrcount;

	/*
	   ** search for the new cache item in the cache list by hostname.
	   ** If found, move the entry to the top of the list and return.
	 */
	cainfo.ca_updates++;

	for (cpp = &cachetop; *cpp; cpp = &((*cpp)->list_next))
		if (cp == *cpp)
			break;
	if (!*cpp)
		return;
	*cpp = cp->list_next;
	cp->list_next = cachetop;
	cachetop = cp;
	if (!rptr)
		return;

#ifdef	DEBUGMODE
	Debug((DEBUG_DEBUG, "u_l:cp %#x na %#x al %#x ad %#x",
	    cp, HE(cp)->h_name, HE(cp)->h_aliases, HE(cp)->h_addr));
	Debug((DEBUG_DEBUG, "u_l:rptr %#x h_n %#x", rptr, HE(rptr)->h_name));
#endif
	/*
	 * Compare the cache entry against the new record.  Add any
	 * previously missing names for this entry.
	 */
	for (i = 0; cp->he.h_aliases[i]; i++)
		;
	addrcount = i;
	for (i = 0, s = HE(rptr)->h_name; s && i < MAXALIASES;
	    s = HE(rptr)->h_aliases[i++])
	{
		for (j = 0, t = HE(cp)->h_name; t && j < MAXALIASES;
		    t = HE(cp)->h_aliases[j++])
			if (!mycmp(t, s))
				break;
		if (!t && j < MAXALIASES - 1)
		{
			base = HE(cp)->h_aliases;

			addrcount++;
			base = (char **)MyRealloc((char *)base,
			    sizeof(char *) * (addrcount + 1));
			HE(cp)->h_aliases = base;
#ifdef	DEBUGMODE
			Debug((DEBUG_DNS, "u_l:add name %s hal %x ac %d",
			    s, HE(cp)->h_aliases, addrcount));
#endif
			base[addrcount - 1] = strdup(s);
			base[addrcount] = NULL;
		}
	}
#ifdef INET6
	for (i = 0; HE(cp)->h_addr_list[i]; i++)
#else
	for (i = 0; HE(cp)->h_addr_list[i]; i++)
#endif
		;
	addrcount = i;

	/*
	 * Do the same again for IP#'s.
	 */
#ifdef INET6
	for (s = (char *)HE(rptr)->h_addr.S_ADDR;
#else
	for (s = (char *)&HE(rptr)->h_addr.S_ADDR;
#endif
	    WHOSTENTP(((struct IN_ADDR *)s)->S_ADDR); s += sizeof(struct IN_ADDR))
	{
#ifdef INET6
		for (i = 0; (t = HE(cp)->h_addr_list[i]); i++)
#else
		for (i = 0; (t = HE(cp)->h_addr_list[i]); i++)
#endif
			if (!bcmp(s, t, sizeof(struct IN_ADDR)))
				break;
		if (i >= MAXADDRS || addrcount >= MAXADDRS)
			break;
		/*
		 * Oh man this is bad...I *HATE* it. -avalon
		 *
		 * Whats it do ?  Reallocate two arrays, one of pointers
		 * to "char *" and the other of IP addresses.  Contents of
		 * the IP array *MUST* be preserved and the pointers into
		 * it recalculated.
		 */
		if (!t)
		{
			struct IN_ADDR **ab;

			ab = (struct IN_ADDR **)HE(cp)->h_addr_list;
			addrcount++;
			t = (char *)MyRealloc((char *)*ab,
			    addrcount * sizeof(struct IN_ADDR));
			base = (char **)MyRealloc((char *)ab,
			    (addrcount + 1) * sizeof(*ab));
			HE(cp)->h_addr_list = base;
			ab = (struct IN_ADDR **)HE(cp)->h_addr_list; /* Update after realloc -- Syzop */
#ifdef	DEBUGMODE
 #ifdef INET6
			Debug((DEBUG_DNS, "u_l:add IP %s hal %x ac %d",
				inet_ntop(((struct IN_ADDR *)s), mydummy,
				          MYDUMMY_SIZE),
				HE(cp)->h_addr_list, addrcount));
 #else
			Debug((DEBUG_DNS, "u_l:add IP %x hal %x ac %d",
			    ntohl(((struct IN_ADDR *)s)->S_ADDR),
			    HE(cp)->h_addr_list, addrcount));
 #endif
#endif
			for (; addrcount; addrcount--)
			{
				*ab++ = (struct IN_ADDR *)t;
				t += sizeof(struct IN_ADDR);
			}
			*ab = NULL;
			bcopy(s, (char *)*--ab, sizeof(struct IN_ADDR));
		}
	}
	return;
}

static aCache *find_cache_name(char *name)
{
	aCache *cp;
	char *s;
	int  hashv, i;

	hashv = hash_name(name);

	cp = hashtable[hashv].name_list;
#ifdef	DEBUGMODE
	Debug((DEBUG_DNS, "find_cache_name:find %s : hashv = %d", name, hashv));
#endif

	for (; cp; cp = cp->hname_next)
		for (i = 0, s = HE(cp)->h_name; s; s = HE(cp)->h_aliases[i++])
			if (mycmp(s, name) == 0)
			{
				cainfo.ca_na_hits++;
				update_list(NULL, cp);
				return cp;
			}

	for (cp = cachetop; cp; cp = cp->list_next)
	{
		/*
		 * if no aliases or the hash value matches, we've already
		 * done this entry and all possiblilities concerning it.
		 */
		if (!*HE(cp)->h_aliases)
			continue;
		if (hashv == hash_name(HE(cp)->h_name))
			continue;
		for (i = 0, s = HE(cp)->h_aliases[i]; s && i < MAXALIASES; i++)
			if (!mycmp(name, s))
			{
				cainfo.ca_na_hits++;
				update_list(NULL, cp);
				return cp;
			}
	}
	return NULL;
}

/*
 * find a cache entry by ip# and update its expire time
 */
static aCache *find_cache_number(ResRQ *rptr, char *numb)
{
	aCache *cp;
	int  hashv, i;
#ifdef	DEBUGMODE
	struct IN_ADDR *ip = (struct IN_ADDR *)numb;
#endif

	hashv = hash_number((u_char *)numb);

	cp = hashtable[hashv].num_list;
#ifdef DEBUGMODE
#ifdef INET6
	Debug((DEBUG_DNS,
	    "find_cache_number:find %s[%08x%08x%08x%08x]: hashv = %d",
	    Inet_ia2p((struct IN_ADDR *)ip), ip->s6_addr[0],
	    ip->s6_addr[1], ip->s6_addr[2], ip->s6_addr[3], hashv));
#else
	Debug((DEBUG_DNS, "find_cache_number:find %s[%08x]: hashv = %d",
	    inetntoa(numb), ntohl(ip->s_addr), hashv));
#endif
#endif
	for (; cp; cp = cp->hnum_next)
	{
#ifdef INET6
		for (i = 0; HE(cp)->h_addr_list[i]; i++)
#else
		for (i = 0; HE(cp)->h_addr_list[i]; i++)
#endif
		{
			if (!bcmp(HE(cp)->h_addr_list[i], numb,
			    sizeof(struct IN_ADDR)))
			{
				cainfo.ca_nu_hits++;
				update_list(rptr, cp);
				return cp;
			}
		}
	}
	for (cp = cachetop; cp; cp = cp->list_next)
	{
		if (!HE(cp)->h_addr_list && !HE(cp)->h_aliases)
		{
			cp = rem_list(cp);
			continue;
		}
		/*
		 * single address entry...would have been done by hashed
		 * search above...
		 */
#ifdef INET6
		if (!HE(cp)->h_addr_list[1])
#else
		if (!HE(cp)->h_addr_list[1])
#endif
			continue;
		/*
		 * if the first IP# has the same hashnumber as the IP# we
		 * are looking for, its been done already.
		 */
		if (hashv == hash_number((u_char *)HE(cp)->h_addr_list[0]))
			continue;
#ifdef INET6
		for (i = 1; HE(cp)->h_addr_list[i]; i++)
#else
		for (i = 1; HE(cp)->h_addr_list[i]; i++)
#endif
			if (!bcmp(HE(cp)->h_addr_list[i], numb,
			    sizeof(struct IN_ADDR)))
			{
				cainfo.ca_nu_hits++;
				update_list(rptr, cp);
				return cp;
			}
	}
	return NULL;
}

static aCache *make_cache(ResRQ *rptr)
{
	aCache *cp;
	int  i, n;
	struct hostent *hp;
	char *s, **t;

	/*
	   ** shouldn't happen but it just might...
	 */
	if (!rptr->he.h_name || !WHOSTENTP(rptr->he.h_addr.S_ADDR) )
		return NULL;
	/*
	   ** Make cache entry.  First check to see if the cache already exists
	   ** and if so, return a pointer to it.
	 */
	for (i = 0; WHOSTENTP(rptr->he.h_addr_list[i].S_ADDR); i++)
		if ((cp = find_cache_number(rptr,
#ifdef INET6
		    (char *)(rptr->he.h_addr_list[i].S_ADDR))))
#else
		    (char *)&(rptr->he.h_addr_list[i].S_ADDR))))
#endif
		return cp;

	/*
	   ** a matching entry wasnt found in the cache so go and make one up.
	 */
	cp = (aCache *)MyMalloc(sizeof(aCache));
	bzero((char *)cp, sizeof(aCache));
	hp = &cp->he;
	for (i = 0; i < MAXADDRS - 1; i++)
		if (!WHOSTENTP(rptr->he.h_addr_list[i].S_ADDR))
			break;

	/*
	   ** build two arrays, one for IP#'s, another of pointers to them.
	 */
	t = hp->h_addr_list = (char **)MyMalloc(sizeof(char *) * (i + 1));
	bzero((char *)t, sizeof(char *) * (i + 1));

	s = (char *)MyMalloc(sizeof(struct IN_ADDR) * i);
	bzero(s, sizeof(struct IN_ADDR) * i);

	for (n = 0; n < i; n++, s += sizeof(struct IN_ADDR))
	{
		*t++ = s;
		bcopy((char *)&rptr->he.h_addr_list[n], s,
		    sizeof(struct IN_ADDR));
	}
	*t = (char *)NULL;

	/*
	   ** an array of pointers to CNAMEs.
	 */
	for (i = 0; i < MAXALIASES - 1; i++)
		if (!rptr->he.h_aliases[i])
			break;
	i++;
	t = hp->h_aliases = (char **)MyMalloc(sizeof(char *) * i);
	for (n = 0; n < i; n++, t++)
	{
		*t = rptr->he.h_aliases[n];
		rptr->he.h_aliases[n] = NULL;
	}

	hp->h_addrtype = rptr->he.h_addrtype;
	hp->h_length = rptr->he.h_length;
	hp->h_name = rptr->he.h_name;
	if (rptr->ttl < AR_TTL)
	{
		reinfo.re_shortttl++;
		cp->ttl = AR_TTL;
	}
	else
		cp->ttl = rptr->ttl;
	cp->expireat = TStime() + cp->ttl;
	/* Update next dns cache clean time, this way it will be cleaned when needed.
	 * I don't know how to do multithreaded (win32), as a consequence it can take
	 * AR_TTL (300s) too much before we expire this entry at win32 -- Syzop
	 */
	if (nextexpire > cp->expireat) {
		nextexpire = cp->expireat;
		Debug((DEBUG_DNS, "Adjusting nextexpire to %lu", nextexpire));
	}
	HE(rptr)->h_name = NULL;
#ifdef DEBUGMODE
	Debug((DEBUG_INFO, "make_cache:made cache %#x", cp));
#endif
	return add_to_cache(cp);
}

/*
 * rem_list
 */
static aCache *rem_list(aCache *cp)
{
	aCache **cpp, *cr = cp->list_next;

	/*
	 * remove cache entry from linked list
	 */
	for (cpp = &cachetop; *cpp; cpp = &((*cpp)->list_next))
		if (*cpp == cp)
		{
			*cpp = cp->list_next;
			MyFree(cp);
			break;
		}
	return cr;
}


/*
 * rem_cache
 *     delete a cache entry from the cache structures and lists and return
 *     all memory used for the cache back to the memory pool.
 */
static void rem_cache(aCache *ocp)
{
	aCache **cp;
	struct hostent *hp = &ocp->he;
	int  hashv;
	aClient *cptr;

#ifdef	DEBUGMODE
	Debug((DEBUG_DNS, "rem_cache: ocp %#x hp %#x l_n %#x aliases %#x",
	    ocp, hp, ocp->list_next, hp->h_aliases));
#endif
	/*
	   ** Cleanup any references to this structure by destroying the
	   ** pointer.
	 */
	for (hashv = LastSlot; hashv >= 0; hashv--)
		if ((cptr = local[hashv]) && (cptr->hostp == hp))
			cptr->hostp = NULL;
	/*
	 * remove cache entry from linked list
	 */
	for (cp = &cachetop; *cp; cp = &((*cp)->list_next))
		if (*cp == ocp)
		{
			*cp = ocp->list_next;
			break;
		}
	/*
	 * remove cache entry from hashed name lists
	 */
	hashv = hash_name(hp->h_name);
#ifdef	DEBUGMODE
	Debug((DEBUG_DEBUG, "rem_cache: h_name %s hashv %d next %#x first %#x",
	    hp->h_name, hashv, ocp->hname_next, hashtable[hashv].name_list));
#endif
	for (cp = &hashtable[hashv].name_list; *cp; cp = &((*cp)->hname_next))
		if (*cp == ocp)
		{
			*cp = ocp->hname_next;
			break;
		}
	/*
	 * remove cache entry from hashed number list
	 */
	hashv = hash_number((u_char *)hp->h_addr);
#ifdef	DEBUGMODE
# ifdef INET6
	Debug((DEBUG_DEBUG, "rem_cache: h_addr %s hashv %d next %#x first %#x",
	    Inet_ia2p((struct IN_ADDR *)hp->h_addr),
	    hashv, ocp->hnum_next, hashtable[hashv].num_list));
# else
	Debug((DEBUG_DEBUG, "rem_cache: h_addr %s hashv %d next %#x first %#x",
	    Inet_ia2p((struct IN_ADDR *)hp->h_addr),
	    hashv, ocp->hnum_next, hashtable[hashv].num_list));
# endif
#endif
	for (cp = &hashtable[hashv].num_list; *cp; cp = &((*cp)->hnum_next))
		if (*cp == ocp)
		{
			*cp = ocp->hnum_next;
			break;
		}
	/*
	 * free memory used to hold the various host names and the array
	 * of alias pointers.
	 */
	if (hp->h_name)
		MyFree(hp->h_name);
	if (hp->h_aliases)
	{
		for (hashv = 0; hp->h_aliases[hashv]; hashv++)
			MyFree(hp->h_aliases[hashv]);
		MyFree(hp->h_aliases);
	}

	/*
	 * free memory used to hold ip numbers and the array of them.
	 */
	if (hp->h_addr_list)
	{
		if (*hp->h_addr_list)
			MyFree(*hp->h_addr_list);
		MyFree(hp->h_addr_list);
	}
	MyFree(ocp);

	incache--;
	cainfo.ca_dels++;

	return;
}

/*
 * removes entries from the cache which are older than their expirey times.
 * returns the time at which the server should next poll the cache.
 */
time_t expire_cache(time_t now)
{
	aCache *cp, *cp2;
	time_t next = 0;

	Debug((DEBUG_DEBUG, "expire_cache(%lu)", now));
	for (cp = cachetop; cp; cp = cp2)
	{
		cp2 = cp->list_next;

		if (now >= cp->expireat)
		{
			cainfo.ca_expires++;
			rem_cache(cp);
		}
		else if (!next || next > cp->expireat)
			next = cp->expireat;
	}
	/* Always check at least AR_TTL seconds, ugly workaround for
	 * (win32 specific) problem with not removing caches (otherwise a new cache could
	 * be added later while the next expire_cache will be about XX hours :/) -- Syzop
	 */
	if (next > now + AR_TTL)
		next = now + AR_TTL;
	Debug((DEBUG_DEBUG, "next expire_cache at %lu", (next > now) ? next : (now + AR_TTL)));
	return (next > now) ? next : (now + AR_TTL);
}

/*
 * remove all dns cache entries.
 */
void flush_cache(void)
{
	aCache *cp;

	while ((cp = cachetop))
		rem_cache(cp);
}

int m_dns(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
	aCache *cp;
	int  i;

	/* Why would normal users need to know all this? */
	if (!IsOper(sptr))
	{
		sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name, parv[0]);
		return 0;
	}

	if (parv[1] && *parv[1] == 'l')
	{
		sendto_realops("%s did a DNS cache list", sptr->name);
		for (cp = cachetop; cp; cp = cp->list_next)
		{
			sendto_one(sptr, "NOTICE %s :Ex %ld ttl %ld host %s(%s)",
			    parv[0], cp->expireat - TStime(), cp->ttl,
#ifdef INET6
			    HE(cp)->h_name, inetntop(AF_INET6,
			    HE(cp)->h_addr, mydummy, MYDUMMY_SIZE));
#else
			    HE(cp)->h_name, inetntoa(HE(cp)->h_addr));
#endif
			for (i = 0; HE(cp)->h_aliases[i]; i++)
				sendto_one(sptr, "NOTICE %s : %s = %s (CN)",
				    parv[0], HE(cp)->h_name,
				    HE(cp)->h_aliases[i]);
#ifdef INET6
			for (i = 1; HE(cp)->h_addr_list[i]; i++)
			{
#else
			for (i = 1; HE(cp)->h_addr_list[i]; i++)
			{
#endif
				sendto_one(sptr, "NOTICE %s : %s = %s (IP)",
				    parv[0], HE(cp)->h_name,
#ifdef INET6
				    inetntop(AF_INET6,
				    HE(cp)->h_addr_list[i],
				    mydummy, MYDUMMY_SIZE));
#else
				    inetntoa(HE(cp)->h_addr_list[i]));
#endif
			}
		}
		return 2;
	}
	if (parv[1] && *parv[1] == 'i')
	{
		int i;
		/* Display nameserver list */
		sendto_one(sptr, "NOTICE %s :Nameserver list has %d server(s):", sptr->name, ircd_res.nscount);
		for (i = 0; i < ircd_res.nscount; i++)
			sendto_one(sptr, "NOTICE %s :%d. %s",
				sptr->name, i, inet_ntoa(ircd_res.nsaddr_list[i].sin_addr));
		sendto_one(sptr, "NOTICE %s :retrans=%d s, retry=%d times", sptr->name, ircd_res.retrans, ircd_res.retry);
		sendto_one(sptr, "NOTICE %s :Default domain name: %s", sptr->name, ircd_res.defdname);
		sendto_one(sptr, "NOTICE %s :End of info.", sptr->name);
		return 2;
	}
	sendto_one(sptr, "NOTICE %s :Ca %d Cd %d Ce %d Cl %d Ch %d:%d Cu %d",
	    sptr->name,
	    cainfo.ca_adds, cainfo.ca_dels, cainfo.ca_expires,
	    cainfo.ca_lookups,
	    cainfo.ca_na_hits, cainfo.ca_nu_hits, cainfo.ca_updates);

	sendto_one(sptr, "NOTICE %s :Re %d Rl %d/%d Rp %d Rq %d",
	    sptr->name, reinfo.re_errors, reinfo.re_nu_look,
	    reinfo.re_na_look, reinfo.re_replies, reinfo.re_requests);
	sendto_one(sptr, "NOTICE %s :Ru %d Rsh %d Rs %d(%d) Rt %d", sptr->name,
	    reinfo.re_unkrep, reinfo.re_shortttl, reinfo.re_sent,
	    reinfo.re_resends, reinfo.re_timeouts);
	return 2;
}

u_long cres_mem(aClient *sptr, char *nick)
{
	register aCache *c = cachetop;
	register struct hostent *h;
	register int i;
	u_long nm = 0, im = 0, sm = 0, ts = 0;

	for (; c; c = c->list_next)
	{
		sm += sizeof(*c);
		h = &c->he;
#ifdef INET6
		for (i = 0; h->h_addr_list[i]; i++)
#else
		for (i = 0; h->h_addr_list[i]; i++)
#endif
		{
			im += sizeof(char *);
			im += sizeof(struct IN_ADDR);
		}
		im += sizeof(char *);
		for (i = 0; h->h_aliases[i]; i++)
		{
			nm += sizeof(char *);
			nm += strlen(h->h_aliases[i]);
		}
		nm += i - 1;
		nm += sizeof(char *);
		if (h->h_name)
			nm += strlen(h->h_name);
	}
	ts = ARES_CACSIZE * sizeof(CacheTable);
	sendto_one(sptr, ":%s %d %s :RES table %ld",
	    me.name, RPL_STATSDEBUG, nick, ts);
	sendto_one(sptr, ":%s %d %s :Structs %ld IP storage %ld Name storage %ld",
	    me.name, RPL_STATSDEBUG, nick, sm, im, nm);
	return ts + sm + im + nm;
}


static int bad_hostname(char *name, int len)
{
	char *s, c;

	for (s = name; (c = *s) && len; s++, len--)
		if (!isalnum(c) && (c != '_') && (c != '-') && (c != '.'))
			return -1;
	return 0;
}
