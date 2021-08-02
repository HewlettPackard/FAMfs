/*
 * (C) Copyright 2019-2020 Hewlett Packard Enterprise Development LP
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to:
 *
 *   Free Software Foundation, Inc.
 *   51 Franklin Street, Fifth Floor
 *   Boston, MA 02110-1301, USA.
 *
 * Written by: Oleg Neverovitch, Dmitry Ivanov
 */

#include <ctype.h>
#include <unistd.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <malloc.h>
#include <arpa/inet.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/sysinfo.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <limits.h>
#include <ifaddrs.h>

#include "f_env.h"
#include "f_error.h"
#include "f_lf_connect.h"


/* x^4 + x + 1 -- CRC-4/ITU-T G.704 Poly -- fast table algorithm */
static const unsigned char crc4_table[16] =		\
	{ 0x0, 0xd, 0x3, 0xe, 0x6, 0xb, 0x5, 0x8,	\
	  0xc, 0x1, 0xf, 0x2, 0xa, 0x7, 0x9, 0x4};

/* 8K table for fast (byte-after-byte) CRC-4 calculation;
  used by f_crc4_chk_fast, f_crc4_fast */
uint16_t f_crc4_fast_table[4096];

/**
 * f_crc4_chk - Check CRC-4
 *
 * Return 0 if CRC is correct.
 */
unsigned char f_crc4_chk(void *buffer, int len)
{
    unsigned char crc = 0;
    unsigned char c;
    int i;

    for (i = 0; i < len; i++) {
	c = ((unsigned char *)buffer)[i];
	crc = crc4_table[(crc ^ c) & 0xf];
	c >>= 4;
	crc = crc4_table[crc ^ c];
    }
    return crc;
}

/**
 * f_crc4 - Calculate CRC-4 on buffer of len bytes;
 *
 * Last four bits of buffer must be zeros.
 * Return crc value to be stored in the last four bits.
 */
inline unsigned char f_crc4(void *buffer, int len)
{
#if 0
    /* x^4 + x + 1 -- Transposed table */
    static const unsigned char crc4_table_tp[16] =	\
	{ 0x0, 0x9, 0xb, 0x2, 0xf, 0x6, 0x4, 0xd,	\
	  0x7, 0xe, 0xc, 0x5, 0x8, 0x1, 0x3, 0xa};
#endif
    /* look in transposed table */
    return crc4_table_tp[ f_crc4_chk(buffer, len) ];
}

void f_crc4_init_table(void)
{
    unsigned char crc, c;
    uint16_t w, r, idx;

    /* initialize table */
    for (crc = 0; crc < 16; crc++) {
	idx = crc;
	idx <<= 8;
	for (w = 0; w < 256; w++) {
	    c = w;
	    r = crc4_table[(crc ^ c) & 0x0f];
	    c >>= 4;
	    r = crc4_table[r ^ c];
	    f_crc4_fast_table[idx + w] = r << 8;
	}
    }
    /* check calculations */
    assert( f_crc4_fast("123456789\x80", 10) == 0x0 ); /*CRC-4/ITU-T*/
}

#define N_STRLIST_DELIM ","
static char** _getstrlist(const char *buf, int *count, int allow_empty)
{
	char **nodelist;
	const char *p;
	char *node;
	size_t l;
	int i;

	p = buf;
	l = strcspn(p, N_STRLIST_DELIM);
	i = 0;
	while (l || allow_empty) {
		i++;
		p += l;
		if (!*p)
			break;
		l = strcspn(++p, N_STRLIST_DELIM);
	}
	if (i == 0)
		return NULL;

	/* Allocate the nodelist array */
	nodelist = (char **)malloc(i*sizeof(char*));

	i = 0;
	p = buf;
	l = strcspn(p, N_STRLIST_DELIM);
	while (l || allow_empty) {
		node = (char *)malloc(l+1);
		if (l)
			strncpy(node, p, l);
		node[l] = '\0';
		nodelist[i++] = node;
		p += l;
		if (!*p)
			break;
		l = strcspn(++p, N_STRLIST_DELIM);
	}
	*count = i;

	return nodelist;
}

char** getstrlist(const char *buf, int *count) {
    return _getstrlist(buf, count, 0);
}

/* allow empty list entries */
char** getstrlist_allow_empty(const char *buf, int *count) {
    return _getstrlist(buf, count, 1);
}


void nodelist_free(char **nodelist, int size) {
	if (nodelist) {
		for (int i = 0; i < size; i++)
			free(nodelist[i]);
		free(nodelist);
	}
}

char *f_get_myhostname(void) {
    char  *p, *hostname;

    hostname =(char*) malloc(HOST_NAME_MAX);
    if (hostname && !gethostname(hostname, HOST_NAME_MAX-1)) {
	hostname[HOST_NAME_MAX-1] = '\0';

	/* Strip domain */
	p = strchr(hostname, '.');
	if (p)
	    *p = '\0';
    }
    return hostname;
}

int f_find_node(char* const* nodelist, int node_cnt, const char *hostname)
{
	char *myhostname = NULL;
	size_t len;
	int i, idx = -1;

	if (!hostname)
		hostname = myhostname = f_get_myhostname();
	if (hostname) {
		len = strlen(hostname);
		for (i = 0; i < node_cnt; i++) {
			if (!strncmp(hostname, nodelist[i], len)) {
				idx = i;
				break;
			}
		}
	}
	free(myhostname);
	return idx;
}

int find_my_node(char* const* nodelist, int node_cnt, char **hostname_p) {
	int i, idx;

	idx = f_find_node(nodelist, node_cnt, NULL);
	if (idx < 0) {
		struct ifaddrs *ifa;

		if(getifaddrs(&ifa))
			ERROR("Failed to obtain my IPs");
		while (ifa) {
			if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET) {
				struct sockaddr_in *sa = (struct sockaddr_in *)ifa->ifa_addr;
				char *ina = inet_ntoa(sa->sin_addr);

				for (i = 0; i < node_cnt; i++) {
					if (!strcmp(ina, nodelist[i])) {
						idx = i;
						break;
					}
				}
				if (idx >= 0)
					break;
			}
			ifa = ifa->ifa_next;
		}
	}

	if (hostname_p) {
		free(*hostname_p);
		if (idx >= 0)
			*hostname_p = strdup(nodelist[idx]);
		else
			*hostname_p = strdup("?");
	}

	return idx;
}

void alloc_affinity(int **affp, int size, int pos)
{
    int		i, cpu_setsize, *affinity = NULL;

    if (!affp)
	return;

    affinity = (int *) malloc(size * sizeof(int));
    ASSERT(affinity && size);
    cpu_setsize = get_nprocs();
    for (i = 0; i < size; i++)
	affinity[i] = (i*(cpu_setsize/size) + pos) % cpu_setsize;
    *affp = affinity;
}

void daemonize(void)
{
    pid_t pid;
    pid_t sid;
    int rc;

    pid = fork();

    if (pid < 0) {
        fprintf(stderr, "fork failed: %s\n", strerror(errno));
        exit(1);
    }

    if (pid > 0)
        exit(0);

    umask(0);

    sid = setsid();
    if (sid < 0) {
        fprintf(stderr, "setsid failed: %s\n", strerror(errno));
        exit(1);
    }

    rc = chdir("/");
    if (rc < 0) {
        fprintf(stderr, "chdir failed: %s\n", strerror(errno));
        exit(1);
    }

    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    pid = fork();
    if (pid < 0) {
        fprintf(stderr, "fork failed: %s\n", strerror(errno));
        exit(1);
    } else if (pid > 0)
        exit(0);
}

static char *strnchr(const char *s, size_t count, int c)
{
	uint64_t	ix;
	const char	*cp = s;

	for (ix = 0; ix < count; ++ix, ++cp) {
		if (*cp == c)
			return (char *)cp;
	}
	return NULL;
}

/*
 * Capacity string parser
 *
 * K, M, G, T, P, E
 * Ki, Mi, Gi, Ti, Pi, Ei
 * S
 */
static int f_parse_capacity(const char *s, uint64_t *c)
{
    char *p;
    uint64_t x, y;

    x = strtoll(s, &p, 10);
    if (p > s && *p) {
	switch (tolower(*p++)) {
	case 'k':	y = 1;	break;
	case 'm':	y = 2;	break;
	case 'g':	y = 3;	break;
	case 't':	y = 4;	break;
	case 'p':	y = 5;	break;
	case 'e':	y = 6;	break;
	case 'b':	if (*p) {
				/* should not be anything after B */
				return 1;
			}
			*c = x;
			return 0;

	case 's':	if (*p) {
				/* should not be anything after S */
				return 1;
			}
			*c = x*512;
			return 0;

	default:	return 1;
	}

	switch (tolower(*p)) {
	case 'i':
	case 0:		/* "K" will be treated as Ki */
		*c = x <<= y*10L;
		return 0;

	case 'b':	/* "KB" will be treated as KB */
		while (y--) {
			x *= 1000;
		}
		*c = x;
		return 0;

	default: ;
	}
    } else if (p > s && !*p) {
	/* skipped B allowed */
	*c = x;
	return 0;
    }
    return 1;
}

/*
 * Moniker	Data	Parity	Mirror	D+P+M	Chunk_size
 * 5D+P:4M	5	1	0	6	4194304	(4MiB)
 * 9D+2P:1M	9	2	0	11	1MiB
 * 9D:2M	9	0	0	9	2MiB
 * D=D:512K	1	0	1	2	512KiB
 * D=2D:4K	1	0	2	3	4096 (4KiB)
**/
int f_parse_moniker(const char *moniker, int *data, int *parity,
    int *mirrors, size_t *chunk_size)
{
    const char *t = moniker, *t0;
    char *t1;
    const char *chunk_sz_token, *next;
    int m, d, p, n;
    size_t c;

    m = d = p = 0;
    c = 0L;

    /* find tokens: '*2' or ':4K' */
    chunk_sz_token = next = strnchr(t, FVAR_MONIKER_MAX, ':');
    if (!chunk_sz_token) {
	if (chunk_size) {
	    err("chunk size not found in moniker:%s", moniker);
	    goto _fail;
	}
	next = t + strnlen(t, FVAR_MONIKER_MAX);
    }

    /* nD[=nD][+nP] */
    while (t < next) {
	/* quantity */
	t0 = t;

	n = strtol(t0, &t1, 10);
	if (!n) {
	    if (t == t0)
		n = 1;
	    else
		goto _syntax;
	}
	t = t1;

	/* type */
	switch (*t++) {
	case 'D':
	    if (m)
		m = n;
	    else
		d += n;
	    break;

	case 'P':
	    if (p) {
		err("parity specified more than once:%s", moniker);
		goto _fail;
	    }
	    p = n;
	    break;

	default:
	    err("extra char>%s", --t);
	    goto _syntax;
	}

	/* separator */
	if (*t == '=') {
	    if (m == 0) {
		if (d > 1) {
		    /* in "nD=..." n must be 1 if present */
		    err("only one primary mirror device allowed:%s", moniker);
		    goto _fail;
		}
	    } else {
		/* don't support "D=nD=mD..." syntax */
		err("asymmetric mirrors not supported yet:%s", moniker);
		goto _fail;
	    }
	    m++;
	    t++;
	    continue;
	} else if (*t == '+') {
	    t++;
	}
    }

    t = chunk_sz_token;
    if (t++ && f_parse_capacity(t, &c)) {
	err("invalid chunk size:%s", moniker);
	goto _fail;
    }

    if (!d) {
	err("at least one data chunk is required:%s", moniker);
	goto _fail;
    }
    if (!IS_POWER2(c) ||
	  !IN_RANGE(c, F_CHUNK_SIZE_MIN, F_CHUNK_SIZE_MAX)) {
	err("invalid chunk size value:%s", moniker);
	goto _fail;
    }

    if (data) {
        *data = d;
    }
    if (parity) {
        *parity = p;
    }
    if (mirrors) {
        *mirrors = m;
    }
    if (chunk_size) {
        *chunk_size = c;
    }

    return 0;

_syntax:
    err("invalid layout moniker:%s", moniker);
_fail:
    return 1;
}


