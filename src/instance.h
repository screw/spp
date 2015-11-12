/*

    Copyright 2008--2013, Centre for Advanced Internet Architectures,
    Swinburne University of Technology, http://caia.swin.edu.au
 
    Author: Amiel Heyde, amiel@swin.edu.au
 
    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2 as 
    published by the Free Software Foundation.
 
    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

    $Id: instance.h 171 2015-05-20 05:58:54Z szander $
 
 */

#ifndef INSTANCE_H
#define INSTANCE_H

#include "spptool.h"

#define NAME_MAX_LEN 20

#define Q_MAX_LEN 10000
//#define Q_MIN_LEN 60


// added by Sebastian Zander (linux support)
#ifndef TAILQ_FOREACH_SAFE
#define TAILQ_FOREACH_SAFE(var, head, field, tvar)                      \
        for ((var) = TAILQ_FIRST((head));                               \
            (var) && ((tvar) = TAILQ_NEXT((var), field), 1);            \
        (var) = (tvar))
#endif



TAILQ_HEAD(instance_q_head, Instance);

typedef enum MP_TYPE_TYPE {none = 0, live, file, remote} mp_type_t;

typedef struct Instance {
	uint32_t pkt_id;     // Hash generated from packet header and some data
	struct timeval ts; 	// Timestamp from PCAP file
        TAILQ_ENTRY(Instance) entries;
} instance_t;

typedef struct Monitor_Point {
        unsigned int id; 
       
        pcap_t * dev;  // Pcap device or file identifier
        mp_type_t type;
        int byte_order_swapped;
        in_addr_t addr;
        
        pthread_cond_t thresh_cond;
        pthread_mutex_t thresh_mutex;
        pthread_t thread;
        
        volatile unsigned int q_size[2];
        pthread_mutex_t q_size_mutex[2];

        struct instance_q_head instance_q[2];
        pthread_mutex_t q_mutex[2];
        
        int datalink_type;

        int finished;
	
} monitor_point_t;


// This is copied here as including the header that contained it caused weird problems
struct ip {
#if BYTE_ORDER == LITTLE_ENDIAN
        u_int   ip_hl:4,                /* header length */
                ip_v:4;                 /* version */
#endif
#if BYTE_ORDER == BIG_ENDIAN
        u_int   ip_v:4,                 /* version */
                ip_hl:4;                /* header length */
#endif
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
#define IP_RF 0x8000                    /* reserved fragment flag */
#define IP_DF 0x4000                    /* dont fragment flag */
#define IP_MF 0x2000                    /* more fragments flag */
#define IP_OFFMASK 0x1fff               /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
} __packed;


typedef struct SPP_HDR {



} spp_hdr_t;
#endif

void removeInstance(instance_t * instance, monitor_point_t * mpoint, direction_t direction);
void removeOldInstances(monitor_point_t * mpoint, direction_t direction, struct timeval * cur_time);
void mpoint_load(monitor_point_t * mpoint, const mp_type_t type, const char * name, mp_id_t id);
void mpoint_unload(monitor_point_t * mpoint);
void mpoint_start(monitor_point_t * mpoint);
uint32_t getHash(const struct ip *ip_hdr);
