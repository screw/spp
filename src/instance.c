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

    $Id: instance.c 176 2015-05-21 00:35:27Z szander $
 
    Note to self - Changes to 0.3.1:
    Used explicit casting to enable compilation on 64bit: *(struct in_addr *)& 
    See http://www.gidforums.com/t-7865.html for details (in_addr_t vs in_addr)

*/

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/queue.h>


#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <unistd.h>

#include "spptool.h"
#include "crc32.h"
#include "timeval.h"
#include "instance.h"
#include "master.h"
#include "slave.h"

//######## VARIABLES #########//
PUBLIC monitor_point_t mp[MP_COUNT];

PRIVATE char errbuf[PCAP_ERRBUF_SIZE];
PUBLIC in_addr_t addr[2];
PUBLIC in_addr_t nat_addr[2];

extern int hash_fields;
extern int finished;
extern int options;
extern int delta_t_max;
extern int verbosity;
extern unsigned int sec_offset;

//######## PROTOTYPES ########//

PUBLIC void mpoint_load(monitor_point_t * mpoint, const mp_type_t type, const char * name, mp_id_t id);
PUBLIC void instance_unload(mp_id_t id);

PRIVATE instance_t* assembleInstance(const struct pcap_pkthdr *pcap_hdr, const struct ip *ip_hdr, direction_t direction);
PUBLIC void createInstance(u_char *args, const struct pcap_pkthdr *pcap_hdr, const u_char *pkt);
PUBLIC void * createInstances(void * args);
PRIVATE void setPcapFilter(monitor_point_t * mpoint, char * filter_string);
PUBLIC uint32_t getHash(const struct ip *ip_hdr);

//######## FUNCTIONS #########//

/*
 * Initialises the monitor point struct. Called once for MON and once for REF.
 * */
PUBLIC void mpoint_load(monitor_point_t * mpoint, const mp_type_t type, const char * name, mp_id_t id) 
{
  mpoint->id = id;

  mpoint->q_size[IN] = 0;
  mpoint->q_size[OUT] = 0;
  mpoint->type = type;
  switch(type) {
    
    case live:
            
                if((mpoint->dev = pcap_open_live(name, BUFSIZ, 1, 500, errbuf)) == NULL) {
                 printf("PCAP error: %s\n", errbuf); 
                 exit(-1);
                }
                //Possible auto IP discovery from interface
               // if(pcap_lookupnet(pcap_lookupdev(errbuf), netp, errbuf)) { 
               //  printf("PCAP error: %s\n", errbuf); 
               //  exit(-1);
               // }
                break;
    case file:
                // Open PCAP file for reading
                if((mpoint->dev = pcap_open_offline(name, errbuf)) == NULL) {
                 printf("Error opening file: %s\n", errbuf); 
                  exit(-2);
                }
                mpoint->byte_order_swapped = pcap_is_swapped(mpoint->dev);
                break;
    case remote:
                loadMaster(mpoint, name);
                break;
    default:
                break;
  }


  TAILQ_INIT(&mpoint->instance_q[IN]);
  TAILQ_INIT(&mpoint->instance_q[OUT]);

  pthread_mutex_init(&mpoint->thresh_mutex, NULL);
  pthread_cond_init(&mpoint->thresh_cond, NULL);

  pthread_mutex_init(&mpoint->q_mutex[IN], NULL);
  pthread_mutex_init(&mpoint->q_mutex[OUT], NULL);
 
  pthread_mutex_init(&mpoint->q_size_mutex[OUT], NULL);
  pthread_mutex_init(&mpoint->q_size_mutex[IN], NULL);

  mpoint->finished = 0;
  if(mpoint->type != remote) {
      mpoint->datalink_type = pcap_datalink(mpoint->dev);
        if(verbosity & 32) printf("Monitor point id %d has datalink type: %d\n", mpoint->id, mpoint->datalink_type);
  }
}


/* 
 * Constructs the PCAP filter string. 
 * Spawns the input reader threads 
 * */
PUBLIC void mpoint_start(monitor_point_t * mpoint) {

 if(mpoint->type != remote) {
    char filter_string[90];
    char buf[8];
    strcpy(filter_string, "host ");
    strcat(filter_string, inet_ntoa(*(struct in_addr *)&addr[REF]));
    if (nat_addr[0] == 0 && nat_addr[1] == 0)
      strcat(filter_string, " and host ");
    else //one of the ends has NAT
      strcat(filter_string, " or host ");
    strcat(filter_string, (char*)inet_ntoa(*(struct in_addr *)&addr[MON]));
    strcat(filter_string, " and !icmp[icmptype]==3 and !port ");
    sprintf(buf, "%d", PORT);
    strcat(filter_string, buf);
        if(verbosity & 32) printf("PCAP filter string: %s\n", filter_string);
    setPcapFilter(mpoint, filter_string);
  }

  switch(mpoint->type) {
    case file:
    case live:
                pthread_create(&mpoint->thread, NULL, &createInstances, (void*)mpoint);
                if(verbosity & 2) printf("INFO: Thread started\n");
                break;
    case remote:
                pthread_create(&mpoint->thread, NULL, &runMaster, (void*)mpoint);
                break;
    default:
                break;
  }



}

/*
 * Shuts down pcap, frees up the TAILQ lists
 * */
PUBLIC void mpoint_unload(monitor_point_t * mpoint) {

  switch(mpoint->type) {
    case live:
    case file:
                // Close pcap device
                pcap_close(mpoint->dev);
                break;
    case remote:
                break;
    default:
                break;
  }

  //CLEAN BOTH INSTANCE QUEUES
  direction_t direction;
  instance_t *ins, *ins_next;


  for(direction = IN; direction <= OUT; direction++) {
    pthread_mutex_lock(&mpoint->q_mutex[direction]);
    ins = TAILQ_FIRST(&mpoint->instance_q[direction]);
    while (ins != NULL) {
      ins_next = TAILQ_NEXT(ins, entries);
      free(ins);
      ins = ins_next;
    }
    pthread_mutex_unlock(&mpoint->q_mutex[direction]);
  }
}

PRIVATE instance_t* assembleInstance(const struct pcap_pkthdr *pcap_hdr, const struct ip *ip_hdr, direction_t direction){

  instance_t * ins = malloc(sizeof(instance_t));
  //printf("))) Malloc to ptr: %u\n", ins);
  ins->pkt_id = getHash(ip_hdr);

  ins->ts = pcap_hdr->ts;                                                                     // Store instance timestamp
  return ins;
}

/*
 * Creates hash of a packet that is used for the pkt_id field. 
 *
 * The pkt_id is crucial for determining whether a packet seen at REF
 * has also been seen at MON. We rely on hashing together one or more fields
 * that are expected to be vary from packet to packet but also be invariant along
 * the path between REF and MON. The global 'hash_fields' holds a bitmask
 * indicating which fields should be included in the hash calculation.
 * 
 * In SPP <= 0.3.6 we assumed IP.ID (Identification) field would be non-zero and
 * unique per packet emitted by a given source (at least for time periods longer than
 * a handful of RTTs). However, RFC 6864 (Feb 2013) officially deprecated this use of
 * IP.ID field, and it is now a largely unreliable mechanism for disambiguating packets
 * that might otherwise look the same based on other header fields.
 * 
 * Some other fields may or may not be invariant along a path. Certain middleboxes have
 * been observed in the wild actually twiddling with the raw TCP sequence numbers,
 * ensuring they wont match between REF and MON.
 * 
 * */
PUBLIC uint32_t getHash(const struct ip *ip_hdr) {

  unsigned int hash_offset = 0;
  unsigned char hash_data[HASH_DATA_LENGTH + 1];
  u_char * transport_hdr = ((u_char *)ip_hdr + (ip_hdr->ip_hl * 4));
  struct tcphdr *tcp_hdr = (struct tcphdr *)transport_hdr;
 
  //printf("assembling\n");
  if (nat_addr[0] == 0 && nat_addr[1] == 0) {	// Do not include IP addresses in hash when running through NAT (This would cause no hashes to match)
    if(hash_fields & 1) {                 // Add Source address field
      memcpy((void*)(hash_data + hash_offset), (void*)&ip_hdr->ip_src, sizeof(ip_hdr->ip_src));
      hash_offset += sizeof(ip_hdr->ip_src);
    }
    if(hash_fields & 2) {                 // Add Destination address field 
      memcpy((void*)(hash_data + hash_offset), (void*)&ip_hdr->ip_dst, sizeof(ip_hdr->ip_dst));
      hash_offset += sizeof(ip_hdr->ip_dst);
    }
  }
  if(hash_fields & 4) {                   // Add Protocol
    memcpy((void*)(hash_data + hash_offset), (void*)&ip_hdr->ip_p, sizeof(ip_hdr->ip_p));
    hash_offset += sizeof(ip_hdr->ip_p);
  }
  if(hash_fields & 8) {                   // Add Identification field
    memcpy((void*)(hash_data + hash_offset), (void*)&ip_hdr->ip_id, sizeof(ip_hdr->ip_id));
    hash_offset += sizeof(ip_hdr->ip_id);
  }


  if(ip_hdr->ip_p == 6 || ip_hdr->ip_p == 17) {  //We have a TCP or UDP packet
    if(hash_fields & 16) {                // Add TCP/UDP src
      memcpy((void*)(hash_data + hash_offset), (void*)transport_hdr, 2);
      hash_offset += 2;
    }
    if(hash_fields & 32) {                // Add TCP/UDP dst
      memcpy((void*)(hash_data + hash_offset), (void*)(transport_hdr + 2), 2);
     hash_offset += 2;
    }

    if(ip_hdr->ip_p == 6) {  //We have a TCP packet
      if(hash_fields & 64) {              // Add TCP Seq No
        memcpy((void*)(hash_data + hash_offset), (void*)(transport_hdr + 4), 4);
        hash_offset += 4;
      }
      if(hash_fields & 128) {             // Add TCP Ack No
        memcpy((void*)(hash_data + hash_offset), (void*)(transport_hdr + 8), 4);
        hash_offset += 4;
      }
      if(hash_fields & 256) {             // Add TCP data offset, flags, window size
	memcpy((void*)(hash_data + hash_offset), (void*)(transport_hdr + 12), 4);
	hash_offset += 4;
      }
      if(hash_fields & 512) {             // Add TCP Checksum, urgent pointer
        memcpy((void*)(hash_data + hash_offset), (void*)(transport_hdr + 16), 4);
        hash_offset += 4;
      }
      if(hash_fields & 8192) {            // Add up to first hash_bytes bytes of TCP payload
	unsigned short hash_bytes = 12;
	unsigned short tcp_data_start = tcp_hdr->th_off * 4;
	unsigned short tcp_data_len = ntohs(ip_hdr->ip_len) - (ip_hdr->ip_hl * 4) - tcp_data_start;
	if (tcp_data_len < hash_bytes) {
		hash_bytes = tcp_data_len;
	}
	memcpy((void*)(hash_data + hash_offset), (void*)(transport_hdr + tcp_data_start), hash_bytes);
	hash_offset += hash_bytes;
      }
      if(hash_fields & 16384) {           // Hash across all TCP options bytes if present
	unsigned short hash_bytes = tcp_hdr->th_off * 4 - 20; // Number of bytes of TCP options
	if (hash_bytes > 0) { // There are options, so off we go
	  memcpy((void*)(hash_data + hash_offset), (void*)(transport_hdr + 20), hash_bytes);
	  hash_offset += hash_bytes;
	}
      }

    }
    else {  //Must be UDP
      if(hash_fields & 1024) {             // Add UDP length, checksum 
        memcpy((void*)(hash_data + hash_offset), (void*)(transport_hdr + 4), 4);
        hash_offset += 4;
      }
      if(hash_fields & 2048) {             // Add UDP payload (up to 12 bytes)
	unsigned short data_len = ntohs(*((unsigned short*)(transport_hdr + 4))) - 8;
	unsigned short hash_bytes = 12;
	if (data_len < hash_bytes) {
		hash_bytes = data_len;
	}
	memcpy((void*)(hash_data + hash_offset), (void*)(transport_hdr + 8), hash_bytes);	      	
	hash_offset += hash_bytes;
      }

    }
  } else {
	if(hash_fields & 4096) {
		// If not TCP or UDP add up to first 20 bytes past IP header
		unsigned short ip_data_len = ntohs(ip_hdr->ip_len) - ip_hdr->ip_hl * 4;
		unsigned short hash_bytes = 20;
		if (ip_data_len < hash_bytes) {
			hash_bytes = ip_data_len;
		}
		memcpy((void*)(hash_data + hash_offset), (void*)transport_hdr, hash_bytes);
		hash_offset += hash_bytes;
	}
  }
  return crc32_le(0, hash_data, hash_offset);
}

/*
 * This is spawned inside its own thread. It is the "read the input stream" 
 * thread. One is created for each input stream (ie, one for each of REF 
 * and MON)
 * */
PUBLIC void * createInstances(void * args) {
    monitor_point_t * mpoint = (monitor_point_t *)args;

    pcap_loop(mpoint->dev, -1, createInstance, (u_char*)mpoint);
    sleep(1);         //Leave some time for all calculations to be finished before sending the telling the program to quit.
    mpoint->finished = 1;

    pthread_exit(NULL);
}

/*
 * Reads a single packet in and adds it to the incoming queue to be processed
 * by a different thread. 
 *
 * */
PUBLIC void createInstance(u_char *args, const struct pcap_pkthdr *pcap_hdr, const u_char *pkt)
{

  direction_t direction;
  struct ip * ip_hdr;

  in_addr_t src_addr, dst_addr;
  instance_t * ins;

  struct ether_header * eth_hdr = (struct ether_header *)pkt;
  monitor_point_t * mpoint = (monitor_point_t *)args; 
  int pkt_err = 0;
  int link_hdr_len = 0;

  if(finished)pthread_exit(NULL);                     // Shut this thread down if we have been told to finish
  
  direction = -1;                                     // No direction by default (-1)
  
 switch(mpoint->datalink_type) {
    case DLT_EN10MB:                                  //printf("Found Ethernet\n");
                      if(eth_hdr->ether_type != 8 && eth_hdr->ether_type != 2048) { // If we are not carrying IP
                            if(verbosity & 32) printf("Skipping Ethernet frame not containing IPv4\n");
                        return;
                      }
                      link_hdr_len = sizeof(struct ether_header);
                      break;
    case DLT_LOOP:
    case DLT_NULL:                                    //printf("Found Null/Loop\n"); 

                      if(*(uint32_t*)pkt != 2) {
                            if(verbosity & 32) printf("Skipping Null/Loopback frame not containing IPv4\n");
                        return;
                      }
                      link_hdr_len = 4;
                      break;
    case DLT_LINUX_SLL:
		      //Changed by David Hayes to reflect the pcap man page
                      link_hdr_len = 16;
                      break;
    case DLT_PPP:
                      // Support PPP-encapsulated frames with/without HDLC encaps
		      if ((*pkt == 0xFF) && (*(pkt+1) == 0x03)) {
			link_hdr_len = 4;
		      } else {
			link_hdr_len = 2;
		      }
                      break;
    default:
                      printf("DataLink type not supported\n");
                      exit(EXIT_FAILURE);
    }

  ip_hdr = (struct ip *)(pkt + link_hdr_len);
  
  if(ip_hdr->ip_v != 4){
    if(verbosity & 32) printf("INFO: Skipping Packet: not IPv4\n");
    pkt_err = 1;
  }

  if(ip_hdr->ip_len == 0){
    // Some instances of captured TSO'ed frames have been seen with ip_len=0,
    // so re-construct a fake a lower-bound IP packet length based on how many bytes
    // actually captured (may be used later during pkt_id generation)
    ip_hdr->ip_len = htons(pcap_hdr->caplen - link_hdr_len);
  }

  if(mpoint->byte_order_swapped){
    src_addr = ntohl(ip_hdr->ip_src.s_addr);   //TEST THIS?
//    printf("%s", src_addr);
    dst_addr = ntohl(ip_hdr->ip_dst.s_addr);   //TEST THIS?
  } else {
    src_addr = ip_hdr->ip_src.s_addr;
    dst_addr = ip_hdr->ip_dst.s_addr;
  }


  if(verbosity & 32) {
    char addr_string[2][16];
    strncpy(addr_string[0], inet_ntoa(*(struct in_addr *)&src_addr), 16); // inet_ntoa() not always thread-safe?
    strncpy(addr_string[1], inet_ntoa(*(struct in_addr *)&dst_addr), 16); // inet_ntoa() not always thread-safe?
    printf("INFO: Next packet from monitor point %u: src %s, dst %s\n", 
           mpoint->id, addr_string[0], addr_string[1]);
  }

  if(src_addr == addr[0] && dst_addr == addr[1])                   // Determine if we have found an OUT packet
    direction = OUT;
  else if (src_addr == nat_addr[0] && dst_addr == addr[1])
    direction = OUT;
  else if (src_addr == addr[0] && dst_addr == nat_addr[1])
    direction = OUT;
  else if(src_addr == addr[1] && dst_addr == addr[0])              // Determine if we have found an IN packet
    direction = IN;
  else if(src_addr == addr[1] && dst_addr == nat_addr[0]) 
    direction = IN;
  else if(src_addr == nat_addr[1] && dst_addr == addr[0]) 
    direction = IN;
  else
    pkt_err = 1;
       

  if(pkt_err != 1) {
     
    if(options & run_slave) {
      sendHashes(pcap_hdr, (const u_char *) ip_hdr, direction);
      //printf("For debugging only \n");
    }
    else {
      ins = assembleInstance(pcap_hdr, ip_hdr, direction);
      pthread_mutex_lock(&mpoint->q_mutex[direction]);
      TAILQ_INSERT_TAIL(&mpoint->instance_q[direction], ins, entries);       // Insert instance into appropriate queue
      pthread_mutex_unlock(&mpoint->q_mutex[direction]); 

      pthread_mutex_lock(&mpoint->q_size_mutex[direction]); //uncommented by David Hayes
      mpoint->q_size[direction]++;                         // Increment queue length
      //printf("DEBUGGING... \n");
      pthread_mutex_unlock(&mpoint->q_size_mutex[direction]);
      //printf("DEBUGGING 2... \n");
      
      if(verbosity & 16) {
        printf("INFO: Added %u to mpoint %u instance_q[%u] - timestamp: %llu.%06llu\n", ins->pkt_id, mpoint->id, direction, 
               (unsigned long long)ins->ts.tv_sec, (unsigned long long)ins->ts.tv_usec);
      }
    }
  }
  else if(verbosity & 32) {
    printf("Packet discarded - (Not matching src and dst address)\n");
    char addr_string[2][16];
    strncpy(addr_string[0], inet_ntoa(*(struct in_addr *)&addr[0]), 16);
    strncpy(addr_string[1], inet_ntoa(*(struct in_addr *)&addr[1]), 16);
    printf("Src and dst should be %s or %s\n", addr_string[0], addr_string[1]);
    
  }

  // Check to see if the processing queues are full. If they are, wait a little bit
  // If we're doign a live or remote capture, do not wait - presumably, the frame
  // is not added to the queue if the queue is full.

  // sza: I removed the sleeping for reading from files. If we sleep here we slow 
  // down the analysis process. We rather use a bit more CPU to finish as quickly
  // as possible
#if 0
  if(mpoint->type == file) {
    pthread_mutex_lock(&mpoint->q_size_mutex[IN]);
    pthread_mutex_lock(&mpoint->q_size_mutex[OUT]);
    while(mpoint->q_size[IN] >= Q_MAX_LEN && mpoint->q_size[OUT] >= Q_MAX_LEN) {
      pthread_mutex_unlock(&mpoint->q_size_mutex[IN]);
      pthread_mutex_unlock(&mpoint->q_size_mutex[OUT]);
      if(verbosity & 2) printf("INFO: Monitor point %u sleeping\n", mpoint->id);
      usleep(10);
      if(finished)pthread_exit(NULL);
      pthread_mutex_lock(&mpoint->q_size_mutex[IN]);
      pthread_mutex_lock(&mpoint->q_size_mutex[OUT]);
    }
    pthread_mutex_unlock(&mpoint->q_size_mutex[IN]);
    pthread_mutex_unlock(&mpoint->q_size_mutex[OUT]);
  }
#endif
  if(finished)pthread_exit(NULL);

}

/*
 * Remove a certain packet pair from the yet-to-be-processed queue
 * */
PUBLIC void removeInstance(instance_t * instance, monitor_point_t * mpoint, direction_t direction) {
    //printf("))) About to free ptr: %u\n", instance);
    pthread_mutex_lock(&mpoint->q_mutex[direction]);
    TAILQ_REMOVE(&mpoint->instance_q[direction], instance, entries);
    //printf("%%% removeInstance: removed from Q\n");
    pthread_mutex_unlock(&mpoint->q_mutex[direction]);
      free(instance);

    //printf("%%% removeInstance: freed\n");
    pthread_mutex_lock(&mpoint->q_size_mutex[direction]);
    mpoint->q_size[direction]--;
    pthread_mutex_unlock(&mpoint->q_size_mutex[direction]);
    //printf("%%% removeInstance: done\n");
    //displayQueueSize();
}

/*
 * Prune packets older than delta_t_max from the yet-to-be-processed queue.
 * Calls removeInstance() on each of the pruned packets
 * */
PUBLIC void removeOldInstances(monitor_point_t * mpoint, direction_t direction, struct timeval * cur_time) {
  int delta_t;
  instance_t *ins, *ins_tmp;
  pthread_mutex_lock(&mpoint->q_mutex[direction]);

  TAILQ_FOREACH_SAFE(ins, &mpoint->instance_q[direction], entries, ins_tmp) {
    pthread_mutex_unlock(&mpoint->q_mutex[direction]);
     delta_t = (cur_time->tv_sec - sec_offset) - ins->ts.tv_sec;

    if(delta_t  > (delta_t_max + 1)) {
      if(verbosity & 8) {
        printf("INFO: Removing old instance %u\n", ins->pkt_id);
      }
      removeInstance(ins, mpoint, direction);
    }
    else {
      return;                    // No point searching any more as items are in chronological order
    }
    pthread_mutex_lock(&mpoint->q_mutex[direction]);
  }
  pthread_mutex_unlock(&mpoint->q_mutex[direction]);

}

/*
 * Applies the filter string, called from mpoint_start
 * */
PRIVATE void setPcapFilter(monitor_point_t * mpoint, char * filter_string) {
  struct bpf_program bpf_prog;
  


  if(pcap_compile(mpoint->dev, &bpf_prog, filter_string,0,1) == -1)
    printf("Error compiling BPF program: %s\n", pcap_geterr(mpoint->dev));

  if(pcap_setfilter(mpoint->dev, &bpf_prog) == -1)
    printf("Error setting BPF filter: %s\n", pcap_geterr(mpoint->dev));

  pcap_freecode(&bpf_prog);
}
