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
  
    $Id: pair.c 176 2015-05-21 00:35:27Z szander $
 
 */

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/queue.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>

#include "spptool.h"
#include "instance.h"
#include "record.h"
#include "pair.h"
#include "timeval.h"

//######## VARIABLES #########//

PUBLIC TAILQ_HEAD(pair_q_head, Pair) pair_q = TAILQ_HEAD_INITIALIZER(pair_q); //Collection of synthetic packet pairs
PUBLIC struct pair_q_head *pair_h;
PUBLIC unsigned int pair_q_size = 0;

extern options_t options;
extern unsigned int rtt_count;
extern int verbosity;

//######## PROTOTYPES ########//

PUBLIC void pair_load();
PUBLIC void pair_unload();
PRIVATE pair_t * assemblePair(record_t * record[2]);
PUBLIC int createPair();


//######## FUNCTIONS #########//

PUBLIC void pair_load() {

  TAILQ_INIT(&pair_q);
}

PUBLIC void pair_unload() {

  pair_t *pair, *pair_next;

  pair = TAILQ_FIRST(&pair_q);
  while (pair != NULL) {
    pair_next = TAILQ_NEXT(pair, entries);
    free(pair);
    pair = pair_next;
  }
}

PRIVATE pair_t * assemblePair(record_t * record[2]) {
  struct timeval tmp_ts;                                                  // Temporary timestamp
  struct timeval tpt;                                                       // Total Pair Time
  direction_t tmp_dir;                                                    // Temporary direction
  pair_t * pair = malloc(sizeof(pair_t));
  static unsigned int pair_no = 0;


 for(tmp_dir = IN; tmp_dir <= OUT; tmp_dir++) {
    pair->rec[tmp_dir] = record[tmp_dir];                                 // Move records into the pair
 }

  timeval_subtract(&tpt, &pair->rec[IN]->ts[REF], &pair->rec[OUT]->ts[REF]);       // Calculate total pair time
  timeval_subtract(&pair->spt, &pair->rec[IN]->ts[MON], &pair->rec[OUT]->ts[MON]);      // Calculate server processing time
  timeval_subtract(&pair->rtt, &tpt, &pair->spt);                                                         // Calculate round trip 

  // Make sure that we dont get negative RTT values (may happen when using large granularity)
  if(pair->rtt.tv_sec < 0) {
    pair->rtt.tv_sec = 0;
    pair->rtt.tv_usec = 0;
  }
  
  // Caculate time that this RTT was experienced
  if(options & use_firstpkt_time) { //Option added by David Hayes - helps to identify pairs with pkts
    pair->ts = pair->rec[OUT]->ts[REF];
  } else {
    if(options & use_monitor_clock) {
      timeval_halve(&tmp_ts, &pair->spt);
      timeval_subtract(&pair->ts, &pair->rec[IN]->ts[MON], &tmp_ts);
    } else {
      timeval_halve(&tmp_ts, &tpt);
      timeval_subtract(&pair->ts, &pair->rec[IN]->ts[REF], &tmp_ts);
    }
  }
  pair_no++;
  if(verbosity & 4) {
    printf("\n");
    printf("* PAIR CREATED --------------------------------------------------\n");
    printf("* Outgoing ID: %u \n", pair->rec[OUT]->pkt_id);
    printf("* REF TS: %6llu.%06llu,   MON TS: %6llu.%06llu\n", 
          (unsigned long long) pair->rec[OUT]->ts[REF].tv_sec,
          (unsigned long long) pair->rec[OUT]->ts[REF].tv_usec,
          (unsigned long long) pair->rec[OUT]->ts[MON].tv_sec,
          (unsigned long long) pair->rec[OUT]->ts[MON].tv_usec );
    printf("* Incoming ID: %u \n", pair->rec[IN]->pkt_id);
    printf("* REF TS: %6llu.%06llu,   MON TS: %10llu.%06llu\n", 
          (unsigned long long) pair->rec[IN]->ts[REF].tv_sec,
          (unsigned long long) pair->rec[IN]->ts[REF].tv_usec,
          (unsigned long long) pair->rec[IN]->ts[MON].tv_sec,
          (unsigned long long) pair->rec[IN]->ts[MON].tv_usec );
    printf("* \n");
    printf("* TPT: %010lld.%06lld, SPT: %lld.%06lld RTT: %lld.%06lld PAIR NO: %d\n", 
           (signed long long) tpt.tv_sec, (signed long long) tpt.tv_usec, (signed long long) pair->spt.tv_sec, 
           (signed long long) pair->spt.tv_usec, (signed long long) pair->rtt.tv_sec, (signed long long) pair->rtt.tv_usec, 
           pair_no);
    printf("*----------------------------------------------------------------\n");
  }
  
  if(options & output_pair_count) printf("%6u ", pair_no);
  printf("%lld.%06lld %lld.%06lld",  (signed long long) pair->ts.tv_sec, (signed long long) pair->ts.tv_usec, 
	  (signed long long) pair->rtt.tv_sec, (signed long long) pair->rtt.tv_usec);
  if(options & output_spt) printf(" %lld.%06lld", (signed long long) pair->spt.tv_sec, 
				  (signed long long) pair->spt.tv_usec);
  printf("\n");
 
  return pair;
}

PUBLIC int createPair() {

  record_t * record[2];
  static record_t * next_rec = NULL;
  pair_t * pair;
  char found;

  // Refill queues and start at the beginning

    record[IN] = createRecord(IN);
    if(record[IN] == NULL)
      return -1;
    record[OUT] = (next_rec == NULL ? createRecord(OUT) : next_rec);
    if(record[OUT] == NULL)
      return -1;
  

  while(!timeval_chronological(&record[OUT]->ts[MON], &record[IN]->ts[MON])) {
    free(record[IN]);
    record[IN] = createRecord(IN);
    if(record[IN] == NULL) 
      return -1;
  }
  found = 0;
  next_rec = createRecord(OUT);
  if(next_rec == NULL) 
    return -1;


  while(!found) {
    if(timeval_chronological(&next_rec->ts[MON], &record[IN]->ts[MON])) {
      free(record[OUT]);
      record[OUT] = next_rec;
      next_rec = createRecord(OUT);
      if(next_rec == NULL)
        return -1;
    } 
    else {
      found = 1;
    }
  }

    // Create pair
    pair = assemblePair(record);
    TAILQ_INSERT_TAIL(&pair_q, pair, entries);
    pair_q_size++;

   if(verbosity & 64) rtt_count += pair->rtt.tv_usec;

   // Remove pair - this is stupid considering we have only just created it.. Original design assumed we would need the pair structs for later processing.
    free(pair->rec[IN]);
    free(pair->rec[OUT]);
    TAILQ_REMOVE(&pair_q, pair, entries);
    pair_q_size--;
    free(pair);

   return 0;
}
