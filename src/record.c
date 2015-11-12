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

    $Id: record.c 176 2015-05-21 00:35:27Z szander $
 
 */
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/queue.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <pthread.h>

#include "spptool.h"
#include "instance.h"
#include "record.h"

//######## VARIABLES #########//

extern monitor_point_t mp[2];
extern int finished;
extern unsigned int rtt_count;
extern unsigned int sec_offset;
extern int delta_t_max;
extern int verbosity;
extern unsigned int max_packet_gap;

//######## PROTOTYPES ########//

PRIVATE int searchInstances(instance_t * instance[2], direction_t direction);


//######## FUNCTIONS #########//

PRIVATE record_t * assembleRecord(instance_t * ins[]) {

    record_t * rec = malloc(sizeof(record_t));
    rec->pkt_id = ins[REF]->pkt_id;
    if (ins[REF]->pkt_id != ins[MON]->pkt_id) {
        printf("FATAL ERORR: PKT ID's don't match in records!!");
        exit(EXIT_FAILURE);
    }
    rec->ts[MON] = ins[MON]->ts;
    rec->ts[REF] = ins[REF]->ts;
    return rec;
}


/*
 * Wraps around the function that finds packet pairs. 
 *
 * Will only return either a packet pair or NULL if the entire input source has been searched
 *  * */
PUBLIC record_t * createRecord(direction_t direction) {
    mp_id_t tmp_mp_id;  // Monitor and REF queues are either stepped through or searched, depending on the packet direction
    instance_t * instance[2];
    char result;
    record_t * rec;

    result = searchInstances(instance, direction);
    while(result != 1) {
        // sza: previous version was buggy, it finished when files where read completely.
        // We should only finish if files are read completely _and_ queues are drained, i.e. we
        // we identified as many pairs as possible
        if (finished) {
            if (verbosity & 64) 
       	        printf("\n\nRTT COUNT: %u\n\n", rtt_count);

    	    return NULL; //No record can be found
        }
        // If the packet time different is too great (default is DELTA_T_MAX seconds)
        else if(result == 2) {//caused by tdelta 
            result = searchInstances(instance, direction);
        }
        else { // Wait and then try again

            pthread_mutex_lock(&mp[MON].q_mutex[direction]);
            instance[MON] = TAILQ_FIRST(&mp[MON].instance_q[direction]);
            pthread_mutex_unlock(&mp[MON].q_mutex[direction]);  

	    // if we read both files completely and mon queue is drained we cannot
	    // find a pair anymore
            if (mp[REF].finished && mp[MON].finished && instance[MON] == NULL) { 
                // Tell other thread to shut down
                finished=1;
                return NULL;
            }

            // Wasn't any packets to read yet. Sleep for a bit if network stream.
	    // sza: don't sleep if we read from file
            if (mp[REF].type != file)
                usleep(TRYAGAIN_DELAY);

            result = searchInstances(instance, direction);
        }
    }

    rec = assembleRecord(instance);

    // keep timestamp
    struct timeval cur_ts = instance[MON]->ts;

    // free current instances (used for pair)
    for(tmp_mp_id = REF; tmp_mp_id <= MON; tmp_mp_id++) {
  	removeInstance(instance[tmp_mp_id], &mp[tmp_mp_id], direction);
    }

    // prune reference point list
    removeOldInstances(&mp[REF], direction, &cur_ts);

    if (verbosity & 8)
        printf("INFO: Created record with ID %u \n", rec->pkt_id);

    return rec;
}


/*
 * Tries to find both records of a packet in the REF and MON queues
 * of a given direction. 
 *
 * Stops trying when:
 *
 * - The would-be RTT exceeds delta_t_max (DELTA_T_MAX sec by default) (returns 2)
 * - The packets are more than MAX_PACKET_GAP packets apart  (returns 2)
 * - The end of one of the lists are reached (returns 0)
 *
 * Returns 1 on successful pair matching
 * */
PRIVATE int searchInstances(instance_t * instance[2], direction_t direction) {
    long int delta_t = 0;
    int count = 0;

    pthread_mutex_lock(&mp[REF].q_mutex[direction]);
    instance[REF] = TAILQ_FIRST(&mp[REF].instance_q[direction]);
    pthread_mutex_unlock(&mp[REF].q_mutex[direction]);

    pthread_mutex_lock(&mp[MON].q_mutex[direction]);
    instance[MON] = TAILQ_FIRST(&mp[MON].instance_q[direction]);
    pthread_mutex_unlock(&mp[MON].q_mutex[direction]);

    while(instance[REF] != NULL && instance[MON] != NULL) {

        count++;
        delta_t = (instance[REF]->ts.tv_sec - (instance[MON]->ts.tv_sec - sec_offset));

        // Check to see if the timestamps differ by > delta_t_max
        if (delta_t > (delta_t_max + 1)) {                 
            if (verbosity & 8) printf("INFO: Skipping instance %u due to T Delta of %ld\n", instance[MON]->pkt_id, delta_t);
            removeInstance(instance[MON], &mp[MON], direction);
            return 2;
        } else if ((0 - delta_t) > (delta_t_max + 1)) { 
            if (verbosity & 8) printf("INFO: Skipping instance %u due to T Delta of %ld\n", instance[REF]->pkt_id, delta_t);
            removeInstance(instance[REF], &mp[REF], direction);
            return 2;
        } 
        // Check if we've searched too many packets
        else if (count >= max_packet_gap ) {  
            if (verbosity & 8) printf("INFO: Skipping instance %u since it wasn't found in over %u entries. Try using -G command line option with a bigger number.\n", 
			    		instance[MON]->pkt_id, max_packet_gap);
            removeInstance(instance[MON], &mp[MON], direction);
            return 2;   
        }
        // Pair found, return it
        else if (instance[REF]->pkt_id == instance[MON]->pkt_id) { //if they are equal
            return 1;
        }

	// advance ref queue
        pthread_mutex_lock(&mp[REF].q_mutex[direction]);
        instance[REF] = TAILQ_NEXT(instance[REF], entries);
        pthread_mutex_unlock(&mp[REF].q_mutex[direction]);
  }
  if(verbosity & 8) printf("INFO: Searched through %u instances\n", count);

  // sza: if we have read both traces completely, and ref queue is empty advance in mon queue. Otherwise, we may deadlock 
  // (if we have fewer packets than the maximum search window). The problem is not solved for a live capture if traffic stops.
  // In that case we cannot do much, a small search window must be used.
  if (mp[MON].finished && mp[REF].finished && instance[REF] == NULL) {
      pthread_mutex_lock(&mp[MON].q_mutex[direction]);
      instance[MON] = TAILQ_FIRST(&mp[MON].instance_q[direction]);
      pthread_mutex_unlock(&mp[MON].q_mutex[direction]);
      if (instance[MON] != NULL) {
          removeInstance(instance[MON], &mp[MON], direction);
      }
  }

  return 0; //Haven't found a match, but maybe we just need to wait for some more packets
}

