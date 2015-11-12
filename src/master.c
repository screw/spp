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

    $Id: master.c 171 2015-05-20 05:58:54Z szander $
 
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/queue.h>
#include <pcap.h>
#include <netdb.h>
#include <pthread.h>

#include "instance.h"
#include "record.h"
#include "pair.h"
#include "spptool.h"
#include "master.h"
#include "rtp.h"


  extern uint16_t scale;
  extern size_t ts_len;
  extern int finished;
  extern int verbosity;

  int sockfd, numbytes;  
  struct hostent *slave;
  struct sockaddr_in slave_addr, my_addr;             // connector's address information 
  socklen_t addr_len;




void loadMaster(monitor_point_t * mpoint, const char * name) {

  struct timeval timeout;
  timeout.tv_sec = 1;
  timeout.tv_usec = 0;
  if ((slave = gethostbyname(name)) == NULL) {        // get the host info 
      perror("Error looking up host");
      exit(EXIT_FAILURE);
  }

  if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
      perror("Error getting socket");
      exit(EXIT_FAILURE);
  }


  if(setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == -1) {
      perror("Error setting socket options");
      exit(EXIT_FAILURE);
  }
  slave_addr.sin_family = AF_INET;                    // host byte order 
  slave_addr.sin_port = htons(PORT);                  // short, network byte order 
  slave_addr.sin_addr = *((struct in_addr *)slave->h_addr);
  memset(slave_addr.sin_zero, '\0', sizeof slave_addr.sin_zero);

  my_addr.sin_family = AF_INET;		             // host byte order
  my_addr.sin_port = htons(PORT);	             // short, network byte order
  my_addr.sin_addr.s_addr = INADDR_ANY;              // automatically fill with my IP
  memset(my_addr.sin_zero, '\0', sizeof my_addr.sin_zero);
  if (bind(sockfd, (struct sockaddr *)&my_addr, sizeof my_addr) == -1) {
    perror("Error binding to port");
      exit(EXIT_FAILURE);
  }
}


void * runMaster(void * args) {

  instance_t * ins;
  char buf[MAX_PKT_LEN];
  void * buf_ptr;
  unsigned int no_to_recv, recv_count;
  direction_t direction;

  char ts_code;
  size_t ts_len;
  char hash_len;

  rtp_hdr_t recv_hdr;

  //ts_len = ts_code;
  hash_len = 4;

  //Offset timestamp vars
  struct timeval prev_ts;

  monitor_point_t * mpoint = (monitor_point_t *)args;


  while(!finished) {

    addr_len = sizeof slave_addr;

    do {
      numbytes = recvfrom(sockfd, buf, MAX_PKT_LEN, 0, (struct sockaddr *)&slave_addr, &addr_len);
      if (finished) break;
    } while(numbytes == -1);

    if(finished) {
      continue; // get out of here so we can exit this function
    } else if(numbytes < 12) {
      printf("ERROR: Received undersized packet!\n");
    }
    else {
      buf_ptr = buf;

      // extract header
      memcpy(&recv_hdr, buf_ptr, sizeof(recv_hdr));
      buf_ptr += sizeof(recv_hdr);

      ts_code = recv_hdr.pt;
      if(ts_code == 0) {                              // If this is an empty packet
        continue;                                     // Ignore it
      }

      prev_ts.tv_sec = recv_hdr.ts;                   // put the reference 'seconds' in the previous to ensure the first timestamp calculation works
      prev_ts.tv_usec = recv_hdr.ssrc;                // grab the usec from ssrc field of rtp

      ts_len = ts_code;                               // may need to change as payload type is defined differently

      if(verbosity & 128) {
        printf("RTP HEADER: ts: %u, pt: %u\n", recv_hdr.ts, recv_hdr.pt);
        printf("Initial Timestamp: %llu, %llu\n", (unsigned long long) prev_ts.tv_sec, (unsigned long long) prev_ts.tv_usec);
      }

      no_to_recv = ((numbytes - sizeof(recv_hdr)) / (ts_len + hash_len));

      if(verbosity & 256) 
        printf("Received %u Bytes, %u Instances\n", numbytes, no_to_recv);


      recv_count = 0;
      while(recv_count < no_to_recv) {
        ins = malloc(sizeof(instance_t));             // allocate space for new instance
        // extract hash
        memcpy(&ins->pkt_id, buf_ptr, sizeof(uint32_t));
        buf_ptr += sizeof(uint32_t);


        if(ts_code == ABSOLUTE) {
            memcpy(&ins->ts, buf_ptr, sizeof(struct timeval));                      //read the timestamp directly
            buf_ptr += sizeof(struct timeval);                   
            direction = (direction_t)((ins->ts.tv_sec & (1 << 31)) != 0);           // clear bit
            ins->ts.tv_sec &= ~(1 << 31);
            break;
        } 
        else {
          direction = (direction_t)((*((u_char *)buf_ptr) & (1 << 7)) != 0);        // get direction from the first bit of the usec offset field
          *(u_char *)buf_ptr &= ~(1 << 7);                                          // clear the direction bit

          memcpy(&ins->ts.tv_usec, buf_ptr, ts_len);                                // start with the offset received usec
          buf_ptr += ts_len;
          ins->ts.tv_usec = ntohl(ins->ts.tv_usec);                                 // put usec offset back to host order
          ins->ts.tv_usec = ins->ts.tv_usec >> (8 * (sizeof(uint32_t) - ts_len));   // realign to adjust for the larger size on the host

          ins->ts.tv_usec *= scale;                                                 // multiply by the offset to correct for division at slave end

              if(verbosity & 1024) printf("Incoming offset: %llu\n", (unsigned long long) ins->ts.tv_usec);

          ins->ts.tv_usec += prev_ts.tv_usec;                                       // add in the previos usec
          ins->ts.tv_sec = ins->ts.tv_usec / 1000000;                               // carry seconds over
          ins->ts.tv_usec %= 1000000;                                               // since we have carried.. set usec as remainder 
          ins->ts.tv_sec += prev_ts.tv_sec;                                         // finally add previous seconds 

          prev_ts = ins->ts;                                                      // prepare the prev_ts for next time
        }

        pthread_mutex_lock(&mpoint->q_mutex[direction]);
        TAILQ_INSERT_TAIL(&mpoint->instance_q[direction], ins, entries);        // Insert instance into appropriate queue
        pthread_mutex_unlock(&mpoint->q_mutex[direction]); 
        pthread_mutex_lock(&mpoint->q_size_mutex[direction]);
        mpoint->q_size[direction]++;
        pthread_mutex_unlock(&mpoint->q_size_mutex[direction]);
            if(verbosity & 16) printf("NETWORK: Added %u to mpoint %u instance_q[%u] - timestamp: %llu.%06llu\n", 
                                      ins->pkt_id, mpoint->id, direction, (unsigned long long) ins->ts.tv_sec, (unsigned long long) ins->ts.tv_usec);
        recv_count++;
      }
    }
  }
  close(sockfd);
  pthread_exit(NULL);
}


