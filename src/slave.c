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

    $Id: slave.c 171 2015-05-20 05:58:54Z szander $
 
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/queue.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>
#include <pcap.h>

#include <netdb.h>
#include "rtp.h"
#include "instance.h"
#include "record.h"
#include "pair.h"
#include "slave.h"
#include "spptool.h"

#define BACKLOG 3	 // how many pending connections queue will hold

PUBLIC int runSlave(monitor_point_t * mpoint);

  uint16_t scale = 100;                               // Default to 100 usec granularity
  size_t ts_len = 2;                                  // Default to 2 byte timestamps (15 bit: 16 - direction bit) 
  uint16_t timeout = 10;                              // Packet send timeout in seconds (will send at least every 'timeout' seconds);  

  extern int finished;
  extern monitor_point_t mp[2];

  int sockfd, new_fd;                                 // listen on sock_fd, new connection on new_fd
  struct sockaddr_in my_addr;	                      // my address information
  struct sockaddr_in  master_addr;                    // connector's address information
  socklen_t sin_size;
  struct hostent * master;
  void * dataToSend;
  void * insertPoint;
  rtp_hdr_t send_hdr;

  int ts_code;
  struct timeval lastSent;



PUBLIC void sendPacket() {      

  gettimeofday(&lastSent, NULL);                      // Record the time we send the packet

  if(insertPoint == dataToSend) {                     // We haven't created any part of a new packet
        send_hdr.pt = 0;
        send_hdr.ts = lastSent.tv_sec;                // We are sending the whole header so we may as well include a timestamp
        send_hdr.ssrc = lastSent.tv_usec;
        memcpy(insertPoint, &send_hdr, sizeof(send_hdr));
        insertPoint += sizeof(send_hdr);
  }
      if(DEBUG_LEVEL & 1024) printf("socket id: %u\n", sockfd);
      if(DEBUG_LEVEL & 1024) printf("SEND ADDRESS: %s:%u\n", inet_ntoa(master_addr.sin_addr),

  ntohs(master_addr.sin_port));
  socklen_t addr_len = sizeof(master_addr);

      if(DEBUG_LEVEL & 1024) printf("trying to send %lu bytes\n", (insertPoint - dataToSend));

  if (sendto(sockfd, dataToSend, (insertPoint - dataToSend), 0, (struct sockaddr *)&master_addr, addr_len) == -1)
                    perror("Sending packet failed\n");

 insertPoint = dataToSend;                           // Set insert point back to the start of the buffer
}



PRIVATE void setupNewPacket(const struct pcap_pkthdr *pcap_hdr, struct timeval * prev_ts) {

  prev_ts->tv_sec = pcap_hdr->ts.tv_sec;  // set our 'seconds' reference to this packet's seconds
  send_hdr.ts = pcap_hdr->ts.tv_sec; // take the current ts seconds value and store it in the header
  
  prev_ts->tv_usec = pcap_hdr->ts.tv_usec; 
  send_hdr.ssrc = pcap_hdr->ts.tv_usec; // use the ssrc spot to hold the usec
  
  send_hdr.pt = ts_code; // again the protocol type may not always be ts_code exactly
  
  memcpy(insertPoint, &send_hdr, sizeof(send_hdr));
  insertPoint += sizeof(send_hdr);
}



PUBLIC void loadSlave(const char * name) {

  master = malloc(sizeof(struct hostent));

  if ((master = gethostbyname(name)) == NULL) {  // get the host info 
      perror("Error looking up host");
      exit(1);
  }

  if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
      perror("Cannot get socket");
      exit(1);
  }

  my_addr.sin_family = AF_INET;		 // host byte order
  my_addr.sin_port = htons(PORT);	 // short, network byte order
  my_addr.sin_addr.s_addr = INADDR_ANY; // automatically fill with my IP
  memset(my_addr.sin_zero, '\0', sizeof my_addr.sin_zero);

  if (bind(sockfd, (struct sockaddr *)&my_addr, sizeof my_addr) == -1) {
          perror("Error binding to socket");
          exit(1);
  }

  master_addr.sin_family = AF_INET;    // host byte order 
  master_addr.sin_port = htons(PORT);  // short, network byte order 
  master_addr.sin_addr = *((struct in_addr *)master->h_addr);
  memset(master_addr.sin_zero, '\0', sizeof master_addr.sin_zero);

  dataToSend = malloc(MAX_PKT_LEN + 1);
  insertPoint = dataToSend;
  
  send_hdr.version = 3;
  send_hdr.p = 0;
  send_hdr.x = 0;
  send_hdr.m = 0;
  send_hdr.ssrc = 0;

  gettimeofday(&lastSent, NULL); //Start from now...
}



PUBLIC void sendHashes(const struct pcap_pkthdr *pcap_hdr, const u_char *pkt, direction_t direction) {

  
  static struct timeval prev_ts;
  //static size_t next_ts_len = 0;

  uint32_t tmp, offset = 0;
  int shouldSendPacket = 0;

  uint32_t hash = getHash((const struct ip *) pkt);

  ts_code = ts_len; //change later
  //next_ts_len = ts_len;

  if(insertPoint == dataToSend) setupNewPacket(pcap_hdr, &prev_ts);                           // If starting a new packet we will need a header

  shouldSendPacket = ((insertPoint - dataToSend) > (MAX_PKT_LEN - sizeof(send_hdr)));         //Send if we have filled it up

//############## Calculate offset from last packet

  if(ts_len != ABSOLUTE) {

    tmp = (pcap_hdr->ts.tv_sec - prev_ts.tv_sec) * 1000000 + pcap_hdr->ts.tv_usec;
    offset = (tmp / scale) - (prev_ts.tv_usec / scale);


    prev_ts = pcap_hdr->ts;
    if(offset >= (1 << (ts_len * 8 - 1))) {           // If this offset is too large for the current packet ts_len
            if(DEBUG_LEVEL & 1024) printf("Offset too large - current ts_len: %zu, offset %u, calc %u\n", ts_len, offset, (1 << (ts_len * 8 - 1)));
      shouldSendPacket = 1;
     // if(offset < (1 << 15 ))                       //Dynamic timestamp lengths will come later
     //   next_ts_len = 2;
     // else if(offset < (1 << 23))
     //   next_ts_len = 3;
    }
  }

//############## Send a packet if neccessary
 
   if(shouldSendPacket) { 
     sendPacket();
     setupNewPacket(pcap_hdr, &prev_ts);
     offset = 0;                                      // The first entry will always be the same as the timestamp stored in the header - so no offset
   }

//############## Add this instance to the packet being constructed

  //Add hash to buffer
  memcpy(insertPoint, &hash, 4);
  insertPoint += 4;


  // Add timestamp to buffer
  if(ts_len == ABSOLUTE) {                            // Absolute timestamping - full timeval struct is sent
    struct timeval ts = pcap_hdr->ts;                 // get timestamp
    ts.tv_sec &= ~(1 << 31);                          // clear bit
    // OR in direction
    ts.tv_sec |= (direction << 31); 
    memcpy(insertPoint, &ts, 8);
    insertPoint += 8;
  }
  else {                                              // Use offset timestamps (1-4 bytes long)
        if(DEBUG_LEVEL & 1024) printf("sec: %llu, usec: %llu, tmp: %u, offset: %u\n", 
                                      (unsigned long long) pcap_hdr->ts.tv_sec, (unsigned long long) pcap_hdr->ts.tv_usec, tmp, offset);

    uint32_t net_offset = htonl(offset);              // make sure we are in big endian.
    u_char * src = (u_char *)(&net_offset);           // get a pointer to the big endian value

    src += (sizeof(uint32_t) - ts_len);               // skip past the byte(s) we are truncating
    *src &= ~(1 << 7);                                // clear msb of first timestamp byte
    *src |= (direction << 7);                         // add in direction

    memcpy(insertPoint, src,ts_len);
    insertPoint += ts_len;
  }
}

