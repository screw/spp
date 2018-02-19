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

    $Id: spptool.c 174 2015-05-21 00:13:39Z szander $
 
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/queue.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <getopt.h>
#include <pthread.h>
#include <signal.h>
#include <ctype.h>

#include "instance.h"
#include "record.h"
#include "pair.h"
#include "slave.h"
#include "spptool.h"
#include "crc32.h"
#include "timeval.h"


//######## VARIABLES #########//

int                 mp_reversed_byte_order[2];
const u_char        *pkt;
struct pcap_pkthdr  hdr;
options_t options;

int finished = 0;
unsigned int hash_fields = 63;
//unsigned int hash_fields = 8191; // by default use all fields
unsigned int rtt_count = 0;
int delta_t_max = DELTA_T_MAX;
unsigned int sec_offset = 0;
unsigned int verbosity = 0;
unsigned int max_packet_gap = MAX_PACKET_GAP;

extern monitor_point_t mp[2];
extern volatile unsigned int pair_q_size;

extern struct timeval lastSent;

extern in_addr_t addr[2];
extern in_addr_t nat_addr[2];

//For setting options:
extern size_t ts_len;
extern uint16_t scale;
extern uint16_t timeout;
//######## PROTOTYPES ########//

int cleanUp();
void displayQueueSize();
void displayUsageInfo();
int initialise();
int main(int argc, char *argv[]);
void sigintproc();

int cleanUp() {

  pair_unload();



  cleanup_crc32();

  if(verbosity > 3)
    printf("INFO: Finished Cleanup\n");
  
  return 0;
}


void displayQueueSize() {
  printf("/ Current Queue Sizes ----------------------------\\\n");
  printf("|               Instances               |  Pairs  |\n");
  printf("| REF IN    REF OUT | MON IN    MON OUT |         |\n");
  printf("|  %3u       %3u    |  %3u       %3u    |   %3u   |\n", 
        mp[REF].q_size[IN], 
        mp[REF].q_size[OUT],
        mp[MON].q_size[IN], 
        mp[MON].q_size[OUT],
        pair_q_size);
  printf("\\-------------------------------------------------/\n");

}

int initialise() {
  int error = 0;

  init_crc32();

  pair_load();

  if(verbosity > 3)
    printf("INFO: Finished Initialisation\n");
  return error;
}

void processArgs(int argc, char *argv[]){
  int user_set_max_packet_gap = 0;
  char c;
  while ((c = getopt(argc, argv, "hg:o:d:v:t:l:G:s:a:A:n:N:f:F:i:I:r:R:#:pcmb")) != -1 ) {
    switch (c) {
      case 'h': displayUsageInfo();
                exit(0);
                break;
      case 'f': mpoint_load(&mp[REF], file, optarg, REF);
                break;
      case 'F': mpoint_load(&mp[MON], file, optarg, MON);
                break;
      case 'i': mpoint_load(&mp[REF], live, optarg, REF);
		if (!user_set_max_packet_gap)
			max_packet_gap = MAX_PACKET_GAP_LIVE;
                break;
      case 'I': mpoint_load(&mp[MON], live, optarg, MON);
		if (!user_set_max_packet_gap)
			max_packet_gap = MAX_PACKET_GAP_LIVE;
                break;
      case 'r': mpoint_load(&mp[REF], remote, optarg, REF); break;
      case 'R': mpoint_load(&mp[MON], remote, optarg, MON); break;
      case 'p': options |= output_spt; break;
      case 'c': options |= output_pair_count; break;
      case 'm': options |= use_monitor_clock; break;
      case 'b': options |= use_firstpkt_time; break; //added by David Hayes
      case 'a': inet_aton(optarg, (struct in_addr *) &addr[REF]); break;
      case 'A': inet_aton(optarg, (struct in_addr *) &addr[MON]); break;
      case 'n': inet_aton(optarg, (struct in_addr *) &nat_addr[REF]); break;
      case 'N': inet_aton(optarg, (struct in_addr *) &nat_addr[MON]); break;
      case '#': hash_fields = atoi(optarg);
               // printf("type: %d", hash_fields);exit(0);printf("%s\n",optarg); 
                break;
      case 's': options |= run_slave; 
                loadSlave(optarg);
                break;
      case 'g': scale = atoi(optarg);
                break;
      case 'G': max_packet_gap = atoi(optarg);  // record.c, searchInstance();
		user_set_max_packet_gap = 1;
                break;
      case 'l': ts_len = atoi(optarg);
                break;
      case 't': timeout = atoi(optarg);
                break;
      case 'd': delta_t_max = atoi(optarg);
                break;
      case 'v': verbosity = atoi(optarg);
                break;
      case 'o': sec_offset = atoi(optarg);
                break;
      case '?':
             if (optopt == 'c')
               fprintf (stderr, "Option -%c requires an argument.\n", optopt);
             else if (isprint (optopt))
               fprintf (stderr, "Unknown option `-%c'.\n", optopt);
             else
               fprintf (stderr,
                        "Unknown option character `\\x%x'.\n",
                        optopt);
             exit(-1);
           default:
             abort ();
    }
  }
}

int main(int argc, char *argv[]){

  if(argc > 2 && argc < 5 ) {
    printf("ERROR: Too few arguements\n\n");
    displayUsageInfo();
    exit(EXIT_FAILURE);
  }

  processArgs(argc, argv);

  if(addr[REF] == 0 || addr[MON] == 0) {
    printf("ERROR: You must specify two valid IP addresses\n\n");
    displayUsageInfo();
    exit(EXIT_FAILURE);
  }
  else if(options & run_slave && mp[MON].dev == NULL) {
    printf("ERROR: When running in slave mode you must specify the capture interface with the -I option.\n\n");
    displayUsageInfo();
    exit(EXIT_FAILURE);
  }

  signal(SIGINT, sigintproc);

  //  Inits CRC32 and the TAILQ of packet pairs
  initialise();

  if(options & run_slave) {
    struct timeval diff, now;
    mpoint_start(&mp[MON]);

    while(!finished) {
      gettimeofday(&now, NULL);
      //lock
      timeval_subtract(&diff, &now, &lastSent);
      if(diff.tv_sec > 0) {
            if(verbosity & 1024) printf("@@@ Sending packet due to timeout\n");
        sendPacket();
      }
      //unlock
      usleep(250000); // wait a quater of a second
    }

    pthread_cancel(mp[MON].thread); // we are in live mode
    pthread_join(mp[MON].thread, NULL);
    mpoint_unload(&mp[MON]);
    cleanUp();
  }
  else {
    
    mpoint_start(&mp[REF]);
    mpoint_start(&mp[MON]);
   
    while(createPair() != -1){        //While we keep getting new pairs, keep going
      if(verbosity & 1)displayQueueSize();

    }

    if (mp[REF].type == live) {
	// make sure we escape from blocking i/o in live mode only
	// (assume that both are either file or live)
    	pthread_cancel(mp[REF].thread);
    	pthread_cancel(mp[MON].thread);
    }
    //printf("joining threads\n");
    pthread_join(mp[REF].thread, NULL);
    pthread_join(mp[MON].thread, NULL);
    //printf("unloading mpoints\n");
    mpoint_unload(&mp[REF]);
    mpoint_unload(&mp[MON]);
    cleanUp();
  }

  return EXIT_SUCCESS;
}

void sigintproc() {
  finished = 1;
  //exit(1);
}
void displayUsageInfo(){
                printf("Synthetic Packet Pairing Tool - 0.3.6\n\n");
                printf("Output: [pair count] timestamp rtt [spt]\n\n");
                printf("Offline file processing usage:\n");
                printf("\tspp -a <IP address> -A <IP address> -f <file>  -F <file>\n\t\t[ -# <hashcode> -p | -c | -m |  ]\n\n");
                printf("Live measurement usage:\n");
                printf("\tspp -a <IP address> -A <IP address> ( -i <interface> | -r <remote server address> )");
                printf("\n\t\t( -I <interface> | -R <remote server address> )\n\t\t[ -# <hashcode> | -g usec | -p | -c | -m ]\n\n");
                printf("Remote slave usage:\n");
                printf("\tspp -a <IP address> -A <IP address> -S <master address> -I <interface> \n\t\t");
                printf("[ -# <hashcode> | -g usec | -l no.bytes | -t seconds]\n\n");
                
                printf("General Options:\n");
                printf("\t-a IP address at the reference point\n");
                printf("\t-A IP address at the monitor point\n");
                printf("\t-n Natted IP address of the reference point\n");
                printf("\t-N Natted IP address of the monitor point\n");
                printf("\t-s Put into slave mode and send SSF to specified host\n");
                printf("\t-v Verbosity Level - see man page\n");
                printf("\t-d T Delta Maximum (seconds) - see Readme (default: %d)\n", DELTA_T_MAX);
                printf("\t-o Offset in seconds of the monitor point with respect to the reference point\n");
                printf("\t-G Maximum number of packets that will be searched to match a pair before giving up (default: %d)\n\n", MAX_PACKET_GAP);

                printf("Source options:\n");
                printf("\t-f File to be read for the reference point (PCAP format)\n");
                printf("\t-F File to be read for the monitor point (PCAP format)\n");
                printf("\t-i Reference point live capture interface\n");
                printf("\t-I Monitor point live capture interface\n\n");
    
                printf("Network Options:\n");
                printf("\t-l Length of remotely measured timestamps in bytes (default: 2)\n");
                printf("\t-g Granularity of remotely measured timestamps in microseconds (default: 100)\n");
                printf("\t-t Timeout - max time in seconds between updates from slave\n");

                printf("\nOutput options:\n");
                printf("\t-p Output 'Server Processing Times'\n");
                printf("\t-c Output 'Pair Count' \n");
                printf("\t-m Calculate timestamps from monitor point clock\n\n");
                printf("\t-b Use the timestamp of the first packet in the pair for the pair timestamp\n\n");

                printf("Packet Matching Options:\n");
                printf("\t-# <code> (default: 63)\n");
                printf("\tThe # option maybe used to set which fields are used in the packet matching process.\n");
                printf("\tThe value of <code> is the total of all the required field IDs as listed below:\n");
                printf("\tIP fields:\n\t\t\t1 Source Address\n\t\t\t2 Destination Address\n\t\t\t4 Protocol\n\t\t\t8 Identification\n");
                printf("\tTCP/UDP fields:\n\t\t\t16 Source Port\n\t\t\t32 Destination Port\n");
                printf("\tTCP fields:\n\t\t\t64 Sequence Number\n\t\t\t128 Acknowledgement Number\n\t\t\t256 Data offset, flags, window size\n\t\t\t512 Checksum, urgent pointer\n");
                printf("\tUDP Fields:\n\t\t\t1024 Length, checksum\n\t\t\t2048 Up to 12 bytes UDP data (limited by packet length)\n");
                printf("\tNot UDP/TCP:\n\t\t\t4096 Up to 20 bytes after IP header (limited by packet length)\n");

		printf("\n");
}




