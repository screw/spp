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
  
    $Id: config.h 160 2013-08-16 01:15:19Z szander $
 
 */

/* SPP Configuration File */

/* Max length of RTP frames
 * Maximum size in bytes that a slave will send to a master */
#define MAX_PKT_LEN 1400

/* Time in microseconds to sleep before trying to create a record again (when a record could not be created)
 * If reading from a file 1/100 of this value is used */
#define TRYAGAIN_DELAY 1000000

/* When creating records - default maximum time difference between an instance that is trying to be matched at one 
 * end and the time of the current instance at the other end (in seconds). Refer to SPP algorithm reference: 
 * http://caia.swin.edu.au/reports/060707A/CAIA-TR-060707A.pdf  */
#define DELTA_T_MAX 60 

/* When searching for a match of a packet seen at the monitor point, by default we search at most this number of 
 * packets seen at the reference point.
 */
#define MAX_PACKET_GAP 10000

/*
 * Set the default packet gap much lower for live capture.
 */
#define MAX_PACKET_GAP_LIVE 500

/*  Amount of extra information printed to the console.. used for testing.
 *  Combinations are allowed eg. 12 is Pair and Record info
 *  1 Queue Size
 *  2 Thread Details
 *  4 Pair Info
 *  8 Record Info
 *  16 Instance Infot
 *  32 Packet Info
 *  64 RTT COUNT - "checksum"
 *  128 Network Details
 *  1024 Verbose Network Details
 */
#define DEBUG_LEVEL 104

/* Maximum length of data from which to create ID hashes
 */
#define HASH_DATA_LENGTH 50

/* Port used for network transmission
 */
#define PORT 9822

