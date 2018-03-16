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

    $Id: spptool.h 175 2015-05-21 00:30:20Z szander $
 
 */

#ifndef SPPTOOL_H
#define SPPTOOL_H

#define PRIVATE static
#define PUBLIC

#ifndef CONFIG
#include "config.h"
#endif


// Number of measure points
#define MP_COUNT 2
#define SDF 4


typedef enum DIR_TYPE {IN = 0, OUT = 1} direction_t;
typedef enum MON_ID_TYPE {REF = 0, MON = 1} mp_id_t;
// added use_firstpkt_time option --- David Hayes
typedef enum OPTIONS_TYPE {

    /*
     * Output the server processing time as a part of 
     * the normal SPP output line
     * */
    output_spt = 1,

    /*
     * Output the pair count figure when SPP finishes 
     * running
     * */
    output_pair_count = 2, 
    use_monitor_clock = 16,

    /* 
     * When determining what time the RTT occured at, 
     * use the timestamp of the first packet instead
     * of subtracting half of the RTT from the second
     * packet timestamp. -b CLI flag.
     * */
    use_firstpkt_time = 32,  
    run_slave = 256,
    
    /*
     * Append 'fake' (uncorrected) OWD in each direction to each RTT line, e.g.
     *          [<paircnt>] <timestamp> <RTT> [<spt>] OWDref2mon OWDmon2ref
     * Note: The OWD are uncorrected in that we make no adjustment for clock
     * offsets between REF and MON. This option is useful to track *relative*
     * changes in OWD in each direciton, rather than infer anything about absolute OWDs.
     * */
    output_fakeowd = 512,
    
     /*
     * When set: compile and activate a pcap filter rule such that only packets
     * travelling between the nominated IP endpoints are passed to spp's processing loop.
     * Pros: May improve performance.
     * Cons: Implicitly limits us to seeing DLT_EN10MB frames, which precludes
     * parsing .pcap files that contain other frame types recognised by instance.c:createInstance(),
     * such as DLT_NULL or DLT_PPP frames.
     * This flag is unset by default (for maximum versatility).
     * */
    use_pcap_filter = 1024

} options_t;


typedef enum TS_CODE {ABSOLUTE = 0, OFFSET_1 = 1, OFFSET_2 = 2, OFFSET_3 = 3, OFFSET_4 = 4} ts_code_t;

typedef enum STATUS_TYPE {OK = 0, FILE_END = 1} status_t; //CHECK THIS HACK

#endif
