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

    $Id: pair.h 171 2015-05-20 05:58:54Z szander $
 
 */

#ifndef PAIR_H
#define PAIR_H
typedef struct Pair {
        
        /*
         * Points to both packets. [IN] and [OUT], which refer
         * to a packet going frrom the REFerence point, to the 
         * MON (remote) point, and the packet going back the 
         * other direction
         *
         * Note - the out packet is Ref to mon, and the in packet
         * is mon to ref. 
         *
         * */
        record_t * rec[2];

        /*
         * The difference between the time meansurements at REF
         * from the IN and the OUT packet. 
         * */
        struct timeval rtt;

        /*
         * The difference between the tiem measurements at MON
         * from the IN and the OUT packet (ie, the turnaround
         * time between receive and sending a reply packet at
         * the remote end)
         * */
        struct timeval spt;

        /*
         * The timestamp that the pair is considered to have 
         * been observed at. If the -b flag is set, it is the 
         * timestamp for the OUT packet at the REF (local) 
         * point
         * */
        struct timeval ts;

        TAILQ_ENTRY(Pair) entries;
} pair_t;


void pair_load();
void pair_unload();
int createPair();


#endif
