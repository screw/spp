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
 
    $Id: slave.h 171 2015-05-20 05:58:54Z szander $
 
 */

PUBLIC void loadSlave(const char * name);
PUBLIC int runSlave(monitor_point_t * mpoint);
PUBLIC void sendPacket();
PUBLIC void sendHashes(const struct pcap_pkthdr *pcap_hdr, const u_char *pkt, direction_t direction);



