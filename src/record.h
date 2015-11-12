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

    $Id: record.h 160 2013-08-16 01:15:19Z szander $
 
 */

#ifndef RECORD_H
#define RECORD_H
#include "spptool.h"
typedef struct Record {
	uint32_t pkt_id;
	struct timeval ts[2];
        TAILQ_ENTRY(Record) entries;
} record_t;


record_t * createRecord(direction_t direction);

#endif
