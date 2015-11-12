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

    $Id: timeval.h 160 2013-08-16 01:15:19Z szander $
 
 */

#ifndef TIMEVAL_H
#define TIMEVAL_H


#define HALF_SECOND_IN_MICRO_SECONDS 500000

//void timeval_subtract(struct timeval *result, struct timeval  *x, struct timeval  *y);
void timeval_subtract(struct timeval *result, const struct timeval  *x, const struct timeval  *y1);
void timeval_halve(struct timeval *result, const struct timeval * x) ;
int timeval_chronological(struct timeval * x, struct timeval * y);
#endif

