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

    $Id: timeval.c 160 2013-08-16 01:15:19Z szander $
 
 */

#include <sys/time.h>
#include "timeval.h"
/* 

   Subtract the `struct timeval' values X and Y,
   storing the result in RESULT.
 */

void timeval_subtract(struct timeval *result, const struct timeval  *x, const struct timeval  *y1)
{
    struct timeval y;
    y = *y1;
  /* Perform the carry for the later subtraction by updating y. */
  if (x->tv_usec < y.tv_usec) {
    int nsec = (y.tv_usec - x->tv_usec) / 1000000 + 1;
    y.tv_usec -= 1000000 * nsec;
    y.tv_sec += nsec;
  }
  if (x->tv_usec - y.tv_usec > 1000000) {
    int nsec = (x->tv_usec - y.tv_usec) / 1000000;
    y.tv_usec += 1000000 * nsec;
    y.tv_sec -= nsec;
  }

  /* Compute the time remaining to wait.
     tv_usec is certainly positive. */
  result->tv_sec = x->tv_sec - y.tv_sec;
  result->tv_usec = x->tv_usec - y.tv_usec;
}


void timeval_halve(struct timeval *result, const struct timeval * x) {

  result->tv_sec = x->tv_sec / 2;   // whole seconds

  // If tv_sec is an odd number, we need to add a half second
  // to the usec value
  result->tv_usec = (x->tv_sec % 2) * HALF_SECOND_IN_MICRO_SECONDS; 
  result->tv_usec += x->tv_usec / 2; // u seconds
}
/*
unsigned int timeval_diff_ms(const struct timeval x, const struct timeval y) {

  unsigned int ms_diff = 0;
  struct timeval tv_diff;

  timeval_subtract(&tv_diff, &x, &y);

  ms_diff = 1000 * tv_diff.tv_sec;                    // Every second is 1000 milliseconds - add that on
  ms_diff += tv_diff.tv_usec / 1000;                   // usec / 1000 = msec - add them on
  if(tv_diff.tv_usec % 1000 > 500)                    // If we need to round up
    ms_diff++;
  return ms_diff;
}
*/

// Return 1 if x < y, 0 otherwise
//
int timeval_chronological(struct timeval * x, struct timeval * y) {

  if(y->tv_sec > x->tv_sec)
    return 1;
  if(y->tv_sec == x->tv_sec && y->tv_usec > x->tv_usec) 
    return 1;
  return 0;
}

