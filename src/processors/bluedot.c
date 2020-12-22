/* $Id$ */
/*
** Copyright (C) 2009-2020 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2009-2020 Champ Clark III <cclark@quadrantsec.com>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>

#include "jae.h"
#include "jae-defs.h"
#include "rules.h"
#include "debug.h"

#include "processors/bluedot.h"

struct _Rules *Rules;
struct _Debug *Debug;



bool Bluedot( uint32_t rule_position, uint8_t s_position, char *json )
{

    unsigned char ip_convert[MAX_IP_BIT_SIZE] = { 0 };

    /* If we have "NOT_FOUND", we can skip this */

    if ( json[0] == 'N' )
        {
            return(false);
        }

    /* Check IP TTL for Bluedot */

    if ( Rules[rule_position].bluedot_type[s_position] == BLUEDOT_TYPE_IP )
        {

            IP_2_Bit(json, ip_convert);

            if ( Is_Not_Routable(ip_convert) || !strcmp(json, "0.0.0.0" ) )
                {

                    if ( Debug->bluedot )
                        {
                            JAE_Log(DEBUG, "[%s, line %d] %s is RFC1918, link local or invalid.", __FILE__, __LINE__, json);
                        }

                    return(false);
                }

            /* Is it in skiplist? */

            printf("Would lookup %s\n", json);
        }

    /* Do cache lookup */

    /* Add IP to "queue" */



//printf("In BLUEDOT: %s\n", json);

}
