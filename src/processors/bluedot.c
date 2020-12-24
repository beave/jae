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
#include <time.h>
#include <pthread.h>

#include "jae.h"
#include "jae-defs.h"
#include "jae-config.h"
#include "rules.h"
#include "debug.h"
#include "counters.h"

#include "processors/bluedot.h"

struct _Rules *Rules;
struct _Debug *Debug;
struct _Config *Config;
struct _Counters *Counters;
struct _Bluedot_Skip *Bluedot_Skip;

pthread_mutex_t JAE_DNS_Mutex=PTHREAD_MUTEX_INITIALIZER;

struct _Bluedot_IP_Queue *BluedotIPQueue = NULL;

bool bluedot_dns_global = 0;

void Bluedot_Init( void )
{

    /* IP Queue */

    if ( Config->processor_bluedot_ip_queue > 0 )
        {

            BluedotIPQueue = malloc(Config->processor_bluedot_ip_queue * sizeof(struct _Bluedot_IP_Queue));

            if ( BluedotIPQueue == NULL )
                {
                    JAE_Log(ERROR, "[%s, line %d] Failed to allocate memory for _Bluedot_IP_Queue. Abort!", __FILE__, __LINE__);
                }

            memset(BluedotIPQueue, 0, Config->processor_bluedot_ip_queue * sizeof(_Bluedot_IP_Queue));
        }

}


bool Bluedot( uint32_t rule_position, uint8_t s_position, char *json )
{

    char timet[20] = { 0 };
    time_t t;
    struct tm *now=NULL;

    t = time(NULL);
    now=localtime(&t);
    strftime(timet, sizeof(timet), "%s",  now);

    uint64_t epoch_time = atol(timet);

    uint64_t i = 0;

    /* If we have "NOT_FOUND", we can skip this */

    if ( json[0] == 'N' )
        {
            return(false);
        }

    /* Check DNS TTL,  do lookup if nessesary */
    /* DO LOOKUP in jae-config.c ( at start up !) */

    if ( bluedot_dns_global == 0 && epoch_time - Config->processor_bluedot_dns_last_lookup > Config->processor_bluedot_dns_ttl )
        {

            if ( Debug->bluedot )
                {
                    JAE_Log(DEBUG, "[%s, line %d] Bluedot host TTL of %d seconds reached.  Doing new lookup for '%s'.", __FILE__, __LINE__, Config->processor_bluedot_dns_ttl, Config->processor_bluedot_host);
                }

            char tmp_host[255] = { 0 };

            pthread_mutex_lock(&JAE_DNS_Mutex);
            bluedot_dns_global = true;

            bool results = false;

            results = DNS_Lookup(Config->processor_bluedot_host, tmp_host, sizeof(tmp_host));

            if ( results == false && Config->processor_bluedot_ip[0] != '\0')
                {
                    JAE_Log(WARN, "[%s, line %d] Cannot lookup DNS for '%s'. Using old value of %s.", __FILE__, __LINE__, Config->processor_bluedot_host, Config->processor_bluedot_ip);

                }
            else
                {

                    strlcpy(Config->processor_bluedot_ip, tmp_host, sizeof(Config->processor_bluedot_ip));

                    if ( Debug->bluedot )
                        {
                            JAE_Log(DEBUG, "[%s, line %d] Bluedot host IP is now: %s", __FILE__, __LINE__, Config->processor_bluedot_ip);
                        }

                }

            Config->processor_bluedot_dns_last_lookup = epoch_time;
            bluedot_dns_global = false;
            pthread_mutex_unlock(&JAE_DNS_Mutex);

        } /* end of DNS lookup */

    if ( Rules[rule_position].bluedot_type[s_position] == BLUEDOT_TYPE_IP )
        {

            unsigned char ip_convert[MAX_IP_BIT_SIZE] = { 0 };

            IP_2_Bit(json, ip_convert);

            /* Don't look up non-routed stuff */

            if ( Is_Not_Routable(ip_convert) || !strcmp(json, "0.0.0.0" ) )
                {

                    if ( Debug->bluedot )
                        {
                            JAE_Log(DEBUG, "[%s, line %d] %s is RFC1918, link local or invalid.", __FILE__, __LINE__, json);
                        }

                    return(false);
                }

            /* Skip anything in skip network array */

            for ( i = 0; i < Counters->processor_bluedot_skip; i++ )
                {

                    if ( Is_In_Range(ip_convert, (unsigned char *)&Bluedot_Skip[i].range, 1) )
                        {

                            if ( Debug->bluedot )
                                {
                                    JAE_Log(DEBUG, "[%s, line %d] IP address %s is in Bluedot 'skip_networks'. Skipping lookup.", __FILE__, __LINE__, json);
                                }

                            return(false);
                        }

                }

            printf("Would add %s to queue\n", json);

            /* DEBUG: Add to queue */
            /* DEBUG: Setup "lookup" */

        }


}
