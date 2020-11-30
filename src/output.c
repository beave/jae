/* $Id$ */
/*
** Copyright (C) 2020 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2020 Champ Clark III <cclark@quadrantsec.com>
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
#include <stdlib.h>

#include "sagan-ng-defs.h"
#include "sagan-ng.h"
#include "sagan-config.h"

#include "parsers/json.h"

#include "output.h"
#include "output-plugins/file.h"

struct _Config *Config;

void Init_Output ( void )
{

    if ( Config->output_file_flag == true )
        {
            File_Init();
        }


}

void Output( struct _JSON_Key_String *JSON_Key_String, uint16_t json_count, uint32_t rule_position )
{

    if ( Config->output_file_flag == true )
        {
//		printf("**** FIRE ****** on %s:%s\n", Config->sensor_name, Config->cluster_name);
            File( JSON_Key_String, json_count, rule_position );
        }

}
