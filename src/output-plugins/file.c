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
#include <errno.h>

#include "jae-defs.h"
#include "jae.h"
#include "jae-config.h"
#include "rules.h"
#include "lockfile.h"

#include "parsers/json.h"

struct _Config *Config;


void File_Init( void )
{

    if (( Config->output_file_stream = fopen(Config->output_file, "a" )) == NULL )
        {
            Remove_Lock_File();
            JAE_Log(ERROR, "[%s, line %d] Can't for 'file' output %s - %s. Abort.", __FILE__, __LINE__, Config->output_file, strerror(errno));
        }

    JAE_Log(NORMAL, "Successfully open %s for 'file' output.", Config->output_file);


}

void File( struct _JSON_Key_String *JSON_Key_String, uint16_t json_count, uint32_t rule_position )
{

    uint16_t i = 0;
    /*
        printf("------------------------------------------\n");

        for (i = 0; i < json_count; i++ )
            {
                printf("%s|%s\n", JSON_Key_String[i].key, JSON_Key_String[i].json);
            }

      printf("------------------------------------------\n");
      */


}
