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

/* lockfile.c
 *
 * Creates a lock file for the Sagan process.    We don't want Sagan to be
 * running more than once.  Also does a simple 'test' to see if the PID
 * in the lock file is 'running' (via kill -0).   Wrote this to decrease
 * the dependancies of Sagan,  as opposed to using liblockfile.
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif


#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pthread.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <pwd.h>
#include <stdbool.h>

//#include "sagan.h"
//#include "sagan-defs.h"
#include "sagan-ng-defs.h"
#include "util.h"
#include "lockfile.h"
#include "sagan-config.h"
//#include "signal-handler.h"

#include "version.h"

struct _Config *Config;


/* Was using liblockfile but decided for portability reasons, it was a
 * bad idea */

void CheckLockFile ( void )
{

    char buf[10];
    FILE *lck;
    int pid;
    struct stat lckcheck;
    struct stat st = {0};
    struct passwd *pw = NULL;

    int ret = 0;

    pw = getpwnam(Config->runas);

    if (!pw)
        {
            Sagan_Log(ERROR, "Couldn't locate user '%s'. Aborting...", Config->runas);
        }

    /* Check for lockfile first */

    if (stat(Config->lock_file, &lckcheck) == 0 )
        {

            /* Lock file is present,  open for read */

            if (( lck = fopen(Config->lock_file, "r" )) == NULL )
                {
                    Sagan_Log(ERROR, "[%s, line %d] Lock file '%s' is present but can't be read [%s]", __FILE__, __LINE__, Config->lock_file, strerror(errno));
                }
            else
                {
                    if (!fgets(buf, sizeof(buf), lck))
                        {
                            Sagan_Log(ERROR, "[%s, line %d] Lock file (%s) is open for reading,  but can't read contents.", __FILE__, __LINE__, Config->lock_file);
                        }

                    fclose(lck);
                    pid = atoi(buf);

                    if ( pid == 0 )
                        {
                            Sagan_Log(ERROR, "[%s, line %d] Lock file read but pid value is zero.  Aborting.....", __FILE__, __LINE__);
                        }

                    /* Check to see if process is running.  We use kill with 0 signal
                     * to determine this.  We check this return value.  Signal 0
                     * won't affect running processes */

                    if ( kill(pid, 0) != -1 )
                        {
                            Sagan_Log(ERROR, "[%s, line %d] It appears that Sagan is already running (pid: %d).", __FILE__, __LINE__, pid);
                        }
                    else
                        {

                            Sagan_Log(NORMAL, "[%s, line %d] Lock file is present,  but Sagan isn't at pid %d (Removing stale %s file)", __FILE__, __LINE__, pid, Config->lock_file);

                            if (unlink(Config->lock_file))
                                {
                                    Sagan_Log(ERROR, "Unable to delete %s. ", Config->lock_file);
                                }
                        }
                }

        }
    else
        {

            /* Check if the lockfile/lockpath is made || attempt to make it */

            if (stat(Config->lock_file_path, &st) == -1)
                {

                    /* Make lockfile with reasonable permissions */

                    if ( mkdir(Config->lock_file_path, 0755) == -1 )
                        {
                            Sagan_Log(ERROR, "[%s, line %d] Cannot create lock file directory (mkdir %s - %s)", __FILE__, __LINE__, Config->lock_file_path, strerror(errno));
                        }

                    /* Make sure the directory is readable */

                    ret = chown(Config->lock_file_path, (unsigned long)pw->pw_uid,(unsigned long)pw->pw_gid);

                    if ( ret < 0 )
                        {
                            Sagan_Log(ERROR, "[%s, line %d] Cannot change ownership of %s to username \"%s\" - %s", __FILE__, __LINE__, Config->lock_file_path, Config->runas, strerror(errno));
                        }


                }

            /* No lock file present, so create it */

            if (( lck = fopen(Config->lock_file, "w" )) == NULL )
                {
                    Sagan_Log(ERROR, "[%s, line %d] Cannot create lock file (%s - %s)", __FILE__, __LINE__, Config->lock_file, strerror(errno));
                }
            else
                {

                    /* Write PID */

                    fprintf(lck, "%d", getpid() );
                    fflush(lck);
                    fclose(lck);

                    /* Change lockfile ownership (so we can work with it on exit) */

                    ret = chown(Config->lock_file, (unsigned long)pw->pw_uid,(unsigned long)pw->pw_gid);

                    if ( ret < 0 )
                        {
                            Sagan_Log(ERROR, "[%s, line %d] Cannot change ownership of %s to username \"%s\" - %s", __FILE__, __LINE__, Config->lock_file, Config->runas, strerror(errno));
                        }

                    /* Let other programs have access to the lockfile */

                    ret = chmod (Config->lock_file, 0644 );

                    if ( ret < 0 )
                        {
                            Sagan_Log(ERROR, "[%s, line %d] Cannot change permissions of %s to username \"%s\" - %s", __FILE__, __LINE__, Config->lock_file, Config->runas, strerror(errno));

                        }

                }
        }
}

void Remove_Lock_File ( void )
{

    struct stat lckcheck;

    if ((stat(Config->lock_file, &lckcheck) == 0) && unlink(Config->lock_file) != 0 )
        {
            Sagan_Log(ERROR, "[%s, line %d] Cannot remove lock file (%s - %s)\n", __FILE__, __LINE__, Config->lock_file, strerror(errno));
        }
}
