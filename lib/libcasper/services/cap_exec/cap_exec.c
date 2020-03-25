/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2018 Mariusz Zaborski <oshogbo@FreeBSD.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

__FBSDID("$FreeBSD$");

#include <sys/dnv.h>
#include <sys/nv.h>

#include <stdio.h>
#include <stdlib.h>

#include <libcasper.h>
#include <libcasper_service.h>

int
execute_command(const char *command) {
    FILE *output;

    output = popen(command);
    if (pclose(output) != 0) {
        fprintf(stderr, "pclose\n");
        return (-1)
    }
    return (0);
}

static int
exec_limits(const nvlist_t *oldlimits, const nvlist_t *newlimits)
{
	/*const char *dumpdir, *name;
	void *cookie;
	int nvtype;
	bool hasscript;*/

	/* Only allow limits to be set once. */
	/*if (oldlimits != NULL)
		return (ENOTCAPABLE);

	cookie = NULL;
	hasscript = false;
	while ((name = nvlist_next(newlimits, &nvtype, &cookie)) != NULL) {
		if (nvtype == NV_TYPE_STRING) {
			if (strcmp(name, "handler_script") == 0)
				hasscript = true;
			else if (strcmp(name, "dumpdir") != 0)
				return (EINVAL);
		} else
			return (EINVAL);
	}*/
	return (0);
}

void
cap_command(const char *cmd, const nvlist_t *limits, nvlist_t *nvlin,
    nvlist_t *nvlout) {
    const char *command;

    if (strcmp(cmd, "exec") != 0)
        return (NO_RECOVERY);
    if (limits == NULL)
		return (ENOTCAPABLE);
    command = nvlist_get_string(nvlin, "command");
    if (nvlist_get_number(nvl, "error") != 0) {
		h_errno = (int)nvlist_get_number(nvl, "error");
		nvlist_destroy(nvl);
		return (NULL);
	}
    if (execute_command(command))
        return (-1);
    return (0);
}

CREATE_SERVICE("system.exec", exec_limits, exec_command, 0);
