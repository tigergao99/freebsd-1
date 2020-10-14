/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2020 The FreeBSD Foundation
 *
 * This software was developed by Tiger Gao under sponsorship from
 * the FreeBSD Foundation.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/capsicum.h>
#include <sys/dnv.h>
#include <sys/errno.h>
#include <sys/nv.h>

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libcasper.h>
#include <libcasper_service.h>

#include "cap_exec.h"

int
cap_exec_init(cap_channel_t *chan, int count, const char **arr)
{
	nvlist_t *allowed_programs;
	int i;

	allowed_programs = nvlist_create(0);
	for(i = 0; i < count; i++) {
		nvlist_add_null(allowed_programs, arr[i]);
	}
	if (cap_limit_set(chan, allowed_programs) < 0) {
		return (-1);
	}
	return (0);
}

int
cap_exec(cap_channel_t *chan, const char *command) 
{
	nvlist_t *nvl;
	int error, fd;

	nvl = nvlist_create(0);
	nvlist_add_string(nvl, "cmd", "exec");
	nvlist_add_string(nvl, "command", command);
	nvl = cap_xfer_nvlist(chan, nvl);
	if (nvl == NULL) {
		return (-1);
	}
	error = (int)dnvlist_get_number(nvl, "error", 0);
	fd = dnvlist_take_descriptor(nvl, "filedesc", -1);
	nvlist_destroy(nvl);
	if (error != 0) {
		if (fd != -1) {
			close(fd);
			fd = -1;
		}
		errno = error;
	}
	return (fd);
}

static int
exec_limits(const nvlist_t *oldlimits, const nvlist_t *newlimits) 
{
	
	/* only allow limit to be set once */
	if (oldlimits != NULL)
		return (ENOTCAPABLE);
	(void) newlimits;
	return (0);
}

static int
exec_command(const char *cmd, const nvlist_t *limits, nvlist_t *nvlin,
    nvlist_t *nvlout) 
{
	const char *command;
	char *prog;
	int fd;
	bool allowed;

	if (strncmp(cmd, "exec", 4) != 0)
		return (EINVAL);
	if (limits == NULL)
		return (ENOTCAPABLE);
	
	command = nvlist_get_string(nvlin, "command");

	/* parse executable */
	char buf[strlen(command) + 1];
	strncpy(buf, command, sizeof(buf));
	prog = strtok(buf, " ");

	/* Check if program in allowed set */
	allowed = nvlist_exists_null(limits, prog);
	if (!allowed)
		return (ENOTCAPABLE);
	fd = fileno(popen(command, "r+"));
	nvlist_move_descriptor(nvlout, "filedesc", fd);
	return (0);
}

CREATE_SERVICE("system.exec", exec_limits, exec_command, 0);
