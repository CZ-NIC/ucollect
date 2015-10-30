/*
    Ucollect - small utility for real-time analysis of network data
    Copyright (C) 2015 CZ.NIC, z.s.p.o. (http://www.nic.cz/)

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#ifndef UCOLLECT_FWUP_QUEUE_H
#define UCOLLECT_FWUP_QUEUE_H

struct queue;

struct context;

/*
 * Create a queue for the commands. It will manage
 * running the ipset command and feed commands to it.
 *
 * The structure is allocated from the context's permanent
 * pool. It is not expected to be destroyed during the lifetime
 * of the plugin.
 *
 * The ipset command is launched on-demand when data are
 * set to it. It is stopped either by explicit flush or
 * by a short timeout.
 */
struct queue *queue_alloc(struct context *context) __attribute__((nonnull)) __attribute__((malloc)) __attribute__((returns_nonnull));
/*
 * Enqueue another command. The ipset command is launched
 * or previous one is reused. Due to internal OS buffering,
 * the command may be delayed for several seconds, but not
 * after flush is performed.
 */
void enqueue(struct context *context, struct queue *queue, const char *command) __attribute__((nonnull));
/*
 * Make sure there are no more waiting commands (close
 * the ipset command if there's one kept running).
 */
void queue_flush(struct context *context, struct queue *queue) __attribute__((nonnull));

/*
 * Callback for when there are data on our FD.
 */
void queue_fd_data(struct context *context, int fd, void *userdata) __attribute__((nonnull));

#endif
