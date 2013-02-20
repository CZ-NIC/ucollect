#ifndef UCOLLECT_UPLINK_H
#define UCOLLECT_UPLINK_H

#include <stdint.h>

struct uplink;
struct loop;

/*
 * Create and connect an uplink. It is expected to be called only once on a given loop.
 *
 * The remote_name and service represent the machine and port to connect to. It can
 * be numerical address and port, or DNS and service name.
 */
struct uplink *uplink_create(struct loop *loop, const char *remote_name, const char *service) __attribute__((malloc)) __attribute__((nonnull));
/*
 * Disconnect and destroy an uplink. It is expected to be called just before the loop
 * is destroyed.
 */
void uplink_destroy(struct uplink *uplink) __attribute__((nonnull));

#endif
