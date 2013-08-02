#ifndef UCOLLECT_CONFIGURE_H
#define UCOLLECT_CONFIGURE_H

#include <stdbool.h>

struct loop;

/*
 * Set the configuration directory. Not copied, should be preserved for the
 * whole lifetime of the program.
 */
void config_set_dir(const char *dir);
bool load_config(struct loop *loop);

#endif
