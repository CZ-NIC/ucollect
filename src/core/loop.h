#ifndef UCOLLECT_LOOP_H
#define UCOLLECT_LOOP_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

struct loop;
struct loop_configurator;

struct plugin;
struct context;
struct uplink;

struct epoll_handler {
	void (*handler)(void *data, uint32_t events);
};

struct loop *loop_create() __attribute__((malloc));
// Warning: This one is not reentrant, due to signal handling :-(
void loop_run(struct loop *loop) __attribute__((nonnull));
void loop_break(struct loop *loop) __attribute__((nonnull));
void loop_destroy(struct loop *loop) __attribute__((nonnull));

/*
 * Get statistics of the interfaces of the loop.
 *
 * It returns an array allocated from the temporary memory pool.
 * First, there's number of interfaces. Then, each iterface has 3 items:
 * (received, dropped, dropped by interface driver).
 *
 * In case the statistics for an interface fail, all the three items of it
 * are set to maximum value.
 */
size_t *loop_pcap_stats(struct context *context) __attribute__((nonnull)) __attribute__((malloc));
/*
 * When you want to configure the loop, you start by loop_config_start. You get
 * a handle to the configurator. You can then call loop_add_pcap, loop_pcap_add_address and
 * loop_add_plugin functions with it. After you are done, you call loop_config_commit,
 * which will make the changes available.
 *
 * You can call loop_config_abort instead, which will throw out all the changes.
 *
 * The whole operation (from _start to _commit or _abort) must happen at once, before
 * any callback or so is left.
 *
 * You need to list all the plugins, addresses, etc. that should be available in the
 * new configuration. The ones that were available in the old config are copied over
 * (not initialized again). The new ones are created and the old ones removed on the
 * commit.
 */
struct loop_configurator *loop_config_start(struct loop *loop) __attribute__((nonnull)) __attribute__((malloc));
void loop_config_commit(struct loop_configurator *configurator) __attribute__((nonnull));
void loop_config_abort(struct loop_configurator *configurator) __attribute__((nonnull));

bool loop_add_pcap(struct loop_configurator *configurator, const char *interface) __attribute__((nonnull));
// Add a local address for the last added pcap interface. Can be net address (eg. 192.168.0.0/16).
bool loop_pcap_add_address(struct loop_configurator *configurator, const char *address) __attribute__((nonnull));
// Add a plugin. Provide the name of the library to load.
bool loop_add_plugin(struct loop_configurator *configurator, const char *plugin) __attribute__((nonnull));
/*
 * Reinitialize the current plugin. Must not be called from outside of a plugin.
 *
 * It'll not return to the plugin, the plugin will be terminated at that moment.
 */
void loop_plugin_reinit(struct context *context) __attribute__((nonnull)) __attribute__((noreturn));

const char *loop_plugin_get_name(const struct context *context) __attribute__((nonnull)) __attribute__((const));
/*
 * Set the uplink used by this loop. This may be called at most once on
 * a given loop.
 */
void loop_uplink_set(struct loop *loop, struct uplink *uplink) __attribute__((nonnull));
// Called by the uplink when connection is made
void loop_uplink_connected(struct loop *loop) __attribute__((nonnull));
// Called by the uplink when connection is lost
void loop_uplink_disconnected(struct loop *loop) __attribute__((nonnull));

// Register a file descriptor for reading & closing events. Removed on close.
void loop_register_fd(struct loop *loop, int fd, struct epoll_handler *handler) __attribute__((nonnull));

/*
 * Create a new memory pool.
 *
 * The pool will be destroyed with the loop or whith the owner of current context,
 * whatever happens first. The current context may be NULL, which means it's out
 * of plugin context (eg. from the framework).
 */
struct mem_pool *loop_pool_create(struct loop *loop, struct context *current_context, const char *name) __attribute__((nonnull(1, 3))) __attribute__((malloc));
// Get a pool that lives for the whole life of the loop
struct mem_pool *loop_permanent_pool(struct loop *loop) __attribute__((nonnull)) __attribute__((pure));
// Get a temporary pool that may be freed any time the control returns to main loop
struct mem_pool *loop_temp_pool(struct loop *loop) __attribute__((nonnull)) __attribute__((pure));

/*
 * Send some data from uplink to a plugin. Plugin is specified by name.
 * Returns true if the plugin exists, false if not.
 */
bool loop_plugin_send_data(struct loop *loop, const char *plugin, const uint8_t *data, size_t length) __attribute__((nonnull));

/*
 * Have a function called after given number of milliseconds.
 * Context may be NULL in case this is called by something else than a plugin.
 * It returns an id that is then passed to the callback. It can also be used to cancel the timeout
 * before it happens.
 *
 * The timeouts are not expected to happen often, so this function is not very optimised.
 */
size_t loop_timeout_add(struct loop *loop, uint32_t after, struct context *context, void *data, void (*callback)(struct context *context, void *data, size_t id)) __attribute__((nonnull(1)));
// Cancel a timeout. It must not have been called yet.
void loop_timeout_cancel(struct loop *loop, size_t id) __attribute__((nonnull));

#endif
