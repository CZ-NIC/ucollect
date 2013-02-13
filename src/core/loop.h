#ifndef UCOLLECT_LOOP_H
#define UCOLLECT_LOOP_H

struct loop;

struct loop *loop_create() __attribute__((malloc));
void loop_run(struct loop *loop) __attribute__((nonnull));
void loop_break(struct loop *loop) __attribute__((nonnull));
void loop_destroy(struct loop *loop) __attribute__((nonnull));

#endif
