#ifndef UCOLLECT_UTIL_H
#define UCOLLECT_UTIL_H

void die(const char *format, ...) __attribute__((format(printf, 1, 2))) __attribute__((noreturn));

#endif
