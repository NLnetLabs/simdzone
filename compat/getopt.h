/*
 * getopt.h -- some useful comment
 *
 * Copyright (c) 2023, NLnet Labs. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#ifndef GETOPT_H
#define GETOPT_H

extern int opterr;
extern int optind;
extern int optopt;
extern char *optarg;

int getopt(int argc, char **argv, const char *opts);

#endif /* GETOPT_H */
