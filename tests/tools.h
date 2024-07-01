/*
 * tools.c -- convenience tools for testing
 *
 * Copyright (c) 2023, NLnet Labs. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#ifndef TOOLS_H
#define TOOLS_H

// this is not safe to use in a production environment, but it's good enough
// for tests
char *get_tempnam(const char *dir, const char *prefix);

#endif // TOOLS_H
