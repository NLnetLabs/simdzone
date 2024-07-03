/*
 * tools.c -- convenience tools for testing
 *
 * Copyright (c) 2023, NLnet Labs. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#if _WIN32
#include <process.h>
#include <sys/types.h>
#include <sys/stat.h>

#if !defined(S_ISDIR) && defined(S_IFMT) && defined(S_IFDIR)
# define S_ISDIR(m) (((m) & S_IFMT) == S_IFDIR)
#endif
#else
#include <unistd.h>
#include <sys/stat.h>
#endif

#include "diagnostic.h"

static bool is_dir(const char *dir)
{
  struct stat sb;
  if (stat(dir, &sb) == 0 && S_ISDIR(sb.st_mode))
    return true;
  return false;
}

static const char *get_tmpdir(const char *dir)
{
  const char *tmpdir = NULL;

#if _WIN32
diagnostic_push()
msvc_diagnostic_ignored(4996)
  tmpdir = getenv("TMP");
diagnostic_pop()
#else
  tmpdir = getenv("TMPDIR");
#endif
  if (is_dir(tmpdir))
    return tmpdir;
  if (dir && is_dir(tmpdir))
    return dir;
#if defined(P_tmpdir)
  if (is_dir(P_tmpdir))
    return P_tmpdir;
#elif !_WIN32
  if (is_dir("/tmp"))
    return "/tmp";
#endif
  return NULL;
}

char *get_tempnam(const char *dir, const char *pfx)
{
  const char *tmpdir = get_tmpdir(dir);
  if (!tmpdir)
    return NULL;

  static unsigned int count = 0;
  unsigned int pid;

diagnostic_push()
msvc_diagnostic_ignored(4996)
  pid = (unsigned int)getpid();
diagnostic_pop()

  srand(pid + count++);

  for (unsigned int i = 0; i < 1000; i++) {
    char tmp[16];
    int rnd = rand();
    int len = snprintf(tmp, sizeof(tmp), "%s/%s.%d", tmpdir, pfx, rnd);
    assert(len >= 0);
    char *tmpfile = malloc((unsigned int)len + 1);
    if (!tmpfile)
      return NULL;
    (void)snprintf(tmpfile, (unsigned int)len + 1, "%s/%s.%d", tmpdir, pfx, rnd);
    struct stat sb;
    if (stat(tmpfile, &sb) == -1)
      return tmpfile;
    free(tmpfile);
  }

  return NULL;
}
