/* libunwind - a platform-independent unwind library
   Copyright (c) 2004-2005 Hewlett-Packard Development Company, L.P.
        Contributed by David Mosberger-Tang <davidm@hpl.hp.com>

This file is part of libunwind.

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.  */

#include "unwind_i.h"

HIDDEN define_lock (hppa_lock);
HIDDEN int tdep_init_done;

HIDDEN int unwind_sigfillset(sigset_t *set) {
      memset(set, ~0, sizeof *set);
      return 0;
}

HIDDEN void
tdep_init (void)
{
  intrmask_t saved_mask;

  unwind_sigfillset (&unwi_full_mask);

  lock_acquire (&hppa_lock, saved_mask);
  {
    if (tdep_init_done)
      /* another thread else beat us to it... */
      goto out;

    mi_init ();

    dwarf_init ();

#ifndef UNW_REMOTE_ONLY
    hppa_local_addr_space_init ();
#endif
    tdep_init_done = 1; /* signal that we're initialized... */
  }
 out:
  lock_release (&hppa_lock, saved_mask);
}
