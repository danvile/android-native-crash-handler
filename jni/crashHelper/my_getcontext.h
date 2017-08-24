#ifndef __MY_GET_CONTEXT__
#define __MY_GET_CONTEXT__
#include <sys/ucontext.h>

extern "C" int my_getcontext(struct ucontext *);
#endif
