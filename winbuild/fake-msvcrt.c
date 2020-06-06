#include <stdio.h>

double
_ltod3(long n)
{
    return (double)n;
}

long _dtol3(double n)
{
    return (long)n;
}

FILE*
acrt_iob_func(int n)
{
    if (n == 0)
        return stdin;
    else if (n == 1)
        return stdout;
    else if (n == 2)
        return stderr;
    return NULL;
}

FILE* (*_imp____acrt_iob_func)(int) = acrt_iob_func;

const int
__sys_nerr(void)
{
    return 32;
}

const int (*_imp____sys_nerr)(void) = __sys_nerr;
