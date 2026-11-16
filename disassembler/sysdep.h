/* Minimal sysdep.h stub so binutils' bfin-dis.c compiles standalone with MSVC. */
#ifndef SYSDEP_H
#define SYSDEP_H
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

typedef unsigned long long bfd_vma;
typedef unsigned char       bfd_byte;

/* Little-endian 16-bit fetch (binutils libbfd helper). */
static __inline unsigned long bfd_getl16 (const void *p)
{
  const unsigned char *q = (const unsigned char *) p;
  return (unsigned long) (q[0] | (q[1] << 8));
}
#endif
