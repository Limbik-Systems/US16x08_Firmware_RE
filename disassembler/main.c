/* Standalone driver for binutils' Blackfin disassembler (bfin-dis.c).
   Usage: bfdis <binfile> <start_off_hex> <count> <base_va_hex>
   Disassembles `count` instructions starting at file offset start_off,
   treating that byte as virtual address base_va. */
#include "sysdep.h"
#include "disassemble.h"
#include <stdarg.h>

extern int print_insn_bfin (bfd_vma pc, disassemble_info *outf);

static unsigned char *g_buf;   /* points at file+start */
static long g_len;             /* bytes available from start */
static bfd_vma g_base;         /* VA of g_buf[0] */

static int rdmem (bfd_vma addr, bfd_byte *buf, unsigned int len, disassemble_info *di)
{
  long off = (long) (addr - g_base);
  if (off < 0 || off + (long) len > g_len)
    return -1;
  memcpy (buf, g_buf + off, len);
  return 0;
}
static void memerr (int s, bfd_vma a, disassemble_info *di) { (void)s;(void)a;(void)di; }
static void praddr (bfd_vma a, disassemble_info *di) { di->fprintf_func (di->stream, "0x%llx", (unsigned long long) a); }
static int  symat  (bfd_vma a, disassemble_info *di) { (void)a;(void)di; return 0; }
static int  myfp   (void *s, const char *fmt, ...) { va_list ap; va_start(ap,fmt); int r=vprintf(fmt,ap); va_end(ap); return r; }

int main (int argc, char **argv)
{
  if (argc < 5) { fprintf (stderr, "usage: bfdis <file> <start_hex> <count> <base_hex>\n"); return 2; }
  FILE *f = fopen (argv[1], "rb");
  if (!f) { fprintf (stderr, "cannot open %s\n", argv[1]); return 2; }
  fseek (f, 0, SEEK_END); long sz = ftell (f); fseek (f, 0, SEEK_SET);
  unsigned char *all = (unsigned char *) malloc (sz);
  if (fread (all, 1, sz, f) != (size_t) sz) { fprintf(stderr,"read err\n"); return 2; }
  fclose (f);

  long start   = strtol  (argv[2], NULL, 16);
  long count   = atol    (argv[3]);
  bfd_vma base = strtoull (argv[4], NULL, 16);

  g_buf = all + start; g_len = sz - start; g_base = base;

  disassemble_info di; memset (&di, 0, sizeof di);
  di.fprintf_func = myfp; di.stream = stdout;
  di.read_memory_func = rdmem; di.memory_error_func = memerr;
  di.print_address_func = praddr; di.symbol_at_address_func = symat;

  bfd_vma pc = base;
  for (long i = 0; i < count; i++)
    {
      printf ("%08llx: ", (unsigned long long) pc);
      int n = print_insn_bfin (pc, &di);
      printf ("\n");
      if (n <= 0) n = 2;      /* keep going past illegals */
      pc += n;
      if ((long)(pc - base) >= g_len) break;
    }
  return 0;
}
