/* Minimal disassemble.h stub: only the disassemble_info fields bfin-dis.c uses. */
#ifndef DISASSEMBLE_H
#define DISASSEMBLE_H

typedef int (*fprintf_ftype) (void *, const char *, ...);

struct disassemble_info
{
  fprintf_ftype fprintf_func;
  void *stream;
  void *private_data;
  int  (*read_memory_func)  (bfd_vma, bfd_byte *, unsigned int, struct disassemble_info *);
  void (*memory_error_func) (int, bfd_vma, struct disassemble_info *);
  void (*print_address_func)(bfd_vma, struct disassemble_info *);
  int  (*symbol_at_address_func)(bfd_vma, struct disassemble_info *);
};
typedef struct disassemble_info disassemble_info;
#endif
