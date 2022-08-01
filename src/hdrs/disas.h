#include <capstone/platform.h>
#include <capstone/capstone.h>



csh handle = NULL;
cs_insn* ins;

void disas(const char* bytes, int size);

void disas(const char* bytes, int size)
{
  if (handle == NULL)
  {
#if defined(__amd64__)
     cs_err ret = cs_open(CS_ARCH_X86, CS_MODE_64, &handle);
#elif defined(__aarch64__)
     cs_err ret = cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &handle);
#endif
  }

  int count = cs_disasm(handle, bytes, size, 0x1000, 0, &ins);
//  printf("count %i\n", count);

  int i;
  for (i=0;i<count;i++)
  {
    printf("%s %s\n", ins[i].mnemonic, ins[i].op_str);
  }
  cs_free(ins, count);
}
