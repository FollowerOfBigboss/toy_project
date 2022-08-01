#include "hdrs/dbg.h"
#include "hdrs/elff.h"

#define TEST_HELLO_PATH "../tests/hello" 
#define TEST_DEADLOCK_PATH "../tests/deadlock"

#if !defined(DBGMAIN)
int main(int argc, char* argv[])
{

  struct MappedElf map;
  MapElf(argv[1], &map);
  return 0;

  int pid = dbg_create_process(argv[1]);
  dbg_catch_process(pid);
  
  int options = PTRACE_O_EXITKILL |
	        PTRACE_O_TRACECLONE |
		PTRACE_O_TRACEEXEC |
		PTRACE_O_TRACEEXIT|
		PTRACE_O_TRACEFORK|
		PTRACE_O_TRACEVFORK;

  ptrace(PTRACE_SETOPTIONS, pid, 0, options);

  int go = 1;
  char tb[4];
  while (go)
  {
    printf("toydbg>");
    scanf("%s", tb);

    switch(tb[0])
    {
      case 'q': go =0; break;
      case 's': {  	
        struct user_regs_struct regs; 
        dbg_singlestep(pid);
        dbg_catch_process(pid);
        dbg_getregs(pid, &regs);
	break;
      }
      case 'c': {
        dbg_cont(pid);
        dbg_catch_process(pid);
        break;
      }
      case 'k': {
        ptrace(PTRACE_SYSCALL, pid, 0, 0);
        dbg_catch_process(pid);
        struct user_regs_struct regs;
        dbg_getregs(pid, &regs);
	break;
      }
    }
    dbg_get_signfo(pid);
    dbg_get_event(pid);
  }
 
  return 0;
}
#endif
