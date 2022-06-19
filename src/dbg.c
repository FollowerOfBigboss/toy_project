#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/uio.h>
// #include <sys/siginfo.h>

#include <elf.h>

int dbg_create_process(const char* filepath)
{
  pid_t pid = fork();
  if (pid == 0)
  {
    
    int ret, berrno;
    // printf("Child process!\n");
    ret = ptrace(PTRACE_TRACEME, 0, NULL, NULL);
    if (ret == -1)
    {
      berrno = errno;
      printf("Error no: %i\nError String: %s\n", berrno, strerror(berrno));
      exit(1); 
    }

    ret = execl(filepath, NULL);
    if (ret == -1)
    {
      berrno = errno;
      printf("Error no: %i\nError String: %s\n", berrno, strerror(berrno));
      exit(1);
    }
  }
  else if (pid == -1)
  {
    int berrno = errno; 
    printf("Error no: %i\nError String: %s\n", berrno, strerror(berrno));
    return -1;
  }
  else
  { 
    printf("Pid of child %i\n", pid);
    return pid;
  }
}

void dbg_catch_process();
void dbg_singlestep();
void dbg_wait();


void dbg_catch_process(int pid)
{
  int status;
  waitpid(pid, &status, 0);
}

void dbg_singlestep(int pid)
{
  ptrace(PTRACE_SINGLESTEP, pid, 0, 0);
}

void dbg_cont(int pid)
{
  ptrace(PTRACE_CONT, pid, 0, 0);
}

void dbg_getregs(int pid, struct user_regs_struct* regs)
{
#if defined(__amd64__)
  ptrace(PTRACE_GETREGS, pid, 0, regs);
  printf("rip %lx\n", regs->rip);
#elif defined(__aarch64__)
  struct iovec iov;
  iov.iov_len = sizeof(*regs);
  iov.iov_base = regs;  
  ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov);
 
  int i;
  for (i=0;i<=30;i++)
  {
    printf("x%i: %lx\n", i, regs->regs[i]);
  }

  printf("pc %lx\n", regs->pc);
  printf("sp %lx\n", regs->sp);
  printf("pstate %lx\n", regs->pstate);
#endif
}

void dbg_get_signfo(int pid)
{
  siginfo_t signfo;
  ptrace(PTRACE_GETSIGINFO, pid, 0, &signfo);
  printf("signo: %i(SIG%s)\n", signfo.si_signo, strsignal(signfo.si_signo));
}

void dbg_get_event(int pid)
{
  unsigned long eventmsg;
  ptrace(PTRACE_GETEVENTMSG, pid, 0, &eventmsg);
  printf("eventmsg %i\n", eventmsg);
}


#define TEST_HELLO_PATH "../tests/hello" 
#define TEST_DEADLOCK_PATH "../tests/deadlock"

#if !defined(DBGMAIN)
int main()
{
  int pid = dbg_create_process(TEST_DEADLOCK_PATH);
  dbg_catch_process(pid);
  
  int options = PTRACE_O_EXITKILL;
  ptrace(PTRACE_SETOPTIONS, pid, 0, options);

  int go = 1;
  char tb[4];
  while (go)
  {
    printf("toydbg>");
    scanf("%s", &tb);

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
