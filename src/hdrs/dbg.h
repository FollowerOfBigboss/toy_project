#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <errno.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/uio.h>
#include <unistd.h>
#include <elf.h>


enum{
  EXECUTABLE_PAUSED,
  EXECUTABLE_RUNNING,
  EXECUTABLE_EXITED
};

struct dbg_info 
{
  const char* executable_path;
  int executable_status;
  int pid;
  
  struct user_regs_struct registers;
};


int dbg_create_process(const char* filepath);
void dbg_catch_process(int pid);

void dbg_singlestep(int pid);
void dbg_cont(int pid);
void dbg_getregs(int pid, struct user_regs_struct* regs);

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

    ret = execl(filepath, NULL, NULL);
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
  
  return 0;
}


void dbg_catch_process(int pid)
{
  int status;
  waitpid(pid, &status, 0);

  if(status>>8 == (SIGTRAP | (PTRACE_EVENT_EXIT<<8)) ){
    printf("status: %i\n", status>>8);
  }
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
  printf("rax %lx\n", regs->rax);
  printf("rcx %lx\n", regs->rcx);
  printf("rdx %lx\n", regs->rdx);
  printf("rsi %lx\n", regs->rsi);
  printf("rdi %lx\n", regs->rdi);
  printf("rsp %lx\n", regs->rsp);
  printf("r8 %lx\n", regs->r8);
  printf("r9 %lx\n", regs->r9);
  printf("r10 %lx\n", regs->r10);

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
  printf("eventmsg %lu\n", eventmsg);
}




