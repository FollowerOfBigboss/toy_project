#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>

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
  char tb[3];
  while (go)
  {
    scanf("%s", &tb);
    if (tb[0] == 'q')
    {
      go = 0;
    }
    if (tb[0] == 's')
    {
      dbg_singlestep(pid);
      dbg_catch_process(pid);

      struct user_regs_struct regs;
      ptrace(PTRACE_GETREGS, pid, 0, &regs);
      printf("rip %lx\n", regs.rip);
    }
    if (tb[0] == 'c')
    {
      dbg_cont(pid);
      dbg_catch_process(pid);
    }
  }
  return 0;
}
#endif
