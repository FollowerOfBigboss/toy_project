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


void dbg_examine_elf(const char* filepath)
{
  /* 
   * EI_NIDENT -> 16  
   * EI_MAG0 -> 0
   * EI_MAG1 -> 1
   * EI_MAG2 -> 2
   * EI_MAG3 -> 3
   * ELFMAG0 -> 0x7f
   * ELFMAG1 -> 'E'
   * ELFMAG2 -> 'L'
   * ELFMAG3 -> 'F'
   * */
  char e_ident[EI_NIDENT]={0};
  FILE* elf = fopen(filepath, "rb");
  fread(e_ident, 1, EI_NIDENT, elf);
  fclose(elf);

  int b_elfmagic = e_ident[EI_MAG0]==ELFMAG0
	           && e_ident[EI_MAG1]==ELFMAG1 
		   && e_ident[EI_MAG2]==ELFMAG2 
		   && e_ident[EI_MAG3]==ELFMAG3;

  /* printf("result %i\n", b_elfmagic); */
  if (b_elfmagic==0){
    printf("This file is not an elf file or magic is corrupted\n");
    printf("Printing magic bytes...\n");
    printf("%x%c%c%c\n", e_ident[EI_MAG0], 
		         e_ident[EI_MAG1],
			 e_ident[EI_MAG2],
			 e_ident[EI_MAG3]);
    return;
  }

  int elfclass= (int)e_ident[EI_CLASS];
  const char* str;
  switch(elfclass){
    case ELFCLASSNONE: str="ELFCLASSNONE"; break;
    case ELFCLASS32: str="ELFCLASS32";  break;
    case ELFCLASS64: str="ELFCLASS64"; break;
    default: break;
  }

  printf("elfclass %s\n", str);


  int eidata = (int)e_ident[EI_DATA];
  switch(eidata){
    case ELFDATANONE: str="ELFDATANONE"; break;
    case ELFDATA2LSB: str="ELFDATA2LSB"; break;
    case ELFDATA2MSB: str="ELFDATA2MSB"; break;
    default: break;
  }

  int eiversion = (int)e_ident[EI_VERSION];
  switch(eiversion){
    case EV_NONE: break;
    case EV_CURRENT: break;
    default: break;
  }

  int eiosabi = (int)e_ident[EI_OSABI];
  switch(eiosabi){
    case ELFOSABI_NONE: break;
    case ELFOSABI_SYSV: break;
    case ELFOSABI_HPUX: break;
    case ELFOSABI_NETBSD: break;
    case ELFOSABI_LINUX: break;
    case ELFOSABI_SOLARIS: break;
    case ELFOSABI_IRIX: break;
    case ELFOSABI_FREEBSD: break;
    case ELFOSABI_TRU64: break;
    case ELFOSABI_ARM: break;
    case ELFOSABI_STANDALONE: break;
    default: break;
  }

}

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
int main(int argc, char* argv[])
{
  dbg_examine_elf(argv[1]);
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
