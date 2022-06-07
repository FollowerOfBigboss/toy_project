#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

int dbg_create_process(const char* filepath)
{
  pid_t pid = fork();
  if (pid == 0)
  {
    // printf("Child process!\n");
    int ret = execl(filepath, NULL);
    if (ret == -1)
    {
      int berrno = errno;
      printf("Error no: %i\nError String: %s\n", berrno, strerror(berrno));
      exit(1);
    }
  }

  if (pid == -1)
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

#define TEST_HELLO_PATH "../tests/hello" 

int main()
{
  dbg_create_process(TEST_HELLO_PATH);
  return 0;
}
