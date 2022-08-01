
void read_proc(int pid)
{
  FILE* proc = fopen("/proc/pid/maps","rb");

  fclose(proc);
}
