#include <stdio.h>
#include <stdint.h>

#include <elf.h>


#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/mman.h>

/*
 * gcn -> Get Constant Name
 * gcn_classnane_wantedthing
 * 
 * */

/*
 * https://stackoverflow.com/questions/1505582/determining-32-vs-64-bit-in-c
 */
#if INTPTR_MAX == INT32_MAX
  #define Elf_Ehdr Elf32_Ehdr
#elif INTPTR_MAX == INT64_MAX
  #define Eld_Ehdr Elf64_Ehdr
#else
  #error "Is there any elf format exist for your architecture?"
#endif

#include "disas.h"

struct MappedElf
{
  void* elfmap;
  int elfclass;
};


void dump_elf_header32(Elf32_Ehdr* elf32);
void dump_elf_header64(Elf64_Ehdr* elf64);
int is_elf_file(struct MappedElf* map);

static const char* gcn_elfsym_info(unsigned char info);
static const char* gcn_elfphdr_type(uint32_t ptype);

void MapElf(const char* filepath, struct MappedElf* map)
{
  int fd = open(filepath, O_RDONLY);
  struct stat sb;
  fstat(fd, &sb);
  
  map->elfmap = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
  
  int b_elf = is_elf_file(map);
  char* elf = (char*)map->elfmap;
  
  if (b_elf == 1) { 
    if (elf[EI_CLASS]==ELFCLASS64)
    {   
      Elf64_Ehdr* elf64ehdr = (Elf64_Ehdr*)map->elfmap;
      // dump_elf_header64(elf64ehdr);
      
      
      Elf64_Phdr* elf64phdr;
      int i;
      for (i =0; i<elf64ehdr->e_phnum; i++){
        elf64phdr = (Elf64_Phdr*)(map->elfmap+elf64ehdr->e_phoff+sizeof(Elf64_Phdr)*i);
	// printf("type: %s\n", gcn_elfphdr_type(elf64phdr->p_type));
      }


      Elf64_Shdr* elf64shdr;
      Elf64_Shdr* section = (Elf64_Shdr*)(map->elfmap+elf64ehdr->e_shoff);
      char* symstr = (char*)(map->elfmap+section[elf64ehdr->e_shstrndx].sh_offset);

      for(i=0; i<elf64ehdr->e_shnum; i++){
        elf64shdr = (Elf64_Shdr*)(map->elfmap+elf64ehdr->e_shoff+i*elf64ehdr->e_shentsize);
	// printf("Section name: %s\n", symstr + elf64shdr->sh_name);

	/*
	if (elf64shdr->sh_type == SHT_STRTAB){
	  char* content = map->elfmap+elf64shdr->sh_offset;

	  int ss=0;
	  for (;ss<elf64shdr->sh_size;ss++){
            printf("%c", content[ss]);    
	  }

	}
	*/

	
	if (elf64shdr->sh_type == SHT_SYMTAB){

	  // printf("Symbol Table!\n");
	  // printf("sh_name %i sh_size %llu\n", elf64shdr->sh_name, elf64shdr->sh_size);
	  
	  // printf("%llu\n", elf64shdr->sh_size/elf64shdr->sh_entsize);

	  Elf64_Sym* symtable = (Elf64_Sym*)(map->elfmap+elf64shdr->sh_offset);
	  char* symbol_names=(char*)(map->elfmap+section[elf64shdr->sh_link].sh_offset);

	  int symbol_count = elf64shdr->sh_size/elf64shdr->sh_entsize;
	  int s;
	  for (s=0;s<symbol_count;s++)
	  {
	    // printf("%x <%s> %i (%s)\n", symtable[s].st_value ,symbol_names+symtable[s].st_name, symtable[s].st_size, gcn_elfsym_info(symtable[s].st_info));
	  
	    if (ELF64_ST_TYPE(symtable[s].st_info) == STT_FUNC)
	    {
              if(symtable[s].st_size ==0)
		      continue;

	    printf("%x <%s> %i (%s)\n", symtable[s].st_value ,symbol_names+symtable[s].st_name, symtable[s].st_size, gcn_elfsym_info(symtable[s].st_info));
	    int addr = symtable[s].st_value;
	    int size = symtable[s].st_size;

            // printf("Elf start: %x symsize %x calculated pos %x", map->elfmap, size, map->elfmap+addr);

	   
            char bytes[300];
	    int ff;
	    char hxx;

	    printf("%i %i %i sfinp 2104\n", addr, 0x1000, addr-0x1000);
	    
	    int calc = addr-0x1000;
	    for(ff=0;ff<size;ff++){
	      hxx =  *(char*)((map->elfmap+calc+ff)); // *(char*)((map->elfmap+addr+ff))-0x1000);
	      bytes[ff]= hxx;
	   
	    //  printf("%x", hxx);
	      // if ((ff+1)%4==0){
	     //   printf("\n");
	      //}
	      
	    }
	    
            disas(bytes, size);

	    printf("\n");
	    }
	  }
	}

	
      }
    }
    else if(elf[EI_CLASS]==ELFCLASS32)
    {
      dump_elf_header32((Elf32_Ehdr*)map->elfmap);
    }
    else
    {
      printf("Unknown elf class!\n");
    }

  }
  else {
    printf("This file is not an elf file or magic is corrupted\n");
    printf("Printing magic bytes...\n"); 
    printf("%x %c %c %c\n", elf[0], elf[1], elf[2], elf[3]);
  }
  
}

static const char* gcn_elf_class(char elfclass)
{
  switch(elfclass){
    case ELFCLASSNONE: return "ELFCLASSNONE";
    case ELFCLASS32: return "ELFCLASS32";
    case ELFCLASS64: return "ELFCLASS64";
    default: return "ELFCLASSUNKNOWN";
  }
}

static const char* gcn_elf_endian(char elfendian)
{

  switch(elfendian){
    case ELFDATANONE: return "ELFDATANONE";
    case ELFDATA2LSB: return "ELFDATA2LSB";
    case ELFDATA2MSB: return "ELFDATA2MSB";
    default: return "ELFDATAUNKNOWN";
  }
}

static const char* gcn_elf_version(char elfversion)
{
  switch(elfversion){
    case EV_NONE: return "EV_NONE";
    case EV_CURRENT: return "EV_CURRENT";
    default: return "EV_UNKNOWN";
  }
}

static const char* gcn_elf_osabi(char elfosabi)
{

  switch(elfosabi){
    /* case ELFOSABI_NONE: return "ELFOSABI_NONE"; */
    case ELFOSABI_SYSV: return "ELFOSABI_SYSV";
    case ELFOSABI_HPUX: return "ELFOSABI_HPUX";
    case ELFOSABI_NETBSD: return "ELFOSABI_NETBSD";
    case ELFOSABI_LINUX: return "ELFOSABI_LINUX";
    case ELFOSABI_SOLARIS: return "ELFOSABI_SOLARIS";
    case ELFOSABI_IRIX: return "ELFOSABI_IRIX";
    case ELFOSABI_FREEBSD: return "ELFOSABI_FREEBSD";
    case ELFOSABI_TRU64: return "ELFOSABI_TRU64";
   /* case ELFOSABI_ARM: break; */
   /* case ELFOSABI_STANDALONE: break; */
    default: return "ELFOSABI_UNKNOWN";
  }

}

static const char* gcn_elf_binary_type(uint16_t elftype)
{
 switch(elftype){
   case ET_NONE: return "ET_NONE";
   case ET_REL: return "ET_REL";
   case ET_EXEC: return "ET_EXEC";
   case ET_DYN: return "ET_DYN";
   case ET_CORE: return "ET_CORE";
   default: return "ET_UNKNOWN";
 }
}

static const char* gcn_elf_machine(uint16_t elfmachine)
{
  switch (elfmachine){
    case EM_NONE: return "EM_NONE";
    case EM_M32: return "EM_M32";
    case EM_SPARC: return "EM_SPARC";
    case EM_386: return "EM_386";
    case EM_68K: return "EM_68K";
    case EM_88K: return "EM_88K";
    case EM_860: return "EM_860";
    case EM_MIPS: return "EM_MIPS";
    case EM_PARISC: return "EM_PARISC";
    case EM_SPARC32PLUS: return "EM_SPARC32PLUS";
    case EM_PPC: return "EM_PPC";
    case EM_PPC64: return "EM_PPC64";
    case EM_S390: return "EM_S390";
    case EM_ARM: return "EM_ARM";
    case EM_SH: return "EM_SH";
    case EM_SPARCV9: return "EM_SPARCV9";
    case EM_IA_64: return "EM_IA_64";
    case EM_X86_64: return "EM_X86_64";
    case EM_VAX: return "EM_VAX";
    default: return "EM_UNKNOWN";
  }
}

static const char* gcn_elfphdr_type(uint32_t ptype)
{
  switch(ptype){
    case PT_NULL: return "PT_NULL";
    case PT_LOAD: return "PT_LOAD";
    case PT_DYNAMIC: return "PT_DYNAMIC";
    case PT_INTERP: return "PT_INTERP";
    case PT_NOTE: return "PT_NOTE";
    case PT_SHLIB: return "PT_SHLIB";
    case PT_PHDR: return "PT_PHDR";
    case PT_GNU_STACK: return "PT_GNU_STACK";
    default: return "PT_UNKNOWN";

  }

}


int is_elf_file(struct MappedElf* map)
{
  char* magic = (char*)map->elfmap;
  int b_elfmagic = magic[0]==ELFMAG0
	           && magic[1]==ELFMAG1 
		   && magic[2]==ELFMAG2 
		   && magic[3]==ELFMAG3;
  return b_elfmagic;
}


void dump_elf_header32(Elf32_Ehdr* elf32)
{
  printf("elftype %s\n", gcn_elf_binary_type(elf32->e_type));
  printf("elfmachine %s\n", gcn_elf_machine(elf32->e_machine));
  printf("elfversion %s\n", gcn_elf_version((char)elf32->e_version));
  printf("elfentry: %x\n", elf32->e_entry);
  printf("elfphoffset: %u\n", elf32->e_phoff);
  printf("elfshoffset: %u\n", elf32->e_shoff);
  printf("elfflags: %i\n", elf32->e_flags);
  printf("elfehsize: %i\n", elf32->e_ehsize);
  printf("elfphentsize: %i\n", elf32->e_phentsize);
  printf("elfphnum %i\n", elf32->e_phnum);
  printf("elfshentsize %i\n", elf32->e_shentsize);
  printf("elfshnum %i\n", elf32->e_shnum);
  printf("elfshstrndx %i\n", elf32->e_shstrndx);
}

void dump_elf_header64(Elf64_Ehdr* elf64) 
{
  printf("Elf Identify(e_ident): ");

  int i;
  for (i =0; i< EI_NIDENT; i++) {
    printf("%x ", elf64->e_ident[i]);
  }
  printf("\n");
  
  printf("-- EI_MAG0 -> 0x%x\n", elf64->e_ident[EI_MAG0]);
  printf("-- EI_MAG1 -> 0x%x(%c)\n", elf64->e_ident[EI_MAG1], elf64->e_ident[EI_MAG1]);
  printf("-- EI_MAG2 -> 0x%x(%c)\n", elf64->e_ident[EI_MAG2], elf64->e_ident[EI_MAG2]);
  printf("-- EI_MAG3 -> 0x%x(%c)\n", elf64->e_ident[EI_MAG3], elf64->e_ident[EI_MAG3]);
  printf("-- EI_CLASS -> %i(%s)\n", elf64->e_ident[EI_CLASS], gcn_elf_class(elf64->e_ident[EI_CLASS]));
  printf("-- EI_DATA -> %i(%s)\n", elf64->e_ident[EI_DATA], gcn_elf_endian(elf64->e_ident[EI_DATA]));
  printf("-- EI_VERSION -> 0x%x(%i)(%s)\n", elf64->e_ident[EI_VERSION], elf64->e_ident[EI_VERSION], gcn_elf_version(elf64->e_ident[EI_VERSION]));
  printf("-- EI_OSABI -> %i(%s)\n", elf64->e_ident[EI_OSABI], gcn_elf_osabi(elf64->e_ident[EI_OSABI]));
  printf("-- EI_ABIVERSION -> %x\n", elf64->e_ident[EI_ABIVERSION]);


  printf("Elf Type(e_type): %s(%i)\n", gcn_elf_binary_type(elf64->e_type), elf64->e_type);
  printf("Elf Machine(e_machine): %s\n", gcn_elf_machine(elf64->e_machine));
  printf("Elf Version(e_version): %s\n", gcn_elf_version((char)elf64->e_version));
  printf("Elf Entry(e_entry): %llx\n", elf64->e_entry);
  printf("Elf Program Header Offset(e_phoff): %llu\n", elf64->e_phoff);
  printf("Elf Section Header Offset(e_shoff): %llu\n", elf64->e_shoff);
  printf("Elf Flags(e_flags): %i\n", elf64->e_flags);
  printf("Elf Header Size(e_ehsize): %i\n", elf64->e_ehsize);
  printf("ElfnProgram Header Entry Size(e_phentsize): %i\n", elf64->e_phentsize);
  printf("Elf Program Header Number(e_phnum): %i\n", elf64->e_phnum);
  printf("Elf Section Header Size(e_shentsize): %i\n", elf64->e_shentsize);
  printf("Elf Section Header Number(e_shnum): %i\n", elf64->e_shnum);
  printf("Elf Section Header String Table Index(e_shstrndx): %i\n", elf64->e_shstrndx);
}

static const char* gcn_elfsym_info(unsigned char info)
{

  switch(ELF64_ST_TYPE(info)){
    case STT_NOTYPE: return "STT_NOTYPE";
    case STT_OBJECT: return "STT_OBJECT";
    case STT_FUNC: return "STT_FUNC";
    case STT_SECTION: return "STT_SECTION";
    case STT_FILE: return "STT_FILE";
  }
  return NULL;
}

enum{
  CLASS,


}

void getconstantname(int constant, int constanttype)
{

}
