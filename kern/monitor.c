// Simple command-line kernel monitor useful for
// controlling the kernel and exploring the system interactively.

#include <inc/stdio.h>
#include <inc/string.h>
#include <inc/memlayout.h>
#include <inc/assert.h>
#include <inc/x86.h>

#include <kern/console.h>
#include <kern/monitor.h>
#include <kern/kdebug.h>
#include <kern/pmap.h>


#define CMDBUF_SIZE	80	// enough for one VGA text line

struct Command {
	const char *name;
	const char *desc;
	// return -1 to force monitor to exit
	int (*func)(int argc, char** argv, struct Trapframe* tf);
};

static struct Command commands[] = { { "help", "Display this list of commands",
		mon_help }, { "kerninfo", "Display information about the kernel",
		mon_kerninfo }, { "backtrace", "Display a list of call frames",
		mon_backtrace }, { "showmappings","Display the physical page mappings", mon_showmappings },
		{ "dump","Display the content of a memory range", mon_memorydump },
		{ "pmsetperm","Sets page mapping permissions bit", mon_pmsetperm },
		{ "pmclearperm","Sets page mapping permissions bit", mon_pmclearperm } };

#define NCOMMANDS (sizeof(commands)/sizeof(commands[0]))
#define NUKE_EBP 0x0 //the end in the chain of saved EBP
#define ARGSC 5  //number of arguments to print from function stack frame


unsigned read_eip();

/***** Implementations of basic kernel monitor commands *****/

int
mon_help(int argc, char **argv, struct Trapframe *tf)
{
	int i;

	for (i = 0; i < NCOMMANDS; i++)
		cprintf("%s - %s\n", commands[i].name, commands[i].desc);
	return 0;
}

int
mon_kerninfo(int argc, char **argv, struct Trapframe *tf)
{
	extern char _start[], etext[], edata[], end[];

	cprintf("Special kernel symbols:\n");
	cprintf("  _start %08x (virt)  %08x (phys)\n", _start, _start - KERNBASE);
	cprintf("  etext  %08x (virt)  %08x (phys)\n", etext, etext - KERNBASE);
	cprintf("  edata  %08x (virt)  %08x (phys)\n", edata, edata - KERNBASE);
	cprintf("  end    %08x (virt)  %08x (phys)\n", end, end - KERNBASE);
	cprintf("Kernel executable memory footprint: %dKB\n",
		(end-_start+1023)/1024);
	return 0;
}

int mon_backtrace(int argc, char **argv, struct Trapframe *tf) {
	uintptr_t *ebp = (uintptr_t*) read_ebp(), *saved_ebp, eip;

	cprintf("\nStack backtrace:\n");
	int i;
	struct Eipdebuginfo info;
	do {
		saved_ebp = (uintptr_t*) *ebp;
		cprintf("  ebp %x ", ebp++);
		eip = (uintptr_t) *ebp;
		cprintf("eip %x ", *ebp++);
		cprintf("args ");
		i = ARGSC;
		while (i--)
			cprintf("%08x ", *ebp++);
		debuginfo_eip((uintptr_t) eip, &info);
		cprintf("\n        ");
		cprintf("%s:%d: ", info.eip_file, info.eip_line);
		cprintf("%.*s+%d\n", info.eip_fn_namelen, info.eip_fn_name, eip
				- info.eip_fn_addr);
		ebp = saved_ebp;
	} while (saved_ebp != NUKE_EBP);
	return 0;
}

void
mon_showmappings_page_info(pte_t* pte,uintptr_t va){
cprintf("\n%11x| %11x| %2d | %4d | %4d | %2d |",va,*pte & 0xfffff000 ,*pte & PTE_P?1:0,*pte & PTE_W?1:0,*pte & PTE_U?1:0,*pte & PTE_D?1:0);
}

int
mon_showmappings(int argc, char **argv, struct Trapframe *tf){

	if(!(argc>2 && argc<4)){
		cprintf("\nWrong arguments");
		cprintf("\nUsage :\n    showmappings [hex start vitual adress] [hex end virtual adress]\n");
		return 1;
	}
	uintptr_t la,ha;
	if((la=strtol(&*argv[1],NULL,16))>(ha=strtol(&*argv[2],NULL,16))){
		cprintf("\nWrong arguments");
		cprintf("\nUsage :\n    showmappings [hex start vitual adress] [hex end virtual adress]\n");
		return 1;
	}

	cprintf("Virtual/Physical Address|   Permission bits     |");
	cprintf("\n    VA     |    PA      |  P |  R/W |  U/S |  D |");

	pte_t *pte;
	int i,size=ha-la;
	for(i=0;i<size;i+=PGSIZE){
		pte=pgdir_walk(boot_pgdir,(void*)(la+i),0);
		mon_showmappings_page_info(pte,la+i);
	}
	cprintf("\n");
return 0;
}

int
mon_memorydump(int argc, char **argv, struct Trapframe *tf){

	if (!(argc > 2 && argc < 4)) {
		cprintf("\nWrong arguments");
		cprintf("\nUsage :\n    dump [hex start adress] [hex end adress]\n");
		return 1;
	}

	void *l, *h;
	if ((l = (uintptr_t*) strtol(&*argv[1], NULL, 16)) > (h
			= (uintptr_t*) strtol(&*argv[2], NULL, 16))) {
		cprintf("\nWrong arguments");
		cprintf("\nUsage :\n    dump [hex start adress] [hex end adress]\n");
		return 1;
	}

	int i, j, size = ((uint32_t)h - (uint32_t)l)/4;

	if ((int) l >= KERNBASE) {
		for (i = 0; i < size; i += CMDBUF_SIZE / 8) {
			for (j = i; j < (i + CMDBUF_SIZE / 8); j++)
				cprintf("%08x ", *(uintptr_t*)(l + j));

			cprintf("\n");

		}
	}
	else{
		uintptr_t *la;
		physaddr_t pp_boundary;
		for (i = 0; i < size; ){
			la=KADDR((physaddr_t)l);
			pp_boundary=(physaddr_t)(*pgdir_walk(boot_pgdir,(void*)la,0)&0xfffff000)+PGSIZE;
			j=i;

			while(pp_boundary>(physaddr_t)(l+i) && i < size){
				if(j+CMDBUF_SIZE/8<i){
					cprintf("\n");
					j=i;
				}

				cprintf("%08x ", *(la + i++));
			}
		}
		cprintf("\n");

	}
	return 0;
}


int
mon_pmsetpermisionbit(int argc, char **argv,int set){

	if (!(argc > 2 && argc < 4))
		return 1;


	void *va;
	if (!(uint32_t)(va = (void*) strtol(&*argv[1], NULL, 16)) > KERNBASE)
		return 1;
     int bit=*argv[2];
	int perm;

	switch (bit) {
	case 'P': {
		perm = PTE_P;
		break;
	}
	case 'W': {
		perm = PTE_W;
		break;
	}
	case 'U': {
		perm = PTE_U;
		break;
	}
	case 'D': {
		perm = PTE_D;
		break;
	}
	default: {
		return 1;
	}
	}

	pte_t *pte;
	pte = pgdir_walk(boot_pgdir, va, 0);

	if (!pte)
		return 1;

	*pte &= ~perm;
	if (set)
		*pte |= perm;

	return 0;
}

int
mon_pmsetperm(int argc, char **argv, struct Trapframe *tf){
	if(mon_pmsetpermisionbit(argc, argv,1))
		cprintf("\nWrong arguments");
		cprintf("\nUsage :\n    pmsetperm [hex virtual adress] [P|W|D|U]\n");
	return 0;

}
int
mon_pmclearperm(int argc, char **argv, struct Trapframe *tf){
	if(mon_pmsetpermisionbit(argc, argv,0))
		cprintf("\nWrong arguments");
		cprintf("\nUsage :\n    pmclearperm [hex virtual adress] [P|W|D|U]\n");
	return 0;
}

/***** Kernel monitor command interpreter *****/

#define WHITESPACE "\t\r\n "
#define MAXARGS 16

static int
runcmd(char *buf, struct Trapframe *tf)
{
	int argc;
	char *argv[MAXARGS];
	int i;

	// Parse the command buffer into whitespace-separated arguments
	argc = 0;
	argv[argc] = 0;
	while (1) {
		// gobble whitespace
		while (*buf && strchr(WHITESPACE, *buf))
			*buf++ = 0;
		if (*buf == 0)
			break;

		// save and scan past next arg
		if (argc == MAXARGS-1) {
			cprintf("Too many arguments (max %d)\n", MAXARGS);
			return 0;
		}
		argv[argc++] = buf;
		while (*buf && !strchr(WHITESPACE, *buf))
			buf++;
	}
	argv[argc] = 0;

	// Lookup and invoke the command
	if (argc == 0)
		return 0;
	for (i = 0; i < NCOMMANDS; i++) {
		if (strcmp(argv[0], commands[i].name) == 0)
			return commands[i].func(argc,argv, tf);
	}
	cprintf("Unknown command '%s'\n", argv[0]);
	return 0;
}

void
monitor(struct Trapframe *tf)
{
	char *buf;

	cprintf("Welcome to the JOS kernel monitor!\n");
	cprintf("Type 'help' for a list of commands.\n");


	while (1) {
		buf = readline("K> ");
		if (buf != NULL)
			if (runcmd(buf, tf) < 0)
				break;
	}
}

// return EIP of caller.
// does not work if inlined.
// putting at the end of the file seems to prevent inlining.
unsigned
read_eip()
{
	uint32_t callerpc;
	__asm __volatile("movl 4(%%ebp), %0" : "=r" (callerpc));
	return callerpc;
}
