/*
  Copyright 2009-2010, jimmikaelkael <jimmikaelkael@wanadoo.fr>
  Copyright 2009-2010, misfire <misfire@xploderfreax.de>

  Licenced under Academic Free License version 3.0
  Review OpenUsbLd README & LICENSE files for further details.
*/

#include <tamtypes.h>
#include <iopcontrol.h>
#include <kernel.h>
#include <sifrpc.h>
#include <loadfile.h>
#include <string.h>
#include <stdio.h>

static inline void BootError(char *filename){
	char *argv[2];
	argv[0]="BootError";
	argv[1]=filename;

	ExecOSD(2, argv);
}

static inline void InitializeUserMemory(unsigned int start, unsigned int end){
	unsigned int i;

	for (i = start; i < end; i += 64) {
		asm(
			"\tsq $0, 0(%0) \n"
			"\tsq $0, 16(%0) \n"
			"\tsq $0, 32(%0) \n"
			"\tsq $0, 48(%0) \n"
			:: "r" (i)
		);
	}
}

int main(int argc, char *argv[])
{
	int result;
 	t_ExecData exd;

	SifInitRpc(0);

	exd.epc = 0;

	//clear memory.
	InitializeUserMemory(0x00100000, GetMemorySize());
	FlushCache(0);

	SifLoadFileInit();

	result = SifLoadElf(argv[0], &exd);

	SifLoadFileExit();

	if (result==0 && exd.epc!=0) {
#ifdef RESET_IOP
		//Final IOP reset, to fill the IOP with the default modules.
		while(!SifIopReset(NULL, 0)){};

		FlushCache(0);
		FlushCache(2);

		while(!SifIopSync()){};

		//Sync with the SIF library on the IOP, or it may crash the IOP kernel during the next reset (Depending on the how the next program initializes the IOP).
		SifInitRpc(0);
		//Load modules.
		SifLoadFileInit();
		SifLoadModule("rom0:SIO2MAN", 0, NULL);
		SifLoadModule("rom0:MCMAN", 0, NULL);
		SifLoadModule("rom0:MCSERV", 0, NULL);
		SifLoadFileExit();

#endif
		SifExitRpc();

		ExecPS2((void*)exd.epc, (void*)exd.gp, argc, argv);
	}
	else{
		SifExitRpc();
	}

	BootError(argv[0]);

	return 0;
}
