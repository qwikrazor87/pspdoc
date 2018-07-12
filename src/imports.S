	.set noreorder

#include "pspstub.s"

	STUB_START	"SystemCtrlForUser",0x40090000,0x00010005
	STUB_FUNC	0x1C90BECB,sctrlHENSetStartModuleHandler
	STUB_END

	STUB_START	"UtilsForUser",0x40010000,0x00010005
	STUB_FUNC	0x920F104A,sceKernelIcacheInvalidateAll
	STUB_END
