/*
 *  Copyright (C) 2018 qwikrazor87
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <pspkernel.h>
#include <string.h>
#include "lib.h"
#include "sctrl.h"

PSP_MODULE_INFO("pspdoc", 0x0800, 1, 0);
PSP_HEAP_SIZE_KB(0);

static STMOD_HANDLER previous = NULL;

SceIoStat stat;
char pathbuf[256], dirpath[128];
u8 docdata[0x80 * 100 + 8];

int (* paf_sprintf)(char *, const char *, ...);

//decrypt offset/size table
int (* vsh_065C5F79)(u8 *buf, int size);
int vsh_065C5F79Hook(u8 *buf, int size)
{
	int ret = vsh_065C5F79(buf, size);
	memcpy(docdata, buf, sizeof(docdata));

	return ret;
}

//grab folder name
SceUID vshIoOpenHook(const char *path, int flags, SceMode mode)
{
	strcpy(pathbuf, path);
	int len = strlen(pathbuf);

	while (pathbuf[len] != '/')
		len--;

	pathbuf[len] = 0;

	while (pathbuf[len] != '/')
		len--;

	strcpy(dirpath, pathbuf + len + 1);

	return sceIoOpen(path, flags, mode);
}

//decryption function
int (* sub_00015DF0)(SceUID fd, u8 *buf, u32 *newsize, u32 *a3);
int sub_00015DF0Hook(SceUID fd, u8 *buf, u32 *newsize, u32 *a3)
{
	int ret = sub_00015DF0(fd, buf, newsize, a3);

	if (ret == 0) {
		paf_sprintf(pathbuf, "ms0:/DOCS/PSP_%s", dirpath);

		if (sceIoGetstat(pathbuf, &stat) < 0) { //assume it's dumped if folder exists.
			sceIoMkdir(pathbuf, 0777);

			int i, j = _lw((u32)docdata + 4);
			for (i = 0; i < j; i++) {
				u32 sz = _lw((u32)docdata + (i << 7) + 20);

				SceUID mem = sceKernelAllocPartitionMemory(2, "tmpbuf", PSP_SMEM_Low, sz, NULL);
				u8 *tmpbuf = (u8 *)sceKernelGetBlockHeadAddr(mem);

				sub_00015DF0(fd, tmpbuf, &sz, (u32 *)((u32)docdata + (i << 7) + 8));

				paf_sprintf(pathbuf, "ms0:/DOCS/PSP_%s/DOC_%03d.png", dirpath, i);

				while (memcmp(tmpbuf + sz - 8, "IEND\xAE\x42\x60\x82", 8))
					sz--;

				SceUID fd = sceIoOpen(pathbuf, 0x602, 0777);
				sceIoWrite(fd, tmpbuf, sz);
				sceIoClose(fd);

				sceKernelFreePartitionMemory(mem);
			}
		}
	}

	return ret;
}

void patch_game_plugin_module(SceModule2 *mod)
{
	u32 addr, data;

	for (addr = mod->text_addr; addr < (mod->text_addr + mod->text_size); addr += 4) {
		data = _lw(addr);

		if (data == 0x2405063D) { //li         $a1, 1597
			vsh_065C5F79 = (void *)U_EXTRACT_CALL(addr - 4);
			_sw(MAKE_CALL(vsh_065C5F79Hook), addr - 4);
		} else if (data == 0x8CEA0000) { //lw         $t2, 0($a3)
			HIJACK_FUNCTION(addr - 0x34, sub_00015DF0Hook, sub_00015DF0);
		} else if (data == 0x27A502C0) { //addiu      $a1, $sp, 704
			_sw(MAKE_CALL(vshIoOpenHook), addr - 0x20);
		} else if (data == 0x1082FF30) { //beq        $a0, $v0, loc_0001CAEC
			paf_sprintf = (void *)U_EXTRACT_CALL(addr - 0x24); //built-in sprintf makes plugin too big.
			break;
		}
	}

	ClearCaches();
}

int module_start_handler(SceModule2 *module)
{
	int ret = previous ? previous(module) : 0;

	if (!strcmp(module->modname, "game_plugin_module"))
		patch_game_plugin_module(module);

	return ret;
}

int thread_start(SceSize args __attribute__((unused)), void *argp __attribute__((unused)))
{
	sceIoMkdir("ms0:/DOCS", 0777);
	previous = sctrlHENSetStartModuleHandler(module_start_handler);

	return 0;
}

int module_start(SceSize args, void *argp)
{
	SceUID thid = sceKernelCreateThread("pspdoc", thread_start, 0x22, 0x2000, 0xC0000000, NULL);

	if (thid >= 0)
		sceKernelStartThread(thid, args, argp);

	return 0;
}

int module_stop(SceSize args __attribute__((unused)), void *argp __attribute__((unused)))
{
	return 0;
}
