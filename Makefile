TARGET = pspdoc
OBJS =  src/main.o src/exports.o src/lib.o src/imports.o

LIBDIR =
LIBS =

CFLAGS = -Wall -Wextra -O2 -G0
ASFLAGS = $(CFLAGS)

PSP_FW_VERSION=660

PSPSDK=$(shell psp-config --pspsdk-path)
include $(PSPSDK)/lib/build_prx.mak
