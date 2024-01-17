include ../Makefile.tests_common

USEMODULE += embunit

USEMODULE += ztimer_usec
USEMODULE += saul
USEMODULE += saul_reg
USEMODULE += saul_default
USEMODULE += printf_float


EXTERNAL_MODULE_DIRS += external
USEMODULE += gen_ibpf


CFLAGS += -I$(CURDIR)

include $(RIOTBASE)/Makefile.include
