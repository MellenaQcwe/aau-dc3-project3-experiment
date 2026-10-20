CONTIKI_PROJECT = sender receiver

all: $(CONTIKI_PROJECT)

CONTIKI = ../../../contiki-ng

# Include the Contiki-NG CoAP module
MODULES += os/net/app-layer/coap

# Set the number of receivers and commands to be sent
NUM_RECEIVERS ?= 2
NUM_COMMANDS ?= 100

CFLAGS += -DNUM_RECEIVERS=$(NUM_RECEIVERS)
CFLAGS += -DNUM_COMMANDS=$(NUM_COMMANDS)

include $(CONTIKI)/Makefile.include