CONTIKI_PROJECT = sender receiver

PLATFORMS_EXCLUDE = sky z1

CONTIKI = ../../../guntzer-contiki-ng

MODULES += os/net/app-layer/coap

MAKE_WITH_OSCORE = 1
MAKE_WITH_GROUPCOM = 1
MAKE_WITH_HW_CRYPTO = 0

WERROR = 0

# Server-side CoAP resource handlers
# Included only when building receiver.cooja
ifneq ($(filter receiver.cooja,$(MAKECMDGOALS)),)
MODULES_REL += ./resources
endif

# #If no SERVER is defined use Server 1
# ifeq ($(strip $(SERVER)),)
# CFLAGS += -DSERVER=1
# else
# CFLAGS += -DSERVER=$(SERVER)
# endif

# #If no TEST is defined do not use any
# ifdef $(TEST)
# CFLAGS += -DTEST=$(TEST)
# endif

include $(CONTIKI)/Makefile.include
