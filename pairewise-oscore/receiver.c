#include "contiki.h"
#include "coap-engine.h"
#include "oscore.h"

#include <stdio.h>
#include <string.h>

#ifndef RECEIVER_ID
#define RECEIVER_ID 2
#endif

#if RECEIVER_ID == 2
static const uint8_t master_secret[16] = {
  0x01, 0x02, 0x03, 0x04,
  0x05, 0x06, 0x07, 0x08,
  0x09, 0x0a, 0x0b, 0x0c,
  0x0d, 0x0e, 0x0f, 0x10
};
#elif RECEIVER_ID == 3
static const uint8_t master_secret[16] = {
  0x11, 0x12, 0x13, 0x14,
  0x15, 0x16, 0x17, 0x18,
  0x19, 0x1a, 0x1b, 0x1c,
  0x1d, 0x1e, 0x1f, 0x20
};
#else
#error "Unsupported RECEIVER_ID"
#endif

static const uint8_t client_id[] = { 0x01 };
static const uint8_t server_id[] = { RECEIVER_ID };

static oscore_ctx_t context;

static void
light_post_handler(coap_message_t *request,
                   coap_message_t *response,
                   uint8_t *buffer,
                   uint16_t preferred_size,
                   int32_t *offset);

RESOURCE(res_light,
         "title=\"OSCORE Light Controller\"",
         NULL,
         light_post_handler,
         NULL,
         NULL);

static void
light_post_handler(coap_message_t *request,
                   coap_message_t *response,
                   uint8_t *buffer,
                   uint16_t preferred_size,
                   int32_t *offset)
{
  const uint8_t *payload;
  int len;

  len = coap_get_payload(request, &payload);

  if(len > 0 && payload != NULL) {
    printf("OSCORE_RECEIVED,receiver=%d,command=%.*s\n",
           RECEIVER_ID, len, (const char *)payload);
  }

  coap_set_status_code(response, CHANGED_2_04);

  memcpy(buffer, "OK", 2);
  coap_set_payload(response, buffer, 2);
}

PROCESS(oscore_receiver_process, "Pairwise OSCORE Receiver");
AUTOSTART_PROCESSES(&oscore_receiver_process);

PROCESS_THREAD(oscore_receiver_process, ev, data)
{
  PROCESS_BEGIN();

  printf("OSCORE_RECEIVER_START,id=%d\n", RECEIVER_ID);

  oscore_derive_ctx(
    &context,
    master_secret,
    sizeof(master_secret),
    NULL, 0,
    10,
    server_id, sizeof(server_id),
    client_id, sizeof(client_id),
    NULL, 0
  );

  coap_activate_resource(&res_light, "light");

  oscore_protect_resource(&res_light);

  printf("OSCORE_CONTEXT_READY,id=%d\n", RECEIVER_ID);

  while(1) {
    PROCESS_WAIT_EVENT();
  }

  PROCESS_END();
}