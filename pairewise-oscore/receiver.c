#include "contiki.h"
#include "coap-engine.h"
#include "oscore.h"

#include <stdio.h>
#include <string.h>

#ifndef RECEIVER_ID
#define RECEIVER_ID 2
#endif

#define MASTER_SECRET_LEN 16

static uint8_t master_secret[MASTER_SECRET_LEN];

static void
initialize_master_secret(uint8_t receiver_id)
{
  int j;

  for(j = 0; j < MASTER_SECRET_LEN; j++) {
    master_secret[j] =
      (uint8_t)((j + 1) ^ receiver_id);
  }
  printf("OSCORE_CREDENTIALS_INITIALIZATION...,receiver=%d,master_secret=", receiver_id);
  for(j = 0; j < MASTER_SECRET_LEN; j++) {
    printf("%02x", master_secret[j]);
  }
  printf("\n");
}

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
    printf("OSCORE_REQUEST_RECEIVED,receiver=%d,command=%.*s\n",
           RECEIVER_ID, len, (const char *)payload);
  }

  coap_set_status_code(response, CHANGED_2_04);
  memcpy(buffer, "OK", 2);
  printf("OSCORE_RESPONSE_SEND,status=2.04,payload=%.*s\n", 2, (const char *)buffer);
  coap_set_payload(response, buffer, 2);
}

PROCESS(oscore_receiver_process, "Pairwise OSCORE Receiver");
AUTOSTART_PROCESSES(&oscore_receiver_process);

PROCESS_THREAD(oscore_receiver_process, ev, data)
{
  PROCESS_BEGIN();

  initialize_master_secret((uint8_t)RECEIVER_ID);

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