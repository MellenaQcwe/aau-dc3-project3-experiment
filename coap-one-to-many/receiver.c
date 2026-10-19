#include "contiki.h"
#include "coap-engine.h"

#include <stdio.h>
#include <string.h>

static void
light_post_handler(coap_message_t *request,
                   coap_message_t *response,
                   uint8_t *buffer,
                   uint16_t preferred_size,
                   int32_t *offset);

/* CoAP resource supporting POST */
RESOURCE(res_light,
         "title=\"Light Controller\";rt=\"control\"",
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
    printf("Received CoAP command: %.*s\n",
           len, (const char *)payload);
  }

  coap_set_status_code(response, CHANGED_2_04);

  /* Send application response */
  memcpy(buffer, "OK", 2);
  coap_set_payload(response, buffer, 2);
}

PROCESS(coap_receiver_process, "CoAP Receiver");
AUTOSTART_PROCESSES(&coap_receiver_process);

PROCESS_THREAD(coap_receiver_process, ev, data)
{
  PROCESS_BEGIN();

  printf("CoAP receiver started\n");

  coap_activate_resource(&res_light, "light");

  while(1) {
    PROCESS_WAIT_EVENT();
  }

  PROCESS_END();
}