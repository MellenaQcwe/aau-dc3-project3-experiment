#include "contiki.h"
#include "coap-engine.h"
#include "coap-blocking-api.h"

#include <stdio.h>
#include <string.h>

#define SEND_INTERVAL (10 * CLOCK_SECOND)

/* Cooja native mote IPv6 addresses */
#define RECEIVER_1 "coap://[fe80::202:2:2:2]"
#define RECEIVER_2 "coap://[fe80::203:3:3:3]"

PROCESS(coap_sender_process, "CoAP Sender");
AUTOSTART_PROCESSES(&coap_sender_process);

static struct etimer timer;
static coap_endpoint_t receiver_1_ep;
static coap_endpoint_t receiver_2_ep;
static coap_message_t request[1];

static void
response_handler(coap_message_t *response)
{
  const uint8_t *payload;
  int len;

  if(response == NULL) {
    printf("CoAP request timed out\n");
    return;
  }

  len = coap_get_payload(response, &payload);

  printf("CoAP response: %.*s\n",
         len, len > 0 ? (const char *)payload : "");
}

PROCESS_THREAD(coap_sender_process, ev, data)
{
  PROCESS_BEGIN();

  printf("CoAP sender started\n");

  coap_endpoint_parse(RECEIVER_1,
                      strlen(RECEIVER_1),
                      &receiver_1_ep);

  coap_endpoint_parse(RECEIVER_2,
                      strlen(RECEIVER_2),
                      &receiver_2_ep);

  /* Allow receivers to initialize */
  etimer_set(&timer, 15 * CLOCK_SECOND);
  PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&timer));

  while(1) {

    printf("Sending LIGHT_ON to Receiver 1\n");

    coap_init_message(request,
                      COAP_TYPE_CON,
                      COAP_POST,
                      0);

    coap_set_header_uri_path(request, "light");

    coap_set_payload(request,
                     (uint8_t *)"LIGHT_ON",
                     strlen("LIGHT_ON"));

    COAP_BLOCKING_REQUEST(&receiver_1_ep,
                          request,
                          response_handler);

    printf("Sending LIGHT_ON to Receiver 2\n");

    coap_init_message(request,
                      COAP_TYPE_CON,
                      COAP_POST,
                      0);

    coap_set_header_uri_path(request, "light");

    coap_set_payload(request,
                     (uint8_t *)"LIGHT_ON",
                     strlen("LIGHT_ON"));

    COAP_BLOCKING_REQUEST(&receiver_2_ep,
                          request,
                          response_handler);

    etimer_set(&timer, SEND_INTERVAL);
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&timer));
  }

  PROCESS_END();
}