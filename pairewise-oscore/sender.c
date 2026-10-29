#include "contiki.h"
#include "coap-engine.h"
#include "coap-blocking-api.h"
#include "oscore.h"

#include <stdio.h>
#include <string.h>

#define NUM_RECEIVERS 2
#define NUM_COMMANDS 100

#define SEND_INTERVAL (10 * CLOCK_SECOND)
#define START_DELAY   (15 * CLOCK_SECOND)

PROCESS(oscore_sender_process, "Pairwise OSCORE Sender");
AUTOSTART_PROCESSES(&oscore_sender_process);

static struct etimer timer;
static coap_endpoint_t endpoints[NUM_RECEIVERS];
static oscore_ctx_t contexts[NUM_RECEIVERS];
static coap_message_t request[1];

/* Demonstration keys only: do not use in production. */
static const uint8_t master_secrets[NUM_RECEIVERS][16] = {
  {
    0x01, 0x02, 0x03, 0x04,
    0x05, 0x06, 0x07, 0x08,
    0x09, 0x0a, 0x0b, 0x0c,
    0x0d, 0x0e, 0x0f, 0x10
  },
  {
    0x11, 0x12, 0x13, 0x14,
    0x15, 0x16, 0x17, 0x18,
    0x19, 0x1a, 0x1b, 0x1c,
    0x1d, 0x1e, 0x1f, 0x20
  }
};

static const uint8_t client_id[] = { 0x01 };
static const uint8_t server_ids[NUM_RECEIVERS][1] = {
  { 0x02 },
  { 0x03 }
};

static unsigned long response_count;
static unsigned long timeout_count;

static void
response_handler(coap_message_t *response)
{
  if(response == NULL) {
    timeout_count++;
    printf("RESULT,TIMEOUT\n");
  } else {
    response_count++;
    printf("RESULT,RESPONSE\n");
  }
}

PROCESS_THREAD(oscore_sender_process, ev, data)
{
  static int i;
  static int command;
  static char uri[80];
  static const char payload[] = "LIGHT_ON";

  PROCESS_BEGIN();

  printf("PAIRWISE_OSCORE_START\n");

  for(i = 0; i < NUM_RECEIVERS; i++) {

    int mote_id = i + 2;

    snprintf(uri, sizeof(uri),
             "coap://[fe80::%x:%x:%x:%x]",
             0x200 + mote_id,
             mote_id,
             mote_id,
             mote_id);

    if(!coap_endpoint_parse(uri, strlen(uri), &endpoints[i])) {
      printf("ERROR,ENDPOINT,%d\n", mote_id);
      PROCESS_EXIT();
    }

    oscore_derive_ctx(
      &contexts[i],
      master_secrets[i],
      sizeof(master_secrets[i]),
      NULL, 0,
      10,
      client_id, sizeof(client_id),
      server_ids[i], sizeof(server_ids[i]),
      NULL, 0
    );

    if(!oscore_ep_ctx_set_association(
         &endpoints[i], "light", &contexts[i])) {
      printf("ERROR,ASSOCIATION,%d\n", mote_id);
      PROCESS_EXIT();
    }

    printf("OSCORE_CONTEXT_READY,receiver=%d\n", mote_id);
  }

  etimer_set(&timer, START_DELAY);
  PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&timer));

  for(command = 1; command <= NUM_COMMANDS; command++) {

    for(i = 0; i < NUM_RECEIVERS; i++) {

      coap_init_message(
        request,
        COAP_TYPE_CON,
        COAP_POST,
        0
      );

      coap_set_header_uri_path(request, "light");

      coap_set_payload(
        request,
        (uint8_t *)payload,
        sizeof(payload) - 1
      );

      printf("OSCORE_SEND,command=%d,receiver_id=%d\n", command, i + 2);

      COAP_BLOCKING_REQUEST(
          &endpoints[i],
          request,
          response_handler
      );
    }

    etimer_set(&timer, SEND_INTERVAL);
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&timer));
  }

  printf("PAIRWISE_OSCORE_END,receivers=%d,responses=%lu,timeouts=%lu\n",
         NUM_RECEIVERS, response_count, timeout_count);

  PROCESS_END();
}