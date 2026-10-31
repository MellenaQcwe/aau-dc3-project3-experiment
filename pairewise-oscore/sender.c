#include "contiki.h"
#include "coap-engine.h"
#include "coap-blocking-api.h"
#include "oscore.h"

#include <stdio.h>
#include <string.h>

#define NUM_RECEIVERS 8
#define NUM_COMMANDS 100

static int current_receiver_id;

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
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10
  },
  {
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20
  },
  {
    0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30
  },
  {
    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40
  },
  {
    0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50
  },
  {
    0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x60
  },
  {
    0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70
  },
  {
    0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x80
  }
};

static const uint8_t client_id[] = { 0x01 };
static const uint8_t server_ids[NUM_RECEIVERS][1] = {
  { 0x02 },
  { 0x03 },
  { 0x04 },
  { 0x05 },
  { 0x06 },
  { 0x07 },
  { 0x08 },
  { 0x09 }
};

static unsigned long response_count;
static unsigned long timeout_count;

static void
response_handler(coap_message_t *response)
{
  const uint8_t *payload = NULL;
  int payload_len;

  if(response == NULL) {
    timeout_count++;
    printf("OSCORE_TIMEOUT,receiver=%d\n",
           current_receiver_id);
    return;
  }

  if(response->code == OSCORE_DECRYPTION_ERROR) {
    printf("OSCORE_DECRYPTION_FAILED,receiver=%d\n",
          current_receiver_id);
    return;
  }

  payload_len = coap_get_payload(response, &payload);
  printf("OSCORE_RESPONSE_RECEIVED,receiver=%d,code=%u,payload=%.*s\n",
         current_receiver_id,
         response->code,
         payload_len,
         (const char *)payload);

  response_count++;
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

      current_receiver_id = i + 2;
      printf("OSCORE_REQUEST_SEND,command=%d,receiver_id=%d\n", command, current_receiver_id);

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
         (current_receiver_id - 1), response_count, timeout_count);

  PROCESS_END();
}