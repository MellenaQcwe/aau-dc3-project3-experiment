#include "contiki.h"
#include "coap-engine.h"
#include "coap-blocking-api.h"
#include "oscore.h"

#include <stdio.h>
#include <string.h>

#define NUM_RECEIVERS 32
#define NUM_COMMANDS 100
#define MASTER_SECRET_LEN 16

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
static uint8_t master_secrets[NUM_RECEIVERS][MASTER_SECRET_LEN];
static uint8_t server_ids[NUM_RECEIVERS][1];

static const uint8_t client_id[] = { 0x01 };

static void
initialize_receiver_credentials(void)
{
  int i;
  int j;

  for(i = 0; i < NUM_RECEIVERS; i++) {

    uint8_t receiver_id = (uint8_t)(i + 2);

    server_ids[i][0] = receiver_id;

    for(j = 0; j < MASTER_SECRET_LEN; j++) {
      master_secrets[i][j] =
        (uint8_t)((j + 1) ^ receiver_id);
    }

    printf("OSCORE_CREDENTIALS_INITIALIZATION...,receiver=%d.server_id=%02x,master_secret=", receiver_id, server_ids[i][0]);
    for(j = 0; j < MASTER_SECRET_LEN; j++) {
      printf("%02x", master_secrets[i][j]);
    }
    printf("\n");
  }
}

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

  // Handle Errors
  if(response->code == OSCORE_DECRYPTION_ERROR) {
    printf("OSCORE_DECRYPTION_FAILED,receiver=%d\n",
          current_receiver_id);
    return;
  }
  if(response->code == UNAUTHORIZED_4_01) {
    printf("OSCORE_AUTHORIZATION_FAILED,receiver=%d\n",
          current_receiver_id);
    return;
  }

  // Handle Success
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

  initialize_receiver_credentials();

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