#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "contiki.h"
#include "contiki-net.h"
#include "coap-engine.h"
#include "coap-callback-api.h"

#include "oscore.h"

/* Log configuration */
#include "coap-log.h"
#define LOG_MODULE "App"
#define LOG_LEVEL  LOG_LEVEL_APP

#define SERVER_EP "coap://[fe80::201:1:1:1]"

#define TOGGLE_INTERVAL 10

static const uint8_t master_secret[16] = {
  0x01, 0x02, 0x03, 0x04,
  0x05, 0x06, 0x07, 0x08,
  0x09, 0x0a, 0x0b, 0x0c,
  0x0d, 0x0e, 0x0f, 0x10
};

static const uint8_t salt[8] = {
  0x9e, 0x7c, 0xa9, 0x22,
  0x23, 0x78, 0x63, 0x40
};

static const uint8_t sender_id[1] = { 0x25 };
static const uint8_t receiver_id[1] = { 0x52 };
static const uint8_t group_id[3] = { 0x44, 0x61, 0x6c };

static const uint8_t client_private_key[32] = {
  0xE8, 0x98, 0x69, 0xAF, 0xA7, 0x69, 0x87, 0xBC,
  0xBC, 0xBF, 0xE3, 0x10, 0xB6, 0xFA, 0xE8, 0x6E,
  0x31, 0x50, 0x64, 0xC0, 0x76, 0x93, 0x32, 0x28,
  0x48, 0xF2, 0x24, 0x15, 0x43, 0x07, 0xAE, 0xF9
};
static const uint8_t client_public_key[64] = {
  0xCA,0x37,0x63,0x38,0x99,0x87,0x8F,0xD0,
  0x32,0xA6,0xCA,0x20,0xBF,0xE3,0x45,0x09,
  0x88,0x02,0x91,0x6D,0xB3,0xD2,0xAA,0xF5,
  0xC7,0xAA,0x4F,0x06,0x52,0xF7,0x17,0x74,
  0xEB,0x7D,0xAB,0x8B,0x46,0x49,0x03,0xF5,
  0xE2,0x67,0x75,0x4E,0x76,0x04,0x79,0x93,
  0x25,0x97,0x92,0x06,0x48,0x48,0x3C,0xE0,
  0xD3,0x50,0xE6,0xE4,0x96,0x4E,0x93,0xDD
};
static const uint8_t server_public_key[64] = {
  0x4C,0x04,0x3D,0xCB,0xA7,0xDC,0x9B,0x21,
  0x39,0xF7,0x49,0x7C,0x03,0x0F,0x4B,0xE1,
  0x3B,0xB6,0x62,0xD3,0x62,0x4C,0xA5,0x5D,
  0x8D,0x96,0xEB,0x40,0xD9,0xB0,0x33,0x6F,
  0x67,0xEB,0x2F,0xB7,0x26,0x92,0x71,0xEB,
  0x04,0x9E,0xC6,0x8A,0xA9,0x9B,0xB1,0x11,
  0x08,0x45,0xA0,0x20,0xC6,0x27,0x94,0x1B,
  0x37,0x6F,0x03,0xD9,0xB0,0x49,0x81,0x89
};

static oscore_ctx_t context;

PROCESS(er_example_client, "Erbium Example Client");
AUTOSTART_PROCESSES(&er_example_client);

static struct etimer et;

static uint8_t cur_token[] = {0,0,0,0,0,0,0,0};//for incremental updates
const uint8_t *token_next(void) 
{
  uint8_t i;
  for(i = sizeof(cur_token); i-- > 0; )
  {
    if (cur_token[i] < 255)
    {//just increment the last digit
      cur_token[i]++;
      break;
    }
    else
    {
      if (i == 0)
      {//total_overflow
        memset(cur_token, 0, sizeof(cur_token));
	break;
      }
      cur_token[i] = 0; //overflow this digit, increment the higher one
      continue;
    }
  }
  return (const uint8_t *)(cur_token);
}

/* Example URIs that can be queried. */
#define NUMBER_OF_URLS 2
/* leading and ending slashes only for demo purposes, get cropped automatically when setting the Uri-Path */
char *service_urls[NUMBER_OF_URLS] =
{ ".well-known/core", "/test/hello" };

/* This function is will be passed to COAP_BLOCKING_REQUEST() to handle responses. */
void
client_chunk_handler(coap_message_t *response)
{
  const uint8_t *chunk;

  int len = coap_get_payload(response, &chunk);

  printf("|%.*s", len, (char *)chunk);
}

/*This function will be called when the response arrives or the timeout expires*/
void my_callback_f(coap_callback_request_state_t *callback_state)
{
  printf("Callback called!\n");
  return;
}

PROCESS_THREAD(er_example_client, ev, data)
{
  static coap_endpoint_t server_ep;
  static coap_callback_request_state_t my_callback_request_state;
  static coap_message_t request[1];

  PROCESS_BEGIN();

  LOG_INFO("TEST: Before CoAP initialization\n");
  coap_engine_init();
  LOG_INFO("TEST: CoAP initialized successfully\n");

  LOG_INFO("CHECKPOINT 1: Client process started\n");
  int endpoint_result =
    coap_endpoint_parse(SERVER_EP, strlen(SERVER_EP), &server_ep);
  LOG_INFO("CHECKPOINT 2: Endpoint parse result = %d\n",
           endpoint_result);

  LOG_INFO("CHECKPOINT 3: Before oscore_derive_ctx\n");
  oscore_derive_ctx(
    &context,
    master_secret, sizeof(master_secret),
    salt, sizeof(salt),
    10,
    sender_id, sizeof(sender_id),
    receiver_id, sizeof(receiver_id),
    group_id, sizeof(group_id),
    group_id
  );
  LOG_INFO("CHECKPOINT 4: After oscore_derive_ctx\n");

  LOG_INFO("CHECKPOINT 5: Before oscore_add_group_keys\n");
  oscore_add_group_keys(
    &context,
    client_public_key,
    client_private_key,
    server_public_key,
    COSE_Algorithm_ES256,
    COSE_Elliptic_Curve_P256
  );
  LOG_INFO("CHECKPOINT 6: After oscore_add_group_keys\n");

  LOG_INFO("TIMER TEST: Before etimer_set\n");
  etimer_set(&et, 10 * CLOCK_SECOND);
  LOG_INFO("TIMER TEST: After etimer_set\n");

  while(1) {
    PROCESS_WAIT_EVENT();

    if(ev == PROCESS_EVENT_TIMER && data == &et) {

      LOG_INFO("TEST A.1: Timer fired\n");

      coap_init_message(request, COAP_TYPE_CON, COAP_POST, 0);

      coap_set_header_uri_path(request, "test/post");

      static const char payload[] = "Plain CoAP test";

      coap_set_payload(
        request,
        (uint8_t *)payload,
        sizeof(payload) - 1
      );

      coap_set_token(request, token_next(), 8);

      LOG_INFO("TEST A.2: Before coap_send_request\n");

      coap_send_request(
        &my_callback_request_state,
        &server_ep,
        request,
        my_callback_f
      );

      LOG_INFO("TEST A.3: After coap_send_request\n");

      break;
    }
  }

  PROCESS_END();
}
