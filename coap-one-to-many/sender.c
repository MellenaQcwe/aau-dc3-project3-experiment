#include "contiki.h"
#include "coap-engine.h"
#include "coap-blocking-api.h"

#include <stdio.h>
#include <string.h>

#ifndef NUM_RECEIVERS
#define NUM_RECEIVERS 2
#endif

#ifndef NUM_COMMANDS
#define NUM_COMMANDS 100
#endif

#define SEND_INTERVAL (10 * CLOCK_SECOND)
#define START_DELAY   (15 * CLOCK_SECOND)

PROCESS(coap_sender_process, "Scalable CoAP Sender");
AUTOSTART_PROCESSES(&coap_sender_process);

static struct etimer timer;
static coap_endpoint_t endpoint;
static coap_message_t request[1];

static unsigned long success_count;
static unsigned long timeout_count;

static void
response_handler(coap_message_t *response)
{
  if(response == NULL) {
    timeout_count++;
    printf("RESULT,TIMEOUT\n");
  } else {
    success_count++;
    printf("RESULT,RESPONSE\n");
  }
}

PROCESS_THREAD(coap_sender_process, ev, data)
{
  static int command;
  static int receiver;
  static int mote_id;
  static char uri[80];
  static const char payload[] = "LIGHT_ON";

  PROCESS_BEGIN();

  printf("EXPERIMENT_START,receivers=%d,commands=%d\n",
         NUM_RECEIVERS, NUM_COMMANDS);

  etimer_set(&timer, START_DELAY);
  PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&timer));

  for(command = 1; command <= NUM_COMMANDS; command++) {

    for(receiver = 0; receiver < NUM_RECEIVERS; receiver++) {

      mote_id = receiver + 2;

      /*
       * Default Cooja native mote IPv6 addressing.
       * Confirm the addresses in your receiver logs.
       */
      snprintf(uri, sizeof(uri),
               "coap://[fe80::%x:%x:%x:%x]",
               0x200 + mote_id,
               mote_id,
               mote_id,
               mote_id);

      if(!coap_endpoint_parse(uri, strlen(uri), &endpoint)) {
        printf("ERROR,ENDPOINT,%d\n", mote_id);
        continue;
      }

      coap_init_message(request,
                        COAP_TYPE_CON,
                        COAP_POST,
                        0);

      coap_set_header_uri_path(request, "light");

      coap_set_payload(request,
                       (uint8_t *)payload,
                       sizeof(payload) - 1);

      printf("SEND,command=%d,receiver=%d\n",
             command, mote_id);

      COAP_BLOCKING_REQUEST(&endpoint,
                            request,
                            response_handler);
    }

    etimer_set(&timer, SEND_INTERVAL);
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&timer));
  }

  printf("EXPERIMENT_END,success=%lu,timeouts=%lu\n",
         success_count, timeout_count);

  PROCESS_END();
}