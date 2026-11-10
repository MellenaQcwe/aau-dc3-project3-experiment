#include "contiki.h"
#include "coap-engine.h"

#include <string.h>

#ifdef PROCESSING_TIME
#include "rtimer.h"
unsigned long _processing_time_start = 0;
unsigned long _processing_time_stop = 0;
#endif

/* Log configuration */
#include "sys/log.h"
#define LOG_MODULE "App"
#define LOG_LEVEL LOG_LEVEL_APP

static void res_post_put_handler(coap_message_t *request, coap_message_t *response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset);

RESOURCE(res_post,
         "",
         NULL,
         res_post_put_handler,
         res_post_put_handler,
         NULL);

static void
res_post_put_handler(coap_message_t *request,
                     coap_message_t *response,
                     uint8_t *buffer,
                     uint16_t preferred_size,
                     int32_t *offset)
{
   LOG_INFO("CHECKPOINT: LIGHT_ON handler entered\n");
#ifdef PROCESSING_TIME
  _processing_time_stop = RTIMER_NOW();
  printf("p: %lu\n",
         (_processing_time_stop - _processing_time_start));
#endif
  LOG_INFO("SERVER CHECKPOINT 1: POST handler entered\n");
  const uint8_t *payload = NULL;
  int payload_len = coap_get_payload(request, &payload);
  LOG_INFO("SERVER CHECKPOINT 2: Payload length = %d\n", payload_len);

  LOG_INFO("SERVER: Light command received\n");

  if(payload != NULL &&
     payload_len == 8 &&
     memcmp(payload, "LIGHT_ON", 8) == 0) {

    LOG_INFO("SERVER: LIGHT_ON executed\n");

    coap_set_status_code(response, CHANGED_2_04);

    static const char reply[] = "OK";

    coap_set_payload(
        response,
        (uint8_t *)reply,
        sizeof(reply) - 1
    );
    LOG_INFO("SERVER CHECKPOINT 3: POST handler completed\n");

  } else {

    LOG_WARN("SERVER: Invalid light command\n");

    coap_set_status_code(response, BAD_REQUEST_4_00);
  }

#ifdef PROCESSING_TIME
  _processing_time_start = RTIMER_NOW();
#endif
}
