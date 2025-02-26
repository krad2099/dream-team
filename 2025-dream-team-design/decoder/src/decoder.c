/*********************** INCLUDES *************************/
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "mxc_device.h"
#include "status_led.h"
#include "board.h"
#include "mxc_delay.h"
#include "simple_flash.h"
#include "host_messaging.h"

#include "simple_uart.h"
#include "simple_crypto.h"  // Ensure we have HMAC functionality

/**********************************************************
 ******************* PRIMITIVE TYPES **********************
 **********************************************************/

#define timestamp_t uint64_t
#define channel_id_t uint32_t
#define decoder_id_t uint32_t
#define pkt_len_t uint16_t

/**********************************************************
 *********************** CONSTANTS ************************
 **********************************************************/

#define MAX_CHANNEL_COUNT 8
#define EMERGENCY_CHANNEL 0
#define FRAME_SIZE 64
#define HMAC_SIZE 32  // HMAC-SHA256 output size
#define DEFAULT_CHANNEL_TIMESTAMP 0xFFFFFFFFFFFFFFFF
#define FLASH_FIRST_BOOT 0xDEADBEEF
#define FLASH_SECRET_ADDR ((MXC_FLASH_MEM_BASE + MXC_FLASH_MEM_SIZE) - (3 * MXC_FLASH_PAGE_SIZE)) // Store secrets here

/**********************************************************
 *********** COMMUNICATION PACKET DEFINITIONS *************
 **********************************************************/

#pragma pack(push, 1)

typedef struct {
    channel_id_t channel;
    timestamp_t timestamp;
    uint8_t data[FRAME_SIZE];
    uint8_t hmac[HMAC_SIZE];
} frame_packet_t;

typedef struct {
    decoder_id_t decoder_id;
    timestamp_t start_timestamp;
    timestamp_t end_timestamp;
    channel_id_t channel;
    uint8_t hmac[HMAC_SIZE];
} subscription_update_packet_t;

typedef struct {
    channel_id_t channel;
    timestamp_t start;
    timestamp_t end;
} channel_info_t;

typedef struct {
    uint32_t n_channels;
    channel_info_t channel_info[MAX_CHANNEL_COUNT];
} list_response_t;

#pragma pack(pop)

/**********************************************************
 ******************** TYPE DEFINITIONS ********************
 **********************************************************/

typedef struct {
    bool active;
    channel_id_t id;
    timestamp_t start_timestamp;
    timestamp_t end_timestamp;
} channel_status_t;

typedef struct {
    uint32_t first_boot;
    channel_status_t subscribed_channels[MAX_CHANNEL_COUNT];
} flash_entry_t;

/**********************************************************
 ************************ GLOBALS *************************
 **********************************************************/

flash_entry_t decoder_status;
uint8_t secret_key[32];  // Store the secret key extracted from flash

/**********************************************************
 ******************* UTILITY FUNCTIONS ********************
 **********************************************************/

void load_secret_key() {
    flash_simple_read(FLASH_SECRET_ADDR, secret_key, 32);
}

/** @brief Checks whether the decoder is subscribed to a given channel
 *
 *  @param channel The channel number to be checked.
 *  @return 1 if the the decoder is subscribed to the channel.  0 if not.
*/
int is_subscribed(channel_id_t channel) {
    if (channel == EMERGENCY_CHANNEL) {
        return 1;
    }
    for (int i = 0; i < MAX_CHANNEL_COUNT; i++) {
        if (decoder_status.subscribed_channels[i].id == channel && decoder_status.subscribed_channels[i].active) {
            return 1;
        }
    }
    return 0;
}

/** @brief Verifies the HMAC signature of an incoming frame
 *
 *  @param frame The frame data structure.
 *  @return 1 if HMAC is valid, 0 otherwise.
*/
int verify_hmac(frame_packet_t *frame) {
    uint8_t computed_hmac[HMAC_SIZE];
    hmac_sha256(secret_key, 32, (uint8_t *)frame, sizeof(frame_packet_t) - HMAC_SIZE, computed_hmac);

    if (memcmp(frame->hmac, computed_hmac, HMAC_SIZE) == 0) {
        return 1;
    } else {
        print_error("HMAC verification failed\n");
        return 0;
    }
}

/**********************************************************
 ********************* CORE FUNCTIONS *********************
 **********************************************************/

/** @brief Updates the channel subscription.
 *
 *  @return 0 upon success, -1 if error.
*/
int update_subscription(pkt_len_t pkt_len, subscription_update_packet_t *update) {
    int i;

    if (update->channel == EMERGENCY_CHANNEL) {
        STATUS_LED_RED();
        print_error("Cannot subscribe to emergency channel\n");
        return -1;
    }

    // Verify HMAC of subscription update
    uint8_t computed_hmac[HMAC_SIZE];
    hmac_sha256(secret_key, 32, (uint8_t *)update, sizeof(subscription_update_packet_t) - HMAC_SIZE, computed_hmac);
    if (memcmp(update->hmac, computed_hmac, HMAC_SIZE) != 0) {
        STATUS_LED_RED();
        print_error("Subscription HMAC invalid\n");
        return -1;
    }

    for (i = 0; i < MAX_CHANNEL_COUNT; i++) {
        if (decoder_status.subscribed_channels[i].id == update->channel || !decoder_status.subscribed_channels[i].active) {
            decoder_status.subscribed_channels[i].active = true;
            decoder_status.subscribed_channels[i].id = update->channel;
            decoder_status.subscribed_channels[i].start_timestamp = update->start_timestamp;
            decoder_status.subscribed_channels[i].end_timestamp = update->end_timestamp;
            break;
        }
    }

    if (i == MAX_CHANNEL_COUNT) {
        STATUS_LED_RED();
        print_error("Max subscriptions reached\n");
        return -1;
    }

    flash_simple_erase_page(FLASH_STATUS_ADDR);
    flash_simple_write(FLASH_STATUS_ADDR, &decoder_status, sizeof(flash_entry_t));
    write_packet(SUBSCRIBE_MSG, NULL, 0);
    return 0;
}

/** @brief Processes a frame packet.
 *
 *  @return 0 if successful, -1 if the data is from an unsubscribed channel.
*/
int decode(pkt_len_t pkt_len, frame_packet_t *new_frame) {
    char output_buf[128] = {0};
    uint16_t frame_size = pkt_len - (sizeof(new_frame->channel) + sizeof(new_frame->timestamp) + HMAC_SIZE);
    channel_id_t channel = new_frame->channel;

    print_debug("Checking subscription\n");
    if (!is_subscribed(channel)) {
        STATUS_LED_RED();
        sprintf(output_buf, "Unsubscribed channel: %u\n", channel);
        print_error(output_buf);
        return -1;
    }

    if (!verify_hmac(new_frame)) {
        STATUS_LED_RED();
        print_error("Frame HMAC verification failed\n");
        return -1;
    }

    write_packet(DECODE_MSG, new_frame->data, frame_size);
    return 0;
}

/**********************************************************
 ************************ MAIN ****************************
 **********************************************************/

void init() {
    flash_simple_init();
    load_secret_key();

    flash_simple_read(FLASH_STATUS_ADDR, &decoder_status, sizeof(flash_entry_t));
    if (decoder_status.first_boot != FLASH_FIRST_BOOT) {
        decoder_status.first_boot = FLASH_FIRST_BOOT;
        memset(decoder_status.subscribed_channels, 0, sizeof(decoder_status.subscribed_channels));
        flash_simple_erase_page(FLASH_STATUS_ADDR);
        flash_simple_write(FLASH_STATUS_ADDR, &decoder_status, sizeof(flash_entry_t));
    }

    if (uart_init() < 0) {
        STATUS_LED_ERROR();
        while (1);
    }
}

int main(void) {
    init();
    print_debug("Decoder Booted!\n");

    while (1) {
        STATUS_LED_GREEN();
        msg_type_t cmd;
        uint8_t uart_buf[100];
        uint16_t pkt_len;

        if (read_packet(&cmd, uart_buf, &pkt_len) < 0) {
            STATUS_LED_ERROR();
            print_error("Failed to receive command\n");
            continue;
        }

        switch (cmd) {
            case LIST_MSG:
                list_channels();
                break;
            case DECODE_MSG:
                decode(pkt_len, (frame_packet_t *)uart_buf);
                break;
            case SUBSCRIBE_MSG:
                update_subscription(pkt_len, (subscription_update_packet_t *)uart_buf);
                break;
            default:
                print_error("Invalid command\n");
                break;
        }
    }
}
