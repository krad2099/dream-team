/**
 * @file    decoder.c
 * @author  Dream Team
 * @brief   eCTF Decoder Design Implementation with Enhanced Security
 * @date    2025
 *
 *
 */

/*********************** INCLUDES *************************/
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "mxc_device.h"
#include "status_led.h"
#include "board.h"
#include "mxc_delay.h"
#include "simple_flash.h"
#include "host_messaging.h"
#include "simple_uart.h"

#ifdef CRYPTO_EXAMPLE
#include "simple_crypto.h"
#include "wolfssl/wolfcrypt/hmac.h"  // Added for HMAC verification
#include "wolfssl/wolfcrypt/sha256.h" // For SHA256 constants if needed
#endif  // CRYPTO_EXAMPLE

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
#define MAX_FRAME_LEN FRAME_SIZE   // Maximum allowed frame payload length
#define DEFAULT_CHANNEL_TIMESTAMP 0xFFFFFFFFFFFFFFFF
#define SIGNATURE_SIZE 32          // HMAC-SHA256 produces a 32-byte signature
// This is a canary value so we can confirm whether this decoder has booted before
#define FLASH_FIRST_BOOT 0xDEADBEEF

/**********************************************************
 ********************* STATE MACROS ***********************
 **********************************************************/

// Calculate the flash address where we will store channel info as the 2nd to last page available
#define FLASH_STATUS_ADDR ((MXC_FLASH_MEM_BASE + MXC_FLASH_MEM_SIZE) - (2 * MXC_FLASH_PAGE_SIZE))

/**********************************************************
 *********** COMMUNICATION PACKET DEFINITIONS *************
 **********************************************************/

#pragma pack(push, 1)
typedef struct {
    channel_id_t channel;
    timestamp_t timestamp;
    uint8_t data[FRAME_SIZE];  // Original fixed-size payload (not used in new decode)
} frame_packet_t;

typedef struct {
    decoder_id_t decoder_id;
    timestamp_t start_timestamp;
    timestamp_t end_timestamp;
    channel_id_t channel;
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
    uint32_t first_boot; // if set to FLASH_FIRST_BOOT, device has booted before.
    channel_status_t subscribed_channels[MAX_CHANNEL_COUNT];
} flash_entry_t;

/**********************************************************
 ************************ GLOBALS *************************
 **********************************************************/

flash_entry_t decoder_status;

#ifdef CRYPTO_EXAMPLE
// Static HMAC key for verifying message signatures.
// In production, replace this with a secure key retrieval mechanism.
static const uint8_t hmac_key[16] = {
    0x00, 0x11, 0x22, 0x33,
    0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb,
    0xcc, 0xdd, 0xee, 0xff
};
#endif

/**********************************************************
 ******************* UTILITY FUNCTIONS ********************
 **********************************************************/

/** @brief Checks whether the decoder is subscribed to a given channel.
 *
 *  @param channel The channel number to be checked.
 *  @return 1 if subscribed; 0 if not.
 */
int is_subscribed(channel_id_t channel) {
    if (channel == EMERGENCY_CHANNEL) {
        return 1;
    }
    for (int i = 0; i < MAX_CHANNEL_COUNT; i++) {
        if (decoder_status.subscribed_channels[i].id == channel &&
            decoder_status.subscribed_channels[i].active) {
            return 1;
        }
    }
    return 0;
}

/**********************************************************
 ********************* CORE FUNCTIONS *********************
 **********************************************************/

/** @brief Lists out the actively subscribed channels over UART.
 *
 *  @return 0 if successful.
 */
int list_channels() {
    list_response_t resp;
    pkt_len_t len;
    resp.n_channels = 0;
    for (uint32_t i = 0; i < MAX_CHANNEL_COUNT; i++) {
        if (decoder_status.subscribed_channels[i].active) {
            resp.channel_info[resp.n_channels].channel = decoder_status.subscribed_channels[i].id;
            resp.channel_info[resp.n_channels].start = decoder_status.subscribed_channels[i].start_timestamp;
            resp.channel_info[resp.n_channels].end = decoder_status.subscribed_channels[i].end_timestamp;
            resp.n_channels++;
        }
    }
    len = sizeof(resp.n_channels) + (sizeof(channel_info_t) * resp.n_channels);
    write_packet(LIST_MSG, &resp, len);
    return 0;
}

/** @brief Updates the channel subscription for a subset of channels.
 *
 *  @param pkt_len The length of the incoming packet.
 *  @param update A pointer to an array of channel_update structs.
 *
 *  @return 0 on success; -1 on error.
 */
int update_subscription(pkt_len_t pkt_len, subscription_update_packet_t *update) {
    int i;
    if (update->channel == EMERGENCY_CHANNEL) {
        STATUS_LED_RED();
        print_error("Failed to update subscription - cannot subscribe to emergency channel\n");
        return -1;
    }
    for (i = 0; i < MAX_CHANNEL_COUNT; i++) {
        if (decoder_status.subscribed_channels[i].id == update->channel ||
            !decoder_status.subscribed_channels[i].active) {
            decoder_status.subscribed_channels[i].active = true;
            decoder_status.subscribed_channels[i].id = update->channel;
            decoder_status.subscribed_channels[i].start_timestamp = update->start_timestamp;
            decoder_status.subscribed_channels[i].end_timestamp = update->end_timestamp;
            break;
        }
    }
    if (i == MAX_CHANNEL_COUNT) {
        STATUS_LED_RED();
        print_error("Failed to update subscription - max subscriptions installed\n");
        return -1;
    }
    flash_simple_erase_page(FLASH_STATUS_ADDR);
    flash_simple_write(FLASH_STATUS_ADDR, &decoder_status, sizeof(flash_entry_t));
    write_packet(SUBSCRIBE_MSG, NULL, 0);
    return 0;
}

/**
 * @brief Processes a packet containing frame data with HMAC-SHA256 signature.
 *
 * Packet layout:
 * [channel (4 bytes)] [timestamp (8 bytes)] [frame payload (variable, <= 64 bytes)]
 * [HMAC-SHA256 signature (32 bytes)]
 *
 * @param pkt_len Length of the entire packet.
 * @param packet Pointer to the packet data.
 *
 * @return 0 if successful; -1 on error.
 */
int decode(pkt_len_t pkt_len, uint8_t *packet) {
#ifdef CRYPTO_EXAMPLE
    // Minimum packet length: header (12 bytes) + signature (32 bytes) = 44 bytes.
    if (pkt_len < (sizeof(channel_id_t) + sizeof(timestamp_t) + SIGNATURE_SIZE)) {
        STATUS_LED_RED();
        print_error("Packet too short for valid decoding\n");
        return -1;
    }

    const int header_len = sizeof(channel_id_t) + sizeof(timestamp_t); // 12 bytes
    int payload_len = pkt_len - SIGNATURE_SIZE;  // Data that was signed
    int frame_data_len = payload_len - header_len;
    if (frame_data_len > MAX_FRAME_LEN) {
        STATUS_LED_RED();
        print_error("Frame payload length exceeds maximum allowed\n");
        return -1;
    }

    // Extract channel and timestamp from header
    channel_id_t channel;
    timestamp_t timestamp;
    memcpy(&channel, packet, sizeof(channel_id_t));
    memcpy(&timestamp, packet + sizeof(channel_id_t), sizeof(timestamp_t));

    // Compute HMAC-SHA256 over header + frame payload (the signed part)
    uint8_t computed_signature[SIGNATURE_SIZE];
    int ret = wc_HmacSha256(hmac_key, sizeof(hmac_key), packet, payload_len, computed_signature);
    if (ret != 0) {
        STATUS_LED_RED();
        print_error("HMAC computation failed\n");
        return -1;
    }

    // Compare computed signature with received signature (last 32 bytes)
    uint8_t *received_signature = packet + pkt_len - SIGNATURE_SIZE;
    if (memcmp(computed_signature, received_signature, SIGNATURE_SIZE) != 0) {
        STATUS_LED_RED();
        print_error("HMAC signature verification failed\n");
        return -1;
    }

    print_debug("HMAC signature verified successfully\n");

    // Check subscription for the channel
    print_debug("Checking subscription\n");
    if (!is_subscribed(channel)) {
        STATUS_LED_RED();
        char output_buf[128];
        sprintf(output_buf, "Receiving unsubscribed channel data.  %u\n", channel);
        print_error(output_buf);
        return -1;
    }

    print_debug("Subscription Valid\n");
    // Pass the frame payload (excluding header and signature) to the host
    uint8_t *frame_payload = packet + header_len;
    write_packet(DECODE_MSG, frame_payload, frame_data_len);
    return 0;
#else
    return -1;
#endif
}

/** @brief Initializes peripherals for system boot.
 */
void init() {
    int ret;
    flash_simple_init();
    flash_simple_read(FLASH_STATUS_ADDR, &decoder_status, sizeof(flash_entry_t));
    if (decoder_status.first_boot != FLASH_FIRST_BOOT) {
        print_debug("First boot.  Setting flash...\n");
        decoder_status.first_boot = FLASH_FIRST_BOOT;
        channel_status_t subscription[MAX_CHANNEL_COUNT];
        for (int i = 0; i < MAX_CHANNEL_COUNT; i++){
            subscription[i].start_timestamp = DEFAULT_CHANNEL_TIMESTAMP;
            subscription[i].end_timestamp = DEFAULT_CHANNEL_TIMESTAMP;
            subscription[i].active = false;
        }
        memcpy(decoder_status.subscribed_channels, subscription, MAX_CHANNEL_COUNT * sizeof(channel_status_t));
        flash_simple_erase_page(FLASH_STATUS_ADDR);
        flash_simple_write(FLASH_STATUS_ADDR, &decoder_status, sizeof(flash_entry_t));
    }
    ret = uart_init();
    if (ret < 0) {
        STATUS_LED_ERROR();
        while (1);
    }
}

#ifdef CRYPTO_EXAMPLE
void crypto_example(void) {
    char *data = "Crypto Example!";
    uint8_t ciphertext[BLOCK_SIZE];
    uint8_t key[KEY_SIZE];
    uint8_t hash_out[HASH_SIZE];
    uint8_t decrypted[BLOCK_SIZE];
    char output_buf[128] = {0};
    bzero(key, BLOCK_SIZE);
    encrypt_sym((uint8_t*)data, BLOCK_SIZE, key, ciphertext);
    print_debug("Encrypted data: \n");
    print_hex_debug(ciphertext, BLOCK_SIZE);
    hash(ciphertext, BLOCK_SIZE, hash_out);
    print_debug("Hash result: \n");
    print_hex_debug(hash_out, HASH_SIZE);
    decrypt_sym(ciphertext, BLOCK_SIZE, key, decrypted);
    sprintf(output_buf, "Decrypted message: %s\n", decrypted);
    print_debug(output_buf);
}
#endif  // CRYPTO_EXAMPLE

int main(void) {
    char output_buf[128] = {0};
    uint8_t uart_buf[128];  // Increased buffer size to accommodate variable packet lengths
    msg_type_t cmd;
    int result;
    uint16_t pkt_len;
    init();
    print_debug("Decoder Booted!\n");
    while (1) {
        print_debug("Ready\n");
        STATUS_LED_GREEN();
        result = read_packet(&cmd, uart_buf, &pkt_len);
        if (result < 0) {
            STATUS_LED_ERROR();
            print_error("Failed to receive cmd from host\n");
            continue;
        }
        switch (cmd) {
            case LIST_MSG:
                STATUS_LED_CYAN();
#ifdef CRYPTO_EXAMPLE
                crypto_example();
#endif
                boot_flag();
                list_channels();
                break;
            case DECODE_MSG:
                STATUS_LED_PURPLE();
                // Pass the raw UART buffer to decode
                decode(pkt_len, uart_buf);
                break;
            case SUBSCRIBE_MSG:
                STATUS_LED_YELLOW();
                update_subscription(pkt_len, (subscription_update_packet_t *)uart_buf);
                break;
            default:
                STATUS_LED_ERROR();
                sprintf(output_buf, "Invalid Command: %c\n", cmd);
                print_error(output_buf);
                break;
        }
    }
}
