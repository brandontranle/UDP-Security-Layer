#include "consts.h"
#include "io.h"
#include "libsecurity.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>

static int global_type = 0;
static char *global_hostname = NULL;

// Handshake state
static uint8_t *cached_client_hello = NULL;
static size_t cached_client_hello_size = 0;
static uint8_t *cached_server_hello = NULL;
static size_t cached_server_hello_size = 0;

// Server state tracking
static int client_hello_received = 0;
static int server_hello_sent = 0;

// Original server key
static EVP_PKEY *original_server_key = NULL;

void init_sec(int type, char *host)
{
    init_io();
    global_type = type;

    if (host != NULL)
    {
        global_hostname = strdup(host);
    }

    if (type == CLIENT)
    {
        // Client initialization
        generate_private_key();
        derive_public_key();
    }
    else if (type == SERVER)
    {
        // Server initialization
        load_certificate("server_cert.bin");
        load_private_key("server_key.bin");
        original_server_key = get_private_key();

        // Generate ephemeral key
        generate_private_key();
        derive_public_key();
    }
}

ssize_t input_sec(uint8_t *buf, size_t max_length)
{
    if (global_type == CLIENT)
    {
        // Client sending Client Hello
        if (cached_client_hello == NULL)
        {
            // Create Client Hello
            tlv *ch = create_tlv(CLIENT_HELLO);

            // Add nonce
            tlv *nn = create_tlv(NONCE);
            uint8_t nonce[NONCE_SIZE];
            generate_nonce(nonce, NONCE_SIZE);
            add_val(nn, nonce, NONCE_SIZE);
            add_tlv(ch, nn);

            // Add public key
            tlv *pk = create_tlv(PUBLIC_KEY);
            add_val(pk, public_key, pub_key_size);
            add_tlv(ch, pk);

            // Serialize Client Hello
            uint16_t len = serialize_tlv(buf, ch);

            // Cache Client Hello
            cached_client_hello = malloc(len);
            memcpy(cached_client_hello, buf, len);
            cached_client_hello_size = len;

            free_tlv(ch);

            return len;
        }
    }
    else if (global_type == SERVER)
    {
        // Server sending Server Hello after receiving Client Hello
        if (client_hello_received && !server_hello_sent && cached_server_hello != NULL)
        {
            size_t len = cached_server_hello_size;
            if (len > max_length)
            {
                len = max_length;
            }

            memcpy(buf, cached_server_hello, len);
            server_hello_sent = 1;

            return len;
        }
    }

    // Pass through to IO layer
    return input_io(buf, max_length);
}

void output_sec(uint8_t *buf, size_t length)
{
    if (global_type == SERVER && !client_hello_received)
    {
        // Check if this is a Client Hello
        tlv *msg = deserialize_tlv(buf, length);
        if (msg && msg->type == CLIENT_HELLO)
        {
            // Cache client hello
            cached_client_hello = malloc(length);
            memcpy(cached_client_hello, buf, length);
            cached_client_hello_size = length;

            // Extract client public key
            tlv *client_pubkey = get_tlv(msg, PUBLIC_KEY);
            if (client_pubkey)
            {
                load_peer_public_key(client_pubkey->val, client_pubkey->length);
            }

            free_tlv(msg);

            // Mark that we've received the client hello
            client_hello_received = 1;

            // Create Server Hello
            tlv *server_hello = create_tlv(SERVER_HELLO);

            // Step 1: Generate nonce
            uint8_t nonce[NONCE_SIZE];
            generate_nonce(nonce, NONCE_SIZE);

            // Add nonce to Server Hello
            tlv *nonce_tlv = create_tlv(NONCE);
            add_val(nonce_tlv, nonce, NONCE_SIZE);
            add_tlv(server_hello, nonce_tlv);

            // Step 2: Add certificate
            tlv *cert_tlv = create_tlv(CERTIFICATE);
            add_val(cert_tlv, certificate, cert_size);
            add_tlv(server_hello, cert_tlv);

            // Step 3: Add ephemeral public key
            tlv *pubkey_tlv = create_tlv(PUBLIC_KEY);
            add_val(pubkey_tlv, public_key, pub_key_size);
            add_tlv(server_hello, pubkey_tlv);

            // Step 4: Create handshake signature
            // Save ephemeral key
            EVP_PKEY *ephemeral_key = get_private_key();

            // Use server private key for signing
            set_private_key(original_server_key);

            // Prepare data to sign: Client-Hello + Nonce + Certificate + Public-Key
            size_t sign_data_len = cached_client_hello_size + NONCE_SIZE + cert_size + pub_key_size;
            uint8_t *sign_data = malloc(sign_data_len);

            size_t offset = 0;
            memcpy(sign_data, cached_client_hello, cached_client_hello_size);
            offset += cached_client_hello_size;
            memcpy(sign_data + offset, nonce, NONCE_SIZE);
            offset += NONCE_SIZE;
            memcpy(sign_data + offset, certificate, cert_size);
            offset += cert_size;
            memcpy(sign_data + offset, public_key, pub_key_size);

            // Sign the data
            uint8_t signature[72]; // Max ECDSA signature size
            size_t sig_len = sign(signature, sign_data, sign_data_len);

            // Add signature to Server Hello
            tlv *sig_tlv = create_tlv(HANDSHAKE_SIGNATURE);
            add_val(sig_tlv, signature, sig_len);
            add_tlv(server_hello, sig_tlv);

            // Free sign data
            free(sign_data);

            // Restore ephemeral key
            set_private_key(ephemeral_key);

            // Serialize Server Hello
            uint8_t server_hello_buf[4096];
            size_t server_hello_len = serialize_tlv(server_hello_buf, server_hello);

            // Cache Server Hello
            cached_server_hello = malloc(server_hello_len);
            memcpy(cached_server_hello, server_hello_buf, server_hello_len);
            cached_server_hello_size = server_hello_len;

            // Clean up
            free_tlv(server_hello);

            return; // Don't pass to output_io
        }

        if (msg)
        {
            free_tlv(msg);
        }
    }

    // Pass through to IO layer
    output_io(buf, length);
}

// Cleanup function
void cleanup_sec()
{
    if (cached_client_hello)
        free(cached_client_hello);
    if (cached_server_hello)
        free(cached_server_hello);
    if (global_hostname)
        free(global_hostname);
}