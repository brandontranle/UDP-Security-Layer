#include "consts.h"
#include "io.h"
#include "libsecurity.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>



/* 
To start the handshake procedure, the client will send a Client Hello message. 
This message contains a random value (called a nonce). 
Generate a public/private key pair and send the public key. 
Make sure to cache the entire Client Hello message-you’ll need it for another step.
*/

static size_t client_nonce_size = 0;
static uint8_t *cached_client_hello = NULL;
static size_t cached_client_hello_size = 0;
int global_type = 0;


static void client_send_hello(uint8_t* buf) {
    // Create CLIENT_HELLO TLV
    tlv *ch = create_tlv(CLIENT_HELLO);
    fprintf(stderr, "CLIENT: Created CLIENT_HELLO TLV with type 0x%02x\n", ch->type);

    // Generate nonce (32 bytes as specified)
    uint8_t client_nonce[NONCE_SIZE];
    generate_nonce(client_nonce, NONCE_SIZE);
    client_nonce_size = NONCE_SIZE;
    
    // Create NONCE TLV (type 0x01)
    tlv *nonce_tlv = create_tlv(NONCE);
    add_val(nonce_tlv, client_nonce, NONCE_SIZE);
    add_tlv(ch, nonce_tlv);

    
    // Create PUBLIC_KEY TLV (type 0x02)
    tlv *pubkey_tlv = create_tlv(PUBLIC_KEY);
    add_val(pubkey_tlv, public_key, pub_key_size);
    add_tlv(ch, pubkey_tlv);
    
    // Serialize and send CLIENT_HELLO
    uint8_t buffer[4096];
    uint16_t len = serialize_tlv(buf, ch);
    
    // Cache the CLIENT_HELLO message for later use (as specified in instructions)
    cached_client_hello = malloc(len);
    memcpy(cached_client_hello, buffer, len);
    cached_client_hello_size = len;
    
    // Send to output
    output_io(buf, len);
    
    // Clean up
    free_tlv(ch);
    
    // Debug output
    fprintf(stderr, "CLIENT: Sent CLIENT_HELLO\n");
}


/*
static void server_handle_client_hello() {
    
    // Deserialize CLIENT_HELLO
    deserialize_tlv(cached_client_hello, cached_client_hello_size);

    // Construct Server Hello
    tlv *server_hello = create_tlv(SERVER_HELLO);
    fprintf(stderr, "SERVER: Created SERVER_HELLO TLV with type 0x%02x\n", server_hello->type);

    // Generate nonce (32 bytes as specified)
    uint8_t *server_nonce = malloc(NONCE_SIZE);
    generate_nonce(server_nonce, NONCE_SIZE);
    



}
*/


void init_sec(int type, char* host) {
    init_io();
    global_type = type;
    

    if (type == CLIENT) { 
            generate_private_key();
            derive_public_key();
    }

    



}

ssize_t input_sec(uint8_t* buf, size_t max_length) {

    // If we haven't sent the CLIENT_HELLO message yet, do so
    if (cached_client_hello == NULL && global_type == CLIENT) {
        // create CLIENT_HELLO TLV
        tlv *ch = create_tlv(CLIENT_HELLO);
        fprintf(stderr, "CLIENT: Created CLIENT_HELLO TLV with type 0x%02x\n", ch->type);

        // add nonce
        tlv* nn = create_tlv(NONCE);
        uint8_t nonce[NONCE_SIZE];
        generate_nonce(nonce, NONCE_SIZE);
        add_val(nn, nonce, NONCE_SIZE);
        add_tlv(ch, nn);

        // add public key
        tlv* pk = create_tlv(PUBLIC_KEY);
        add_val(pk, public_key, pub_key_size);
        add_tlv(ch, pk);

        uint16_t len = serialize_tlv(buf, ch);

        cached_client_hello = malloc(len);
        memcpy(cached_client_hello, buf, len);
        cached_client_hello_size = len;

        free_tlv(ch);

        return len;
    }


    return input_io(buf, max_length);
}

void output_sec(uint8_t* buf, size_t length) {
    output_io(buf, length);
}
