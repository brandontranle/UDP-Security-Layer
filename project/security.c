#include "consts.h"
#include "io.h"
#include "libsecurity.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>

#define IN_CLIENT_HELLO 0
#define IN_SERVER_HELLO 1
#define IN_CLIENT_FINISHED 2
#define IN_SERVER_FINISHED 3
#define HANDSHAKE_DONE 4

static uint8_t *client_nonce = NULL;
static size_t client_nonce_size = 0;
static uint8_t *server_nonce = NULL;
static size_t server_nonce_size = 0;
static uint8_t *cached_client_hello = NULL;
static size_t cached_client_hello_size = 0;
static uint8_t *cached_server_hello = NULL;
static size_t cached_server_hello_size = 0;
static uint8_t *cached_finished = NULL;
static size_t cached_finished_size = 0;

// State tracking
static int client_hello_received = 0;
static int server_hello_received = 0;
static int server_hello_sent = 0;
static int finished_sent = 0;
static int finished_received = 0;
static int handshake_complete = 0;

bool client_hello_received = false;
bool server_hello_received = false;

void init_sec(int type, char* host) {
    init_io();
    global_type = type;
    
    if (type == CLIENT) {
        global_hs_state = IN_CLIENT_HELLO;
        generate_private_key();
        derive_public_key();
        // Client needs to load CA public key to verify server certificate
        load_ca_public_key("ca_public_key.bin");
        // Store expected DNS name for verification
        if (host) {
            expected_dns_name = strdup(host);
        }
    } else if (type == SERVER) {
        global_hs_state = IN_SERVER_HELLO;
        load_certificate("server_cert.bin");
        load_private_key("server_key.bin");
        derive_public_key();
    }
}

// Client processes Server Hello and generates Finished message
static void client_process_server_hello(uint8_t* buf, size_t length) {
    // Cache the server hello
    cached_server_hello = malloc(length);
    memcpy(cached_server_hello, buf, length);
    cached_server_hello_size = length;
    
    // Parse the server hello to extract required components
    tlv *server_hello = deserialize_tlv(buf, length);
    if (!server_hello || server_hello->type != SERVER_HELLO) {
        exit(6); // Unexpected message
    }
    
    // Extract certificate from server hello
    tlv *cert_tlv = get_tlv(server_hello, CERTIFICATE);
    if (!cert_tlv) {
        exit(6); // Invalid message format
    }
    
    // Parse certificate to access its components
    tlv *certificate = deserialize_tlv(cert_tlv->val, cert_tlv->length);
    if (!certificate) {
        exit(6); // Invalid certificate
    }
    
    // Extract DNS name from certificate
    tlv *dns_name = get_tlv(certificate, DNS_NAME);
    if (!dns_name) {
        exit(6); // Invalid certificate format
    }
    
    // Extract server public key from certificate
    tlv *server_pubkey = get_tlv(certificate, PUBLIC_KEY);
    if (!server_pubkey) {
        exit(6); // Invalid certificate format
    }
    
    // Extract certificate signature
    tlv *cert_sig = get_tlv(certificate, SIGNATURE);
    if (!cert_sig) {
        exit(6); // Invalid certificate format
    }
    
    // Verify certificate was signed by CA
    load_ca_public_key("ca_public_key.bin");
    
    // Prepare data for verification (DNS-Name + Public-Key)
    uint8_t *cert_data = malloc(dns_name->length + server_pubkey->length);
    memcpy(cert_data, dns_name->val, dns_name->length);
    memcpy(cert_data + dns_name->length, server_pubkey->val, server_pubkey->length);
    
    if (!verify(cert_sig->val, cert_sig->length, cert_data, dns_name->length + server_pubkey->length, ec_ca_public_key)) {
        free(cert_data);
        exit(1); // Bad certificate
    }
    free(cert_data);
    
    // Verify DNS name matches expected hostname
    if (global_hostname) {
        char *cert_hostname = malloc(dns_name->length + 1);
        memcpy(cert_hostname, dns_name->val, dns_name->length);
        cert_hostname[dns_name->length] = '\0';
        
        if (strcmp(cert_hostname, global_hostname) != 0) {
            free(cert_hostname);
            exit(2); // Bad DNS name
        }
        free(cert_hostname);
    }
    
    // Extract server's ephemeral public key from Server Hello
    tlv *server_eph_pubkey = get_tlv(server_hello, PUBLIC_KEY);
    if (!server_eph_pubkey) {
        exit(6); // Invalid Server Hello format
    }
    
    // Extract nonce from Server Hello
    tlv *server_nonce = get_tlv(server_hello, NONCE);
    if (!server_nonce) {
        exit(6); // Invalid Server Hello format
    }
    
    // Extract signature from Server Hello
    tlv *handshake_sig = get_tlv(server_hello, HANDSHAKE_SIGNATURE);
    if (!handshake_sig) {
        exit(6); // Invalid Server Hello format
    }
    
    // Load server's public key from certificate for verification
    load_peer_public_key(server_pubkey->val, server_pubkey->length);
    
    // Prepare data for verification (Client-Hello + Nonce + Certificate + Ephemeral-Public-Key)
    size_t verify_data_len = cached_client_hello_size + server_nonce->length + cert_tlv->length + server_eph_pubkey->length;
    uint8_t *verify_data = malloc(verify_data_len);
    
    size_t offset = 0;
    memcpy(verify_data, cached_client_hello, cached_client_hello_size);
    offset += cached_client_hello_size;
    memcpy(verify_data + offset, server_nonce->val, server_nonce->length);
    offset += server_nonce->length;
    memcpy(verify_data + offset, cert_tlv->val, cert_tlv->length);
    offset += cert_tlv->length;
    memcpy(verify_data + offset, server_eph_pubkey->val, server_eph_pubkey->length);
    
    if (!verify(handshake_sig->val, handshake_sig->length, verify_data, verify_data_len, ec_peer_public_key)) {
        free(verify_data);
        exit(3); // Bad signature
    }
    free(verify_data);
    
    // Load server's ephemeral public key for Diffie-Hellman
    load_peer_public_key(server_eph_pubkey->val, server_eph_pubkey->length);
    
    // Derive shared secret
    derive_secret();
    
    // Create salt (Client-Hello + Server-Hello)
    size_t salt_len = cached_client_hello_size + cached_server_hello_size;
    uint8_t *salt = malloc(salt_len);
    memcpy(salt, cached_client_hello, cached_client_hello_size);
    memcpy(salt + cached_client_hello_size, cached_server_hello, cached_server_hello_size);
    
    // Derive keys
    derive_keys(salt, salt_len);
    
    // Calculate transcript (HMAC of Client-Hello + Server-Hello)
    uint8_t transcript_data[32];
    hmac(transcript_data, salt, salt_len);
    free(salt);
    
    // Create Finished message - THIS IS THE CRITICAL PART
    tlv *finished = create_tlv(FINISHED);
    
    // Create Transcript TLV and add it to Finished
    tlv *transcript = create_tlv(TRANSCRIPT);
    add_val(transcript, transcript_data, 32);
    add_tlv(finished, transcript);
    
    // Serialize the Finished message
    uint8_t finished_buf[4096];
    size_t finished_len = serialize_tlv(finished_buf, finished);
    
    // Cache the Finished message
    cached_finished = malloc(finished_len);
    memcpy(cached_finished, finished_buf, finished_len);
    cached_finished_size = finished_len;
    
    // Clean up
    free_tlv(finished);
    free_tlv(server_hello);
    free_tlv(certificate);
    
    // Mark that we've processed the server hello
    server_hello_received = 1;
}

// Server verifies client's Finished message
static void server_process_finished(uint8_t* buf, size_t length) {
    // Parse the finished message
    tlv *finished = deserialize_tlv(buf, length);
    if (!finished || finished->type != FINISHED) {
        exit(6); // Unexpected message
    }
    
    // Extract transcript
    tlv *transcript = get_tlv(finished, TRANSCRIPT);
    if (!transcript || transcript->length != 32) {
        exit(6); // Invalid finished message
    }
    
    // Calculate our own transcript
    size_t salt_len = cached_client_hello_size + cached_server_hello_size;
    uint8_t *salt = malloc(salt_len);
    
    memcpy(salt, cached_client_hello, cached_client_hello_size);
    memcpy(salt + cached_client_hello_size, cached_server_hello, cached_server_hello_size);
    
    // Derive shared secret
    derive_secret();
    
    // Derive keys
    derive_keys(salt, salt_len);
    
    // Calculate HMAC
    uint8_t our_transcript[32];
    hmac(our_transcript, salt, salt_len);
    
    free(salt);
    
    // Compare transcripts
    if (memcmp(transcript->val, our_transcript, 32) != 0) {
        exit(4); // Bad transcript
    }
    
    free_tlv(finished);
    
    // Mark handshake as complete
    finished_received = 1;
    handshake_complete = 1;
}

ssize_t input_sec(uint8_t* buf, size_t max_length) {
    // CLIENT HELLO PHASE
    if (global_type == CLIENT && global_hs_state == IN_CLIENT_HELLO) {
        fprintf(stderr, "CLIENT_HELLO\n");

        // Create CLIENT_HELLO TLV
        tlv *ch = create_tlv(CLIENT_HELLO);

        // Add nonce
        tlv* nn = create_tlv(NONCE);
        uint8_t nonce[NONCE_SIZE];
        generate_nonce(nonce, NONCE_SIZE);
        
        // Save the client nonce for later verification
        if (client_nonce) free(client_nonce);
        client_nonce = malloc(NONCE_SIZE);
        memcpy(client_nonce, nonce, NONCE_SIZE);
        client_nonce_size = NONCE_SIZE;
        
        add_val(nn, nonce, NONCE_SIZE);
        add_tlv(ch, nn);

        // Add public key
        tlv* pk = create_tlv(PUBLIC_KEY);
        add_val(pk, public_key, pub_key_size);
        add_tlv(ch, pk);

        // Serialize and send
        uint16_t len = serialize_tlv(buf, ch);

        // Cache the client hello - Make sure to create a fresh copy
        if (cached_client_hello) free(cached_client_hello);
        cached_client_hello = malloc(len);
        memcpy(cached_client_hello, buf, len);
        cached_client_hello_size = len;

        // Debug output for verification
        fprintf(stderr, "Cached Client Hello (%zu bytes):\n", cached_client_hello_size);
        print_tlv_bytes(cached_client_hello, cached_client_hello_size);

        // Clean up
        free_tlv(ch);

        global_hs_state = IN_SERVER_HELLO;

        fprintf(stderr, "CLIENT_HELLO done\n");
        return len;
    } 
    else if (global_type == SERVER && global_hs_state == IN_SERVER_HELLO && client_hello_received) {
        fprintf(stderr, "SERVER_HELLO\n");
    
        // Create SERVER_HELLO TLV
        tlv* sh = create_tlv(SERVER_HELLO);
        
        // 1. Generate a nonce
        tlv* nn = create_tlv(NONCE);
        uint8_t nonce[NONCE_SIZE];
        generate_nonce(nonce, NONCE_SIZE);
        
        // Save the server nonce for later use
        if (server_nonce) free(server_nonce);
        server_nonce = malloc(NONCE_SIZE);
        memcpy(server_nonce, nonce, NONCE_SIZE);
        server_nonce_size = NONCE_SIZE;
        
        add_val(nn, nonce, NONCE_SIZE);
        add_tlv(sh, nn);
        
        // 2. Add the certificate - IMPORTANT: This is already in TLV format
        tlv* cert_from_file = deserialize_tlv(certificate, cert_size);
    
        if (cert_from_file == NULL || cert_from_file->type != CERTIFICATE) {
            fprintf(stderr, "Invalid certificate format\n");
            return -1;
        }
        
        // Client sending Finished message
        if (server_hello_received && !finished_sent && cached_finished != NULL) {
            size_t len = cached_finished_size;
            if (len > max_length) {
                len = max_length;
            }
            
            memcpy(buf, cached_finished, len);
            finished_sent = 1;
            
            return len;
        }
    } else if (global_type == SERVER) {
        // Server sending Server Hello
        if (client_hello_received && !server_hello_sent && cached_server_hello != NULL) {
            size_t len = cached_server_hello_size;
            if (len > max_length) {
                len = max_length;
            }
            
        // Serialize the complete SERVER_HELLO
        uint16_t sh_len = serialize_tlv(buf, sh);
        
        // Cache the server hello for later use
        if (cached_server_hello) free(cached_server_hello);
        cached_server_hello = malloc(sh_len);
        memcpy(cached_server_hello, buf, sh_len);
        cached_server_hello_size = sh_len;

        fprintf(stderr, "Server hello size: %zu\n", sh_len);
        
        // Clean up
        free_tlv(sh);
        
        global_hs_state = IN_CLIENT_FINISHED;
        return sh_len;
    }    
    // CLIENT SENDING FINISHED
    else if (global_type == CLIENT && global_hs_state == IN_CLIENT_FINISHED && server_hello_received) {
        fprintf(stderr, "CLIENT_FINISHED\n");
        
        // Calculate transcript digest
        uint8_t transcript_digest[MAC_SIZE];
        calculate_transcript(transcript_digest);

        // Build the FINISHED message with the transcript
        tlv* transcript = create_tlv(TRANSCRIPT);
        add_val(transcript, transcript_digest, MAC_SIZE);
        
        tlv* finished = create_tlv(FINISHED);
        add_tlv(finished, transcript);
        
        // Serialize the finished message
        uint16_t len = serialize_tlv(buf, finished);
        
        // Debug print to see what we're sending
        fprintf(stderr, "Serialized FINISHED message (%u bytes):\n", len);
        print_tlv_bytes(buf, len);
        
        // Cache the finished message
        if (cached_client_finished) free(cached_client_finished);
        cached_client_finished = malloc(len);
        memcpy(cached_client_finished, buf, len);
        cached_client_finished_size = len;
        
        // Clean up
        free_tlv(finished);
        
        fprintf(stderr, "CLIENT_FINISHED done\n");
        global_hs_state = IN_SERVER_FINISHED;
        return len;
    }

    // SERVER PROCESSING CLIENT FINISHED
    else if (global_type == SERVER && global_hs_state == IN_CLIENT_FINISHED) {
        return 0;
    }
    
    // CLIENT PROCESSING SERVER FINISHED
    else if (global_type == CLIENT && global_hs_state == IN_SERVER_FINISHED) {
        return 0;
    }
    
    // DATA EXCHANGE AFTER HANDSHAKE COMPLETED
    else if (handshake_complete) {
        return 0;
    }
    
    // Default case: pass through to transport layer
    return input_io(buf, max_length);
}

void output_sec(uint8_t* buf, size_t length) {
    if (global_type == SERVER) {
        if (!client_hello_received) {
            // Check if this is a Client Hello
            tlv *msg = deserialize_tlv(buf, length);
            if (msg && msg->type == CLIENT_HELLO) {
                // Cache client hello
                cached_client_hello = malloc(length);
                memcpy(cached_client_hello, buf, length);
                cached_client_hello_size = length;
                
                // Extract client public key
                tlv *client_pubkey = get_tlv(msg, PUBLIC_KEY);
                if (client_pubkey) {
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
            
            if (msg) {
                free_tlv(msg);
            }
        }
        else if (!finished_received) {
            // Check if this is a Finished message
            tlv *msg = deserialize_tlv(buf, length);
            if (msg && msg->type == FINISHED) {
                // Process the Finished message
                server_process_finished(buf, length);
                
                free_tlv(msg);
                return; // Don't pass to output_io
            }
            
            if (msg) {
                free_tlv(msg);
            }
        }
    } else if (global_type == CLIENT) {
        if (!server_hello_received) {
            // Check if this is a Server Hello
            tlv *msg = deserialize_tlv(buf, length);
            if (msg && msg->type == SERVER_HELLO) {
                // Process the Server Hello
                client_process_server_hello(buf, length);
                
                free_tlv(msg);
                return; // Don't pass to output_io
            }
            
            if (msg) {
                free_tlv(msg);
            }
        }
    }
    
    // CLIENT PROCESSING SERVER HELLO
    if (global_type == CLIENT && !server_hello_received && global_hs_state == IN_SERVER_HELLO) {
        process_server_hello(buf, length);
        return;
    }

    // If handshake is complete, encrypt outgoing data
    if (handshake_complete) {
       //to-do
        return;
    }
    
    // If not in secure mode, pass through to io layer
    output_io(buf, length);
}

// Cleanup function
void cleanup_sec() {
    if (cached_client_hello) free(cached_client_hello);
    if (cached_server_hello) free(cached_server_hello);
    if (cached_finished) free(cached_finished);
    if (global_hostname) free(global_hostname);
}
