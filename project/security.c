#include "consts.h"
#include "io.h"
#include "libsecurity.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>

static int global_type = 0;
static char* global_hostname = NULL;

// Handshake state
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

// Original server key
static EVP_PKEY *original_server_key = NULL;

void init_sec(int type, char* host) {
    init_io();
    global_type = type;
    
    if (host != NULL) {
        global_hostname = strdup(host);
    }
    
    if (type == CLIENT) {
        // Client initialization
        generate_private_key();
        derive_public_key();
    } else if (type == SERVER) {
        // Server initialization
        load_certificate("server_cert.bin");
        load_private_key("server_key.bin");
        original_server_key = get_private_key();
        
        // Generate ephemeral key
        generate_private_key();
        derive_public_key();
    }
}

// Client processes Server Hello and verifies it
static void client_process_server_hello(uint8_t* buf, size_t length) {
    // Cache the server hello
    cached_server_hello = malloc(length);
    memcpy(cached_server_hello, buf, length);
    cached_server_hello_size = length;
    
    // Parse the server hello
    tlv *server_hello = deserialize_tlv(buf, length);
    if (!server_hello || server_hello->type != SERVER_HELLO) {
        exit(6); // Unexpected message
    }
    
    // Extract the certificate from the server hello
    tlv *cert_tlv = get_tlv(server_hello, CERTIFICATE);
    if (!cert_tlv) {
        exit(6); // Unexpected message format
    }
    
    // Parse the certificate
    tlv *certificate = deserialize_tlv(cert_tlv->val, cert_tlv->length);
    if (!certificate || certificate->type != CERTIFICATE) {
        exit(6); // Invalid certificate
    }
    
    // Extract DNS name from certificate
    tlv *dns_name = get_tlv(certificate, DNS_NAME);
    if (!dns_name) {
        exit(6); // Invalid certificate
    }
    
    // Extract server's public key from certificate
    tlv *server_pubkey = get_tlv(certificate, PUBLIC_KEY);
    if (!server_pubkey) {
        exit(6); // Invalid certificate
    }
    
    // Extract certificate signature
    tlv *cert_sig = get_tlv(certificate, SIGNATURE);
    if (!cert_sig) {
        exit(6); // Invalid certificate
    }
    
    // Step 1: Verify the certificate was signed by the CA
    load_ca_public_key("ca_public_key.bin");
    
    // Create data to verify: DNS-Name + Public-Key
    size_t cert_data_len = dns_name->length + 2 + server_pubkey->length + 2;
    uint8_t *cert_data = malloc(cert_data_len);
    
    size_t offset = 0;
    memcpy(cert_data, dns_name->val - 2, dns_name->length + 2);
    offset += dns_name->length + 2;
    memcpy(cert_data + offset, server_pubkey->val - 2, server_pubkey->length + 2);
    
    // Verify certificate signature
    if (!verify(cert_sig->val, cert_sig->length, cert_data, cert_data_len, ec_ca_public_key)) {
        exit(1); // Bad certificate
    }
    
    free(cert_data);
    
    // Step 2: Verify DNS name matches
    if (global_hostname) {
        // Compare DNS name
        char *cert_dns_name = malloc(dns_name->length + 1);
        memcpy(cert_dns_name, dns_name->val, dns_name->length);
        cert_dns_name[dns_name->length] = '\0';
        
        if (strcmp(cert_dns_name, global_hostname) != 0) {
            free(cert_dns_name);
            exit(2); // Bad DNS name
        }
        
        free(cert_dns_name);
    }
    
    // Step 3: Verify Server Hello signature
    // Extract server's ephemeral public key
    tlv *eph_pubkey = get_tlv(server_hello, PUBLIC_KEY);
    if (!eph_pubkey) {
        exit(6); // Unexpected message format
    }
    
    // Extract handshake signature
    tlv *handshake_sig = get_tlv(server_hello, HANDSHAKE_SIGNATURE);
    if (!handshake_sig) {
        exit(6); // Unexpected message format
    }
    
    // Extract server nonce
    tlv *server_nonce = get_tlv(server_hello, NONCE);
    if (!server_nonce) {
        exit(6); // Unexpected message format
    }
    
    // Load server's public key
    load_peer_public_key(server_pubkey->val, server_pubkey->length);
    
    // Create data to verify: Client-Hello + Nonce + Certificate + Public-Key
    size_t verify_data_len = cached_client_hello_size + server_nonce->length + 2 + cert_tlv->length + 2 + eph_pubkey->length + 2;
    uint8_t *verify_data = malloc(verify_data_len);
    
    offset = 0;
    memcpy(verify_data, cached_client_hello, cached_client_hello_size);
    offset += cached_client_hello_size;
    memcpy(verify_data + offset, server_nonce->val - 2, server_nonce->length + 2);
    offset += server_nonce->length + 2;
    memcpy(verify_data + offset, cert_tlv->val - 2, cert_tlv->length + 2);
    offset += cert_tlv->length + 2;
    memcpy(verify_data + offset, eph_pubkey->val - 2, eph_pubkey->length + 2);
    
    // Verify server hello signature
    if (!verify(handshake_sig->val, handshake_sig->length, verify_data, verify_data_len, ec_peer_public_key)) {
        exit(3); // Bad signature
    }
    
    free(verify_data);
    
    // Load server's ephemeral public key for Diffie-Hellman
    load_peer_public_key(eph_pubkey->val, eph_pubkey->length);
    
    // Derive shared secret
    derive_secret();
    
    // Create salt: Client-Hello + Server-Hello
    size_t salt_len = cached_client_hello_size + cached_server_hello_size;
    uint8_t *salt = malloc(salt_len);
    
    memcpy(salt, cached_client_hello, cached_client_hello_size);
    memcpy(salt + cached_client_hello_size, cached_server_hello, cached_server_hello_size);
    
    // Derive keys
    derive_keys(salt, salt_len);
    
    free(salt);
    
    // Create Finished message
    tlv *finished = create_tlv(FINISHED);
    
    // Calculate transcript (HMAC of Client-Hello + Server-Hello)
    uint8_t transcript_data[32];
    hmac(transcript_data, salt, salt_len);
    
    // Add transcript to Finished
    tlv *transcript = create_tlv(TRANSCRIPT);
    add_val(transcript, transcript_data, 32);
    add_tlv(finished, transcript);
    
    // Serialize Finished message
    uint8_t finished_buf[4096];
    size_t finished_len = serialize_tlv(finished_buf, finished);
    
    // Cache Finished message
    cached_finished = malloc(finished_len);
    memcpy(cached_finished, finished_buf, finished_len);
    cached_finished_size = finished_len;
    
    free_tlv(finished);
    free_tlv(server_hello);
    free_tlv(certificate);
    
    // Mark that we've received the server hello and can send the finished message
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
    if (global_type == CLIENT) {
        // Client sending Client Hello
        if (cached_client_hello == NULL) {
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
            
            memcpy(buf, cached_server_hello, len);
            server_hello_sent = 1;
            
            return len;
        }
    }
    
    // Pass through to IO layer
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
    
    // Pass through to IO layer
    output_io(buf, length);
}

// Cleanup function
void cleanup_sec() {
    if (cached_client_hello) free(cached_client_hello);
    if (cached_server_hello) free(cached_server_hello);
    if (cached_finished) free(cached_finished);
    if (global_hostname) free(global_hostname);
}