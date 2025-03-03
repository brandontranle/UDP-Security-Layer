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
static uint8_t *cached_client_finished = NULL;
static size_t cached_client_finished_size = 0;
static char *expected_dns_name = NULL;

int global_type = 0;
int global_hs_state = 0;
int handshake_complete = 0;

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
        
        // Add the certificate to server hello
        add_tlv(sh, cert_from_file);
        
        // 3. Add the server's public key
        tlv* server_pk = create_tlv(PUBLIC_KEY);
        add_val(server_pk, public_key, pub_key_size);
        add_tlv(sh, server_pk);
    
        // 4. Create handshake signature
        fprintf(stderr, "Creating handshake signature\n");

        // We need to serialize each component (except client_hello which is already serialized)
        uint8_t* nonce_buf = malloc(NONCE_SIZE + 16);  // Extra space for TLV overhead
        tlv* nonce_tlv = create_tlv(NONCE);
        add_val(nonce_tlv, server_nonce, server_nonce_size);
        uint16_t nonce_len = serialize_tlv(nonce_buf, nonce_tlv);
        free_tlv(nonce_tlv);

        uint8_t* pk_buf = malloc(pub_key_size + 16);  // Extra space for TLV overhead
        tlv* pk_tlv = create_tlv(PUBLIC_KEY);
        add_val(pk_tlv, public_key, pub_key_size);
        uint16_t pk_len = serialize_tlv(pk_buf, pk_tlv);
        free_tlv(pk_tlv);

        // Calculate total size and allocate buffer
        size_t sign_data_size = cached_client_hello_size + nonce_len + cert_size + pk_len;
        uint8_t* sign_data = malloc(sign_data_size);
        uint8_t* ptr = sign_data;

        // 1. Add the raw client hello bytes (already TLV encoded)
        memcpy(ptr, cached_client_hello, cached_client_hello_size);
        ptr += cached_client_hello_size;

        // 2. Add the server's nonce TLV
        memcpy(ptr, nonce_buf, nonce_len);
        ptr += nonce_len;
        free(nonce_buf);

        // 3. Add the server's certificate TLV
        memcpy(ptr, certificate, cert_size);
        ptr += cert_size;

        // 4. Add the server's public key TLV
        memcpy(ptr, pk_buf, pk_len);
        free(pk_buf);

        // Sign the data
        uint8_t signature[256];
        size_t sig_size = sign(signature, sign_data, sign_data_size);
        free(sign_data);

        // Add signature to SERVER_HELLO
        tlv* hs_sig = create_tlv(HANDSHAKE_SIGNATURE);
        add_val(hs_sig, signature, sig_size);
        add_tlv(sh, hs_sig);
            
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
    // SERVER PROCESSING CLIENT HELLO
    if (global_type == SERVER && !client_hello_received) {
        process_client_hello(buf, length);
        return;
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

void process_client_hello(uint8_t* buf, size_t length) {
    // When we receive client hello from client (in server)
    tlv* ch = deserialize_tlv(buf, length);
    if (ch == NULL || ch->type != CLIENT_HELLO) {
        if (ch) free_tlv(ch);
        fprintf(stderr, "Invalid CLIENT_HELLO message\n");
        return;
    }

    // Extract the nonce
    tlv* nonce_tlv = get_tlv(ch, NONCE);
    if (nonce_tlv == NULL) {
        free_tlv(ch);
        fprintf(stderr, "No nonce found in CLIENT_HELLO\n");
        return;
    } else {
        // Save the client nonce for later verification
        if (client_nonce) free(client_nonce);
        client_nonce = malloc(nonce_tlv->length);
        memcpy(client_nonce, nonce_tlv->val, nonce_tlv->length);
        client_nonce_size = nonce_tlv->length;
    }

    // Extract the public key
    tlv* pk_tlv = get_tlv(ch, PUBLIC_KEY);
    if (pk_tlv == NULL) {
        free_tlv(ch);
        fprintf(stderr, "No public key found in CLIENT_HELLO\n");
        return;
    } else {
        load_peer_public_key(pk_tlv->val, pk_tlv->length);
        fprintf(stderr, "Loaded client public key\n");
    }

    // Cache the client hello - make sure to create an exact copy
    if (cached_client_hello != NULL) {
        free(cached_client_hello);
    }
    cached_client_hello = malloc(length);
    cached_client_hello_size = length;
    memcpy(cached_client_hello, buf, length);
    
    // Debug output
    fprintf(stderr, "Server received and cached Client Hello (%zu bytes):\n", cached_client_hello_size);
    print_tlv_bytes(cached_client_hello, cached_client_hello_size);

    // Clean up
    free_tlv(ch);
    
    // We've processed client hello, now let input_sec know it should generate server hello
    global_hs_state = IN_SERVER_HELLO;
    client_hello_received = true;
}

void process_server_hello(uint8_t* buf, size_t length) {   
    fprintf(stderr, "Processing server hello\n");

    tlv* sh = deserialize_tlv(buf, length);
    if (sh == NULL || sh->type != SERVER_HELLO) {
        if (sh) free_tlv(sh);
        fprintf(stderr, "Invalid SERVER_HELLO message\n");
        return;
    }

    fprintf(stderr, "Server hello received\n");

    // CRITICAL: Cache the server hello - IMPORTANT: store the exact bytes received
    if (cached_server_hello != NULL) {
        free(cached_server_hello);
    }
    cached_server_hello = malloc(length);
    memcpy(cached_server_hello, buf, length);
    cached_server_hello_size = length;
    
    // Debug output
    fprintf(stderr, "Client cached Server Hello (%zu bytes):\n", cached_server_hello_size);
    print_tlv_bytes(cached_server_hello, cached_server_hello_size);

    // Extract certificate from the server hello
    tlv* cert_tlv = get_tlv(sh, CERTIFICATE);
    if (cert_tlv == NULL) {
        free_tlv(sh);
        fprintf(stderr, "No certificate found in SERVER_HELLO\n");
        return;
    }

    // Extract DNS name from certificate
    tlv* dns_tlv = get_tlv(cert_tlv, DNS_NAME);
    if (dns_tlv == NULL) {
        free_tlv(sh);
        fprintf(stderr, "No DNS name found in certificate\n");
        return;
    }

    // Extract signature from certificate
    tlv* cert_sig_tlv = get_tlv(cert_tlv, SIGNATURE);
    if (cert_sig_tlv == NULL) {
        free_tlv(sh);
        fprintf(stderr, "No signature found in certificate\n");
        return;
    }

    // Extract server's public key from the certificate
    tlv* server_pk_tlv = get_tlv(cert_tlv, PUBLIC_KEY);
    if (server_pk_tlv == NULL) {
        free_tlv(sh);
        fprintf(stderr, "No public key found in certificate\n");
        return;
    }

    // Extract server nonce
    tlv* server_nonce_tlv = get_tlv(sh, NONCE);
    if (server_nonce_tlv == NULL) {
        free_tlv(sh);
        fprintf(stderr, "No server nonce found in SERVER_HELLO\n");
        return;
    }
    
    // Save server nonce for later use
    if (server_nonce) {
        free(server_nonce);
    }
    server_nonce = malloc(server_nonce_tlv->length);
    memcpy(server_nonce, server_nonce_tlv->val, server_nonce_tlv->length);
    server_nonce_size = server_nonce_tlv->length;

    // Extract handshake signature
    tlv* hs_sig_tlv = get_tlv(sh, HANDSHAKE_SIGNATURE);
    if (hs_sig_tlv == NULL) {
        free_tlv(sh);
        fprintf(stderr, "No handshake signature found in SERVER_HELLO\n");
        return;
    }

    // 1. Verify certificate was signed by certificate authority
    uint8_t* dns_and_pk = malloc(dns_tlv->length + 16 + server_pk_tlv->length + 16); // +16 for TLV overhead
    uint8_t* ptr = dns_and_pk;
    
    // Serialize DNS name TLV
    tlv* dns_tlv_copy = create_tlv(DNS_NAME);
    add_val(dns_tlv_copy, dns_tlv->val, dns_tlv->length);
    uint16_t dns_len = serialize_tlv(ptr, dns_tlv_copy);
    ptr += dns_len;
    free_tlv(dns_tlv_copy);
    
    // Serialize public key TLV
    tlv* pk_tlv_copy = create_tlv(PUBLIC_KEY);
    add_val(pk_tlv_copy, server_pk_tlv->val, server_pk_tlv->length);
    uint16_t pk_len = serialize_tlv(ptr, pk_tlv_copy);
    free_tlv(pk_tlv_copy);
    
    // Debug output for verification data
    fprintf(stderr, "Verifying certificate signature over DNS and public key (%u bytes):\n", dns_len + pk_len);
    print_tlv_bytes(dns_and_pk, dns_len + pk_len);
    
    // Debug output for certificate signature
    fprintf(stderr, "Certificate signature (%u bytes):\n", cert_sig_tlv->length);
    print_hex(cert_sig_tlv->val, cert_sig_tlv->length);
    
    // Verify the certificate with the CA's public key
    int cert_verify = verify(cert_sig_tlv->val, cert_sig_tlv->length, dns_and_pk, dns_len + pk_len, ec_ca_public_key);
    free(dns_and_pk);
    
    fprintf(stderr, "Certificate verification result: %d\n", cert_verify);
    
    if (cert_verify != 1) {
        free_tlv(sh);
        fprintf(stderr, "Certificate verification failed\n");
        exit(1); // Exit with status 1 if verification fails
    }

    // Check if expected_dns_name is contained within the actual DNS name
    char* dns_str = malloc(dns_tlv->length + 1);
    memcpy(dns_str, dns_tlv->val, dns_tlv->length);
    dns_str[dns_tlv->length] = '\0'; // Null-terminate the string

    if (expected_dns_name == NULL || strstr(dns_str, expected_dns_name) == NULL) {
        free(dns_str);
        free_tlv(sh);
        fprintf(stderr, "DNS name mismatch: expected '%s', got '%s'\n", 
                expected_dns_name ? expected_dns_name : "(null)", dns_str);
        exit(2); // Exit with status 2 if DNS name doesn't match
    }
    free(dns_str);
    
    // Load server's public key from the certificate
    load_peer_public_key(server_pk_tlv->val, server_pk_tlv->length);
    
    // 3. Verify Server Hello signature
    // The data that was signed should include:
    // 1. Client Hello (complete TLV)
    // 2. Server Nonce (just the TLV)
    // 3. Certificate (complete TLV)
    // 4. Server Public Key from Server Hello (complete TLV)
    
    // Get server's public key from the server hello (not certificate)
    tlv* server_pk_hello_tlv = get_tlv(sh, PUBLIC_KEY);
    if (server_pk_hello_tlv == NULL) {
        free_tlv(sh);
        fprintf(stderr, "No server public key found in SERVER_HELLO\n");
        return;
    }
    
    // Step 1: Gather all the components that need to be signed
    
    // Step 1a: Client Hello (already in TLV format)
    fprintf(stderr, "Signature verification component 1 - Client Hello (%zu bytes)\n", cached_client_hello_size);
    print_tlv_bytes(cached_client_hello, cached_client_hello_size);
    
    // Step 1b: Serialize server nonce
    uint8_t* nonce_buf = malloc(server_nonce_size + 16); // +16 for TLV overhead
    tlv* nonce_tlv = create_tlv(NONCE);
    add_val(nonce_tlv, server_nonce, server_nonce_size);
    uint16_t nonce_len = serialize_tlv(nonce_buf, nonce_tlv);
    free_tlv(nonce_tlv);
    
    fprintf(stderr, "Signature verification component 2 - Server Nonce (%u bytes)\n", nonce_len);
    print_tlv_bytes(nonce_buf, nonce_len);
    
    // Step 1c: Certificate - we need to serialize this from the cert_tlv
    uint8_t* cert_buf = malloc(1024); // Generous buffer for certificate
    uint16_t cert_len = serialize_tlv(cert_buf, cert_tlv);
    
    fprintf(stderr, "Signature verification component 3 - Certificate (%u bytes)\n", cert_len);
    print_tlv_bytes(cert_buf, MIN(cert_len, 64));
    
    // Step 1d: Server Public Key - Fix: Renamed pk_len to pk_hello_len to avoid redefinition
    uint8_t* pk_buf = malloc(server_pk_hello_tlv->length + 16); // +16 for TLV overhead
    tlv* pk_tlv = create_tlv(PUBLIC_KEY);
    add_val(pk_tlv, server_pk_hello_tlv->val, server_pk_hello_tlv->length);
    uint16_t pk_hello_len = serialize_tlv(pk_buf, pk_tlv);
    free_tlv(pk_tlv);
    
    fprintf(stderr, "Signature verification component 4 - Server Public Key (%u bytes)\n", pk_hello_len);
    print_tlv_bytes(pk_buf, pk_hello_len);
    
    // Step 2: Concatenate all components for signature verification
    size_t sig_data_size = cached_client_hello_size + nonce_len + cert_len + pk_hello_len;
    uint8_t* sig_data = malloc(sig_data_size);
    uint8_t* sig_ptr = sig_data;
    
    // Add client hello
    memcpy(sig_ptr, cached_client_hello, cached_client_hello_size);
    sig_ptr += cached_client_hello_size;
    
    // Add server nonce
    memcpy(sig_ptr, nonce_buf, nonce_len);
    sig_ptr += nonce_len;
    free(nonce_buf);
    
    // Add certificate
    memcpy(sig_ptr, cert_buf, cert_len);
    sig_ptr += cert_len;
    free(cert_buf);
    
    // Add server public key
    memcpy(sig_ptr, pk_buf, pk_hello_len);
    free(pk_buf);
    
    // Debug the signature
    fprintf(stderr, "Handshake signature to verify (%u bytes):\n", hs_sig_tlv->length);
    print_hex(hs_sig_tlv->val, hs_sig_tlv->length);
    
    // Debug the data being verified
    fprintf(stderr, "Data being verified for handshake signature (%zu bytes):\n", sig_data_size);
    print_hex(sig_data, MIN(sig_data_size, 64));
    if (sig_data_size > 64) fprintf(stderr, "... (truncated)\n");
    
    // Step 3: Verify the signature
    int sig_verify = verify(hs_sig_tlv->val, hs_sig_tlv->length, sig_data, sig_data_size, ec_peer_public_key);
    
    free(sig_data);
    
    fprintf(stderr, "Server Hello signature verification result: %d\n", sig_verify);
    
    if (sig_verify != 1) {
        free_tlv(sh);
        fprintf(stderr, "Server Hello signature verification failed\n");
        exit(3); // Exit with status 3 if server hello signature verification fails
    }
    
    // Derive the shared Diffie-Hellman secret
    derive_secret();
    fprintf(stderr, "Shared secret derived\n");

    
    // i read the spec.... the salt should be Client Hello + Server Hello (NOT just the nonces)
    fprintf(stderr, "Creating salt from Client Hello (%zu bytes) + Server Hello (%zu bytes)\n", 
            cached_client_hello_size, cached_server_hello_size);

    //NOW this is where we get the EC + MAC keys
    
    // Create the salt as Client Hello + Server Hello
    size_t salt_size = cached_client_hello_size + cached_server_hello_size;
    uint8_t* salt = malloc(salt_size);
    
    // First copy the Client Hello
    memcpy(salt, cached_client_hello, cached_client_hello_size);
    
    // Then append the Server Hello
    memcpy(salt + cached_client_hello_size, cached_server_hello, cached_server_hello_size);
    
    // Derive encryption and MAC keys using the correct salt
    fprintf(stderr, "Deriving keys with salt length: %zu\n", salt_size);
    
    // This sets up the global MAC key that will be used by hmac()
    derive_keys(salt, salt_size);
    
    fprintf(stderr, "Keys derived successfully\n");
    free(salt);
    
    // Move to next state - generate client finished message
    global_hs_state = IN_CLIENT_FINISHED;
    server_hello_received = true;
    
    free_tlv(sh);
}

// Helper function to print buffers in hex
void print_buffer_hex(const char* label, const uint8_t* buffer, size_t length) {
    fprintf(stderr, "%s (%zu bytes): ", label, length);
    for (size_t i = 0; i < MIN(32, length); i++) {
        fprintf(stderr, "%02x ", buffer[i]);
    }
    if (length > 32) fprintf(stderr, "...");
    fprintf(stderr, "\n");
}

// Let's try a simpler client finished message calculation
void calculate_transcript(uint8_t* transcript_digest) {
    if (cached_client_hello == NULL || cached_server_hello == NULL) {
        fprintf(stderr, "CRITICAL ERROR: Cached messages are missing for transcript\n");
        memset(transcript_digest, 0, MAC_SIZE);
        return;
    }
    
    // Try SERVER_HELLO + CLIENT_HELLO (reverse of your original implementation)
    size_t transcript_data_length = cached_server_hello_size + cached_client_hello_size;
    uint8_t* transcript_data = malloc(transcript_data_length);
    
    if (!transcript_data) {
        fprintf(stderr, "Memory allocation failed\n");
        memset(transcript_digest, 0, MAC_SIZE);
        return;
    }
    
    //Client-hello with server-hello appended after
    memcpy(transcript_data, cached_client_hello, cached_client_hello_size);
    memcpy(transcript_data + cached_client_hello_size, cached_server_hello, cached_server_hello_size);
    
    fprintf(stderr, "Transcript data (%zu bytes):\n", transcript_data_length);
    
    // Calculate HMAC
    hmac(transcript_digest, transcript_data, transcript_data_length);
    
    free(transcript_data);
}
