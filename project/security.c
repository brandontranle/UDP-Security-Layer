#include "consts.h"
#include "io.h"
#include "libsecurity.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

//i fucking hate c


/* 
To start the handshake procedure, the client will send a Client Hello message. 
This message contains a random value (called a nonce). 
Generate a public/private key pair and send the public key. 
Make sure to cache the entire Client Hello message-you'll need it for another step.
*/

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


tlv* cached_ch = NULL;
tlv* cached_ch_nonce = NULL;
tlv* cached_ch_pk = NULL;
tlv* cached_ch_sig = NULL;


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
            expected_dns_name = host;
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

        // Cache the client hello
        cached_client_hello = malloc(len);
        memcpy(cached_client_hello, buf, len);
        cached_client_hello_size = len;

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
        server_nonce = malloc(NONCE_SIZE);
        memcpy(server_nonce, nonce, NONCE_SIZE);
        server_nonce_size = NONCE_SIZE;
        
        add_val(nn, nonce, NONCE_SIZE);
        add_tlv(sh, nn);
        
        // 2. Add the certificate - IMPORTANT: This is already in TLV format
        // The certificate variable should contain a properly formatted TLV structure
        tlv* cert_from_file = deserialize_tlv(certificate, cert_size);
    
        print_tlv_bytes(certificate, cert_size);
    
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
    
    
        // 4. handshake signature   
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
        cached_server_hello = malloc(sh_len);
        memcpy(cached_server_hello, buf, sh_len);
        cached_server_hello_size = sh_len;

        fprintf(stderr, "Server hello size: %zu\n", sh_len);
        
        // Clean up
        free_tlv(sh);
        
        global_hs_state = IN_CLIENT_FINISHED;
        
        return sh_len;
}    
//CLIENT SENDING CLIENT FINISHED
else if (global_type == CLIENT && global_hs_state == IN_CLIENT_FINISHED && server_hello_received) {
    fprintf(stderr, "CLIENT_FINISHED\n");
    
    // Calculate transcript
    uint8_t transcript_digest[MAC_SIZE];
    calculate_transcript(transcript_digest);
    
    // Create FINISHED message
    tlv* finished = create_tlv(FINISHED);
    tlv* transcript = create_tlv(TRANSCRIPT);
    add_val(transcript, transcript_digest, MAC_SIZE);
    add_tlv(finished, transcript);
    
    // Serialize the FINISHED message
    uint16_t len = serialize_tlv(buf, finished);
    
    // Clean up
    free_tlv(finished);
    
    global_hs_state = IN_SERVER_FINISHED;
    
    return len;
}
    // SERVER PROCESSING CLIENT FINISHED
    else if (global_type == SERVER && global_hs_state == IN_CLIENT_FINISHED) {
        //add logic here
    }
    
    // CLIENT PROCESSING SERVER FINISHED
    else if (global_type == CLIENT && global_hs_state == IN_SERVER_FINISHED) {
       return;
    }
    
    // DATA EXCHANGE AFTER HANDSHAKE COMPLETED
    else if (handshake_complete) {
        //add logic here
    }
    
    // Default case: pass through to transport layer
    return input_io(buf, max_length);
}

void output_sec(uint8_t* buf, size_t length) {    

    switch (global_type)
    {
        case CLIENT:
            if (!server_hello_received && global_hs_state == IN_SERVER_HELLO)
            {
                process_server_hello(buf, length);
                return;
            }
            break;
        case SERVER:
            if (!client_hello_received)
            {
                process_client_hello(buf, length);
                return;
            }
            break;
        default:
            break;
    }



    // If handshake is complete, encrypt outgoing data
    if (handshake_complete) {
        // Create DATA TLV
        tlv* data = create_tlv(DATA);
        
        // Add IV
        tlv* iv_tlv = create_tlv(IV);
        uint8_t iv[IV_SIZE];
        generate_nonce(iv, IV_SIZE);  // Generate random IV
        add_val(iv_tlv, iv, IV_SIZE);
        add_tlv(data, iv_tlv);
        
        // Add ciphertext
        tlv* ciphertext_tlv = create_tlv(CIPHERTEXT);
        uint8_t ciphertext[length + 16];  // Add some padding for encryption
        size_t ciphertext_len = encrypt_data(iv, ciphertext, buf, length);
        add_val(ciphertext_tlv, ciphertext, ciphertext_len);
        add_tlv(data, ciphertext_tlv);
        
        // Add MAC
        tlv* mac_tlv = create_tlv(MAC);
        uint8_t mac_value[MAC_SIZE];
        hmac(mac_value, ciphertext, ciphertext_len);
        add_val(mac_tlv, mac_value, MAC_SIZE);
        add_tlv(data, mac_tlv);
        
        // Serialize the DATA message
        uint8_t* output_buf = malloc(length + 256);  // Generous buffer size
        uint16_t data_len = serialize_tlv(output_buf, data);
        free_tlv(data);
        
        // Send the encrypted data
        output_io(output_buf, data_len);
        free(output_buf);
        return;
    }
    
    // If not in secure mode, pass through to io layer
    output_io(buf, length);
}


//handshake helpers i made :)

void process_client_hello(uint8_t* buf, size_t length)
{
    // when we receive ch from client (in server)
        tlv* ch = deserialize_tlv(buf, length);
        if (ch == NULL || ch->type != CLIENT_HELLO) {
            if (ch) free_tlv(ch);
            fprintf(stderr, "Invalid CLIENT_HELLO message\n");
            return;
        }

        //print_tlv_bytes(buf, length);

        // Extract the nonce
        cached_ch_nonce = get_tlv(ch, NONCE);
        if (cached_ch_nonce == NULL) {
            free_tlv(ch);
            fprintf(stderr, "No nonce found in CLIENT_HELLO\n");
            return;
        } else {
            // Save the client nonce for later verification
            client_nonce = malloc(cached_ch_nonce->length);
            memcpy(client_nonce, cached_ch_nonce->val, cached_ch_nonce->length);
            client_nonce_size = cached_ch_nonce->length;
        }

        // Extract the public key
        cached_ch_pk = get_tlv(ch, PUBLIC_KEY);
        if (cached_ch_pk == NULL) {
            free_tlv(ch);
            fprintf(stderr, "No public key found in CLIENT_HELLO\n");
            return;
        } else {
            load_peer_public_key(cached_ch_pk->val, cached_ch_pk->length);
            fprintf(stderr, "Loaded client public key\n");
        }

        // Cache the client hello
        cached_ch = ch;
        cached_client_hello = malloc(length);
        cached_client_hello_size = length;
        memcpy(cached_client_hello, buf, length);

        free_tlv(ch);

        
        // We've processed client hello, now let input_sec know it should generate server hello
        global_hs_state = IN_SERVER_HELLO;
        client_hello_received = true;
        
        return;
}




// The issue might be in how we're caching the server hello and what data we're using
void process_server_hello(uint8_t* buf, size_t length) {   
    fprintf(stderr, "Processing server hello\n");

    tlv* sh = deserialize_tlv(buf, length);
    if (sh == NULL || sh->type != SERVER_HELLO) {
        if (sh) free_tlv(sh);
        fprintf(stderr, "Invalid SERVER_HELLO message\n");
        return;
    }

    fprintf(stderr, "Server hello received\n");

    cached_server_hello = malloc(length);
    memcpy(cached_server_hello, buf, length);
    cached_server_hello_size = length;

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
    uint8_t dns_and_pk[dns_tlv->length + server_pk_tlv->length + 16]; // +16 for TLV overhead
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
    
    // Verify the certificate with the CA's public key
    int cert_verify = verify(cert_sig_tlv->val, cert_sig_tlv->length, dns_and_pk, dns_len + pk_len, ec_ca_public_key);
    if (cert_verify != 1) {
        free_tlv(sh);
        fprintf(stderr, "Certificate verification failed\n");
        exit(1); // Exit with status 1 if verification fails
    }

    // Check if expected_dns_name is contained within the actual DNS name
    char* dns_str = malloc(dns_tlv->length + 1);
    memcpy(dns_str, dns_tlv->val, dns_tlv->length);
    dns_str[dns_tlv->length] = '\0'; // Null-terminate the string

    if (strstr(dns_str, expected_dns_name) == NULL) {
        free(dns_str);
        free_tlv(sh);
        fprintf(stderr, "DNS name mismatch\n");
        exit(2); // Exit with status 2 if DNS name doesn't match
    }
    free(dns_str);
    
    // Load server's public key
    load_peer_public_key(server_pk_tlv->val, server_pk_tlv->length);
    
    // 3. Verify Server Hello signature
    // We need to rebuild the data that was signed, which includes:
    // Client Hello + Server Nonce + Certificate + Server Public Key
    
    // Get server's public key from the server hello (not certificate)
    tlv* server_pk_hello_tlv = get_tlv(sh, PUBLIC_KEY);
    if (server_pk_hello_tlv == NULL) {
        free_tlv(sh);
        fprintf(stderr, "No server public key found in SERVER_HELLO\n");
        return;
    }
    
    // Calculate total size and allocate buffer for verification data
    size_t verify_data_size = cached_client_hello_size + 
                            server_nonce_tlv->length + 16 + // +16 for TLV overhead
                            cert_tlv->length + 16 +         // +16 for TLV overhead
                            server_pk_hello_tlv->length + 16; // +16 for TLV overhead
                            
    uint8_t* verify_data = malloc(verify_data_size);
    ptr = verify_data;
    
    // Add client hello (already in TLV format)
    memcpy(ptr, cached_client_hello, cached_client_hello_size);
    ptr += cached_client_hello_size;
    
    // Add server nonce TLV
    tlv* nonce_tlv_copy = create_tlv(NONCE);
    add_val(nonce_tlv_copy, server_nonce_tlv->val, server_nonce_tlv->length);
    uint16_t nonce_len = serialize_tlv(ptr, nonce_tlv_copy);
    ptr += nonce_len;
    free_tlv(nonce_tlv_copy);
    
    // Add certificate TLV
    uint16_t cert_len = serialize_tlv(ptr, cert_tlv);
    ptr += cert_len;
    
    // Add server public key TLV
    tlv* pk_tlv_copy2 = create_tlv(PUBLIC_KEY);
    add_val(pk_tlv_copy2, server_pk_hello_tlv->val, server_pk_hello_tlv->length);
    uint16_t pk_len2 = serialize_tlv(ptr, pk_tlv_copy2);
    free_tlv(pk_tlv_copy2);
    
    // Verify the signature with the server's public key
    int sig_verify = verify(hs_sig_tlv->val, hs_sig_tlv->length, verify_data, 
                           ptr - verify_data + pk_len2, ec_peer_public_key);
    
    free(verify_data);
    
    if (sig_verify != 1) {
        free_tlv(sh);
        fprintf(stderr, "Server Hello signature verification failed\n");
        exit(3); // Exit with status 3 if server hello signature verification fails
    }
    
    // Derive the shared Diffie-Hellman secret
    derive_secret();
    fprintf(stderr, "Shared secret derived\n");
    
    // IMPORTANT: Use the correct salt for key derivation
    // The salt should be Client Hello + Server Hello (NOT just the nonces)
    fprintf(stderr, "Creating salt from Client Hello (%zu bytes) + Server Hello (%zu bytes)\n", 
            cached_client_hello_size, cached_server_hello_size);
    
    uint8_t* salt = malloc(cached_client_hello_size + cached_server_hello_size);
    memcpy(salt, cached_client_hello, cached_client_hello_size);
    memcpy(salt + cached_client_hello_size, cached_server_hello, cached_server_hello_size);
    
    // Derive encryption and MAC keys using the correct salt
    fprintf(stderr, "Deriving keys with salt length: %zu\n", 
            cached_client_hello_size + cached_server_hello_size);
    derive_keys(salt, cached_client_hello_size + cached_server_hello_size);
    fprintf(stderr, "Keys derived successfully\n");
    free(salt);
    
    // Move to next state - generate client finished message
    global_hs_state = IN_CLIENT_FINISHED;
    server_hello_received = true;
    
    free_tlv(sh);
}


void print_buffer_hex(const char* label, const uint8_t* buffer, size_t length) {
    fprintf(stderr, "%s (%zu bytes): ", label, length);
    for (size_t i = 0; i < MIN(32, length); i++) {
        fprintf(stderr, "%02x ", buffer[i]);
    }
    if (length > 32) fprintf(stderr, "...");
    fprintf(stderr, "\n");
}

void calculate_transcript(uint8_t* transcript_digest) {
    // Verify we have both cached messages
    if (cached_client_hello == NULL || cached_server_hello == NULL) {
        fprintf(stderr, "CRITICAL ERROR: Cached messages are missing for transcript\n");
        memset(transcript_digest, 0, MAC_SIZE);
        return;
    }
    
    // EXACT specification: Client-Hello THEN Server-Hello
    size_t transcript_data_length = cached_client_hello_size + cached_server_hello_size;
    
    // Allocate buffer for concatenated messages
    uint8_t* transcript_data = malloc(transcript_data_length);
    
    // CRITICAL: Append Server-Hello EXACTLY after Client-Hello
    memcpy(transcript_data, cached_client_hello, cached_client_hello_size);
    memcpy(transcript_data + cached_client_hello_size, cached_server_hello, cached_server_hello_size);
    
    // Debug output
    fprintf(stderr, "Transcript Calculation Details:\n");
    fprintf(stderr, "Client Hello Size: %zu\n", cached_client_hello_size);
    fprintf(stderr, "Server Hello Size: %zu\n", cached_server_hello_size);
    fprintf(stderr, "Total Transcript Size: %zu\n", transcript_data_length);
    
    // Calculate HMAC digest
    hmac(transcript_digest, transcript_data, transcript_data_length);
    
    // Print digest for verification
    fprintf(stderr, "Transcript Digest: ");
    for (int i = 0; i < MAC_SIZE; i++) {
        fprintf(stderr, "%02x ", transcript_digest[i]);
    }
    fprintf(stderr, "\n");
    
    // Free temporary buffer
    free(transcript_data);
}