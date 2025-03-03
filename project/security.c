#include "consts.h"
#include "io.h"
#include "libsecurity.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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
        load_ca_public_key("ca_public_key.bin");
        fprintf(stderr, "Loaded CA public key\n");
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

        tlv *ch = create_tlv(CLIENT_HELLO);

        //nonce
        tlv* nn = create_tlv(NONCE);
        uint8_t nonce[NONCE_SIZE];
        generate_nonce(nonce, NONCE_SIZE);
        
        if (client_nonce) free(client_nonce);
        client_nonce = malloc(NONCE_SIZE);
        memcpy(client_nonce, nonce, NONCE_SIZE);
        client_nonce_size = NONCE_SIZE;
        
        add_val(nn, nonce, NONCE_SIZE);
        add_tlv(ch, nn);

        // pub key
        tlv* pk = create_tlv(PUBLIC_KEY);
        add_val(pk, public_key, pub_key_size);
        add_tlv(ch, pk);

        // drop ship
        uint16_t len = serialize_tlv(buf, ch);

        // cache for future use
        if (cached_client_hello) free(cached_client_hello);
        cached_client_hello = malloc(len);
        memcpy(cached_client_hello, buf, len);
        cached_client_hello_size = len;

        /*
        fprintf(stderr, "Cached Client Hello (%zu bytes):\n", cached_client_hello_size);
        print_tlv_bytes(cached_client_hello, cached_client_hello_size);
        */

        free_tlv(ch);

        global_hs_state = IN_SERVER_HELLO;

        fprintf(stderr, "CLIENT_HELLO done\n");
        return len;
    } 
    else if (global_type == SERVER && global_hs_state == IN_SERVER_HELLO && client_hello_received) {
        fprintf(stderr, "SERVER_HELLO\n");
    
        tlv* sh = create_tlv(SERVER_HELLO);
        
        // nonce
        tlv* nn = create_tlv(NONCE);
        uint8_t nonce[NONCE_SIZE];
        generate_nonce(nonce, NONCE_SIZE);
        
        if (server_nonce) free(server_nonce);
        server_nonce = malloc(NONCE_SIZE);
        memcpy(server_nonce, nonce, NONCE_SIZE);
        server_nonce_size = NONCE_SIZE;
        
        add_val(nn, nonce, NONCE_SIZE);
        add_tlv(sh, nn);
        
        // add certificate (preloaded in init_sec)
        tlv* cert_from_file = deserialize_tlv(certificate, cert_size);
    
        if (cert_from_file == NULL || cert_from_file->type != CERTIFICATE) {
            fprintf(stderr, "Invalid certificate format\n");
            return -1;
        }
        
        add_tlv(sh, cert_from_file);
        
        // server's public key
        tlv* server_pk = create_tlv(PUBLIC_KEY);
        add_val(server_pk, public_key, pub_key_size);
        add_tlv(sh, server_pk);
    
        // hs sig
        fprintf(stderr, "Creating handshake signature\n");

        uint8_t* nonce_buf = malloc(NONCE_SIZE);  
        tlv* nonce_tlv = create_tlv(NONCE);
        add_val(nonce_tlv, server_nonce, server_nonce_size);
        uint16_t nonce_len = serialize_tlv(nonce_buf, nonce_tlv);
        free_tlv(nonce_tlv);

        uint8_t* pk_buf = malloc(pub_key_size);  
        tlv* pk_tlv = create_tlv(PUBLIC_KEY);
        add_val(pk_tlv, public_key, pub_key_size);
        uint16_t pk_len = serialize_tlv(pk_buf, pk_tlv);
        free_tlv(pk_tlv);

        // total size and allocate buffer
        size_t sign_data_size = cached_client_hello_size + nonce_len + cert_size + pk_len;
        uint8_t* sign_data = malloc(sign_data_size);
        uint8_t* ptr = sign_data;

        // append client hello
        memcpy(ptr, cached_client_hello, cached_client_hello_size);
        ptr += cached_client_hello_size;

        // append server nonce
        memcpy(ptr, nonce_buf, nonce_len);
        ptr += nonce_len;
        free(nonce_buf);

        // append cert
        memcpy(ptr, certificate, cert_size);
        ptr += cert_size;

        // append pub key
        memcpy(ptr, pk_buf, pk_len);
        free(pk_buf);

        // sign the data
        uint8_t signature[256];
        size_t sig_size = sign(signature, sign_data, sign_data_size);
        free(sign_data);

        // add hs sig to sh
        tlv* hs_sig = create_tlv(HANDSHAKE_SIGNATURE);
        add_val(hs_sig, signature, sig_size);
        add_tlv(sh, hs_sig);
            
        // drop ship
        uint16_t sh_len = serialize_tlv(buf, sh);
        
        // cache sh
        if (cached_server_hello) free(cached_server_hello);
        cached_server_hello = malloc(sh_len);
        memcpy(cached_server_hello, buf, sh_len);
        cached_server_hello_size = sh_len;

        fprintf(stderr, "Server hello size: %zu\n", sh_len);
        
        free_tlv(sh);
        
        global_hs_state = IN_CLIENT_FINISHED;
        return sh_len;
    }    
    // CLIENT SENDING FINISHED
    else if (global_type == CLIENT && global_hs_state == IN_CLIENT_FINISHED && server_hello_received) {
        fprintf(stderr, "CLIENT_FINISHED\n");
        //print_tlv_bytes(cached_client_hello, cached_client_hello_size);

        
        // hmac calculation
        uint8_t transcript_digest[MAC_SIZE];
        calculate_transcript(transcript_digest);

        // build the FINISHED message w/ the transcript
        tlv* transcript = create_tlv(TRANSCRIPT);
        add_val(transcript, transcript_digest, MAC_SIZE);
        
        tlv* finished = create_tlv(FINISHED);
        add_tlv(finished, transcript);
        
        uint16_t len = serialize_tlv(buf, finished);
        
        fprintf(stderr, "Serialized FINISHED message (%u bytes):\n", len);
        print_tlv_bytes(buf, len);
        
        // caching it
        if (cached_client_finished) free(cached_client_finished);
        cached_client_finished = malloc(len);
        memcpy(cached_client_finished, buf, len);
        cached_client_finished_size = len;
        
        free_tlv(finished);
        
        fprintf(stderr, "CLIENT_FINISHED done\n");
        global_hs_state = IN_SERVER_FINISHED;
        return len;
    }
    /*
    // server processing client FINISHED
    else if (global_type == SERVER && global_hs_state == IN_CLIENT_FINISHED) {
        fprintf(stderr, "SERVER_FINISHED\n");
        return 0;
    }
    
    // client processing server FINISHED
    else if (global_type == CLIENT && global_hs_state == IN_SERVER_FINISHED) {
        return 0;
    }
    */
    // data exchange phase
    else if (handshake_complete) {
        return 0;
    }
    
    // default: pass through to transport layer
    return input_io(buf, max_length);
}

void output_sec(uint8_t* buf, size_t length) {    
    // SERVER PROCESSING CLIENT HELLO
    if (global_type == SERVER && !client_hello_received) {
        process_client_hello(buf, length);
        return;
    }
    
    // CLIENT PROCESSING SERVER HELLO (leads to key derivation + FINISHED message)
    if (global_type == CLIENT && !server_hello_received && global_hs_state == IN_SERVER_HELLO) {
        process_server_hello(buf, length);
        return;
    }

    // encrypt outgoing data
    if (handshake_complete) {
        return;
    }

    output_io(buf, length);
}

void process_client_hello(uint8_t* buf, size_t length) {

    // process the received ch in output_sec (according to TLV helpers)
    tlv* ch = deserialize_tlv(buf, length);
    if (ch == NULL || ch->type != CLIENT_HELLO) {
        if (ch) free_tlv(ch);
        fprintf(stderr, "Invalid CLIENT_HELLO message\n");
        return;
    }

    // extract nonce
    tlv* nonce_tlv = get_tlv(ch, NONCE);
    if (nonce_tlv == NULL) {
        free_tlv(ch);
        fprintf(stderr, "No nonce found in CLIENT_HELLO\n");
        return;
    } else {
        if (client_nonce) free(client_nonce);
        client_nonce = malloc(nonce_tlv->length);
        memcpy(client_nonce, nonce_tlv->val, nonce_tlv->length);
        client_nonce_size = nonce_tlv->length;
    }

    // extract pub key
    tlv* pk_tlv = get_tlv(ch, PUBLIC_KEY);
    if (pk_tlv == NULL) {
        free_tlv(ch);
        fprintf(stderr, "No public key found in CLIENT_HELLO\n");
        return;
    } else {
        load_peer_public_key(pk_tlv->val, pk_tlv->length);
        fprintf(stderr, "Loaded client public key\n");
    }

    // cache the received ch
    if (cached_client_hello != NULL) {
        free(cached_client_hello);
    }
    cached_client_hello = malloc(length);
    cached_client_hello_size = length;
    memcpy(cached_client_hello, buf, length);
    
    fprintf(stderr, "Server received and cached Client Hello (%zu bytes):\n", cached_client_hello_size);
    print_tlv_bytes(cached_client_hello, cached_client_hello_size);

    free_tlv(ch);
    
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

    if (cached_server_hello != NULL) {
        free(cached_server_hello);
    }
    cached_server_hello = malloc(length);
    memcpy(cached_server_hello, buf, length);
    cached_server_hello_size = length;
    
    fprintf(stderr, "Client cached Server Hello (%zu bytes):\n", cached_server_hello_size);
    print_tlv_bytes(cached_server_hello, cached_server_hello_size);

    // extract cert
    tlv* cert_tlv = get_tlv(sh, CERTIFICATE);
    if (cert_tlv == NULL) {
        free_tlv(sh);
        fprintf(stderr, "No certificate found in SERVER_HELLO\n");
        return;
    }
    // extract dns
    tlv* dns_tlv = get_tlv(cert_tlv, DNS_NAME);
    if (dns_tlv == NULL) {
        free_tlv(sh);
        fprintf(stderr, "No DNS name found in certificate\n");
        return;
    }

    // extract sig from cert
    tlv* cert_sig_tlv = get_tlv(cert_tlv, SIGNATURE);
    if (cert_sig_tlv == NULL) {
        free_tlv(sh);
        fprintf(stderr, "No signature found in certificate\n");
        return;
    }

    // extract pub key from cert
    tlv* server_pk_tlv = get_tlv(cert_tlv, PUBLIC_KEY);
    if (server_pk_tlv == NULL) {
        free_tlv(sh);
        fprintf(stderr, "No public key found in certificate\n");
        return;
    }

    // extract nonce
    tlv* server_nonce_tlv = get_tlv(sh, NONCE);
    if (server_nonce_tlv == NULL) {
        free_tlv(sh);
        fprintf(stderr, "No server nonce found in SERVER_HELLO\n");
        return;
    }
    
    if (server_nonce) {
        free(server_nonce);
    }
    server_nonce = malloc(server_nonce_tlv->length);
    memcpy(server_nonce, server_nonce_tlv->val, server_nonce_tlv->length);
    server_nonce_size = server_nonce_tlv->length;

    // extract hs sig
    tlv* hs_sig_tlv = get_tlv(sh, HANDSHAKE_SIGNATURE);
    if (hs_sig_tlv == NULL) {
        free_tlv(sh);
        fprintf(stderr, "No handshake signature found in SERVER_HELLO\n");
        return;
    }

    // 1. verify certificate was signed by certificate authority
    uint8_t* dns_and_pk = malloc(dns_tlv->length + server_pk_tlv->length);
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
    
    /*
    fprintf(stderr, "Verifying certificate signature over DNS and public key (%u bytes):\n", dns_len + pk_len);
    print_tlv_bytes(dns_and_pk, dns_len + pk_len);
    
    fprintf(stderr, "Certificate signature (%u bytes):\n", cert_sig_tlv->length);
    */

    // spec says to verify the cert with the CA's public key
    int cert_verify = verify(cert_sig_tlv->val, cert_sig_tlv->length, dns_and_pk, dns_len + pk_len, ec_ca_public_key);
    free(dns_and_pk);
    
    fprintf(stderr, "Certificate verification result: %d\n", cert_verify);
    
    if (!cert_verify) {
        free_tlv(sh);
        fprintf(stderr, "Certificate verification failed\n");
        exit(1); // exit with status 1 if verification fails
    }

    // check for dns mismatch
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
    
   
    //fprintf(stderr, "DNS name matches\n");
    
    /*
     3. Verify Server Hello signature
     The data that was signed should include:
        1. Client Hello 
        2. Server Nonce 
        3. Certificate 
        4. Server Public Key from Server Hello 
     */
    
    // get server's public key from the server hello (not certificate)
    tlv* server_pk_hello_tlv = get_tlv(sh, PUBLIC_KEY);
    if (server_pk_hello_tlv == NULL) {
        free_tlv(sh);
        fprintf(stderr, "No server public key found in SERVER_HELLO\n");
        return;
    }

    fprintf(stderr, "Server public key found in Server Hello\n");

    // step 1: gather all the components that need to be signed

    //note: we NEED to load the server's public key from the certificate BEFORE signature verification
    load_peer_public_key(server_pk_tlv->val, server_pk_tlv->length);

    //client hello is alrd cached
    
    // server nonce
    uint8_t* nonce_buf = malloc(server_nonce_size);
    tlv* nonce_tlv = create_tlv(NONCE);
    add_val(nonce_tlv, server_nonce, server_nonce_size);
    uint16_t nonce_len = serialize_tlv(nonce_buf, nonce_tlv);
    free_tlv(nonce_tlv);
    
    // certificate
    uint8_t* cert_buf = malloc(1024); // arbitrary buffer
    uint16_t cert_len = serialize_tlv(cert_buf, cert_tlv);
    
    // server public key
    uint8_t* pk_buf = malloc(server_pk_hello_tlv->length);
    tlv* pk_tlv = create_tlv(PUBLIC_KEY);
    add_val(pk_tlv, server_pk_hello_tlv->val, server_pk_hello_tlv->length);
    uint16_t pk_hello_len = serialize_tlv(pk_buf, pk_tlv);
    free_tlv(pk_tlv);
    
    // step 2: concatenate all components for signature verification
    size_t sig_data_size = cached_client_hello_size + nonce_len + cert_len + pk_hello_len;
    uint8_t* sig_data = malloc(sig_data_size);
    uint8_t* sig_ptr = sig_data;
    
    // client hello
    memcpy(sig_ptr, cached_client_hello, cached_client_hello_size);
    sig_ptr += cached_client_hello_size;
    
    // server nonce
    memcpy(sig_ptr, nonce_buf, nonce_len);
    sig_ptr += nonce_len;
    free(nonce_buf);
    
    // certificate
    memcpy(sig_ptr, cert_buf, cert_len);
    sig_ptr += cert_len;
    free(cert_buf);
    
    // server public key
    memcpy(sig_ptr, pk_buf, pk_hello_len);
    free(pk_buf);

    fprintf(stderr, "Server Hello signature (%zu bytes):\n", hs_sig_tlv->length);
        
    fprintf(stderr, "EC PEER PUBLIC KEY: %p\n", ec_peer_public_key);    

    // step 3: verify the signature
    int sig_verify = verify(hs_sig_tlv->val, hs_sig_tlv->length, sig_data, sig_data_size, ec_peer_public_key);

    free(sig_data);
    
    fprintf(stderr, "Server Hello signature verification result: %d\n", sig_verify);
    
if (sig_verify != 1) {  // Check for != 1 instead of !sig_verify
        free_tlv(sh);
        fprintf(stderr, "Server Hello signature verification failed\n");
        exit(3); // exit with status 3 if server hello signature verification fails per the spec
    }
    

    
     // NOW: we can load the server's actual public key for the key derivation (this shits so stupid)
     load_peer_public_key(server_pk_hello_tlv->val, server_pk_hello_tlv->length);
    

    // use Diffie-Hellman to derive secret
    derive_secret();
    fprintf(stderr, "Shared secret derived\n");

    
    // i read the spec.... the salt should be Client Hello + Server Hello (NOT just the nonces)
    fprintf(stderr, "Creating salt from Client Hello (%zu bytes) + Server Hello (%zu bytes)\n", 
            cached_client_hello_size, cached_server_hello_size);

    //NOW this is where we get the EC + MAC keys
    
    // create the salt as Client Hello + Server Hello
    size_t salt_size = cached_client_hello_size + cached_server_hello_size;
    uint8_t* salt = malloc(salt_size);
    
    // first copy the Client Hello
    memcpy(salt, cached_client_hello, cached_client_hello_size);
    
    // then append the Server Hello
    memcpy(salt + cached_client_hello_size, cached_server_hello, cached_server_hello_size);
    
    // derive encryption and MAC keys using this salt
    fprintf(stderr, "Deriving keys with salt length: %zu\n", salt_size);
    
    // this sets up the global MAC key that will be used by hmac()
    derive_keys(salt, salt_size);
    
    fprintf(stderr, "Keys derived successfully\n");
    free(salt);
    
    // move to next state - generate client finished message in init_sec
    global_hs_state = IN_CLIENT_FINISHED;
    server_hello_received = true;
    
    free_tlv(sh);
}


void calculate_transcript(uint8_t* transcript_digest) {
    if (cached_client_hello == NULL || cached_server_hello == NULL) {
        fprintf(stderr, "cached messages are missing for transcript\n");
        memset(transcript_digest, 0, MAC_SIZE);
        return;
    }
    
    // client hello + server hello
    size_t transcript_data_length = cached_client_hello_size + cached_server_hello_size;
    uint8_t* transcript_data = malloc(transcript_data_length);
    
    if (!transcript_data) {
        fprintf(stderr, "Memory allocation failed\n");
        memset(transcript_digest, 0, MAC_SIZE);
        return;
    }
    
    // client-hello with server-hello appended after
    memcpy(transcript_data, cached_client_hello, cached_client_hello_size);
    memcpy(transcript_data + cached_client_hello_size, cached_server_hello, cached_server_hello_size);
    
    fprintf(stderr, "Transcript data (%zu bytes):\n", transcript_data_length);
    
    // calculate HMAC
    hmac(transcript_digest, transcript_data, transcript_data_length);

    print_tlv_bytes(transcript_data, transcript_data_length); // i stg this is right!
    
    free(transcript_data);
}