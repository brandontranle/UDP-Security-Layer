#define IN_CLIENT_HELLO 0
#define IN_SERVER_HELLO 1
#define IN_CLIENT_FINISHED 2
#define HANDSHAKE_DONE 3
#define MAX_PLAINTEXT_LEN 943

static uint8_t *client_nonce = NULL;
static size_t client_nonce_size = 0;
static uint8_t *server_nonce = NULL;
static size_t server_nonce_size = 0;
static uint8_t *cached_client_hello = NULL;
static size_t cached_client_hello_size = 0;
static uint8_t *cached_server_hello = NULL;
static size_t cached_server_hello_size = 0;

static char* expected_dns_name = NULL;


int global_type = 0;
int global_hs_state = 0;
int handshake_complete = 0;

bool client_hello_received = false;
bool server_hello_received = false;

//functions we use in output_sec
void process_client_hello(uint8_t* buf, size_t length) {
    // process the received ch in output_sec (according to TLV helpers)
    tlv* ch = deserialize_tlv(buf, length);
    if (ch == NULL || ch->type != CLIENT_HELLO) {
        if (ch) free_tlv(ch);
        return;
    }

    // extract nonce
    tlv* nonce_tlv = get_tlv(ch, NONCE);
    if (nonce_tlv == NULL) {
        free_tlv(ch);
        return;
    } else {
        client_nonce = malloc(nonce_tlv->length);
        memcpy(client_nonce, nonce_tlv->val, nonce_tlv->length);
        client_nonce_size = nonce_tlv->length;
    }

    // extract pub key
    tlv* pk_tlv = get_tlv(ch, PUBLIC_KEY);
    if (pk_tlv == NULL) {
        free_tlv(ch);
        return;
    } else load_peer_public_key(pk_tlv->val, pk_tlv->length);

    // cache the received ch
    if (cached_client_hello != NULL) {
        free(cached_client_hello);
    }
    cached_client_hello = malloc(length);
    cached_client_hello_size = length;
    memcpy(cached_client_hello, buf, length);
    
    free_tlv(ch);
    
    global_hs_state = IN_SERVER_HELLO;
    client_hello_received = true;
}

void process_server_hello(uint8_t* buf, size_t length) {   
    tlv* sh = deserialize_tlv(buf, length);
    if (sh == NULL || sh->type != SERVER_HELLO) {
        if (sh) free_tlv(sh);
        return;
    }

    if (cached_server_hello != NULL) {
        free(cached_server_hello);
    }
    cached_server_hello = malloc(length);
    memcpy(cached_server_hello, buf, length);
    cached_server_hello_size = length;

    // extract cert
    tlv* cert_tlv = get_tlv(sh, CERTIFICATE);
    if (cert_tlv == NULL) {
        free_tlv(sh);
        return;
    }

    // extract dns
    tlv* dns_tlv = get_tlv(cert_tlv, DNS_NAME);
    if (dns_tlv == NULL) {
        free_tlv(sh);
        return;
    }

    // extract sig from cert
    tlv* cert_sig_tlv = get_tlv(cert_tlv, SIGNATURE);
    if (cert_sig_tlv == NULL) {
        free_tlv(sh);
        return;
    }

    // extract pub key from cert
    tlv* server_pk_tlv = get_tlv(cert_tlv, PUBLIC_KEY);
    if (server_pk_tlv == NULL) {
        free_tlv(sh);
        return;
    }

    // extract nonce
    tlv* server_nonce_tlv = get_tlv(sh, NONCE);
    if (server_nonce_tlv == NULL) {
        free_tlv(sh);
        return;
    }
    
    server_nonce = malloc(server_nonce_tlv->length);
    memcpy(server_nonce, server_nonce_tlv->val, server_nonce_tlv->length);
    server_nonce_size = server_nonce_tlv->length;

    // extract hs sig
    tlv* hs_sig_tlv = get_tlv(sh, HANDSHAKE_SIGNATURE);
    if (hs_sig_tlv == NULL) {
        free_tlv(sh);
        return;
    }

    // 1. verify certificate was signed by certificate authority
    uint8_t* dns_and_pk = malloc(dns_tlv->length + server_pk_tlv->length);
    uint8_t* ptr = dns_and_pk;
    
    // serialize DNS name TLV
    tlv* dns_tlv_copy = create_tlv(DNS_NAME);
    add_val(dns_tlv_copy, dns_tlv->val, dns_tlv->length);
    uint16_t dns_len = serialize_tlv(ptr, dns_tlv_copy);
    ptr += dns_len;
    free_tlv(dns_tlv_copy);
    
    // serialize pub key TLV
    tlv* pk_tlv_copy = create_tlv(PUBLIC_KEY);
    add_val(pk_tlv_copy, server_pk_tlv->val, server_pk_tlv->length);
    uint16_t pk_len = serialize_tlv(ptr, pk_tlv_copy);
    free_tlv(pk_tlv_copy);
    

    // spec says to verify the cert with the CA's public key
    int cert_verify = verify(cert_sig_tlv->val, cert_sig_tlv->length, dns_and_pk, dns_len + pk_len, ec_ca_public_key);
    free(dns_and_pk);
        
    if (!cert_verify) {
        free_tlv(sh);
        exit(1); // exit with status 1 if verification fails
    }

    // check for dns mismatch
    char* dns_str = malloc(dns_tlv->length + 1);
    memcpy(dns_str, dns_tlv->val, dns_tlv->length);
    dns_str[dns_tlv->length] = '\0'; // null terminate

    if (expected_dns_name == NULL || strstr(dns_str, expected_dns_name) == NULL) {
        free(dns_str);
        free_tlv(sh);
        exit(2); // exit with status 2 if DNS name doesn't match
    }
    free(dns_str);
        
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
        return;
    }

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

    // step 3: verify the signature
    int sig_verify = verify(hs_sig_tlv->val, hs_sig_tlv->length, sig_data, sig_data_size, ec_peer_public_key);

    free(sig_data);
        
    if (sig_verify != 1) {  // Check for != 1 instead of !sig_verify
        free_tlv(sh);
        exit(3); // exit with status 3 if server hello signature verification fails per the spec
    }
    
     // NOW: we can load the server's actual public key for the key derivation (this shits so stupid)
     load_peer_public_key(server_pk_hello_tlv->val, server_pk_hello_tlv->length);
    

    // use Diffie-Hellman to derive secret
    derive_secret();

    // i read the spec.... the salt should be Client Hello + Server Hello (NOT just the nonces)

    //NOW this is where we get the EC + MAC keys
    
    // create the salt as Client Hello + Server Hello
    size_t salt_size = cached_client_hello_size + cached_server_hello_size;
    uint8_t* salt = malloc(salt_size);
    
    // first copy the Client Hello
    memcpy(salt, cached_client_hello, cached_client_hello_size);
    
    // then append the Server Hello
    memcpy(salt + cached_client_hello_size, cached_server_hello, cached_server_hello_size);
        
    // this sets up the global MAC key that will be used by hmac()
    derive_keys(salt, salt_size);
    
    free(salt);
    
    // move to next state - generate client finished message in init_sec
    global_hs_state = IN_CLIENT_FINISHED;
    server_hello_received = true;
    
    free_tlv(sh);
}
void process_client_finished(uint8_t* buf, size_t length) {
    
    // find fininshed message
    tlv* finished = deserialize_tlv(buf, length);
    if (finished == NULL || finished->type != FINISHED) {
        if (finished) free_tlv(finished);
        return;
    }
    
    // extract transcript
    tlv* transcript_tlv = get_tlv(finished, TRANSCRIPT);
    if (transcript_tlv == NULL || transcript_tlv->length != MAC_SIZE) {
        free_tlv(finished);
        return;
    }
    
    //to do this next part, we need to mimic the client. follow the same steps as the client. 

    derive_secret();
    
    size_t salt_size = cached_client_hello_size + cached_server_hello_size;
    uint8_t* salt = malloc(salt_size);
    if (!salt) {
        free_tlv(finished);
        return;
    }
    
    // create salt in same order: ch + sh
    memcpy(salt, cached_client_hello, cached_client_hello_size);
    memcpy(salt + cached_client_hello_size, cached_server_hello, cached_server_hello_size);
    
    // rederive keys with this salt to match client
    derive_keys(salt, salt_size);
    free(salt);
    
    size_t transcript_data_length = cached_client_hello_size + cached_server_hello_size;
    uint8_t* transcript_data = malloc(transcript_data_length);
    if (!transcript_data) {
        free_tlv(finished);
        return;
    }
    
    // ch + sh
    memcpy(transcript_data, cached_client_hello, cached_client_hello_size);
    memcpy(transcript_data + cached_client_hello_size, cached_server_hello, cached_server_hello_size);
    
    uint8_t server_transcript[MAC_SIZE];
    memset(server_transcript, 0, MAC_SIZE);
    
    // calculate hmac
    hmac(server_transcript, transcript_data, transcript_data_length);
    free(transcript_data);

    // compare client vs server digest
    if (memcmp(transcript_tlv->val, server_transcript, MAC_SIZE) != 0) {
        free_tlv(finished);
        exit(4); // exit with status 4 if transcript verification fails (stated in spec)
    }
    
    free_tlv(finished);
    
    // next state
    global_hs_state = HANDSHAKE_DONE;
    handshake_complete = 1;
    return;
}


void calculate_transcript(uint8_t* transcript_digest) {
    if (cached_client_hello == NULL || cached_server_hello == NULL) {
        memset(transcript_digest, 0, MAC_SIZE);
        return;
    }
   
    size_t transcript_data_length = cached_client_hello_size + cached_server_hello_size;
    uint8_t* transcript_data = malloc(transcript_data_length);
    
    if (!transcript_data) {
        memset(transcript_digest, 0, MAC_SIZE);
        return;
    }
    
    // concatenate cached messages (ch+sh)
    memcpy(transcript_data, cached_client_hello, cached_client_hello_size);
    memcpy(transcript_data + cached_client_hello_size, cached_server_hello, cached_server_hello_size);
    
    // calculate HMAC using the established key
    hmac(transcript_digest, transcript_data, transcript_data_length);

    free(transcript_data);
}

void process_msg(uint8_t* buf, size_t length) {

        tlv* data_tlv = deserialize_tlv(buf, length);
        if (data_tlv == NULL || data_tlv->type != DATA) {
            if (data_tlv) free_tlv(data_tlv);
            return;
        }
        
        // extract IV
        tlv* iv_tlv = get_tlv(data_tlv, IV);
        if (iv_tlv == NULL || iv_tlv->length != IV_SIZE) {
            free_tlv(data_tlv);
            return;
        }
        
        // extract CIPHERTEXT
        tlv* cipher_tlv = get_tlv(data_tlv, CIPHERTEXT);
        if (cipher_tlv == NULL) {
            free_tlv(data_tlv);
            return;
        }
        
        // extract MAC
        tlv* mac_tlv = get_tlv(data_tlv, MAC);
        if (mac_tlv == NULL || mac_tlv->length != MAC_SIZE) {
            free_tlv(data_tlv);
            return;
        }
        
        // we need to verify the MAC using the TLV encoding (thanks omar)
        uint8_t iv_tlv_buf[100];
        uint16_t iv_tlv_len = serialize_tlv(iv_tlv_buf, iv_tlv);
        
        uint8_t cipher_tlv_buf[1024]; 
        uint16_t cipher_tlv_len = serialize_tlv(cipher_tlv_buf, cipher_tlv);
        
        // buffer for both serialized tlvs
        uint8_t* iv_cipher_buf = malloc(iv_tlv_len + cipher_tlv_len);
        if (!iv_cipher_buf) {
            free_tlv(data_tlv);
            return;
        }
        
        // combine the serialized TLVs
        memcpy(iv_cipher_buf, iv_tlv_buf, iv_tlv_len);
        memcpy(iv_cipher_buf + iv_tlv_len, cipher_tlv_buf, cipher_tlv_len);
        
        uint8_t calculated_mac[MAC_SIZE];
        hmac(calculated_mac, iv_cipher_buf, iv_tlv_len + cipher_tlv_len);
        free(iv_cipher_buf);
        
        // compare the MACs (exact memory comparison as specified)
        if (memcmp(mac_tlv->val, calculated_mac, MAC_SIZE) != 0) {
            free_tlv(data_tlv);
            exit(5); // exit with status 5 as specified
        }
        
        uint8_t plaintext[1024];
        size_t plaintext_len = decrypt_cipher(plaintext, cipher_tlv->val, cipher_tlv->length, iv_tlv->val);
        
        output_io(plaintext, plaintext_len);
        
        free_tlv(data_tlv);
        return;
    }


// functions we use in input_sec
static size_t send_client_hello (uint8_t* buf) {
    
    tlv *ch = create_tlv(CLIENT_HELLO);

    //nonce
    tlv* nn = create_tlv(NONCE);
    uint8_t nonce[NONCE_SIZE];
    generate_nonce(nonce, NONCE_SIZE);
    
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
    cached_client_hello = malloc(len);
    memcpy(cached_client_hello, buf, len);
    cached_client_hello_size = len;

    free_tlv(ch);

    global_hs_state = IN_SERVER_HELLO;

    return len;
}

static size_t send_server_hello(uint8_t* buf) {

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
        return -1;
    }
    
    add_tlv(sh, cert_from_file);
    
    // server's public key
    tlv* server_pk = create_tlv(PUBLIC_KEY);
    add_val(server_pk, public_key, pub_key_size);
    add_tlv(sh, server_pk);

    // hs sig
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

    memcpy(sign_data, cached_client_hello, cached_client_hello_size); // append client hello
    memcpy(sign_data + cached_client_hello_size, nonce_buf, nonce_len); // append server nonce
    free(nonce_buf);
    memcpy(sign_data + cached_client_hello_size + nonce_len, certificate, cert_size); // append cert
    memcpy(sign_data + cached_client_hello_size + nonce_len + cert_size, pk_buf, pk_len); // append pub key
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
    
    free_tlv(sh);
    
    global_hs_state = IN_CLIENT_FINISHED;
    return sh_len;
}

size_t send_client_finished(uint8_t* buf) {
    // hmac calculation
    uint8_t transcript_digest[MAC_SIZE];
    calculate_transcript(transcript_digest);

    // build the FINISHED message w/ the transcript
    tlv* transcript = create_tlv(TRANSCRIPT);
    add_val(transcript, transcript_digest, MAC_SIZE);
    
    tlv* finished = create_tlv(FINISHED);
    add_tlv(finished, transcript);
    
    uint16_t len = serialize_tlv(buf, finished);
    
    print_tlv_bytes(buf, len);
    
    free_tlv(finished);
    
    global_hs_state = HANDSHAKE_DONE;
    handshake_complete = 1;
    return len;
}

size_t send_msg(uint8_t* buf, size_t max_length) {
    // Read plaintext from input (max 943 bytes)
    uint8_t plaintext[MAX_PLAINTEXT_LEN]; 
    ssize_t plaintext_len = input_io(plaintext, MAX_PLAINTEXT_LEN);
    
    if (plaintext_len > 0) {
        // Create DATA TLV
        tlv* data_tlv = create_tlv(DATA);
        
        // Create IV TLV - but don't generate the IV yet
        tlv* iv_tlv = create_tlv(IV);
        uint8_t iv[IV_SIZE]; // IV will be filled by encrypt_data
        add_val(iv_tlv, iv, IV_SIZE); // Add placeholder value, will be updated
        add_tlv(data_tlv, iv_tlv);
        
        // Create CIPHERTEXT TLV
        tlv* cipher_tlv = create_tlv(CIPHERTEXT);
        uint8_t ciphertext[1024]; // Buffer for ciphertext
        
        // encrypt_data will fill the IV and return the ciphertext length
        // The IV is passed as both input and output parameter
        size_t cipher_len = encrypt_data(iv, ciphertext, plaintext, plaintext_len);
        add_val(cipher_tlv, ciphertext, cipher_len);
        add_tlv(data_tlv, cipher_tlv);
        
        // Since IV has been updated by encrypt_data, update the value in the TLV
        // (If our add_val makes a copy, we need to update it)
        memcpy(iv_tlv->val, iv, IV_SIZE);
        
        // Serialize the IV and CIPHERTEXT TLVs for MAC calculation
        uint8_t iv_tlv_buf[100];
        uint16_t iv_tlv_len = serialize_tlv(iv_tlv_buf, iv_tlv);
        
        uint8_t cipher_tlv_buf[1024];
        uint16_t cipher_tlv_len = serialize_tlv(cipher_tlv_buf, cipher_tlv);
        
        // Allocate buffer for both serialized TLVs
        uint8_t* mac_data = malloc(iv_tlv_len + cipher_tlv_len);
        if (!mac_data) {
            free_tlv(data_tlv);
            return 0;
        }
        
        // Combine the serialized TLVs for MAC calculation
        memcpy(mac_data, iv_tlv_buf, iv_tlv_len);
        memcpy(mac_data + iv_tlv_len, cipher_tlv_buf, cipher_tlv_len);
        
        // Create MAC TLV
        tlv* mac_tlv = create_tlv(MAC);
        uint8_t digest[MAC_SIZE];
        hmac(digest, mac_data, iv_tlv_len + cipher_tlv_len);
        free(mac_data);
        
        add_val(mac_tlv, digest, MAC_SIZE);
        add_tlv(data_tlv, mac_tlv);
        
        // Serialize the DATA message
        uint16_t len = serialize_tlv(buf, data_tlv);
        free_tlv(data_tlv);
        
        return len;
    }
    return 0;
}
