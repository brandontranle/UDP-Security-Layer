#include "consts.h"
#include "io.h"
#include "libsecurity.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "helpers.h"

void init_sec(int type, char* host) {
    init_io();
    global_type = type;
    
    if (type == CLIENT) {
        global_hs_state = IN_CLIENT_HELLO;
        generate_private_key();
        derive_public_key();
        load_ca_public_key("ca_public_key.bin");
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
        return send_client_hello(buf);
    } 
    // SERVER HELLO PHASE
    else if (global_type == SERVER && global_hs_state == IN_SERVER_HELLO && client_hello_received) {
        return send_server_hello(buf);
    }    
    // CLIENT SENDING FINISHED
    else if (global_type == CLIENT && global_hs_state == IN_CLIENT_FINISHED && server_hello_received) {
        return send_client_finished(buf);  
    }
    // DATA EXCHANGE PHASE
    else if (handshake_complete) {
        return send_msg(buf, max_length);
    }
    return 0;
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

    // SERVER PROCESSING CLIENT FINISHED
    if (global_type == SERVER && global_hs_state == IN_CLIENT_FINISHED) {
        process_client_finished(buf, length);
        return;
    }

    // handle receiving data ~ decryption
    if (handshake_complete) {
        process_msg(buf, length);
        return;
    }

    output_io(buf, length);
}