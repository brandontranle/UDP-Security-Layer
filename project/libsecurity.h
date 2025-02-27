#pragma once

#include <openssl/evp.h>
#include <stdint.h>

extern EVP_PKEY* ec_peer_public_key;
extern EVP_PKEY* ec_ca_public_key;
extern uint8_t* certificate;
extern size_t cert_size;
extern uint8_t* public_key;
extern size_t pub_key_size;

void load_private_key(const char* filename);

EVP_PKEY* get_private_key();

void set_private_key(EVP_PKEY* key);

void load_peer_public_key(const uint8_t* peer_key, size_t size);

void load_ca_public_key(const char* filename);

void load_certificate(const char* filename);

void generate_private_key();

void derive_public_key();

void derive_secret();

void derive_keys(const uint8_t* salt, size_t size);

size_t sign(uint8_t* signature, const uint8_t* data, size_t size);

int verify(const uint8_t* signature, size_t sig_size, const uint8_t* data,
           size_t size, EVP_PKEY* authority);

void generate_nonce(uint8_t* buf, size_t size); 

size_t encrypt_data(uint8_t* iv, uint8_t* cipher, const uint8_t* data, size_t size);

size_t decrypt_cipher(uint8_t* data, const uint8_t* cipher, size_t size, const uint8_t* iv);

void hmac(uint8_t* digest, const uint8_t* data, size_t size);
