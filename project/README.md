# Description of Work

### Design Choices
As we began this project, we didn't really know how to approach the design until we read through the TLV helpers doc. Thus, we strictly made `output_sec` responsible for processing packets, `input_sec` was responsible for creating new packets, and `init_sec` was responsbile for initializing and storing the values needed for first few steps of the handshake (i.e. Client-Hello & Server-Hello). Additionally, we wanted to have some sort of state management feature just to keep everything organized or easier to read/work with together; thus, we made a global variable "global_hs_state" that tracked the state of the handshake starting from the Client-hello till its Completion. Every feature in `security.c` is modularized into `helpers.h` for the sake of readability.


### Challenges
Test case 1 and 2 were fairly straight forward by following the instructions. The most difficult part of this was possibly importing the certificate. We did not realize we had to import the certificate from server_cert.bin. We kept creating a new one and then I realized where I was wrong. 

Test case 3 was fairly difficult in the sense that, we could not find what we were doing wrong. There was a minor mistake in our process where our Client was not using the correct MAC key to send the Client FINISHED. The mistake in our code was that we were not loading in the correct key using the `load_peer_public_key` before deriving our secret. Thus, we have two different calls of this function, where we load the server's public key from the certificate (which is used to verify the signature), then we have another call to load the server's ACTUAL public key for the key deriviation, leading to us passing the test case upon creating the correct TRANSCRIPT. 

Test Case 4 and 5 were straight forward test cases--however, we found challenges in processing the Client's FINISHED message (from the server's POV). That is, the digest was wrong because the MAC key was inconsistent to the Client's, thus we had to mimic the client's behavior of deriving the secret using the salt (ch + sh). 

Another challenge of this test case was again, verifying the MAC of incoming DATA packets. After posting on Piazza, we found that our issue was that we were not using the correct encodings, we had to use the TLV encodings of both the IV and CIPHERTEXT. After combining both TLVs in a buffer, our MAC calculation was correct. 

The last challenge we encountered while tackling this test case was configuring the correct behavior for our SERVER after processing the CLIENT FINISHED message. The ref client starts inputting data after we send our ACK packet back upon establishing the handshake connection, but our SERVER had issues in processing it because it was stuck in an infinite loop, sending ACK packets. To fix this, we erased the input_io() call in our input_sec which presumably was the default case.

