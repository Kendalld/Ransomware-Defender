/* Objective: Encrypts users data using Linux crypto library. By using
sockets to send data to kernal space for enryption, all encryption system
calls can be captured to determine if ransomware attack is occuring. This
program will demonstrate a encryption system call an attacker may use. 
*/

#define _GNU_SOURCE

#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <sys/random.h>
#include <sys/socket.h> // Used for socke handeling
#include <linux/if_alg.h>   // Defines struct (sockaddr_alg) for interface with encrypting over socket

#define PT_LEN (63 * 1024) // Max number of data used by zero copy interface (63 kilobytes * size of Kilobyte )
#define CT_LEN PT_LEN
#define IV_LEN 16
#define KEY_LEN 16
#define ITER_COUNT 100000

static uint8_t pt[PT_LEN];  // Plain Text
static uint8_t ct[CT_LEN];  // Cipher Text
static uint8_t key[KEY_LEN];// Cipher Key
static uint8_t iv[IV_LEN];  // Cipher Initialization Vector

int main(void){

    // Fill test data
    * int key;
    std::getrandom(pt, sizeof(pt), GRNC_NONBLOCK);
    std::getrandom(ct, sizeof(ct), GRNC_NONBLOCK);
    std::getrandom(key, sizeof(key), GRNC_NONBLOCK);
    std::getrandom(iv, sizeof(iv), GRNC_NONBLOCK);

    // Set up AF_ALG Socket
    int alg_s, aes_ctr;
    struct sockaddr_alg sa = { .salg_faimly = AF_ALG};
    strcpy(sa.salg_type, "skcipher");
    strcpy(sa.salg_name, "ctr-aes-aesni");

    alg_s = socket(AF_ALG, SOCK_SEQPACKET, 0);  // AF_ALG determines that socket will be for encryption
    bind(alg_s,(const struct sockaddr *)&sa, sizeof(sa));   // Assigns an address to a socket using file descriptor.
    setsockopt(alg_s, SOL_ALG, ALG_SET_KEY, key, KEY_LEN);  // Sets options at the option name and level, defining that this socket will be used for encryption and be used as a key.
    aes_ctr = accept(alg_s, NULL, NULL);    // Controller that accepts connection on the socket. Returns file descriptor used to identify socket.

    // Set up Initializaiton Vector (IV)
    // Need ssize_t sendmsg (int socket, const struct msghdr *message, int flags);
    uint_8_t cmsg_buf[CMSG_SPACE(sizeof(uint32_t)) + CMSG_SPACE(sizeof(struct af_alg_iv) + IV_LEN)] = {0};  // (cmsghdr + uint32) + (cmsghdr + (algorithm IV struct{ivlen, and iv[]} + Bytes of IV)). Defines space needed to store IV vector pairs [cmsghdr, dataarray[]]. 
    struct msghdr msg{          // Need to construct mghdr message
        .msg_control = cmsg_buf,
        .msg_controllen = sizeof(csmg_buf)
    };

    // Setup first sequence of cmsghdr to store operations
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);     // Returns pointer to cmsghdr struct from msghdr to set cmsghdr attributes
    cmsg->cmsg_len = CMSG_LEN(sizeof(uint32_t));    // data byte count including cmsghdr
    cmsg->cmsg_level = SOL_ALG;                     // Symetric encryption algorithm protocol
    cmsg->cmsg_type = ALG_SET_OP;                   // Socket performs operations.
    *((uint32_t *)CMSG_DATA(cmsg)) = ALG_OP_ENCRYPT;// Operation of Encrypt Or Decrypt. Points to data array in Ancillary data

    // Setups up next sequence of cmsghdr structure
    cmsg = CMSG_NXTHDR(&msg, cmsg);                 // Cmsg points to next sequence of cmsghdr.
    cmsg->csmg_len = CMSG_LEN(sizeof(struct af_alg_iv) + IV_LEN);   // Af_alg_iv struct + 16 Bytes.
    cmsg->cmsg_level = SOL_ALG;
    cmsg->cmsg_type = ALG_SET_IV;
    ((struct af_alg_iv *))CMSG_DATA(cmsg)->ivlen = IV_LEN           // Set IV length to 16 Bytes.
    memcpy(((struct af_alg_iv *)CMSG_DATA(cmsg))-> iv, iv, IV_LEN); // copies data from iv array into CMSG data array which is 16 Bytes.
    sendmsg(aes_ctr, &msg, 0);                                      // Sends system call to kernal space.

    // Set up pipes for Zero-Copy interface
    int pipes[2];   // File descriptors that point at files
    pipe(pipes);

    // Input Output Structure. 
    struct iovec pt_iov = {
        .iov_base = pt;
        .iov_len = sizeof(pt);
    }

    // Call system call multiple times for Block encryption
    int i;
    for(int i = 0; i < ITER_COUNT; i++){
        vmsplice(pipes[1],&pt_iov, 1, SPLICE_F_GIFT);    // Takes output/ writing interface of pipe and maps input/output vector segment into a pipe.
        splice(pipes[0], NULL, aes_ctr, NULL, sizeof(pt), SPLICE_F_MORE);   // Takes input of pipe and sends to aes contol socket. SPLICE_F_MORE means more data is comming
        read(aes_ctr, ct, sizeof(ct));  // Takes aes pointer/ file descriptor buffer and store into cipher text buffer.
    }
    // Final call to read data.
    vmsplice(pipes[1],&pt_iov, 1, SPLICE_F_GIFT);
    splice(pipes[0], NULL, aes_ctr, NULL, sizeof(pt), 0);
    read(aes_ctr, ct, sizeof(ct));

    // Close file descriptors connected to open pipes and sockets 
    close(pipes[0]);
    close(pipes[1]);
    close(aes_ctr);


    return 0;
}

