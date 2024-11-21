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

static uint8_t pt[PT_LEN];
static uint8_t ct[CT_LEN];
static uint8_t key[KEY_LEN];
static uint8_t iv[IV_LEN];

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
    aes_ctr = accept(alg_s, NULL, NULL);    // Controller that accepts connection on the socket.

    // Set up Initializaiton Vector (IV)
    // Need ssize_t sendmsg (int socket, const struct msghdr *message, int flags);
    uint_8_t cmsg_buf[CMSG_SPACE(sizeof(uint32_t)) + CMSG_SPACE(sizeof(struct af_alg_iv) + IV_LEN)] = {0};  // (cmsghdr + uint32) + (cmsghdr + algorithm IV struct{ivlen, and iv[]} + Bytes of IV) 
    struct msghdr msg{          // Need to construct mghdr message
        .msg_control = cmsg_buf,
        .msg_controllen = sizeof(csmg_buf)
    };

    // Setup first sequence of cmsghdr to store operations
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);     // Returns pointer to cmsghdr struct from msghdr to set cmsghdr attributes
    cmsg->cmsg_len = CMSG_LEN(sizeof(uint32_t));    // data byte count including cmsghdr
    cmsg->cmsg_level = SOL_ALG;                     // symetric encryption algorithm protocol
    cmsg->cmsg_type = ALG_SET_OP;                   // socket performs operations.
    *((uint32_t *)CMSG_DATA(cmsg)) = ALG_OP_ENCRYPT;// Operation of Encrypt Or Decrypt. Points to data array in Ancillary data

    // Setups up next sequence of cmsghdr structure
    cmsg = CMSG_NXTHDR(&msg, cmsg);

    // Set up pipes for Zero-Copy interface


    // Call system call multiple times for Block encryption


    return 0;
}

