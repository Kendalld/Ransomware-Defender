/* Objective: Encrypts users data using Linux crypto library. By using
sockets to send data to kernal space for enryption, all encryption system
calls can be captured to determine if ransomware attack is occuring. This
program will demonstrate a encryption system call an attacker may use. 
*/

#define _GNU_SOURCE

#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <sys/stat.h>

#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <sys/random.h>
#include <sys/socket.h> // Used for socke handeling
#include <linux/if_alg.h>   // Defines struct (sockaddr_alg) for interface with encrypting over socket
#include <poll.h>

#define PT_LEN (63 * 1024) // Max number of data used by zero copy interface (63 kilobytes * size of Kilobyte )[64512]
#define CT_LEN PT_LEN
#define IV_LEN 16
#define KEY_LEN 16
#define ITER_COUNT 100000

static uint8_t pt[PT_LEN];  // Plain Text
static uint8_t ct[CT_LEN];  // Cipher Text
static uint8_t key[KEY_LEN];// Cipher Key
static uint8_t iv[IV_LEN];  // Cipher Initialization Vector


static const unsigned char crypto_key[] = "testtest12345678";
static const char plain_text[] = "stringtoencrypt0";
static int opfd = -1, tfmfd = -1;
static const char algo[] = "ecb(aes)";

int main(void){

    char dst[16] = {0};
    char afalg_plain[16] = {0};

    // Open file and return file descriptor
    int fd;
    fd = open("ImportantInfo.txt", O_RDWR);
    if (fd == -1){
        perror("Could not open file");
    }
    struct stat file_stat;
    if(fstat(fd, &file_stat) == -1){
        perror("fstat");
    }

    int fdsize = file_stat.st_size;
    printf("The size of file is: %d bytes\n", fdsize);

    int plaintxtlen = fdsize/sizeof(u_char);
    u_char plaintxt[plaintxtlen] = {0};
    u_char ciphertxt[plaintxtlen] = {0};

    struct sockaddr_alg sa = {
		.salg_family = AF_ALG,
		.salg_type = "skcipher",
		.salg_name = "ecb(aes)"
	};

	tfmfd = socket(AF_ALG, SOCK_SEQPACKET, 0);
	if (tfmfd == -1){
	    perror("Socket failed");
        return 1;
    }
	if (bind(tfmfd, (struct sockaddr *)&sa, sizeof(sa)) == -1){
        perror("bind failed");
        return 1;
    }
	if (setsockopt(tfmfd, SOL_ALG, ALG_SET_KEY, crypto_key, 16) == -1){
        perror("setting options of socket failed");
        return 1;
    }
	opfd = accept(tfmfd, NULL, 0);
	if (opfd == -1){
        perror("accepting connections failed");
        return 1;
    }

    struct msghdr msg = {};
	struct cmsghdr *cmsg;           // Refer to https://github.com/torvalds/linux/blob/aaf20f870da056752f6386693cc0d8e25421ef35/net/sctp/socket.c#L8807 for breakdown of cmsghdr Structure
	char cbuf[CMSG_SPACE(4)] = {0};
	struct iovec iov;

	msg.msg_control = cbuf;
	msg.msg_controllen = sizeof(cbuf);

	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_ALG;
	cmsg->cmsg_type = ALG_SET_OP;
	cmsg->cmsg_len = CMSG_LEN(4);
	*(__u32 *)CMSG_DATA(cmsg) = ALG_OP_ENCRYPT;


    if(read(fd, plaintxt, fdsize) == -1){
        perror("read 1");
    }

    fflush(stdout);
    printf("This is in plaintxt: %s\n", plaintxt);
    iov.iov_base = (char *)plaintxt;
	iov.iov_len = sizeof(plaintxt);

	// iov.iov_base = (char *)plain_text;
	// iov.iov_len = sizeof(dst);

	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	printf("The output of sendmsg: %d\n",sendmsg(opfd, &msg, 0));
    if(read(opfd, ciphertxt, plaintxtlen) == -1){
        perror("read 2");
    }

    printf("The CipherTxt is: %s\n",ciphertxt);

    // Decrypt
    cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_ALG;
	cmsg->cmsg_type = ALG_SET_OP;
	cmsg->cmsg_len = CMSG_LEN(4);
	*(__u32 *)CMSG_DATA(cmsg) = ALG_OP_DECRYPT;

    fflush(stdout);
    printf("This is in ciphertxt: %s\n", ciphertxt);
    iov.iov_base = (char *)ciphertxt;
	iov.iov_len = sizeof(ciphertxt);

    printf("The output of sendmsg: %d\n",sendmsg(opfd, &msg, 0));
    if(read(opfd, plaintxt, plaintxtlen) == -1){
        perror("read 3");
    }

    printf("The Plaintxt is: %s\n",plaintxt);


	//printf("The amount of bytes read are :%ld. The characters stored in dst are: %s",read(opfd, dst, sizeof(dst)), dst);

    
    // // Fill test data
    // getrandom(pt, sizeof(pt), GRND_NONBLOCK);
    // getrandom(ct, sizeof(ct), GRND_NONBLOCK);
    // getrandom(key, sizeof(key), GRND_NONBLOCK);
    // getrandom(iv, sizeof(iv), GRND_NONBLOCK);

    // // Set up AF_ALG Socket
    // int alg_s, aes_ctr;
    // struct sockaddr_alg sa = {
    //     .salg_family = AF_ALG,
    //     .salg_type = "skcipher",
    //     .salg_name = "ecb(aes)"
    // };
    
    // // strcpy(sa.salg_type, "skcipher");
    // // strcpy(sa.salg_name, "ctr-aes-aesni");

    // alg_s = socket(AF_ALG, SOCK_SEQPACKET, 0);  // AF_ALG determines that socket will be for encryption
    // if(alg_s < 0){
    //     perror("Socket failed");
    //     return 1;
    // }
    // int bind_result = bind(alg_s,(struct sockaddr *)&sa, sizeof(sa));   // Assigns an address to a socket using file descriptor.
    // if(bind_result < 0){
    //     perror("bind failed");
    //     return 1;
    // }
    // int sockset_result = setsockopt(alg_s, SOL_ALG, ALG_SET_KEY, key, KEY_LEN);  // Sets options at the option name and level, defining that this socket will be used for encryption and be used as a key.
    // if(sockset_result < 0){
    //     perror("setting options of socket failed");
    //     return 1;
    // }
    // aes_ctr = accept(alg_s, NULL, 0);    // Controller that accepts connection on the socket. Returns file descriptor used to identify socket.
    // if(aes_ctr < 0){
    //     perror("accepting connections failed");
    //     return 1;
    // }
    // // int notClosed = close(alg_s);
    // // if(notClosed){
    // //     perror("Socket closing failed");
    // //     return 1;
    // // }

    // // Set up Initializaiton Vector (IV)
    // // Need ssize_t sendmsg (int socket, const struct msghdr *message, int flags); msg_control described in Socket.c
    // uint8_t cmsg_buf[CMSG_SPACE(sizeof(uint32_t)) + CMSG_SPACE(sizeof(struct af_alg_iv)/* + IV_LEN*/)] = {0};  // (cmsghdr + uint32) + (cmsghdr + (algorithm IV struct{ivlen, and iv[]} + Bytes of IV)). Defines space needed to store IV vector pairs [cmsghdr, dataarray[]]. 
    // struct msghdr msg = {          // Need to construct mghdr message
    //     .msg_control = cmsg_buf,
    //     .msg_controllen = sizeof(cmsg_buf)
    // };

    // // Setup first sequence of cmsghdr to store operations
    // struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);     // Returns pointer to cmsghdr struct from msghdr to set cmsghdr attributes
    // cmsg->cmsg_len = CMSG_LEN(sizeof(uint32_t));    // data byte count. This is size of "ALG_OP_ENCRYPT" which is an uint32.
    // cmsg->cmsg_level = SOL_ALG;                     // Symetric encryption algorithm protocol
    // cmsg->cmsg_type = ALG_SET_OP;                   // Socket performs operations.
    // *((uint32_t *)CMSG_DATA(cmsg)) = ALG_OP_ENCRYPT;// Operation of Encrypt Or Decrypt. Points to data array in Ancillary data

    // // Setups up next sequence of cmsghdr structure
    // cmsg = CMSG_NXTHDR(&msg, cmsg);                 // Cmsg points to next sequence of cmsghdr.
    // cmsg->cmsg_len = CMSG_LEN(sizeof(struct af_alg_iv)/* + IV_LEN*/);   // Af_alg_iv struct + 16 Bytes.
    // cmsg->cmsg_level = SOL_ALG;
    // cmsg->cmsg_type = ALG_SET_IV;
    // ((struct af_alg_iv *)CMSG_DATA(cmsg))->ivlen = IV_LEN;          // Set IV length to 16 Bytes.
    // memcpy(((struct af_alg_iv *)CMSG_DATA(cmsg))->iv, iv, IV_LEN);  // copies data from iv array into CMSG data array which is 16 Bytes.

    // // Input Output Structure. Stores buffer of plain text for pipe to access.
    // struct iovec pt_iov = {
    //     .iov_base = pt,
    //     .iov_len = PT_LEN
    // };

    // msg.msg_iov = &pt_iov;
    // msg.msg_iovlen = 1;

    // // int flags = fcntl(aes_ctr, F_GETFL, 0);
    // // if(flags == -1){
    // //     perror("fcntl F_GETFL");
    // // }
    // // if (fcntl(aes_ctr, F_SETFL, flags | O_NONBLOCK) == -1) {
    // // perror("fcntl F_SETFL");
    // // }

    // printf("Now sending message\n");
    // if(-1 == sendmsg(aes_ctr, &msg, MSG_DONTWAIT)){
    //     perror("error with Socket");
    // }

    // END OF COMMENT********************************************** */ 
    // // printf("Bytes sent were: %d",bytesSent );                                 // Sends system call to kernal space.
    // // read(aes_ctr, ct, CT_LEN);

    // // // Set up pipes for Zero-Copy interface
    // // int pipes[2];   // File descriptors that point at files
    // // pipe(pipes);


    // printf("Finished I/O structure\n");


    // Call system call multiple times for Block encryption
    // int i;
    // for(i = 0; i < ITER_COUNT; i++){
    //     vmsplice(pipes[1],&pt_iov, 1, SPLICE_F_GIFT);    // Takes output/ writing interface of pipe and maps input/output vector segment into a pipe.
    //     splice(pipes[0], NULL, aes_ctr, NULL, sizeof(pt), SPLICE_F_MORE);   // Takes input of pipe and sends to aes contol socket. SPLICE_F_MORE means more data is comming

    //     struct pollfd pfd;
    //     pfd.fd = aes_ctr,       // Socket file descriptor
    //     pfd.events = POLLIN,    // Interested in read events (POLLIN)
    //     pfd.revents = 0;        // will be set by kernal poll()

    //     int ret = poll(&pfd, 1, 1000);    // Timeout is in milliseconds.
    //     if(ret > 0){
    //         if(pfd.revents & POLLIN){    // Mask of kernal sigifying polling.
    //             // Data avaliable to be read
    //             int bytes_read = read(aes_ctr, ct, sizeof(ct));
    //             if(bytes_read > 0){
    //                 printf("Bytes have been read: %c\n", ct[i]);
    //             }else if(bytes_read == 0){
    //                 printf("Socket has no more data");
    //             }else{
    //                 printf("Error reading from socket");
    //             }
    //         }
    //     } else if(ret == 0){
    //         printf("Timeout: No data avaliable on the socket");
    //     } else{ 
    //         printf("Error in Poll()");
    //     }


    //     //vmsplice(pipes[1],&pt_iov, 1, SPLICE_F_GIFT);    // Takes output/ writing interface of pipe and maps input/output vector segment into a pipe.
    //     //splice(pipes[0], NULL, aes_ctr, NULL, sizeof(pt), SPLICE_F_MORE);   // Takes input of pipe and sends to aes contol socket. SPLICE_F_MORE means more data is comming
    //     //read(aes_ctr, ct, sizeof(ct));  // Takes aes pointer/ file descriptor buffer and store into cipher text buffer.
    // }
    // // // Final call to read data.
    // // vmsplice(pipes[1],&pt_iov, 1, SPLICE_F_GIFT);
    // // splice(pipes[0], NULL, aes_ctr, NULL, sizeof(pt), 0);
    // // read(aes_ctr, ct, sizeof(ct));

    // // Close file descriptors connected to open pipes and sockets 
    // close(pipes[0]);
    // close(pipes[1]);
    // close(aes_ctr);
    // printf("all sockets and pipes are closed\n");

    return 0;
}

