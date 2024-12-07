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
#include <stdbool.h>
#include <stdlib.h>

#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <sys/random.h>
#include <sys/socket.h> // Used for socke handeling
#include <linux/if_alg.h>   // Defines struct (sockaddr_alg) for interface with encrypting over socket

#define IV_LEN 16

static const unsigned char crypto_key[] = "testtest12345678";   //128 Byte Key
static const char plain_text[] = "stringtoencrypt0";
static int opfd = -1, tfmfd = -1;
static const char algo[] = "ecb(aes)";

static const unsigned char iv[IV_LEN];

void cryptFile(char *FileName, bool encrypt);

int main(void){

    char *filename = "ImportantInfo.txt";
    cryptFile(filename, true);
    cryptFile(filename, false);

    return 0;
}

void cryptFile(char *FileName, bool encrypt){

    // Open file and return file descriptor
    int fd;
    fd = open(FileName, O_RDWR);
    if (fd == -1){
        perror("Could not open file");
    }
    struct stat file_stat;
    if(fstat(fd, &file_stat) == -1){
        perror("fstat");
    }

    int fdsize = file_stat.st_size;         // Size in bytes of file.

    // Set field of Plaintxt and Ciphertxt to number of characters in file.
    int txtlen = fdsize/sizeof(u_char);
    u_char inputtxt[txtlen] = {};
    u_char outputtxt[txtlen] = {};

    // Set address of the socket.
    struct sockaddr_alg sa = {
		.salg_family = AF_ALG,
		.salg_type = "skcipher",
		.salg_name = "cbc(aes)"//"ecb(aes)"
	};

	tfmfd = socket(AF_ALG, SOCK_SEQPACKET, 0);
	if (tfmfd == -1){
	    perror("Socket failed");
        exit(1);
    }
	if (bind(tfmfd, (struct sockaddr *)&sa, sizeof(sa)) == -1){
        perror("bind failed");
        exit(1);
    }
	if (setsockopt(tfmfd, SOL_ALG, ALG_SET_KEY, crypto_key, 16) == -1){
        perror("setting options of socket failed");
        exit(1);
    }
	opfd = accept(tfmfd, NULL, 0);
	if (opfd == -1){
        perror("accepting connections failed");
        exit(1);
    }

    getrandom(iv, sizeof(iv), 0);

    struct msghdr msg = {};
	struct cmsghdr *cmsg;           // Refer to https://github.com/torvalds/linux/blob/aaf20f870da056752f6386693cc0d8e25421ef35/net/sctp/socket.c#L8807 for breakdown of cmsghdr Structure
	char cbuf[CMSG_SPACE(4)/*+ CMSG_SPACE(sizeof(struct af_alg_iv))*/] = {};  // Insures that theres enough space for cmsghdr and 4 bytes(int) to store Encrypt or Decrypt macro
	struct iovec iov;

	msg.msg_control = cbuf;
	msg.msg_controllen = sizeof(cbuf);

	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_ALG;
	cmsg->cmsg_type = ALG_SET_OP;
	cmsg->cmsg_len = CMSG_LEN(4);
	*(__u32 *)CMSG_DATA(cmsg) = encrypt ? ALG_OP_ENCRYPT : ALG_OP_DECRYPT;

    // CMSG_NXTHDR(&msg, cmsg);
    // cmsg->cmsg_level = SOL_ALG;
    // cmsg->cmsg_type = ALG_SET_IV;
    // cmsg->cmsg_len = CMSG_LEN(sizeof(struct af_alg_iv));
    // ((struct af_alg_iv *)CMSG_DATA(cmsg))->ivlen = IV_LEN;            // Sets length of IV.
    // memcpy(((struct af_alg_iv *)CMSG_DATA(cmsg))->iv, iv, IV_LEN);

    // Storedata from file into iotxt buffer.
    if(read(fd, inputtxt, fdsize) == -1){
        perror("read 1");
    }

    fflush(stdout);
    printf("This is in inputtxt:%s\n", inputtxt);

    // Set buffer location for I/O operations.
    iov.iov_base = (char *)inputtxt;
	iov.iov_len = sizeof(inputtxt);

    // Set message Scatter/Gather Operations buffer.
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

    fflush(stdout);
    int smsgOut = sendmsg(opfd, &msg, 0) == -1;
    if(smsgOut == -1){
        perror("sendmsg Error");
    }

	printf("The output of sendmsg: %ld\n", smsgOut);
    if(read(opfd, outputtxt, txtlen) == -1){
        perror("read 2");
    }

    // Storedata from file into iotxt buffer.
    if(ftruncate(fd, 0) == -1){
        perror("Error Truncating file");
        close(fd);
    }

    lseek(fd, 0, SEEK_SET);

    fflush(stdout);
    printf("The outputtxt is:%s\n",outputtxt);
    // write ciphertxt to the File. Effectively completeing ransomware encryption.
    int temp = write(fd, outputtxt, txtlen);

    close(fd);
    close(tfmfd);
    close(opfd);

    return;

}