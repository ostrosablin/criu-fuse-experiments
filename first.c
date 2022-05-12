#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdint.h>

#define SOCK_PATH  "/tmp/fuse_uds"

static int send_fd(int via, int fd)
{
	struct msghdr h = {};
	struct cmsghdr *ch;
	struct iovec iov;
	char buf[CMSG_SPACE(sizeof(int))], c = '\0';
	int *fdp;

	h.msg_control = buf;
	h.msg_controllen = sizeof(buf);
	ch = CMSG_FIRSTHDR(&h);
	ch->cmsg_level = SOL_SOCKET;
	ch->cmsg_type = SCM_RIGHTS;
	ch->cmsg_len = CMSG_LEN(sizeof(int));
	fdp = (int *)CMSG_DATA(ch);
	*fdp = fd;
	h.msg_iov = &iov;
	h.msg_iovlen = 1;
	iov.iov_base = &c;
	iov.iov_len = sizeof(c);

	while (sendmsg(via, &h, 0) <= 0 && errno == ENOTCONN);

	return 0;
}

static int recv_fd(int via)
{
	struct msghdr h = {};
	struct cmsghdr *ch;
	struct iovec iov;
	char buf[CMSG_SPACE(sizeof(int))], c;
	int *fdp;

	h.msg_control = buf;
	h.msg_controllen = sizeof(buf);
	h.msg_iov = &iov;
	h.msg_iovlen = 1;
	iov.iov_base = &c;
	iov.iov_len = sizeof(c);

	if (recvmsg(via, &h, 0) <= 0)
		return -1;

	ch = CMSG_FIRSTHDR(&h);
	if (h.msg_flags & MSG_TRUNC)
		return -2;
	if (ch == NULL)
		return -3;
	if (ch->cmsg_type != SCM_RIGHTS)
		return -4;

	fdp = (int *)CMSG_DATA(ch);
	return *fdp;
}

int main(int argc, char **argv)
{
	int fd;

	int sk;
	struct sockaddr_un sockaddress;
	uint32_t buf[2] = { 100, 100};

	sockaddress.sun_family = AF_UNIX;
	strcpy(sockaddress.sun_path, SOCK_PATH);

	fd = open("./hello_ll", O_RDONLY);

	sk = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (setsockopt(sk, SOL_SOCKET, SO_SNDBUFFORCE, &buf[0], sizeof(buf[0])) < 0 ||
		setsockopt(sk, SOL_SOCKET, SO_RCVBUFFORCE, &buf[1], sizeof(buf[1])) < 0) {
		printf("Unable to set SO_SNDBUFFORCE/SO_RCVBUFFORCE");
		close(sk);
		return -1;
	}

	while(access(SOCK_PATH, F_OK | R_OK)) sleep(1);

	if (connect(sk, (struct sockaddr *) &sockaddress, sizeof(struct sockaddr_un)) == -1) {
		printf("socket: %s\n", strerror(errno));
		exit(1);
	}

	unlink(SOCK_PATH);

	if (send_fd(sk, fd) < 0) {
		printf("Can't send FUSE dev descriptor");
		exit(1);
	}

	

	return 0;
}