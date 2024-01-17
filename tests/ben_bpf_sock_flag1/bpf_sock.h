#include<stdio.h>
#include<stdint.h>

struct bpf_sock {
	uint32_t bound_dev_if;
	uint32_t family;
	uint32_t type;
	uint32_t protocol;
	uint32_t mark;
	uint32_t priority;
	/* IP address also allows 1 and 2 bytes access */
	uint32_t src_ip4;
	uint32_t src_ip6[4];
	uint32_t src_port;	/* host byte order */
	//__be16 dst_port;	/* network byte order */
	//uint16_t :16;		/* zero padding */
	uint32_t dst_ip4;
	uint32_t dst_ip6[4];
	uint32_t state;
	int32_t  rx_queue_mapping;
};

#define AF_UNSPEC	0
#define AF_UNIX	1	/* Unix domain sockets 	*/
#define AF_LOCAL	1	/* POSIX name for AF_UNIX	*/
#define AF_INET	2	/* Internet IP Protocol 	*/
#define AF_AX25	3	/* Amateur Radio AX.25 	*/
#define AF_IPX		4	/* Novell IPX 			*/
#define AF_APPLETALK	5	/* AppleTalk DDP 		*/
#define AF_NETROM	6	/* Amateur Radio NET/ROM 	*/
#define AF_BRIDGE	7	/* Multiprotocol bridge 	*/
#define AF_ATMPVC	8	/* ATM PVCs			*/
#define AF_X25		9	/* Reserved for X.25 project 	*/
#define AF_INET6	10	/* IP version 6		*/

enum sock_type {
	SOCK_DGRAM	= 1,
	SOCK_STREAM	= 2,
	SOCK_RAW	= 3,
	SOCK_RDM	= 4,
	SOCK_SEQPACKET	= 5,
	SOCK_DCCP	= 6,
	SOCK_PACKET	= 10,
};

#define ETH_P_802_3_MIN 0x0600
#define ETH_P_8021Q 0x8100
#define ETH_P_8021AD 0x88A8
#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD
#define ETH_P_ARP 0x0806
#define IPPROTO_ICMP 2
#define IPPROTO_ICMPV6 58
