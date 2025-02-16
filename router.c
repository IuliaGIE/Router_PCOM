#include <arpa/inet.h> /* ntoh, hton and inet_ functions */
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include "lib.h"
#include "list.h"
#include "queue.h"
#include "protocols.h"
#include <string.h>
#include <linux/if_ether.h>

/* Routing table */
struct route_table_entry *rtable;
int rtable_len;

/* Mac table */
struct arp_table_entry *arp_table;
int arp_table_len;

int check_checksumIP(struct iphdr *header_ip) {
	uint16_t old_check = ntohs(header_ip->check);
	header_ip->check = 0;
	return (old_check == checksum((uint16_t *)header_ip, sizeof(struct iphdr))) ? 0 : -1;
}

/* Returns a pointer (eg. &rtable[i]) to the best matching route, or NULL if there
 is no matching route. */
//LPM algorithm using binary search to find the best route
struct route_table_entry *get_best_route(int left, int right, uint32_t ip_dest, struct route_table_entry *best_route) {
	int mid = (left + right) / 2;
	return (right - left < 0) ? best_route :
		(ntohl(rtable[mid].prefix & rtable[mid].mask) < ntohl(ip_dest & rtable[mid].mask)) 
			? get_best_route(mid + 1, right, ip_dest, best_route) :
			  (ntohl(rtable[mid].prefix & rtable[mid].mask) > ntohl(ip_dest & rtable[mid].mask)) 
			  	? get_best_route(left, mid - 1, ip_dest, best_route) :
				  (best_route = rtable + mid, get_best_route(mid + 1, right, ip_dest, best_route));
}


struct arp_table_entry *get_arp_entry(uint32_t given_ip) {
	/* Iterate through the MAC table and search for an entry
	 that matches given_ip. */
	int i;
	for (i = 0; i < arp_table_len && given_ip != arp_table[i].ip; i++);
	return (i < arp_table_len) ? &arp_table[i] : NULL;
}

int compare(const void *x, const void *y) {
    struct route_table_entry *r1 = (struct route_table_entry *) x;
    struct route_table_entry *r2 = (struct route_table_entry *) y;

    return (ntohl(r1->prefix & r1->mask) == ntohl(r2->prefix & r2->mask)) ? 
           (ntohl(r1->mask) - ntohl(r2->mask)) : 
           (ntohl(r1->prefix & r1->mask) - ntohl(r2->prefix & r2->mask));
}


/* Send an ICMP message depending on the given type */
void send_icmp(char *buf, int interface, uint8_t type) {
    struct ether_header *eth_hdr = (struct ether_header *) buf;
    struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));
    struct icmphdr *icmp_hdr = (struct icmphdr *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));

    // Ethernet Header
	memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);
	get_interface_mac(interface, eth_hdr->ether_shost);
	
    // IP Header
	ip_hdr->protocol = IPPROTO_ICMP;
	ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
	ip_hdr->id = htons(1);
	ip_hdr->ttl = 63;
	ip_hdr->check = 0;
	ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));

	uint32_t tmp = ip_hdr->daddr;
	ip_hdr->daddr = ip_hdr->saddr;
	ip_hdr->saddr = tmp;

    // ICMP Header
	icmp_hdr->type = type;
	icmp_hdr->code = 0;
	icmp_hdr->checksum = 0;
	icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr, sizeof(struct icmphdr)));

	send_to_link(interface, buf, sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr));
}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	/* Don't touch this */
	init(argc - 2, argv + 2);

	/* Code to allocate the MAC and route tables */
	rtable = malloc(sizeof(struct route_table_entry) * 100000);
	/* DIE is a macro for sanity checks */
	DIE(rtable == NULL, "memory");

	arp_table = malloc(sizeof(struct  arp_table_entry) * 10);
	DIE(arp_table == NULL, "memory");
	
	/* Read the static routing table and the MAC table */
	rtable_len = read_rtable(argv[1], rtable);
	arp_table_len = parse_arp_table("arp_table.txt", arp_table);

	qsort(rtable, rtable_len, sizeof(struct route_table_entry), compare);

	while (1) {
		/* We call recv_from_any_link to receive a buf. 
		recv_from_any_link returns the interface it has received 
		the data from. And writes to len the size of the buf. */
		int interface;
		size_t len;
		
		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *) buf;
		/* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */
		struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));
		struct icmphdr *icmp_hdr = (struct icmphdr *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));

		/* Check if we got an IPv4 packet */
		if (ntohs(eth_hdr->ether_type) == 0x0800) {
			/* Check the ip_hdr integrity using checksum */
			if (check_checksumIP(ip_hdr) < 0) {
				continue;
				}
			
			/*Check if the router is the destination of the received packet and 
			  if the protocol in the IP header is ICMP*/
			// if an ECHO REQUEST was received => Send an ECHO REPLY
			if(ip_hdr->daddr == inet_addr(get_interface_ip(interface)) && 
		   	   ip_hdr->protocol == 1 && icmp_hdr->type == 8) {
				send_icmp(buf, interface, 0);
				continue;
				}
			
			/* Call get_best_route to find the most specific route, continue; (drop) if null */
			struct route_table_entry *best_route = get_best_route(0, rtable_len - 1 ,ip_hdr->daddr, NULL);
			// If route is not found, send ICMP reply and drop the package
			if (best_route == NULL) {
				// ICMP DEST UNREACHABLE
				send_icmp(buf, interface, 3);
				continue;
				}
				
			/* Check TTL >= 1. */
			if(ip_hdr->ttl<=1){
			/*Verificare și actualizare TTL: pachetele cu câmpul TTL 
			având valoarea 1 sau 0 trebuiesc aruncate. Routerul va 
			trimite înapoi, către emițătorul pachetului un mesaj 
			ICMP de tip "Time exceeded" (mai multe detalii în 
			secțiunea ICMP). Altfel, câmpul TTL e decrementat.
			- fragment din cerinta :))*/
			// ICMP_TIME_EXCEEDED
			send_icmp(buf, interface, 11);
			continue;
		  }

		  /* Update TLL. Update checksum  */
		  ip_hdr->ttl -= 1;
		  ip_hdr->check = 0;
		  ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));

		  /* Update the ethernet addresses. Use get_arp_entry to find the destination MAC
		  address. */
		  struct arp_table_entry *dest_arp = get_arp_entry(best_route->next_hop);
		  if (dest_arp == NULL) {
			// No ARP entry
			continue;
			}
		
		memcpy(eth_hdr->ether_dhost, dest_arp->mac, ETH_ALEN);
		get_interface_mac(best_route->interface, eth_hdr->ether_shost);
		  
		send_to_link(best_route->interface, buf, len);
		}
	}
	free(rtable);
	free(arp_table);
}