#include "skel.h"

struct route_table_entry *rtable;
int rtable_size;

struct arp_entry *arp_table;
int arp_table_len;

struct route_table_entry *get_best_route(__u32 dest_ip) {
	int left = 0, right = rtable_size - 1, mid, res = -1;
	while (left <= right) {
		mid = (left + right) / 2;
		if (rtable[mid].prefix <= (dest_ip & rtable[mid].mask)) {
			res = mid;
			left = mid + 1;
		} else {
			right = mid - 1;
		}
	}
	if ((dest_ip & rtable[res].mask) == rtable[res].prefix) {
		return &rtable[res];
	}
	return NULL;
}

struct arp_entry *get_arp_entry(__u32 ip) {
  	for (int i = 0; i < arp_table_len; i++) {
  		if (ip == arp_table[i].ip) {
  			return &arp_table[i];
  		}
  	}  
    return NULL;
}

int cmp_prefix(const void *a, const void *b) {
	const struct route_table_entry *pa =  a;
	const struct route_table_entry *pb =  b;
	uint32_t val = pa->prefix - pb->prefix;
	if (val == 0) {
		uint32_t msk = pa->mask - pb->mask;
		if (msk < 0) val = 1;
		if (msk > 0) val = -1;
		if (msk == 0) val = 0;
	}
	return val;
}

void sort_route_table() {
	qsort(rtable, rtable_size, sizeof(struct route_table_entry), cmp_prefix);
}

void create_new_packet(packet *pkt, struct ether_header *eth_hdr, struct iphdr *ip_hdr, int type, int interface) {
	memset(pkt->payload, 0, sizeof(pkt->payload));
	pkt->len = 0;
	pkt->interface = interface;
	struct ether_header *ethhdr = (struct ether_header *)pkt->payload;
	struct iphdr *ip_header = (struct iphdr *)(pkt->payload + sizeof(struct ether_header));
	struct icmphdr *icmp_header = (struct icmphdr *)(pkt->payload + sizeof(struct ether_header) + sizeof(struct iphdr));
	uint8_t mac[6];
	ethhdr->ether_type = htons(ETHERTYPE_IP);
	memcpy(mac, eth_hdr->ether_shost, 6);
	memcpy(ethhdr->ether_dhost, mac, 6);
	memcpy(mac, eth_hdr->ether_dhost, 6);
	memcpy(ethhdr->ether_shost, mac, 6);
	pkt->len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr);
	ip_header->version = 4;
	ip_header->ihl = sizeof(struct iphdr) / sizeof(int);
	ip_header->tos = 0;
	ip_header->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
	ip_header->id = htons(1);
	ip_header->frag_off = 0;
	ip_header->ttl = 64;
	ip_header->protocol = IPPROTO_ICMP;
	ip_header->saddr = ip_hdr->daddr;
	ip_header->daddr = ip_hdr->saddr;
	ip_header->check = 0;
	ip_header->check = ip_checksum(ip_header, sizeof(struct iphdr));
	icmp_header->code = 0;
	icmp_header->type = type;
	icmp_header->un.echo.id = 9;
	icmp_header->un.echo.sequence = htons(1);
	icmp_header->checksum = 0;
	icmp_header->checksum = ip_checksum(icmp_header, sizeof(struct icmphdr));
}

int main(int argc, char *argv[])
{
	packet m;
	int rc;

	init();

	rtable = malloc(sizeof(struct route_table_entry) * 100000);
	arp_table = malloc(sizeof(struct  arp_entry) * 100);
	parse_rtable();
	parse_arp_table();
	sort_route_table();

	while (1) {
		rc = get_packet(&m);
		DIE(rc < 0, "get_message");
		struct ether_header *eth_hdr = (struct ether_header *)m.payload;

		if (eth_hdr->ether_type == htons(ETHERTYPE_IP)) {
			struct iphdr *ip_hdr = (struct iphdr *)(m.payload + sizeof(struct ether_header));
			if (ip_hdr->protocol == IPPROTO_ICMP && ip_hdr->daddr == inet_addr(get_interface_ip(m.interface))) {
				struct icmphdr *icmp_hdr = (struct icmphdr *)(m.payload + sizeof(struct ether_header) + sizeof(struct iphdr));
				if (icmp_hdr->type == ICMP_ECHO) {
					packet pkt;
					create_new_packet(&pkt, eth_hdr, ip_hdr, ICMP_ECHOREPLY, m.interface);
					send_packet(pkt.interface, &pkt);
				}
			}
			
			if (ip_checksum(ip_hdr, sizeof(struct iphdr)) != 0) {
				continue;
			}
				
			if (ip_hdr->ttl <= 1) {
				packet pkt;
				create_new_packet(&pkt, eth_hdr, ip_hdr, ICMP_TIME_EXCEEDED, m.interface);
				send_packet(pkt.interface, &pkt);
				continue;
			}
			
			struct route_table_entry *best_route = get_best_route(ip_hdr->daddr);
			if (best_route == NULL) {
				packet pkt;
				create_new_packet(&pkt, eth_hdr, ip_hdr, ICMP_DEST_UNREACH, m.interface);
				send_packet(pkt.interface, &pkt);
				continue;
			}

			ip_hdr->ttl--;
			ip_hdr->check = 0;
			ip_hdr->check = ip_checksum(ip_hdr, sizeof(struct iphdr));
	
			struct arp_entry *arp_best_entry = get_arp_entry(ip_hdr->daddr);
			if (arp_best_entry == NULL) {
				continue;
			}
			
			memcpy(eth_hdr->ether_dhost, arp_best_entry->mac, sizeof(arp_best_entry->mac));
			send_packet(best_route->interface, &m);
		}
	}

}