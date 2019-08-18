#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "socket/interface.h"
#include "socket/sock.h"
#include "net_headers/dns.h"
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <pthread.h>
#include <errno.h>
#include <time.h>
#include <signal.h>

char *dns_to_str(char *dns);
void print_results(u_char *mac, u_char *ip, char *query, time_t time_point, FILE *file);
int set_signal_capture(int signum, void *function);
void sigint_handler();

int STOP = 1;

int main(int argc, char **argv)
{
	if(argc < 3)
	{
		printf("Using: ./dns_sniff [INTERFACE] [IP ADDRESS]\n");

		exit(-1);
	}

	FILE *journal;
	int sock;
	struct interface *iface;
	struct ethhdr *eth;
	struct iphdr *ip;
	struct udphdr *udp;
	dnshdr *dns;
	char *queries;
	char *resource;
	u_int target_ip;
	unsigned char packet[254];
	char errbuf[255];
	time_t current_time;

	current_time = time(NULL);

	// open a file for saving of results
	if((journal = fopen(ctime(&current_time), "w")) == NULL)
	{
		printf("[!] Can't open file \"%s\", %s\n", argv[3], strerror(errno));

		exit(-1);
	}

	// get interface parameters
	if((iface = get_interface_params(argv[1], errbuf)) == NULL)
	{
		printf("[!] %s\n", errbuf);

		exit(-1);
	}

	// open a packet socket
	if((sock = create_packet_socket(iface, errbuf)) == -1)
	{
		printf("[!] %s\n", errbuf);

		exit(-1);
	}

	eth = (struct ethhdr *)packet;
	ip = (struct iphdr *)(packet + ETH_HLEN);

	target_ip = inet_addr(argv[2]);

	set_signal_capture(SIGINT, &sigint_handler);

	while(STOP)
	{
		memset(packet, 0, 255);

		if(recv(sock, packet, 254, 0) <= 0)
		{
			printf("[!] %s\n", strerror(errno));

			break;
		}

		udp = (struct udphdr *)(packet + ETH_HLEN + ip->ihl*4);
		dns = (dnshdr *)(packet + ETH_HLEN + ip->ihl*4 + sizeof(struct udphdr));
		queries = (packet + ETH_HLEN + ip->ihl*4 + sizeof(struct udphdr) + sizeof(dnshdr));

		if((ntohs(udp->uh_dport) == 53) && (*(u_int *)&ip->saddr == target_ip))
		{
			if(dns->opcode == 0)
			{
				current_time = time(NULL);

				resource = dns_to_str(queries);

				print_results(eth->h_source, (u_char *)&ip->saddr, resource, current_time, journal);

			}
		}
	}

	fclose(journal);
	close(sock);

	printf("[*] Sniffing interrupted, exit\n");

}

char *dns_to_str(char *dns)
{
	int str_count = 0, dns_count = 0, domain_len;
	static char str[56];

	memset(str, 0, 56);

	while(dns[dns_count] != 0)
	{
		domain_len = dns[dns_count];

		strncpy(&str[str_count], &dns[dns_count + 1], domain_len);

		str_count += domain_len;

		// set character '.' to current position
		str[str_count] = '.';
		str_count++;

		// set value pointers to new positions
		dns_count += domain_len + 1;
	}

	str[str_count-1] = '\0';

	return str;
}

void print_results(u_char *mac, u_char *ip, char *query, time_t time_point, FILE *file)
{
	printf("%s", ctime(&time_point));

	printf("%02x", mac[0]);
	for(int i = 1; i < 6; i++)
		printf(":%02x", mac[i]);

	putchar(' ');

	printf("%s ", inet_ntoa(*(struct in_addr *)ip));
	printf("%s\n\n", query);

	fprintf(file, "%s", ctime(&time_point));

	fprintf(file, "Mac: %02x", mac[0]);
	for(int i = 1; i < 6; i++)
		fprintf(file, ":%02x", mac[i]);

	putc(' ', file);

	fprintf(file, "Ip: %s\n", inet_ntoa(*(struct in_addr *)ip));
	fprintf(file, "Query: %s\n\n", query);
}

int set_signal_capture(int signum, void *function)
{
	struct sigaction sa;

	sa.sa_flags = SA_RESTART;
	sigemptyset(&sa.sa_mask);
	sa.sa_sigaction = function;

	if(sigaction(signum, &sa, NULL) == -1)
		return -1;

	return 0;
}

void sigint_handler()
{
	STOP--;
}
