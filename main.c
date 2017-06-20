#include <locale.h>
#include <ncurses.h>
#include <signal.h>

#include <stdlib.h>
#include <string.h>

#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <net/ethernet.h>
#include <arpa/inet.h>

#define PACKET_BUFSIZE 65536
#define SA struct sockaddr

static WINDOW *info_win;
static WINDOW *main_win;

// initscr successfully called
bool ncurses_on;

// program is running
bool running = 1;

// statistic counter
size_t packets_total;

void fail_exit(char const *msg);

void term_deinit(void);
void term_init(void);

void sniff(int rsock, unsigned char *buf, size_t bufsize);
void print_statistic(WINDOW *win);

void process_packet(unsigned char *buf, int size);

void print_eth_hdr(unsigned char* buf);
void print_ip_hdr(unsigned char* buf);

void print_tcp_packet(unsigned char *buf, int bufsize);
void print_tcp_hdr(unsigned char *buf);

void print_udp_packet(unsigned char *buf, int bufsize);
void print_udp_hdr(unsigned char* buf);

void print_icmp_packet(unsigned char* buf, int bufsize);
void print_icmp_hdr(unsigned char* buf);

void print_unknown_packet(unsigned char *buf, int bufsize);

void print_data_hex(unsigned char *buf, int size);
void print_data_ascii(unsigned char *buf, int size);

void sig_handle(int unused);

int main(void)
{
	struct sigaction act = {0};
	act.sa_handler = sig_handle;
	sigaction(SIGINT, &act, NULL);
	sigaction(SIGTERM, &act, NULL);

	term_init();

	unsigned char *buf = (unsigned char *)malloc(PACKET_BUFSIZE);
	if (!buf)
		fail_exit("Error. malloc");

	int sock_raw = socket( PF_PACKET, SOCK_RAW, htons(ETH_P_ALL)) ;
	if (sock_raw < 0)
		fail_exit("Error. Could not create raw socket.");

	print_statistic(info_win);
	doupdate();

	while (running) {
		sniff(sock_raw, buf, PACKET_BUFSIZE);
		print_statistic(info_win);
		doupdate();
	}

	term_deinit();
	free(buf);

	exit(EXIT_SUCCESS);
}

void sig_handle(int unused)
{
	(void) unused;
	running = false;
}

void fail_exit(char const *msg)
{
	//? !isendwin()
	if (ncurses_on)
		endwin();
	fprintf(stderr, "%s\n", msg);
	exit(EXIT_FAILURE);
}

void term_init(void)
{
	setlocale(LC_ALL, "");

	if (initscr() == NULL)
		fail_exit("Failed to initialize ncurses");

	ncurses_on = true;

	cbreak();
	noecho();
	curs_set(0);

	if (LINES >= 2) {
		info_win = newwin(LINES -1, COLS, LINES - 1, 0);
		main_win = newwin(LINES - 1, COLS, 0, 0);
	} else {
		fail_exit("Window is too small.");
	}

	if (info_win == NULL || main_win == NULL)
		fail_exit("Failed to ctreate windows.");

	keypad(main_win, TRUE);
	scrollok(main_win,TRUE);
}

void term_deinit(void)
{
	delwin(info_win);
	delwin(main_win);
	if (ncurses_on) {
		endwin();
		ncurses_on = false;
	}
}

void print_statistic(WINDOW *win)
{
	werase(win);
	wattron(win, A_REVERSE);
	wprintw(win, "Packets: %d", packets_total);
	wattroff(win, A_REVERSE);
	wnoutrefresh(win);
}

void sniff(int rsock, unsigned char *buf, size_t bufsize)
{
	struct sockaddr_storage saddr;
	socklen_t saddr_size = sizeof(saddr);

	int data_size = recvfrom(rsock, buf, bufsize,
	                         0, (SA *)&saddr, &saddr_size);
	if (data_size < 0)
		wprintw(main_win, "\nRecvfrom error , failed to get packets\n");

	process_packet(buf, data_size);
	packets_total++;
}

void process_packet(unsigned char* buf, int size)
{
	struct iphdr *iph = (struct iphdr*)(buf + sizeof(struct ethhdr));
	switch (iph->protocol) {
	case IPPROTO_ICMP:
		print_icmp_packet(buf, size);
		break;

	case IPPROTO_TCP:
		print_tcp_packet(buf, size);
		break;

	case IPPROTO_UDP:
		print_udp_packet(buf, size);
		break;

	default:
		print_unknown_packet(buf, size);
		break;
	}
	wprintw(main_win, "\n\n");
	wnoutrefresh(main_win);
}

void print_eth_hdr(unsigned char* buf)
{
	struct ethhdr *eth = (struct ethhdr *)(buf);

	wprintw(main_win, "ETH\t");

	wprintw(main_win, "src %.2X-%.2X-%.2X-%.2X-%.2X-%.2X",
	        eth->h_source[0], eth->h_source[1], eth->h_source[2],
	        eth->h_source[3], eth->h_source[4], eth->h_source[5]);

	wprintw(main_win, "  dest %.2X-%.2X-%.2X-%.2X-%.2X-%.2X",
	        eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
	        eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);

	wprintw(main_win, "  protocol: %d", eth->h_proto);
}

void print_ip_hdr(unsigned char* buf)
{
	struct iphdr *ip = (struct iphdr*)buf;
	struct sockaddr_in source, dest;

	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = ip->saddr;
	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = ip->daddr;

	wprintw(main_win, "IP\t");
	wprintw(main_win, "ver %d", (unsigned int)ip->version);
	wprintw(main_win, "   len %d", ntohs(ip->tot_len));
	wprintw(main_win, "   ttl %d",(unsigned int)ip->ttl);
	wprintw(main_win, "   prot %d",(unsigned int)ip->protocol);
	wprintw(main_win, "   checksum %d",ntohs(ip->check));
	wprintw(main_win, "   srcIP %s",  inet_ntoa(source.sin_addr));
	wprintw(main_win, "   destIP %s", inet_ntoa(dest.sin_addr));
}

void print_tcp_packet(unsigned char *buf, int bufsize)
{
	int ethhdr_len = sizeof(struct ethhdr);
	struct iphdr *ip = (struct iphdr*)(buf + ethhdr_len);
	int iphdr_len = ip->ihl * 4;

	 struct tcphdr *tcph=(struct tcphdr*)(buf + iphdr_len + ethhdr_len);
	int tcphdr_len = tcph->doff * 4;

	int hdrs_len = iphdr_len  + ethhdr_len  + tcphdr_len;
	int pdata_size = bufsize - hdrs_len;
	unsigned char *pdata = buf + hdrs_len;

	print_eth_hdr(buf);
	wprintw(main_win, "\n");
	print_ip_hdr(buf + ethhdr_len);
	wprintw(main_win, "\n");
	print_tcp_hdr(buf + ethhdr_len + iphdr_len);
	wprintw(main_win, "\n");
	print_data_ascii(pdata, pdata_size);
	wprintw(main_win, "\n");
	print_data_hex(pdata, pdata_size);
}

void print_tcp_hdr(unsigned char *buf)
{
	struct tcphdr *tcp = (struct tcphdr *)buf;
	wprintw(main_win, "TCP\t");
	wprintw(main_win, "src port %u",ntohs(tcp->source));
	wprintw(main_win, "   dest port %u",ntohs(tcp->dest));
	wprintw(main_win, "   seq# %u",ntohl(tcp->seq));
	wprintw(main_win, "   ack# %u",ntohl(tcp->ack_seq));
	wprintw(main_win, "   win size %d", ntohs(tcp->window));
	wprintw(main_win, "   checksum %d", ntohs(tcp->check));

	wprintw(main_win, "   flags(");
	if (tcp->urg)
		wprintw(main_win, " urg");
	if (tcp->ack)
		wprintw(main_win, " ack");
	if (tcp->psh)
		wprintw(main_win, " psh");
	if (tcp->rst)
		wprintw(main_win, " psh");
	if (tcp->syn)
		wprintw(main_win, " syn");
	if (tcp->fin)
		wprintw(main_win, " fin");
	wprintw(main_win, ")");
}

void print_udp_packet(unsigned char *buf, int bufsize)
{
	int ethhdr_len = sizeof(struct ethhdr);
	struct iphdr *ip = (struct iphdr*)(buf + ethhdr_len);
	int iphdr_len = ip->ihl * 4;
	int udphdr_len = sizeof(struct udphdr);
	int hdrs_len = iphdr_len  + ethhdr_len  + udphdr_len;
	int pdata_size = bufsize - hdrs_len;
	unsigned char *pdata = buf + hdrs_len;

	print_eth_hdr(buf);
	wprintw(main_win, "\n");
	print_ip_hdr(buf + ethhdr_len);
	wprintw(main_win, "\n");
	print_udp_hdr(buf + ethhdr_len + iphdr_len);
	wprintw(main_win, "\n");
	print_data_ascii(pdata, pdata_size);
	wprintw(main_win, "\n");
	print_data_hex(pdata, pdata_size);
}

void print_udp_hdr(unsigned char* buf)
{
	struct udphdr *udp = (struct udphdr *)buf;
	wprintw(main_win, "UDP\t");
	wprintw(main_win, "src port %d", ntohs(udp->source));
	wprintw(main_win, "   dest port %d", ntohs(udp->dest));
	wprintw(main_win, "   length %d", ntohs(udp->len));
	wprintw(main_win, "   checksum %d", ntohs(udp->check));
}

void print_icmp_packet(unsigned char* buf, int bufsize)
{
	int ethhdr_len = sizeof(struct ethhdr);
	struct iphdr *ip = (struct iphdr*)(buf + ethhdr_len);
	int iphdr_len = ip->ihl * 4;
	int icmphdr_len = sizeof(struct icmphdr);
	int hdrs_len = iphdr_len  + ethhdr_len + icmphdr_len;
	int pdata_size = bufsize - hdrs_len;
	unsigned char *pdata = buf + hdrs_len;

	print_eth_hdr(buf);
	wprintw(main_win, "\n");
	print_ip_hdr(buf + ethhdr_len);
	wprintw(main_win, "\n");
	print_icmp_hdr(buf + ethhdr_len + iphdr_len);
	wprintw(main_win, "\n");
	print_data_ascii(pdata, pdata_size);
	wprintw(main_win, "\n");
	print_data_hex(pdata, pdata_size);
}

void print_icmp_hdr(unsigned char* buf)
{
	struct icmphdr *icmp = (struct icmphdr *)buf;
	wprintw(main_win, "ICMP\t");
	wprintw(main_win, "type %d", (unsigned int)(icmp->type));
	wprintw(main_win, "   code %d",(unsigned int)(icmp->code));
	wprintw(main_win, "   checksum %d",ntohs(icmp->checksum));
}

void print_data_hex(unsigned char *buf, int size)
{
	wprintw(main_win, "DATA HEX\t");
	for(int i=0; i < size; i++)
		wprintw(main_win," %.2X ", buf[i]);
}

void print_data_ascii(unsigned char *buf, int size)
{
	wprintw(main_win, "DATA ASCII\t");
	for(int i=0; i < size; i++)
		wprintw(main_win,"%c", buf[i]);
}

void print_unknown_packet(unsigned char *buf, int bufsize)
{
	wprintw(main_win, "UNKNOWN\t");
	wprintw(main_win, "\n");
	print_data_ascii(buf, bufsize);
	wprintw(main_win, "\n");
	print_data_hex(buf, bufsize);
}

