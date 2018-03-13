
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>

#include <pcap.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>

#define ERR(...)				\
	do {					\
		warnx(__VA_ARGS__);		\
		goto cleanup;			\
	} while (0)

/*
 * There are various ways WoL could be sent.  Some simple common values are:
 * - `ether proto 0x0842` -- common ethernet packet type (used by e.g. `etherwake`)
 * - `udp port [079]` -- common UDP ports
 * - `udp port 40000` -- uncommon UDP port, but used by `wol`
 *
 * Since MagicPacket can be part of any payload you can always miss one if using
 * any rule at all, but no rule means scanning every packet, which is very costly.
*/
#define WOL_FILTER \
	"ether proto 0x0842 or "					\
	"udp port 0 or udp port 7 or udp port 9 or "			\
	"udp port 40000"

#define SYNC_STREAM_BYTES 6
#define NUM_ADDRESSES 16
static const uint8_t sync_stream[SYNC_STREAM_BYTES] = { 0xff, 0xff, 0xff,
							0xff, 0xff, 0xff };

static void
cleanup_pcap(pcap_t **opaque)
{
	pcap_t *handle = *opaque;
	if (handle)
		pcap_close(handle);
}


struct mac_addr {
	uint8_t octet[ETH_ALEN];
} __attribute__((packed));


struct magic_packet {
	uint8_t sync_stream[SYNC_STREAM_BYTES];
	struct mac_addr addrs[NUM_ADDRESSES];
} __attribute__((packed));


static bool
is_magic_packet(const struct magic_packet *pkt)
{
	size_t i = 0;

	if (memcmp(pkt->sync_stream, &sync_stream, SYNC_STREAM_BYTES) != 0)
		return false;

	for (i = 1; i < NUM_ADDRESSES; i++) {
		if (memcmp(pkt->addrs, pkt->addrs + i, ETH_ALEN) != 0)
			return false;
	}

	return true;
}


static const struct magic_packet *
check_packet(const u_char *packet, size_t length)
{
	const struct magic_packet *payload = (const struct magic_packet *) packet;

	do {
		size_t remaining = length - ((const u_char *) payload - packet);
		size_t places = remaining - sizeof(struct magic_packet);

		if (places < 0)
			return NULL;

		payload = memmem(payload, remaining + sizeof(sync_stream),
				 &sync_stream, sizeof(sync_stream));

		if (payload && is_magic_packet(payload))
			break;
	} while (payload);

	return payload;
}


static void
handle_packet(u_char *user,
	      const struct pcap_pkthdr *h,
	      const u_char *bytes)
{
	pcap_t *handle = (void *) user;
	const struct magic_packet *payload = check_packet(bytes, h->caplen);

	if (!payload)
		return;

	pcap_breakloop(handle);

	if (isatty(STDOUT_FILENO))
		printf("Found MAC address to wake up: ");

	printf("%02x:%02x:%02x:%02x:%02x:%02x\n",
	       payload->addrs[0].octet[0], payload->addrs[0].octet[1],
	       payload->addrs[0].octet[2], payload->addrs[0].octet[3],
	       payload->addrs[0].octet[4], payload->addrs[0].octet[5]);
}


int
main(int argc, char **argv)
{
	pcap_t __attribute__((cleanup(cleanup_pcap))) *handle = NULL;
	char error_string[PCAP_ERRBUF_SIZE];
	const char *device = NULL;
	struct bpf_program filter = {0};
	int ret = EXIT_FAILURE;

	device = pcap_lookupdev(error_string);
        if(!device)
                ERR("%s", error_string);

	handle = pcap_open_live("any", BUFSIZ, 1, 0, error_string);
	if(!handle)
		ERR("%s", error_string);

	if (pcap_compile(handle, &filter,
			 argc > 1 ? argv[1] : WOL_FILTER,
			 1, PCAP_NETMASK_UNKNOWN) < 0)
		ERR("%s", pcap_geterr(handle));

	if (pcap_setfilter(handle, &filter) < 0)
		ERR("%s", pcap_geterr(handle));

	if (pcap_loop(handle, -1, handle_packet, (void *) handle) == -1)
		ERR("%s", pcap_geterr(handle));

	ret = EXIT_SUCCESS;
 cleanup:
	return ret;
}
