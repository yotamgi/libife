#include <stdlib.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <memory.h>
#include <unistd.h>
#include <ife.h>

#define PACKET_LEN_MAX 5000

int tun_alloc(char *dev, int flags)
{
	struct ifreq ifr;
	int fd, err;
	char *clonedev = "/dev/net/tun";

	fd = open(clonedev, O_RDWR);
	if (fd < 0)
		return fd;

	/* preparation of the struct ifr, of type "struct ifreq" */
	memset(&ifr, 0, sizeof(ifr));

	ifr.ifr_flags = flags;

	if (*dev) {
		/* if a device name was specified, put it in the structure;
		 * otherwise,the kernel will try to allocate the "next" device
		 * of the specified type
		 */
		strncpy(ifr.ifr_name, dev, IFNAMSIZ);
	}

	/* try to create the device */
	err = ioctl(fd, TUNSETIFF, (void *) &ifr);
	if (err < 0) {
		close(fd);
		return err;
	}

	return fd;
}

void dump_buf(const __u8 *buf, int size)
{
	int i;

	for (i = 0; i < size; i++) {
		printf("%02x ", (unsigned int) buf[i]);
		if (i % 16 == 15)
			printf("\n");
	}
	printf("\n");
}

const char *metatype_to_str(int metatype)
{
	switch (metatype) {
	case IFE_META_SKBMARK:
		return "skbmark";
	case IFE_META_HASHID:
		return "hashid";
	case IFE_META_PRIO:
		return "prio";
	case IFE_META_QMAP:
		return "amap";
	case IFE_META_TCINDEX:
		return "tcindex";
	case IFE_META_IN_IFINDEX:
		return "in ifindex";
	case IFE_META_OUT_IFINDEX:
		return "out ifindex";
	case IFE_META_ORIGSIZE:
		return "origsize";
	case IFE_META_SIZE:
		return "size";
	case IFE_META_SAMPLER_ID:
		return "sampler id";
	case IFE_META_SEQ:
		return "seq";
	}
	return "UNKNOWN_FIELD";
}

void parse_ife(const __u8 *packet, ssize_t size)
{
	struct ife_attr *attrs[__IFE_META_MAX] = { 0 };
	int metatype;
	u_char *payload;

	payload = ife_packet_parse(packet, size, attrs);
	if (!payload) {
		printf("Packet is not a valid IFE packet\n");
		dump_buf(packet, size);
		return;
	}

	for (metatype = 1; metatype < __IFE_META_MAX; metatype++) {
		if (!attrs[metatype])
			continue;

		printf("packet IFE meta %s with value 0x%x\n",
		       metatype_to_str(metatype),
		       ife_get_attr_num(attrs[metatype]));
	}

	printf("The encapsulated packet is:\n");
	dump_buf(payload, size - (payload - packet));
}

int main(int argc, char **argv)
{
	unsigned char buf[PACKET_LEN_MAX];
	ssize_t num_read;
	int fd;

	if (argc != 2) {
		printf("usage: %s <tap device>\n", argv[0]);
		return -1;
	}

	fd = tun_alloc(argv[1], IFF_TAP | IFF_NO_PI);
	if (fd < 0) {
		printf("Could not open tap\n");
		return -1;
	}

	while (1) {
		num_read = read(fd, buf, PACKET_LEN_MAX);
		printf("Read %d bytes\n", (unsigned int)num_read);
		parse_ife(buf, num_read);
		printf("\n");
	}

	return 0;
}

