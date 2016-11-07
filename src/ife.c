#include "ife.h"
#include <linux/if_ether.h>
#include <linux/types.h>
#include <stdio.h>

#define ADVANCE(p, size, howmuch) \
	((size) -= (howmuch), \
	((__u8 *) (p)) + (howmuch))

#define ADVANCE_ALIGN(p, size, howmuch) ADVANCE(p, size, RTA_ALIGN(howmuch))

#define LOG(level, ...) \
		libife_log(level, __FILE__, __LINE__, __func__, __VA_ARGS__) \

#define LOG_DEBUG(...) LOG(IFE_LOG_DEBUG, __VA_ARGS__)
#define LOG_INFO(...)  LOG(IFE_LOG_DEBUG, __VA_ARGS__)
#define LOG_WARN(...)  LOG(IFE_LOG_DEBUG, __VA_ARGS__)
#define LOG_ERR(...)   LOG(IFE_LOG_DEBUG, __VA_ARGS__)

static void logfn_stderr(enum ife_log_level level, const char *file, int line,
			 const char *fn, const char *format, va_list args);

enum ife_log_level libife_loglevel = IFE_LOG_WARN;
logfn libife_logfunc = logfn_stderr;

void ife_set_log_level(enum ife_log_level level)
{
	libife_loglevel = level;
}

enum ife_log_level get_log_level(void)
{
	return libife_loglevel;
}

void ife_set_log_func(logfn func)
{
	libife_logfunc = func;
}

static const char *loglevel_str(enum ife_log_level level)
{
	switch (level) {
	case IFE_LOG_DEBUG:
		return "DEBUG";
	case IFE_LOG_INFO:
		return "INFO";
	case IFE_LOG_WARN:
		return "WARN";
	case IFE_LOG_ERR:
		return "ERROR";
	default:
		return "UNKNOWN";
	}
}

static void logfn_stderr(enum ife_log_level level, const char *file, int line,
			 const char *fn, const char *format, va_list args)
{
	fprintf(stderr, "libife %s %s: ", loglevel_str(level), fn);
	vfprintf(stderr, format, args);
	fprintf(stderr, "\n");
}

void libife_log(enum ife_log_level level,
		const char *file, int line, const char *fn,
		const char *format, ...)
{
	va_list args;

	va_start(args, format);

	if (level >= libife_loglevel)

	libife_logfunc(level, file, line, fn, format, args);
	va_end(args);
}

__u8 *ife_packet_parse(const __u8 *packet_data, __u32 packet_len,
		       struct ife_attr **parsed_data)
{
	struct ife_attr *attr;
	int ife_hlen;
	int attrlen;

	if (!packet_data || !parsed_data) {
		LOG_ERR("Could not process NULL args");
		return NULL;
	}

	if (packet_len < ETH_ALEN + IFE_METAHDRLEN) {
		LOG_ERR("Packet len %d too short to be IFE packet",
		       packet_len);
		return NULL;
	}

	packet_data += ETH_HLEN;
	ife_hlen = ntohs(*(__u16 *)packet_data);
	LOG_INFO("Got packet ife header len %d", ife_hlen);
	if (packet_len < ETH_ALEN + ife_hlen) {
		LOG_ERR("Packet len %d too short to have the ife header",
		       packet_len);
		return NULL;
	}

	packet_data = ADVANCE(packet_data, ife_hlen, IFE_METAHDRLEN);

	attr = (struct ife_attr *) packet_data;
	while (ife_hlen > 0) {
		parsed_data[ntohs(attr->type)] = attr;
		LOG_DEBUG("Got ife attr of type %x and len %x",
			ntohs(attr->type), ntohs(attr->len));

		attrlen = ntohs(attr->len);
		if (attrlen == 0)
			break;

		attr = (struct ife_attr *)ADVANCE_ALIGN(attr, ife_hlen,
							attrlen);
	}

	if (ife_hlen != 0) {
		LOG_ERR("IFE packet damaged, as the total tlv lengths does not add to ife header len");
		return NULL;
	}

	return (__u8 *)attr;
}
