#ifndef __LIBIFE_IFE_H__
#define __LIBIFE_IFE_H__

#if defined(__cplusplus)
extern "C" {
#endif

#include <linux/rtnetlink.h>
#include <arpa/inet.h>
#include <linux/ife.h>
#include <assert.h>
#include <stdbool.h>
#include <stdarg.h>

enum ife_log_level {
	IFE_LOG_DEBUG,
	IFE_LOG_INFO,
	IFE_LOG_WARN,
	IFE_LOG_ERR,
	IFE_LOG_NONE
};

typedef void (*logfn)(enum ife_log_level, const char *file, int line,
		      const char *fn, const char *format, va_list args);

void ife_set_log_level(enum ife_log_level level);
enum ife_log_level ife_get_log_level(void);
void ife_set_log_func(logfn func);

struct ife_attr {
	__u16 type;
	__u16 len;
	__u8 value[0];
};

__u8 *ife_packet_parse(const __u8 *packet_data, __u32 packet_len,
		       struct ife_attr **parsed_data);

static inline __u32 ife_get_attr_u32(struct ife_attr *attr)
{
	__u32 *pdata;

	assert(attr->len >= sizeof(__u32));
	pdata = (__u32 *)attr->value;
	return ntohl(*pdata);
}

static inline __u16 ife_get_attr_u16(struct ife_attr *attr)
{
	__u16 *pdata;

	assert(attr->len >= sizeof(__u16));
	pdata = (__u16 *)attr->value;
	return ntohs(*pdata);
}

static inline __u8 ife_get_attr_u8(struct ife_attr *attr)
{
	assert(attr->len >= sizeof(__u8));
	return attr->value[0];
}

static inline bool ife_attr_valid_num(struct ife_attr *attr)
{
	return (attr && ntohs(attr->len) >= 1);
}

static inline __u32 ife_get_attr_num(struct ife_attr *attr)
{
	int attrlen = ntohs(attr->len);

	assert(attrlen >= 1);

	if (attrlen >= 4)
		return ife_get_attr_u32(attr);
	else if (attrlen >= 2)
		return (__u32)ife_get_attr_u16(attr);
	else
		return (__u32)ife_get_attr_u8(attr);
}

#if defined(__cplusplus)
}
#endif

#endif /* __LIBIFE_IFE_H__ */
