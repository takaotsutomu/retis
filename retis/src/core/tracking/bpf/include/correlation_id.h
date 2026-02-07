#ifndef __CORE_CORRELATION_ID__
#define __CORE_CORRELATION_ID__

/*
 * Correlation ID computation for cross-node packet correlation.
 *
 * The correlation_id is a deterministic hash computed from packet content
 * that will produce the same value regardless of which node observes the
 * packet. Unlike tracking_id (which uses node-local memory addresses and
 * timestamps), correlation_id enables true cross-node correlation.
 *
 * Supported protocols:
 *   - TCP: header-only hash (see __compute_tcp_hash for details)
 *   - UDP: length + payload sample
 *   - ICMP Echo: identifier + sequence number
 *
 * Returns 0 for unsupported protocols (no cross-node correlation available).
 */

#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

/* Jenkins hash implementation - inlined to avoid include path issues.
 * Taken from include/linux/jhash.h in the kernel tree.
 */

static inline __u32 __correlation_id_rol32(__u32 word, unsigned int shift)
{
	return (word << (shift & 31)) | (word >> ((-shift) & 31));
}

#define __correlation_id_mix(a, b, c)				\
{								\
	a -= c;  a ^= __correlation_id_rol32(c, 4);  c += b;	\
	b -= a;  b ^= __correlation_id_rol32(a, 6);  a += c;	\
	c -= b;  c ^= __correlation_id_rol32(b, 8);  b += a;	\
	a -= c;  a ^= __correlation_id_rol32(c, 16); c += b;	\
	b -= a;  b ^= __correlation_id_rol32(a, 19); a += c;	\
	c -= b;  c ^= __correlation_id_rol32(b, 4);  b += a;	\
}

#define __correlation_id_final(a, b, c)				\
{								\
	c ^= b; c -= __correlation_id_rol32(b, 14);		\
	a ^= c; a -= __correlation_id_rol32(c, 11);		\
	b ^= a; b -= __correlation_id_rol32(a, 25);		\
	c ^= b; c -= __correlation_id_rol32(b, 16);		\
	a ^= c; a -= __correlation_id_rol32(c, 4);		\
	b ^= a; b -= __correlation_id_rol32(a, 14);		\
	c ^= b; c -= __correlation_id_rol32(b, 24);		\
}

#define CORRELATION_ID_INITVAL	0xdeadbeef
#define CORRELATION_ID_SEED	0xC0FFEE42

static __always_inline u32 correlation_id_3words(u32 a, u32 b, u32 c, u32 initval)
{
	a += initval + CORRELATION_ID_INITVAL + (3 << 2);
	b += initval + CORRELATION_ID_INITVAL + (3 << 2);
	c += initval + CORRELATION_ID_INITVAL + (3 << 2);

	__correlation_id_final(a, b, c);

	return c;
}

/* Protocol numbers */
#define IPPROTO_ICMP	1
#define IPPROTO_TCP	6
#define IPPROTO_UDP	17
#define IPPROTO_ICMPV6	58

/* ETH_P values in network byte order for quick comparison */
#define ETH_P_IP	0x0800
#define ETH_P_IPV6	0x86dd

/* UDP payload sample size for hash computation. Using 16 bytes for better uniqueness. */
#define UDP_PAYLOAD_SAMPLE_SIZE	16

/*
 * Compute correlation ID for TCP packets using header-only fields.
 *
 * Hash inputs:
 *   - TCP sequence number (4 bytes)
 *   - TCP acknowledgment number (4 bytes)
 *   - TCP segment length (2 bytes) - derived from IP length
 *   - IP identification field (2 bytes, IPv4 only)
 *
 * Note: Payload bytes are intentionally NOT included. On the RX path (e.g.,
 * tcp_v4_rcv), TCP payload may reside in paged sk_buff memory that is
 * inaccessible to bpf_probe_read_kernel(). This causes reads to return zeros,
 * breaking cross-node correlation for data packets. Header fields are always
 * in the linear portion and can be read reliably at any probe point.
 *
 * Collision analysis:
 *   - IPv4: ip_id changes on retransmission, providing ~16 bits of entropy
 *     beyond (seq, ack, len). Retransmit collisions are prevented.
 *   - IPv6: No ip_id field. Relies on ~80 bits from (seq, ack, len). True
 *     retransmit collisions are theoretically possible but extremely rare
 *     (same seq/ack/len within the correlation window).
 */
static __always_inline u64 __compute_tcp_hash(
	unsigned char *head, int transport,
	u16 ip_id, int tcp_segment_len)
{
	u32 seq, ack, hash_lo, hash_hi;

	/* Read TCP sequence number (offset 0) and ack number (offset 4) */
	if (bpf_probe_read_kernel(&seq, 4, head + transport) < 0)
		return 0;
	if (bpf_probe_read_kernel(&ack, 4, head + transport + 4) < 0)
		return 0;
	seq = bpf_ntohl(seq);
	ack = bpf_ntohl(ack);

	/* Compute 32-bit Jenkins hash from seq, ack, and tcp_segment_len.
	 * tcp_segment_len is pre-normalized by the caller to account for
	 * IPv4/IPv6 ip_len semantic differences.
	 */
	hash_lo = correlation_id_3words(seq, ack, (u32)tcp_segment_len,
				      CORRELATION_ID_SEED);

	/* Compute second hash for upper 32 bits using ip_id.
	 * For IPv4, ip_id provides retransmission differentiation.
	 * For IPv6, ip_id is 0 but the seq/ack/len combination is still
	 * highly unique within a correlation window.
	 */
	hash_hi = correlation_id_3words(ip_id, seq ^ ack, (u32)tcp_segment_len,
				      CORRELATION_ID_SEED ^ 0x12345678);

	/* Combine into 64-bit hash */
	return ((u64)hash_hi << 32) | (u64)hash_lo;
}

/*
 * Compute correlation ID for UDP packets.
 *
 * Hash inputs:
 *   - UDP length (2 bytes) - differentiates zero-payload packets
 *   - First 16 bytes of UDP payload (16 bytes) - provides uniqueness
 *
 * UDP has GRO (Generic Receive Offload) similar to TCP, so high-throughput
 * UDP traffic may see packet coalescing that breaks correlation. Low-volume
 * traffic like DNS queries should correlate well.
 */
static __always_inline u64 __compute_udp_hash(
	unsigned char *head, int transport)
{
	u16 udp_len;
	u8 payload[UDP_PAYLOAD_SAMPLE_SIZE];
	u32 hash_lo, hash_hi;
	int payload_len;

	/* Read UDP length (bytes 4-5 of UDP header) */
	if (bpf_probe_read_kernel(&udp_len, 2, head + transport + 4) < 0)
		return 0;
	udp_len = bpf_ntohs(udp_len);

	__builtin_memset(payload, 0, UDP_PAYLOAD_SAMPLE_SIZE);

	/* Only read payload if there is any (UDP header is 8 bytes) */
	if (udp_len > 8) {
		/* Calculate payload start offset */
		int data_start = transport + 8; /* UDP header is 8 bytes */

		/* UDP length field includes header (8 bytes) + payload.
		 * The udp_len field is in the UDP header itself, so it's always
		 * the same regardless of IPv4/IPv6 - no version-specific handling needed.
		 * This avoids using skb->data which differs between probe points.
		 */
		payload_len = udp_len - 8;
		if (payload_len > UDP_PAYLOAD_SAMPLE_SIZE)
			payload_len = UDP_PAYLOAD_SAMPLE_SIZE;

		if (payload_len > 0) {
			/* Clamp for BPF verifier - ensures non-negative bounded value */
			payload_len &= 0x1f; /* Max 31, actual max is 16 */
			bpf_probe_read_kernel(payload, payload_len, head + data_start);
		}
	}

	/* Include UDP length in hash - differentiates zero-payload UDP packets
	 * like keepalives from actual data packets.
	 */
	hash_lo = correlation_id_3words(
		udp_len,
		((u32)payload[0] << 24) | ((u32)payload[1] << 16) |
		((u32)payload[2] << 8) | (u32)payload[3],
		((u32)payload[4] << 24) | ((u32)payload[5] << 16) |
		((u32)payload[6] << 8) | (u32)payload[7],
		CORRELATION_ID_SEED);

	hash_hi = correlation_id_3words(
		((u32)payload[8] << 24) | ((u32)payload[9] << 16) |
		((u32)payload[10] << 8) | (u32)payload[11],
		((u32)payload[12] << 24) | ((u32)payload[13] << 16) |
		((u32)payload[14] << 8) | (u32)payload[15],
		udp_len, /* Include length again for better mixing */
		CORRELATION_ID_SEED ^ 0x12345678);

	return ((u64)hash_hi << 32) | (u64)hash_lo;
}

/*
 * Compute correlation ID for ICMP Echo packets (ping request/reply).
 *
 * Hash inputs:
 *   - ICMP identifier (2 bytes) - per-process unique
 *   - ICMP sequence number (2 bytes) - increments per request
 *
 * Only Echo Request (type 8 for ICMPv4, type 128 for ICMPv6) and Echo Reply
 * (type 0 for ICMPv4, type 129 for ICMPv6) have identifier and sequence fields.
 * Other ICMP types return 0 (no cross-node correlation).
 *
 * ICMP does NOT have GRO, so correlation should be very reliable.
 */
static __always_inline u64 __compute_icmp_hash(
	unsigned char *head, int transport, int is_ipv6)
{
	u8 type;
	u16 id, seq;
	u32 hash;

	if (bpf_probe_read_kernel(&type, 1, head + transport) < 0)
		return 0;

	/* Check for echo request/reply types.
	 * ICMPv4: type 0 (echo reply), type 8 (echo request)
	 * ICMPv6: type 128 (echo request), type 129 (echo reply)
	 */
	if (is_ipv6) {
		if (type != 128 && type != 129)
			return 0;
	} else {
		if (type != 0 && type != 8)
			return 0;
	}

	/* Read identifier (offset 4) and sequence (offset 6) */
	if (bpf_probe_read_kernel(&id, 2, head + transport + 4) < 0)
		return 0;
	if (bpf_probe_read_kernel(&seq, 2, head + transport + 6) < 0)
		return 0;

	id = bpf_ntohs(id);
	seq = bpf_ntohs(seq);

	/* The id+seq combination is highly unique:
	 * - id is assigned per ping process (random or based on PID)
	 * - seq increments for each request
	 * Use a simple encoding that preserves these values directly in the hash.
	 */
	hash = correlation_id_3words(id, seq, type, CORRELATION_ID_SEED);

	/* Encode id and seq directly in upper bits for extra uniqueness.
	 * This creates a 64-bit value that is both a proper hash and
	 * preserves the original id/seq for debugging.
	 */
	return ((u64)id << 48) | ((u64)seq << 32) | (u64)hash;
}

/*
 * Main entry point for correlation ID computation.
 * See file header for supported protocols.
 */
static __always_inline u64 compute_correlation_id(
	struct sk_buff *skb, unsigned char *head)
{
	u8 ip_version, ip_proto;
	u16 ip_len, ip_id = 0;
	int network, transport;

	/* Validate that network and transport headers are set */
	if (!head)
		return 0;

	/* Check if network header offset is valid.
	 * network_header == (u16)~0U means "not set" in the kernel.
	 */
	network = BPF_CORE_READ(skb, network_header);
	if (network == 0xFFFF)
		return 0;

	/* Check if transport header offset is valid */
	transport = BPF_CORE_READ(skb, transport_header);
	if (transport == 0xFFFF)
		return 0;

	/* Calculate IP header length (including IPv6 extension headers).
	 * The kernel sets transport_header after parsing all IP headers,
	 * so this automatically handles IPv4 IHL and IPv6 extension headers.
	 */
	int ip_hdr_len = transport - network;
	if (ip_hdr_len < 20 || ip_hdr_len > 512)
		return 0; /* Sanity check: 512 allows many IPv6 extensions */

	/* Read IP version from first nibble of network header */
	if (bpf_probe_read_kernel(&ip_version, 1, head + network) < 0)
		return 0;
	ip_version >>= 4;

	/* Extract protocol and length based on IP version */
	if (ip_version == 4) {
		/* IPv4: protocol at offset 9, total length at offset 2,
		 * identification at offset 4 */
		if (bpf_probe_read_kernel(&ip_proto, 1, head + network + 9) < 0)
			return 0;
		if (bpf_probe_read_kernel(&ip_len, 2, head + network + 2) < 0)
			return 0;
		if (bpf_probe_read_kernel(&ip_id, 2, head + network + 4) < 0)
			return 0;
		ip_len = bpf_ntohs(ip_len);
		ip_id = bpf_ntohs(ip_id);
	} else if (ip_version == 6) {
		/* IPv6: next header at offset 6, payload length at offset 4.
		 *
		 * TODO: If extension headers are present, offset 6 gives the
		 * extension type, not the transport protocol — returns 0.
		 * Fix requires walking the chain with a BPF-verifier-safe
		 * bounded loop. Low impact: extension headers are rare in
		 * normal cluster traffic.
		 */
		if (bpf_probe_read_kernel(&ip_proto, 1, head + network + 6) < 0)
			return 0;
		if (bpf_probe_read_kernel(&ip_len, 2, head + network + 4) < 0)
			return 0;
		ip_len = bpf_ntohs(ip_len);
		/* IPv6 has no identification field in base header. Set to 0. */
		ip_id = 0;
	} else {
		/* Not IPv4 or IPv6 */
		return 0;
	}

	/* Calculate TCP segment length (accounts for IPv4/IPv6 ip_len semantic difference).
	 * This avoids using skb->data which differs between probe points like
	 * ip_output (points to IP header) vs tcp_v4_rcv (pulled past IP to TCP).
	 *
	 * IPv4: ip_len = total packet length (includes IP header)
	 * IPv6: ip_len = payload length (excludes 40-byte base header)
	 */
	int tcp_segment_len;
	if (ip_version == 4) {
		/* IPv4: ip_len includes everything */
		tcp_segment_len = ip_len - ip_hdr_len;
	} else {
		/* IPv6: ip_len excludes 40-byte base header.
		 * ip_hdr_len includes base header, so extension_len = ip_hdr_len - 40
		 */
		tcp_segment_len = ip_len - (ip_hdr_len - 40);
	}

	/* Dispatch to protocol-specific hash function */
	switch (ip_proto) {
	case IPPROTO_TCP:
		return __compute_tcp_hash(head, transport, ip_id, tcp_segment_len);

	case IPPROTO_UDP:
		return __compute_udp_hash(head, transport);

	case IPPROTO_ICMP:
		return __compute_icmp_hash(head, transport, 0 /* is_ipv6=false */);

	case IPPROTO_ICMPV6:
		return __compute_icmp_hash(head, transport, 1 /* is_ipv6=true */);

	default:
		/* Unsupported protocol - no cross-node correlation available */
		return 0;
	}
}

#endif /* __CORE_CORRELATION_ID__ */
