/*
 *  Software Name : bmc-cache
 *  SPDX-FileCopyrightText: Copyright (c) 2021 Orange
 *  SPDX-License-Identifier: LGPL-2.1-only
 *
 *  This software is distributed under the
 *  GNU Lesser General Public License v2.1 only.
 *
 *  Author: Yoann GHIGOFF <yoann.ghigoff@orange.com> et al.
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>

#include "bmc_common.h"

#define ADJUST_HEAD_LEN 128

#ifndef memmove
# define memmove(dest, src, n)  __builtin_memmove((dest), (src), (n))
#endif

struct memcached_udp_header {
    __be16 request_id;
    __be16 seq_num;
    __be16 num_dgram;
    __be16 unused;
    char data[];
} __attribute__((__packed__));


/*
 * eBPF maps
*/

/* cache */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct bmc_cache_entry);
	__uint(max_entries, BMC_CACHE_ENTRY_COUNT);
} map_kcache SEC(".maps");


/* keys */
struct memcached_key {
	__u32 hash;
	char data[BMC_MAX_KEY_LENGTH];
	unsigned int len;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, unsigned int);
	__type(value, struct memcached_key);
	__uint(max_entries, BMC_MAX_KEY_IN_PACKET);
} map_keys SEC(".maps");

/* context */
struct parsing_context {
	unsigned int key_count;
	unsigned int current_key;
	unsigned short read_pkt_offset;
	unsigned short write_pkt_offset;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, unsigned int);
	__type(value, struct parsing_context);
} map_parsing_context SEC(".maps");

/* stats */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, unsigned int);
	__type(value, struct bmc_stats);
} map_stats SEC(".maps");

/* program maps */
struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, BMC_PROG_XDP_MAX);
	__type(key, __u32);
	__type(value, __u32);
} map_progs_xdp SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, BMC_PROG_TC_MAX);
	__type(key, __u32);
	__type(value, __u32);
} map_progs_tc SEC(".maps");


static inline __u16 compute_ip_checksum(struct iphdr *ip)
{
    __u32 csum = 0;
    __u16 *next_ip_u16 = (__u16 *)ip;

    ip->check = 0;

#pragma clang loop unroll(full)
    for (int i = 0; i < (sizeof(*ip) >> 1); i++) {
        csum += *next_ip_u16++;
    }

	return ~((csum & 0xffff) + (csum >> 16));
}

SEC("bmc_rx_filter")
int bmc_rx_filter_main(struct xdp_md *ctx)
{
    bpf_printk("Entering bmc_rx_filter prog");
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth;
    struct iphdr *ip;
    struct udphdr *udp;
    struct tcphdr *tcp;
    void *transp;
    __u8 *payload;
    __be16 dport;

    // Check Ethernet header
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;
    eth = data;

    // Check IP header
    if (data + sizeof(*eth) + sizeof(*ip) > data_end)
        return XDP_PASS;
    ip = (struct iphdr *)(eth + 1);

    // Check transport layer header
    transp = (void *)ip + sizeof(*ip);
    switch (ip->protocol) {
        case IPPROTO_UDP:
            if (transp + sizeof(*udp) > data_end)
                return XDP_PASS;
            udp = transp;
            dport = udp->dest;
            payload = transp + sizeof(*udp) + sizeof(struct memcached_udp_header);
            break;
        case IPPROTO_TCP:
            if (transp + sizeof(*tcp) > data_end)
                return XDP_PASS;
            tcp = transp;
            dport = tcp->dest;
            payload = transp + sizeof(*tcp);
            break;
        default:
            return XDP_PASS;
    }

    // Check if it's a Memcached packet
    if (dport != htons(11211) || payload + 4 > data_end)
        return XDP_PASS;

    if (ip->protocol == IPPROTO_UDP) {
      
            __u32 zero = 0;
	    // Check if it's a GET request
        if (payload[0] == 'g' && payload[1] == 'e' && payload[2] == 't' && payload[3] == ' ') {
	    struct bmc_stats *stats = bpf_map_lookup_elem(&map_stats, &zero);
			if (!stats) {
				return XDP_PASS;
			}
			stats->get_recv_count++;
            struct parsing_context *pctx = bpf_map_lookup_elem(&map_parsing_context, &zero);
            if (!pctx)
                return XDP_PASS;
            pctx->key_count = 0;
            pctx->current_key = 0;
            pctx->write_pkt_offset = 0;

            // Find the start of the first key
            __u32 off;
            #pragma clang loop unroll(full)
            for (off = 4; off < BMC_MAX_PACKET_LENGTH && off < 64; off++) {
                if (payload + off >= data_end)
                    return XDP_PASS;
                if (payload[off] != ' ')
                    break;
            }

            if (off < BMC_MAX_PACKET_LENGTH && off < 64) {
                pctx->read_pkt_offset = off;
                int adjust_len = sizeof(*eth) + sizeof(*ip) + sizeof(*udp) + 
                                 sizeof(struct memcached_udp_header) + off;
                if (bpf_xdp_adjust_head(ctx, adjust_len) == 0) {
                    bpf_tail_call(ctx, &map_progs_xdp, BMC_PROG_XDP_HASH_KEYS);
                }
            }
        } else if(payload[0] == 's' && payload[1] == 'e' && payload[2] == 't' && payload[3] == ' ') {	
		bpf_printk("SET command detected, calling XDP invalidate cache prog");
		bpf_tail_call(ctx, &map_progs_xdp, BMC_PROG_XDP_INVALIDATE_CACHE);
	
	}
    }

    return XDP_PASS;
}


SEC("bmc_hash_keys")
int bmc_hash_keys_main(struct xdp_md *ctx)
{
	bpf_printk("Entering bmc_hash_keys");
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	char *payload = (char *) data;
	unsigned int zero = 0;

	if (payload >= data_end)
		return XDP_PASS;

	struct parsing_context *pctx = bpf_map_lookup_elem(&map_parsing_context, &zero);
	if (!pctx) {
		return XDP_PASS;
	}

	struct memcached_key *key = bpf_map_lookup_elem(&map_keys, &pctx->key_count);
	if (!key) {
		return XDP_PASS;
	}
	key->hash = FNV_OFFSET_BASIS_32;

	//TODO: hard-coded key_len for verifier bug issues
	unsigned int off, done_parsing = 0, key_len = 1;
#pragma clang loop unroll(disable)
	for (off = 0; off < BMC_MAX_KEY_LENGTH+1 && payload+off+1 <= data_end; off++) {
		if (payload[off] == '\r') {
			done_parsing = 1;
			break;
		}
		else if (payload[off] == ' ') {
			break;
		}
		else if (payload[off] != ' ') {
			key->hash ^= payload[off];
			key->hash *= FNV_PRIME_32;
			key_len += 1;
		}
	}


	if (key_len == 0 || key_len > BMC_MAX_KEY_LENGTH) {
		bpf_xdp_adjust_head(ctx, 0 - (sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct memcached_udp_header) + pctx->read_pkt_offset)); // unexpected key, let the netstack handle it
		return XDP_PASS;
	}

	__u32 cache_idx = key->hash % BMC_CACHE_ENTRY_COUNT;
	struct bmc_cache_entry *entry = bpf_map_lookup_elem(&map_kcache, &cache_idx);
	if (!entry) { // should never happen since cache map is of type BPF_MAP_TYPE_ARRAY
		return XDP_PASS;
	}

	bpf_spin_lock(&entry->lock);
	if (entry->valid){//  && entry->hash == key->hash) { // potential cache hit
		bpf_spin_unlock(&entry->lock);
		bpf_printk("Key hit | Hash value: %d | Key length: %d", key->hash, key_len);
		unsigned int i = 0;
#pragma clang loop unroll(disable)
		for (; i < 1 && payload+i+1 <= data_end; i++) { // copy the request key to compare it with the one stored in the cache later
			key->data[i] = payload[i];
		}
		key->len = 1;
		pctx->key_count++;
	} else { // cache miss
		
		bpf_spin_unlock(&entry->lock);
		bpf_printk("Computed hash value: %d", key->hash);
		bpf_printk("Key miss");
		bpf_printk("Data: %s", entry->data);
		struct bmc_stats *stats = bpf_map_lookup_elem(&map_stats, &zero);
		if (!stats) {
			return XDP_PASS;
		}
		stats->miss_count++;
	}

	if (done_parsing) { // the end of the request has been reached
		bpf_xdp_adjust_head(ctx, 0 - (sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct memcached_udp_header) + pctx->read_pkt_offset)); // pop headers + 'get ' + previous keys
		if (pctx->key_count > 0) {
			bpf_tail_call(ctx, &map_progs_xdp, BMC_PROG_XDP_PREPARE_PACKET);
		}
	} else { // more keys to process
		off++; // move offset to the start of the next key
		pctx->read_pkt_offset += off;
		if (bpf_xdp_adjust_head(ctx, off)) // push the previous key
			return XDP_PASS;
		bpf_tail_call(ctx, &map_progs_xdp, BMC_PROG_XDP_HASH_KEYS);
	}

	return XDP_PASS;
}

SEC("bmc_prepare_packet")
int bmc_prepare_packet_main(struct xdp_md *ctx)
{
	bpf_printk("Entering bmc_prepare_packet program");
	bpf_printk("Value of ctx before xdp_adjust_head: %ld", ctx);
	if (bpf_xdp_adjust_head(ctx, -ADJUST_HEAD_LEN)) // // pop empty packet buffer memory to increase the available packet size
		return XDP_PASS;
	bpf_printk("Value of ctx after xdp_adjust_head: %ld", ctx);

	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
	struct iphdr *ip = data + sizeof(*eth);
	struct udphdr *udp = data + sizeof(*eth) + sizeof(*ip);
	struct memcached_udp_header *memcached_udp_hdr = data + sizeof(*eth) + sizeof(*ip) + sizeof(*udp);
	char *payload = (char *) (memcached_udp_hdr + 1);
	void *old_data = data + ADJUST_HEAD_LEN;
	char *old_payload = (char *) (old_data + sizeof(*eth) + sizeof(*ip) + sizeof(*udp) + sizeof(*memcached_udp_hdr));

	if (payload >= data_end || old_payload+1 >= data_end)
		return XDP_PASS;

	// use old headers as a base; then update addresses and ports to create the new headers
	memmove(eth, old_data, sizeof(*eth) + sizeof(*ip) + sizeof(*udp) + sizeof(*memcached_udp_hdr));

	unsigned char tmp_mac[ETH_ALEN];
	__be32 tmp_ip;
	__be16 tmp_port;

	memcpy(tmp_mac, eth->h_source, ETH_ALEN);
	memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
	memcpy(eth->h_dest, tmp_mac, ETH_ALEN);

	tmp_ip = ip->saddr;
	ip->saddr = ip->daddr;
	ip->daddr = tmp_ip;

	tmp_port = udp->source;
	udp->source = udp->dest;
	udp->dest = tmp_port;

	if (bpf_xdp_adjust_head(ctx, sizeof(*eth) + sizeof(*ip) + sizeof(*udp) + sizeof(*memcached_udp_hdr))) // push new headers
		return XDP_PASS;

	bpf_tail_call(ctx, &map_progs_xdp, BMC_PROG_XDP_WRITE_REPLY);

	return XDP_PASS;
}

SEC("bmc_write_reply")
int bmc_write_reply_main(struct xdp_md *ctx)
{
	bpf_printk("Entering bmc_write_reply program");
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	char *payload = (char *) data;
	unsigned int zero = 0;

	if (payload >= data_end)
		return XDP_PASS;

	struct parsing_context *pctx = bpf_map_lookup_elem(&map_parsing_context, &zero);
	if (!pctx) {
		return XDP_PASS;
	}

	struct memcached_key *key = bpf_map_lookup_elem(&map_keys, &pctx->current_key);
	if (!key) {
		return XDP_PASS;
	}

	unsigned int cache_hit = 1, written = 0;
	__u32 cache_idx = key->hash % BMC_CACHE_ENTRY_COUNT;
	struct bmc_cache_entry *entry = bpf_map_lookup_elem(&map_kcache, &cache_idx);
	if (!entry) {
		return XDP_DROP;
	}
	bpf_printk("Checking entry validity before returning from BMC");
	bpf_printk("entry->data: %s | entry->len: %d | entry->valid: %d", entry->data, entry->len, entry->valid);

	bpf_spin_lock(&entry->lock);
	if (entry->valid){// && key->hash == entry->hash) { // if saved key still matches its corresponding cache entry
#pragma clang loop unroll(disable)
		for (int i = 0; i < BMC_MAX_KEY_LENGTH && i < key->len; i++) { // compare the saved key with the one stored in the cache entry
			if (key->data[i] != entry->data[6+i]) {
				cache_hit = 0;
			}
		}
		if (cache_hit) { // if cache HIT then copy cached data
			unsigned int off;
#pragma clang loop unroll(disable)
			for (off = 0; off+sizeof(unsigned long long) < BMC_MAX_CACHE_DATA_SIZE && off+sizeof(unsigned long long) <= entry->len && payload+off+sizeof(unsigned long long) <= data_end; off++) {
				*((unsigned long long *) &payload[off]) = *((unsigned long long *) &entry->data[off]);
				off += sizeof(unsigned long long)-1;
				written += sizeof(unsigned long long);
			}
#pragma clang loop unroll(disable)
			for (; off < BMC_MAX_CACHE_DATA_SIZE && off < entry->len && payload+off+1 <= data_end; off++) {
				payload[off] = entry->data[off];
				written += 1;
			}
		}
	}
	bpf_spin_unlock(&entry->lock);

	bpf_printk("Key hit | Key: %s, Data: %s", entry->hash, entry->data);
	struct bmc_stats *stats = bpf_map_lookup_elem(&map_stats, &zero);
	if (!stats) {
		return XDP_PASS;
	}
	if (cache_hit) {
		stats->hit_count++;
	} else {
		stats->miss_count++;
	}

	pctx->current_key++;
	//written = written - 5; 
	bpf_printk("[DEBUG] pctx->current_key: %d | pctx->key_count: %d pctx->key_count | pctx->write_pkt_offset: %d | written: %d", pctx->current_key, pctx->key_count, pctx->write_pkt_offset, written);
	bpf_printk("pctx->current_key == pctx->key_count: %b", pctx->current_key == pctx->key_count);
	bpf_printk("written > 0 || pctx->write_pkt_offset > 0 || written > 0: %b", written > 0 || pctx->write_pkt_offset > 0 || written > 0);
	if (pctx->current_key == pctx->key_count && (written > 0 || pctx->write_pkt_offset > 0 || written > 0)) { // if all saved keys have been processed and a least one cache HIT
		bpf_printk("First if conditions have passed");
		bpf_printk("Payload: %ld | data_end: %ld", payload, data_end);
		if (payload+written+5 <= data_end) {
			payload[written++] = 'E';
			payload[written++] = 'N';
			payload[written++] = 'D';
			payload[written++] = '\r';
			payload[written++] = '\n';
			
			bpf_printk("Final payload: %s", payload);

			if (bpf_xdp_adjust_head(ctx, 0 - (int) (sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr)
													+ sizeof(struct memcached_udp_header) + pctx->write_pkt_offset))) { // pop headers + previously written data
				return XDP_DROP;
			}

			void *data_end = (void *)(long)ctx->data_end;
			void *data = (void *)(long)ctx->data;
			struct iphdr *ip = data + sizeof(struct ethhdr);
			struct udphdr *udp = data + sizeof(struct ethhdr) + sizeof(*ip);
			payload = data + sizeof(struct ethhdr) + sizeof(*ip) + sizeof(*udp) + sizeof(struct memcached_udp_header);

			if (udp + 1 > data_end)
				return XDP_PASS;

			ip->tot_len = htons((payload+pctx->write_pkt_offset+written) - (char*)ip);
			ip->check = compute_ip_checksum(ip);
			udp->check = 0; // computing udp checksum is not required
			udp->len = htons((payload+pctx->write_pkt_offset+written) - (char*)udp);

			bpf_xdp_adjust_tail(ctx, 0 - (int) ((long) data_end - (long) (payload+pctx->write_pkt_offset+written))); // try to strip additional bytes

			return XDP_TX;
		}
	} else if (pctx->current_key == pctx->key_count) { // else if all saved keys have been processed but got no cache HIT; either because of a hash colision or a race with a cache update
		stats->hit_misprediction += pctx->key_count;
		bpf_xdp_adjust_head(ctx, ADJUST_HEAD_LEN - (int) (sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct memcached_udp_header))); // pop to the old headers and transmit to netstack
		bpf_printk("Error in xdp_adjust_head, XDP_PASS");
		return XDP_PASS;
	} else if (pctx->current_key < BMC_MAX_KEY_IN_PACKET) { // else if there are still keys to process
		pctx->write_pkt_offset += written; // save packet write offset
		if (bpf_xdp_adjust_head(ctx, written)) // push written data
		{
			bpf_printk("Error in xdp_adjust_head, XDP_DROP");
			return XDP_DROP;
		}
		bpf_printk("tail calling write prog");
		bpf_tail_call(ctx, &map_progs_xdp, BMC_PROG_XDP_WRITE_REPLY);
	}

	bpf_printk("IDK, it just dropped :(");
	return XDP_DROP;
}

SEC("bmc_invalidate_cache")
int bmc_invalidate_cache_main(struct xdp_md *ctx)
{
	bpf_printk("Starting invalidate_cache prog");

	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	struct ethhdr *eth = data;
	struct iphdr *ip = data + sizeof(*eth);
	struct udphdr *udp = data + sizeof(*eth) + sizeof(*ip);
	struct memcached_udp_header *memcached_udp_hdr = data + sizeof(*eth) + sizeof(*ip) + sizeof(*udp);
	char *payload = (char *) (memcached_udp_hdr + 1);
	
	unsigned int zero = 0;

	if (payload >= data_end)
		return XDP_PASS;

	struct bmc_stats *stats = bpf_map_lookup_elem(&map_stats, &zero);
	if (!stats) {
		return XDP_PASS;
	}

	int key_found = 0;
	__u32 hash = FNV_OFFSET_BASIS_32;

	if(payload+4+1<=data_end && payload[0]=='s' && payload[1]=='e' && payload[2]=='t' && payload[3]==' ') {
		key_found = 1;
		stats->set_recv_count++;
	} else {
		return XDP_PASS;
	} 

#pragma clang loop unroll(disable)
	for (unsigned int off = 4; payload+off+1 <= data_end && off<20; off++) {
		hash ^= payload[off];
		hash *= FNV_PRIME_32;
	}
	bpf_printk("Computed hash value: %d", hash);

	__u32 cache_idx = hash % BMC_CACHE_ENTRY_COUNT;
                struct bmc_cache_entry *entry = bpf_map_lookup_elem(&map_kcache, &cache_idx);
		if(!entry) return XDP_PASS;

		unsigned int count = 0;	
		
		bpf_spin_lock(&entry->lock);
		entry->len = 6;
		entry->data[0] = 'V'; entry->data[1] = 'A'; entry->data[2] = 'L'; entry->data[3] = 'U'; entry->data[4] = 'E'; entry->data[5] = ' ';	
#pragma clang loop unroll(disable)
		for(unsigned int j = 4; entry->len<BMC_MAX_CACHE_DATA_SIZE && payload+j+1 <= data_end && count<2; j++) {
			entry->data[entry->len] = payload[j];
			entry->len++;
			if(payload[j] == '\n') count++;
		}
		if(count == 2) {
			entry->valid = 1;
			entry->hash = hash;
			bpf_spin_unlock(&entry->lock);
			bpf_printk("Persisted entry->data: %s", entry->data);
			stats->update_count++;
			bpf_tail_call(ctx, &map_progs_xdp, BMC_PROG_XDP_WRITE_SET_REPLY);
		} else {
			bpf_spin_unlock(&entry->lock);
		}

	return XDP_PASS;
}
 
SEC("bmc_write_set_reply")
int bmc_write_set_reply_main(struct xdp_md *ctx)
{
    bpf_printk("Entering bmc_write_set_reply");
    void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
	struct iphdr *ip = data + sizeof(*eth);
	struct udphdr *udp = data + sizeof(*eth) + sizeof(*ip);
	struct memcached_udp_header *memcached_udp_hdr = data + sizeof(*eth) + sizeof(*ip) + sizeof(*udp);
	char *payload = (char *) (memcached_udp_hdr + 1);

	if(payload>=data_end) return XDP_PASS;

	unsigned char tmp_mac[ETH_ALEN];
	__be32 tmp_ip;
	__be16 tmp_port;

	memcpy(tmp_mac, eth->h_source, ETH_ALEN);
	memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
	memcpy(eth->h_dest, tmp_mac, ETH_ALEN);

	tmp_ip = ip->saddr;
	ip->saddr = ip->daddr;
	ip->daddr = tmp_ip;

	tmp_port = udp->source;
	udp->source = udp->dest;
	udp->dest = tmp_port;

    // Write the "STORED\r\n" response
    if (payload + 8 > data_end)
        return XDP_DROP;

    memcpy(payload, "STORED\r\n", 8);

    ip->tot_len = htons((payload+8) - (char*)ip);
    ip->check = compute_ip_checksum(ip);
    udp->check = 0; // computing udp checksum is not required
    udp->len = htons((payload+8) - (char*)udp);

    bpf_printk("Returning UDP packet | payload: %s", payload);
    return XDP_TX;
}

SEC("bmc_tx_filter")
int bmc_tx_filter_main(struct __sk_buff *skb)
{
	void *data_end = (void *)(long)skb->data_end;
	void *data     = (void *)(long)skb->data;
	struct ethhdr *eth = data;
	struct iphdr *ip = data + sizeof(*eth);
	struct udphdr *udp = data + sizeof(*eth) + sizeof(*ip);
	char *payload = data + sizeof(*eth) + sizeof(*ip) + sizeof(*udp) + sizeof(struct memcached_udp_header);
	unsigned int zero = 0;

	// if the size exceeds the size of a cache entry do not bother going further
	if (skb->len > BMC_MAX_CACHE_DATA_SIZE + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct memcached_udp_header))
		return TC_ACT_OK;

	if (ip + 1 > data_end)
		return XDP_PASS;

	if (ip->protocol != IPPROTO_UDP)
		return TC_ACT_OK;

	if (udp + 1 > data_end)
		return TC_ACT_OK;

	__be16 sport = udp->source;

	if (sport == htons(11211) && payload+5+1 <= data_end && payload[0] == 'V' && payload[1] == 'A' && payload[2] == 'L'
		&& payload[3] == 'U' && payload[4] == 'E' && payload[5] == ' ') { // if this is a GET reply

		struct bmc_stats *stats = bpf_map_lookup_elem(&map_stats, &zero);
		if (!stats) {
			return XDP_PASS;
		}
		stats->get_resp_count++;

		bpf_tail_call(skb, &map_progs_tc, BMC_PROG_TC_UPDATE_CACHE);
	}

	return TC_ACT_OK;
}

SEC("bmc_update_cache")
int bmc_update_cache_main(struct __sk_buff *skb)
{
	bpf_printk("Entering bmc_update_cache");
	void *data_end = (void *)(long)skb->data_end;
	void *data = (void *)(long)skb->data;
	char *payload = (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct memcached_udp_header));
	unsigned int zero = 0;

	__u32 hash = FNV_OFFSET_BASIS_32;

	// compute the key hash
#pragma clang loop unroll(disable)
	for (unsigned int off = 6; off-6 < BMC_MAX_KEY_LENGTH && payload+off+1 <= data_end && payload[off] != ' '; off++) {
		hash ^= payload[off];
		hash *= FNV_PRIME_32;
	}

	__u32 cache_idx = hash % BMC_CACHE_ENTRY_COUNT;
	struct bmc_cache_entry *entry = bpf_map_lookup_elem(&map_kcache, &cache_idx);
	if (!entry) {
		return TC_ACT_OK;
	}

	bpf_spin_lock(&entry->lock);
	if (entry->valid && entry->hash == hash) { // cache is up-to-date; no need to update
		int diff = 0;
		// loop until both bytes are spaces ; or break if they are different
#pragma clang loop unroll(disable)
		for (unsigned int off = 6; off-6 < BMC_MAX_KEY_LENGTH && payload+off+1 <= data_end && off < entry->len && (payload[off] != ' ' || entry->data[off] != ' '); off++) {
			if (entry->data[off] != payload[off]) {
				diff = 1;
				break;
			}
		}
		if (diff == 0) {
			bpf_spin_unlock(&entry->lock);
			return TC_ACT_OK;
		}
	}

	unsigned int count = 0;
	entry->len = 0;
	// store the reply from start to the '\n' that follows the data
#pragma clang loop unroll(disable)
	for (unsigned int j = 0; j < BMC_MAX_CACHE_DATA_SIZE && payload+j+1 <= data_end && count < 2; j++) {
		entry->data[j] = payload[j];
		entry->len++;
		if (payload[j] == '\n')
			count++;
	}

	if (count == 2) { // copy OK
		entry->valid = 1;
		entry->hash = hash;
		bpf_spin_unlock(&entry->lock);
		struct bmc_stats *stats = bpf_map_lookup_elem(&map_stats, &zero);
		if (!stats) {
			return XDP_PASS;
		}
		stats->update_count++;
	} else {
		bpf_spin_unlock(&entry->lock);
	}

	return TC_ACT_OK;
}
char _license[] SEC("license") = "GPL";
// to test colisions: keys declinate0123456 and macallums0123456 have hash colision
