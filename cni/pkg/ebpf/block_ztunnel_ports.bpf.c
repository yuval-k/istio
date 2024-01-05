// clang-format off
#include "vmlinux.h"
// clang-format on

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define AF_INET 2
#define AF_INET6 10

volatile const __u32 ztunnel_mark = 3;
volatile const __u16 ztunnel_outbound_port = 15001;
volatile const __u16 ztunnel_inbound_port = 15008;
volatile const __u16 ztunnel_inbound_plain_port = 15006;
volatile const __u16 ztunnel_dns_port = 15053;

#define MAX_ENTRIES 1024

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __type(key, u64);
  __type(value, bool);
  __uint(max_entries, MAX_ENTRIES);
  __uint(pinning, LIBBPF_PIN_BY_NAME);

} should_enforce_bind SEC(".maps");

static __always_inline int bind_prog(struct bpf_sock_addr *ctx, int family) {
  struct bpf_sock *sk;
  __u32 port;
  __u32 mark;
  bool should_enforce;
  bool is_ztunnel;

  sk = ctx->sk;
  if (!sk) return 1;

  if (sk->family != family) return 1;

  port = bpf_ntohs(ctx->user_port);
  if (ctx->type == SOCK_STREAM) {
    if ((port != ztunnel_outbound_port) && (port != ztunnel_inbound_port) &&
        (port != ztunnel_inbound_plain_port)) {
      return 1;
    }
  } else if (ctx->type == SOCK_DGRAM) {
    if (port != ztunnel_dns_port) {
      return 1;
    }
  }

  should_enforce = true;
  is_ztunnel = (sk->mark & ztunnel_mark) == ztunnel_mark;

  // option 1:
  // check if sidecar user:
  {
    u64 uidgid = bpf_get_current_uid_gid();
    u32 uid = uidgid & 0xFFFFFFFF;

    // TODO: need to check if this is in the context of the current user ns.
    if (uid == 1337) {
      should_enforce = false;
    }
  }

  // option 2:
  // (this option needs user mode component that GC's the map, for kernels that
  // don't support BPF_MAP_TYPE_LRU_HASH)
  u64 cgroup_id = bpf_get_current_cgroup_id();
  bool *should_enforce_p =
      bpf_map_lookup_elem(&should_enforce_bind, &cgroup_id);

  if (should_enforce_p == NULL) {
    // first time! save if we should enforce next time
    bpf_map_update_elem(&should_enforce_bind, &cgroup_id, &is_ztunnel, BPF_ANY);
  } else {
    should_enforce = *should_enforce_p;
  }

  if (should_enforce) {
    return is_ztunnel ? 1 : 0;
  }
  return 1;
}

SEC("cgroup/bind4")
int bind_v4_prog(struct bpf_sock_addr *ctx) { return bind_prog(ctx, AF_INET); }

SEC("cgroup/bind6")
int bind_v6_prog(struct bpf_sock_addr *ctx) { return bind_prog(ctx, AF_INET6); }

// char _license[] SEC("license") = "GPL";
