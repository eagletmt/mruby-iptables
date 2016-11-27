#include <arpa/inet.h>
#include <errno.h>
#include <libiptc/libip6tc.h>
#include <mruby.h>
#include <mruby/array.h>
#include <mruby/class.h>
#include <mruby/data.h>
#include <mruby/string.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
#include <xtables.h>

static void libip6tc_handle_free(mrb_state *mrb, void *ptr) {
  struct xtc_handle *h = (struct xtc_handle *)ptr;

  if (h != NULL) {
    ip6tc_free(h);
  }
}

static void libip6tc_rule_free(mrb_state *mrb, void *ptr) {
  if (ptr != NULL) {
    mrb_free(mrb, ptr);
  }
}

static const struct mrb_data_type libip6tc_handle_type = {"Handle",
                                                          libip6tc_handle_free};
static const struct mrb_data_type libip6tc_rule_type = {"Libip6tc::Rule",
                                                        libip6tc_rule_free};

struct ip6t_entry_wrapper {
  const struct ip6t_entry *entry;
};

static struct xtc_handle *unwrap_xtc_handle(mrb_state *mrb, mrb_value v) {
  struct xtc_handle *h =
      (struct xtc_handle *)mrb_data_get_ptr(mrb, v, &libip6tc_handle_type);

  if (h == NULL) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "internal error: xtc_handle is null");
  }
  return h;
}

static const struct ip6t_entry *unwrap_entry(mrb_state *mrb, mrb_value v) {
  struct ip6t_entry_wrapper *w = (struct ip6t_entry_wrapper *)mrb_data_get_ptr(
      mrb, v, &libip6tc_rule_type);

  if (w == NULL) {
    mrb_raise(mrb, E_RUNTIME_ERROR,
              "internal error: ip6t_entry_wrapper is null");
  }
  if (w->entry == NULL) {
    mrb_raise(mrb, E_RUNTIME_ERROR,
              "internal error: ip6t_entry_wrapper->entry is null");
  }
  return w->entry;
}

static mrb_value m_handle_initialize(mrb_state *mrb, mrb_value self) {
  struct xtc_handle *h;
  mrb_value name;

  h = (struct xtc_handle *)DATA_PTR(self);
  if (h != NULL) {
    ip6tc_free(h);
  }

  mrb_get_args(mrb, "S", &name);

  h = ip6tc_init(mrb_string_value_cstr(mrb, &name));
  if (h != NULL) {
    mrb_data_init(self, h, &libip6tc_handle_type);
  } else {
    mrb_value msg;

    msg = mrb_str_new_cstr(mrb, ip6tc_strerror(errno));
    mrb_data_init(self, NULL, &libip6tc_handle_type);
    mrb_raisef(mrb, E_RUNTIME_ERROR, "ip6tc_init failed: %S", msg);
  }

  return self;
}

static mrb_value m_handle_first_chain(mrb_state *mrb, mrb_value self) {
  struct xtc_handle *h;
  const char *chain;

  h = unwrap_xtc_handle(mrb, self);
  chain = ip6tc_first_chain(h);
  if (chain == NULL) {
    return mrb_nil_value();
  } else {
    return mrb_str_new_cstr(mrb, chain);
  }
}

static mrb_value m_handle_next_chain(mrb_state *mrb, mrb_value self) {
  struct xtc_handle *h;
  const char *chain;

  h = unwrap_xtc_handle(mrb, self);
  chain = ip6tc_next_chain(h);
  if (chain == NULL) {
    return mrb_nil_value();
  } else {
    return mrb_str_new_cstr(mrb, chain);
  }
}

static mrb_value make_rule(mrb_state *mrb, const struct ip6t_entry *entry) {
  struct RClass *rule_class;
  struct ip6t_entry_wrapper *wrapper;

  rule_class =
      mrb_class_get_under(mrb, mrb_module_get(mrb, "Libip6tc"), "Rule");
  wrapper = mrb_malloc(mrb, sizeof(*wrapper));
  wrapper->entry = entry;
  return mrb_obj_value(
      mrb_data_object_alloc(mrb, rule_class, wrapper, &libip6tc_rule_type));
}

static mrb_value m_handle_first_rule(mrb_state *mrb, mrb_value self) {
  struct xtc_handle *h;
  mrb_value chain;
  const struct ip6t_entry *entry;

  mrb_get_args(mrb, "S", &chain);

  h = unwrap_xtc_handle(mrb, self);
  entry = ip6tc_first_rule(mrb_string_value_cstr(mrb, &chain), h);
  if (entry == NULL) {
    return mrb_nil_value();
  } else {
    return make_rule(mrb, entry);
  }
}

static mrb_value m_handle_next_rule(mrb_state *mrb, mrb_value self) {
  struct xtc_handle *h;
  mrb_value prev_rule;
  const struct ip6t_entry *entry;

  mrb_get_args(mrb, "o", &prev_rule);
  entry = unwrap_entry(mrb, prev_rule);

  h = unwrap_xtc_handle(mrb, self);
  entry = ip6tc_next_rule(entry, h);
  if (entry == NULL) {
    return mrb_nil_value();
  } else {
    return make_rule(mrb, entry);
  }
}

static mrb_value m_handle_buildin_p(mrb_state *mrb, mrb_value self) {
  mrb_value chain;

  mrb_get_args(mrb, "S", &chain);

  if (ip6tc_builtin(mrb_string_value_cstr(mrb, &chain),
                    unwrap_xtc_handle(mrb, self))) {
    return mrb_true_value();
  } else {
    return mrb_false_value();
  }
}

static mrb_value m_handle_get_policy(mrb_state *mrb, mrb_value self) {
  mrb_value chain;
  const char *policy;
  struct xt_counters counters;

  mrb_get_args(mrb, "S", &chain);

  policy = ip6tc_get_policy(mrb_string_value_cstr(mrb, &chain), &counters,
                            unwrap_xtc_handle(mrb, self));
  if (policy == NULL) {
    return mrb_nil_value();
  } else {
    mrb_value argv[3];

    argv[0] = mrb_str_new_cstr(mrb, policy);
    argv[1] = mrb_fixnum_value(counters.pcnt);
    argv[2] = mrb_fixnum_value(counters.bcnt);
    return mrb_obj_new(mrb, mrb_class_get_under(
                                mrb, mrb_module_get(mrb, "Libip6tc"), "Policy"),
                       3, argv);
  }
}

static mrb_value m_rule_pcnt(mrb_state *mrb, mrb_value self) {
  /* FIXME: counters.pcnt is u64 but mrb_int isn't capable */
  return mrb_fixnum_value(unwrap_entry(mrb, self)->counters.pcnt);
}

static mrb_value m_rule_bcnt(mrb_state *mrb, mrb_value self) {
  /* FIXME: counters.pcnt is u64 but mrb_int isn't capable */
  return mrb_fixnum_value(unwrap_entry(mrb, self)->counters.bcnt);
}

static int prefix_length(const struct in6_addr *addr) {
  int i, len = 0;

  for (i = 0; i < 4; i++) {
    const uint32_t n = ntohl(addr->s6_addr32[i]);
    const int l = __builtin_popcount(n);
    if (l == 0) {
      break;
    }
    if ((n & ((1U << (32 - l)) - 1)) != 0) {
      return -1;
    }
    len += l;
  }
  return len;
}

static mrb_value m_rule_src(mrb_state *mrb, mrb_value self) {
  char buf[INET6_ADDRSTRLEN] = {0};
  const struct ip6t_entry *entry;

  entry = unwrap_entry(mrb, self);
  inet_ntop(AF_INET6, &entry->ipv6.src, buf, sizeof(buf));
  return mrb_format(mrb, "%S/%S", mrb_str_new_cstr(mrb, buf),
                    mrb_fixnum_value(prefix_length(&entry->ipv6.smsk)));
}

static mrb_value m_rule_dst(mrb_state *mrb, mrb_value self) {
  char buf[INET6_ADDRSTRLEN] = {0};
  const struct ip6t_entry *entry;

  entry = unwrap_entry(mrb, self);
  inet_ntop(AF_INET6, &entry->ipv6.dst, buf, sizeof(buf));
  return mrb_format(mrb, "%S/%S", mrb_str_new_cstr(mrb, buf),
                    mrb_fixnum_value(prefix_length(&entry->ipv6.dmsk)));
}

static mrb_value m_rule_iniface(mrb_state *mrb, mrb_value self) {
  const char *iface = unwrap_entry(mrb, self)->ipv6.iniface;

  if (iface[0] == '\0') {
    return mrb_nil_value();
  } else {
    return mrb_str_new_cstr(mrb, iface);
  }
}

static mrb_value m_rule_outiface(mrb_state *mrb, mrb_value self) {
  const char *iface = unwrap_entry(mrb, self)->ipv6.outiface;

  if (iface[0] == '\0') {
    return mrb_nil_value();
  } else {
    return mrb_str_new_cstr(mrb, iface);
  }
}

static mrb_value m_rule_proto(mrb_state *mrb, mrb_value self) {
  const uint16_t proto = unwrap_entry(mrb, self)->ipv6.proto;

  if (proto == 0) {
    return mrb_nil_value();
  } else {
    const struct protoent *result = getprotobynumber(proto);

    if (result != NULL) {
      return mrb_str_new_cstr(mrb, result->p_name);
    } else {
      return mrb_fixnum_value(proto);
    }
  }
}

static mrb_value test_flags(mrb_state *mrb, mrb_value rule, unsigned flag) {
  if (unwrap_entry(mrb, rule)->ipv6.flags & flag) {
    return mrb_true_value();
  } else {
    return mrb_false_value();
  }
}

static mrb_value m_rule_proto_p(mrb_state *mrb, mrb_value self) {
  return test_flags(mrb, self, IP6T_F_PROTO);
}

static mrb_value m_rule_tos_p(mrb_state *mrb, mrb_value self) {
  return test_flags(mrb, self, IP6T_F_TOS);
}

static mrb_value m_rule_goto_p(mrb_state *mrb, mrb_value self) {
  return test_flags(mrb, self, IP6T_F_GOTO);
}

static mrb_value test_inv_flags(mrb_state *mrb, mrb_value rule, unsigned flag) {
  if (unwrap_entry(mrb, rule)->ipv6.invflags & flag) {
    return mrb_true_value();
  } else {
    return mrb_false_value();
  }
}

static mrb_value m_rule_inv_via_in_p(mrb_state *mrb, mrb_value self) {
  return test_inv_flags(mrb, self, IP6T_INV_VIA_IN);
}

static mrb_value m_rule_inv_via_out_p(mrb_state *mrb, mrb_value self) {
  return test_inv_flags(mrb, self, IP6T_INV_VIA_OUT);
}

static mrb_value m_rule_inv_tos_p(mrb_state *mrb, mrb_value self) {
  return test_inv_flags(mrb, self, IP6T_INV_TOS);
}

static mrb_value m_rule_inv_srcip_p(mrb_state *mrb, mrb_value self) {
  return test_inv_flags(mrb, self, IP6T_INV_SRCIP);
}

static mrb_value m_rule_inv_dstip_p(mrb_state *mrb, mrb_value self) {
  return test_inv_flags(mrb, self, IP6T_INV_DSTIP);
}

static mrb_value m_rule_inv_frag_p(mrb_state *mrb, mrb_value self) {
  return test_inv_flags(mrb, self, IP6T_INV_FRAG);
}

static mrb_value m_rule_inv_proto_p(mrb_state *mrb, mrb_value self) {
  return test_inv_flags(mrb, self, IP6T_INV_PROTO);
}

static mrb_value m_rule_get_target(mrb_state *mrb, mrb_value self) {
  mrb_value handle;
  struct xtc_handle *h;
  const char *target;

  mrb_get_args(mrb, "o", &handle);
  h = unwrap_xtc_handle(mrb, handle);
  target = ip6tc_get_target(unwrap_entry(mrb, self), h);
  if (target == NULL) {
    return mrb_nil_value();
  } else {
    return mrb_str_new_cstr(mrb, target);
  }
}

static mrb_value capture_match_args(
    mrb_state *mrb, const struct xtables_match *match,
    const struct ip6t_ip6 *ip, const struct ip6t_entry_match *entry_match) {
  int fds[2];
  pid_t pid;
  int status;
  char buf[1024];
  ssize_t read_bytes;
  mrb_value result = mrb_str_new(mrb, NULL, 0);

  if (pipe(fds) == -1) {
    mrb_raisef(mrb, E_RUNTIME_ERROR, "pipe failed: %S",
               mrb_str_new_cstr(mrb, strerror(errno)));
  }

  fflush(stdout);
  fflush(stderr);
  pid = fork();
  if (pid == -1) {
    mrb_raisef(mrb, E_RUNTIME_ERROR, "fork failed: %S",
               mrb_str_new_cstr(mrb, strerror(errno)));
  }

  if (pid == 0) {
    close(fds[0]);
    if (dup2(fds[1], STDOUT_FILENO) == -1) {
      perror("dup2");
      exit(EXIT_FAILURE);
    }
    match->save(ip, entry_match);
    close(fds[1]);
    exit(EXIT_SUCCESS);
  }

  close(fds[1]);
  while ((read_bytes = read(fds[0], buf, sizeof(buf))) != 0) {
    mrb_str_cat(mrb, result, buf, read_bytes);
  }
  waitpid(pid, &status, 0);

  if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
    mrb_raisef(mrb, E_RUNTIME_ERROR, "Child process %S exited with %S",
               mrb_fixnum_value(pid), mrb_fixnum_value(WEXITSTATUS(status)));
  }
  return mrb_str_substr(mrb, result, 1, RSTRING_LEN(result) - 1);
}

static int push_match(const struct ip6t_entry_match *match, mrb_state *mrb,
                      mrb_value matches, const struct ip6t_ip6 *ip) {
  const struct xtables_match *m;
  struct RClass *match_class =
      mrb_class_get_under(mrb, mrb_module_get(mrb, "Libip6tc"), "Match");

  xtables_set_nfproto(NFPROTO_IPV6);
  m = xtables_find_match(match->u.user.name, XTF_TRY_LOAD, NULL);
  if (m != NULL) {
    mrb_value argv[2];

    argv[0] = mrb_str_new_cstr(mrb, match->u.user.name);
    argv[1] = capture_match_args(mrb, m, ip, match);
    mrb_ary_push(mrb, matches, mrb_obj_new(mrb, match_class, 2, argv));
  }
  return 0;
}

static mrb_value m_rule_matches(mrb_state *mrb, mrb_value self) {
  const struct ip6t_entry *entry;
  mrb_value matches = mrb_ary_new(mrb);

  entry = unwrap_entry(mrb, self);
  IP6T_MATCH_ITERATE(entry, push_match, mrb, matches, &entry->ipv6);

  return matches;
}

void mrb_mruby_libip6tc_gem_init(mrb_state *mrb) {
  struct RClass *module = mrb_define_module(mrb, "Libip6tc");
  struct RClass *handle =
      mrb_define_class_under(mrb, module, "Handle", mrb->object_class);
  struct RClass *rule =
      mrb_define_class_under(mrb, module, "Rule", mrb->object_class);

  MRB_SET_INSTANCE_TT(handle, MRB_TT_DATA);
  mrb_define_method(mrb, handle, "initialize", m_handle_initialize,
                    MRB_ARGS_REQ(1));
  mrb_define_method(mrb, handle, "first_chain", m_handle_first_chain,
                    MRB_ARGS_NONE());
  mrb_define_method(mrb, handle, "next_chain", m_handle_next_chain,
                    MRB_ARGS_NONE());
  mrb_define_method(mrb, handle, "first_rule", m_handle_first_rule,
                    MRB_ARGS_REQ(1));
  mrb_define_method(mrb, handle, "next_rule", m_handle_next_rule,
                    MRB_ARGS_REQ(1));
  mrb_define_method(mrb, handle, "builtin?", m_handle_buildin_p,
                    MRB_ARGS_REQ(1));
  mrb_define_method(mrb, handle, "get_policy", m_handle_get_policy,
                    MRB_ARGS_REQ(1));

  MRB_SET_INSTANCE_TT(rule, MRB_TT_DATA);
  mrb_undef_class_method(mrb, rule, "new");
  mrb_define_method(mrb, rule, "pcnt", m_rule_pcnt, MRB_ARGS_NONE());
  mrb_define_method(mrb, rule, "bcnt", m_rule_bcnt, MRB_ARGS_NONE());
  mrb_define_method(mrb, rule, "src", m_rule_src, MRB_ARGS_NONE());
  mrb_define_method(mrb, rule, "dst", m_rule_dst, MRB_ARGS_NONE());
  mrb_define_method(mrb, rule, "iniface", m_rule_iniface, MRB_ARGS_NONE());
  mrb_define_method(mrb, rule, "outiface", m_rule_outiface, MRB_ARGS_NONE());
  mrb_define_method(mrb, rule, "proto", m_rule_proto, MRB_ARGS_NONE());
  mrb_define_method(mrb, rule, "proto?", m_rule_proto_p, MRB_ARGS_NONE());
  mrb_define_method(mrb, rule, "tos?", m_rule_tos_p, MRB_ARGS_NONE());
  mrb_define_method(mrb, rule, "goto?", m_rule_goto_p, MRB_ARGS_NONE());
  mrb_define_method(mrb, rule, "inv_via_in?", m_rule_inv_via_in_p,
                    MRB_ARGS_NONE());
  mrb_define_method(mrb, rule, "inv_via_out?", m_rule_inv_via_out_p,
                    MRB_ARGS_NONE());
  mrb_define_method(mrb, rule, "inv_tos?", m_rule_inv_tos_p, MRB_ARGS_NONE());
  mrb_define_method(mrb, rule, "inv_srcip?", m_rule_inv_srcip_p,
                    MRB_ARGS_NONE());
  mrb_define_method(mrb, rule, "inv_dstip?", m_rule_inv_dstip_p,
                    MRB_ARGS_NONE());
  mrb_define_method(mrb, rule, "inv_frag?", m_rule_inv_frag_p, MRB_ARGS_NONE());
  mrb_define_method(mrb, rule, "inv_proto?", m_rule_inv_proto_p,
                    MRB_ARGS_NONE());
  mrb_define_method(mrb, rule, "get_target", m_rule_get_target,
                    MRB_ARGS_REQ(1));
  mrb_define_method(mrb, rule, "matches", m_rule_matches, MRB_ARGS_NONE());
}
