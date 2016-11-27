#include <arpa/inet.h>
#include <errno.h>
#include <libiptc/libiptc.h>
#include <mruby.h>
#include <mruby/array.h>
#include <mruby/class.h>
#include <mruby/data.h>
#include <mruby/string.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
#include <xtables.h>

static void libip4tc_handle_free(mrb_state *mrb, void *ptr) {
  struct xtc_handle *h = (struct xtc_handle *)ptr;

  if (h != NULL) {
    iptc_free(h);
  }
}

static void libip4tc_rule_free(mrb_state *mrb, void *ptr) {
  if (ptr != NULL) {
    mrb_free(mrb, ptr);
  }
}

static const struct mrb_data_type libip4tc_handle_type = {"Libip4tc::Handle",
                                                          libip4tc_handle_free};
static const struct mrb_data_type libip4tc_rule_type = {"Libip4tc::Rule",
                                                        libip4tc_rule_free};

struct ipt_entry_wrapper {
  const struct ipt_entry *entry;
};

static struct xtc_handle *unwrap_xtc_handle(mrb_state *mrb, mrb_value v) {
  struct xtc_handle *h =
      (struct xtc_handle *)mrb_data_get_ptr(mrb, v, &libip4tc_handle_type);

  if (h == NULL) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "internal error: xtc_handle is null");
  }
  return h;
}

static const struct ipt_entry *unwrap_entry(mrb_state *mrb, mrb_value v) {
  struct ipt_entry_wrapper *w =
      (struct ipt_entry_wrapper *)mrb_data_get_ptr(mrb, v, &libip4tc_rule_type);

  if (w == NULL) {
    mrb_raise(mrb, E_RUNTIME_ERROR,
              "internal error: ipt_entry_wrapper is null");
  }
  if (w->entry == NULL) {
    mrb_raise(mrb, E_RUNTIME_ERROR,
              "internal error: ipt_entry_wrapper->entry is null");
  }
  return w->entry;
}

static mrb_value m_handle_initialize(mrb_state *mrb, mrb_value self) {
  struct xtc_handle *h;
  mrb_value name;

  h = (struct xtc_handle *)DATA_PTR(self);
  if (h != NULL) {
    iptc_free(h);
  }

  mrb_get_args(mrb, "S", &name);

  h = iptc_init(mrb_string_value_cstr(mrb, &name));
  if (h != NULL) {
    mrb_data_init(self, h, &libip4tc_handle_type);
  } else {
    mrb_value msg;

    msg = mrb_str_new_cstr(mrb, iptc_strerror(errno));
    mrb_data_init(self, NULL, &libip4tc_handle_type);
    mrb_raisef(mrb, E_RUNTIME_ERROR, "iptc_init failed: %S", msg);
  }

  return self;
}

static mrb_value m_handle_first_chain(mrb_state *mrb, mrb_value self) {
  struct xtc_handle *h;
  const char *chain;

  h = unwrap_xtc_handle(mrb, self);
  chain = iptc_first_chain(h);
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
  chain = iptc_next_chain(h);
  if (chain == NULL) {
    return mrb_nil_value();
  } else {
    return mrb_str_new_cstr(mrb, chain);
  }
}

static mrb_value make_rule(mrb_state *mrb, const struct ipt_entry *entry) {
  struct RClass *rule_class;
  struct ipt_entry_wrapper *wrapper;

  rule_class =
      mrb_class_get_under(mrb, mrb_module_get(mrb, "Libip4tc"), "Rule");
  wrapper = mrb_malloc(mrb, sizeof(*wrapper));
  wrapper->entry = entry;
  return mrb_obj_value(
      mrb_data_object_alloc(mrb, rule_class, wrapper, &libip4tc_rule_type));
}

static mrb_value m_handle_first_rule(mrb_state *mrb, mrb_value self) {
  struct xtc_handle *h;
  mrb_value chain;
  const struct ipt_entry *entry;

  mrb_get_args(mrb, "S", &chain);

  h = unwrap_xtc_handle(mrb, self);
  entry = iptc_first_rule(mrb_string_value_cstr(mrb, &chain), h);
  if (entry == NULL) {
    return mrb_nil_value();
  } else {
    return make_rule(mrb, entry);
  }
}

static mrb_value m_handle_next_rule(mrb_state *mrb, mrb_value self) {
  struct xtc_handle *h;
  mrb_value prev_rule;
  const struct ipt_entry *entry;

  mrb_get_args(mrb, "o", &prev_rule);
  entry = unwrap_entry(mrb, prev_rule);

  h = unwrap_xtc_handle(mrb, self);
  entry = iptc_next_rule(entry, h);
  if (entry == NULL) {
    return mrb_nil_value();
  } else {
    return make_rule(mrb, entry);
  }
}

static mrb_value m_handle_buildin_p(mrb_state *mrb, mrb_value self) {
  mrb_value chain;

  mrb_get_args(mrb, "S", &chain);

  if (iptc_builtin(mrb_string_value_cstr(mrb, &chain),
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

  policy = iptc_get_policy(mrb_string_value_cstr(mrb, &chain), &counters,
                           unwrap_xtc_handle(mrb, self));
  if (policy == NULL) {
    return mrb_nil_value();
  } else {
    mrb_value argv[3];

    argv[0] = mrb_str_new_cstr(mrb, policy);
    argv[1] = mrb_fixnum_value(counters.pcnt);
    argv[2] = mrb_fixnum_value(counters.bcnt);
    return mrb_obj_new(mrb, mrb_class_get_under(
                                mrb, mrb_module_get(mrb, "Libip4tc"), "Policy"),
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

static int prefix_length(const struct in_addr *addr) {
  int len = 0;

  const uint32_t n = ntohl(addr->s_addr);
  const int l = __builtin_popcount(n);
  if ((n & ((1U << (32 - l)) - 1)) != 0) {
    return -1;
  }
  return len;
}

static mrb_value m_rule_src(mrb_state *mrb, mrb_value self) {
  char buf[INET_ADDRSTRLEN] = {0};
  const struct ipt_entry *entry;

  entry = unwrap_entry(mrb, self);
  inet_ntop(AF_INET, &entry->ip.src, buf, sizeof(buf));
  return mrb_format(mrb, "%S/%S", mrb_str_new_cstr(mrb, buf),
                    mrb_fixnum_value(prefix_length(&entry->ip.smsk)));
}

static mrb_value m_rule_dst(mrb_state *mrb, mrb_value self) {
  char buf[INET_ADDRSTRLEN] = {0};
  const struct ipt_entry *entry;

  entry = unwrap_entry(mrb, self);
  inet_ntop(AF_INET, &entry->ip.dst, buf, sizeof(buf));
  return mrb_format(mrb, "%S/%S", mrb_str_new_cstr(mrb, buf),
                    mrb_fixnum_value(prefix_length(&entry->ip.dmsk)));
}

static mrb_value m_rule_iniface(mrb_state *mrb, mrb_value self) {
  const char *iface = unwrap_entry(mrb, self)->ip.iniface;

  if (iface[0] == '\0') {
    return mrb_nil_value();
  } else {
    return mrb_str_new_cstr(mrb, iface);
  }
}

static mrb_value m_rule_outiface(mrb_state *mrb, mrb_value self) {
  const char *iface = unwrap_entry(mrb, self)->ip.outiface;

  if (iface[0] == '\0') {
    return mrb_nil_value();
  } else {
    return mrb_str_new_cstr(mrb, iface);
  }
}

static mrb_value test_flags(mrb_state *mrb, mrb_value rule, unsigned flag) {
  if (unwrap_entry(mrb, rule)->ip.flags & flag) {
    return mrb_true_value();
  } else {
    return mrb_false_value();
  }
}

static mrb_value m_rule_frag_p(mrb_state *mrb, mrb_value self) {
  return test_flags(mrb, self, IPT_F_FRAG);
}

static mrb_value m_rule_goto_p(mrb_state *mrb, mrb_value self) {
  return test_flags(mrb, self, IPT_F_GOTO);
}

static mrb_value test_inv_flags(mrb_state *mrb, mrb_value rule, unsigned flag) {
  if (unwrap_entry(mrb, rule)->ip.invflags & flag) {
    return mrb_true_value();
  } else {
    return mrb_false_value();
  }
}

static mrb_value m_rule_inv_via_in_p(mrb_state *mrb, mrb_value rule) {
  return test_inv_flags(mrb, rule, IPT_INV_VIA_IN);
}

static mrb_value m_rule_inv_via_out_p(mrb_state *mrb, mrb_value rule) {
  return test_inv_flags(mrb, rule, IPT_INV_VIA_OUT);
}

static mrb_value m_rule_inv_tos_p(mrb_state *mrb, mrb_value rule) {
  return test_inv_flags(mrb, rule, IPT_INV_TOS);
}

static mrb_value m_rule_inv_srcip_p(mrb_state *mrb, mrb_value rule) {
  return test_inv_flags(mrb, rule, IPT_INV_SRCIP);
}

static mrb_value m_rule_inv_dstip_p(mrb_state *mrb, mrb_value rule) {
  return test_inv_flags(mrb, rule, IPT_INV_DSTIP);
}

static mrb_value m_rule_inv_frag_p(mrb_state *mrb, mrb_value rule) {
  return test_inv_flags(mrb, rule, IPT_INV_FRAG);
}

static mrb_value m_rule_inv_proto_p(mrb_state *mrb, mrb_value rule) {
  return test_inv_flags(mrb, rule, IPT_INV_PROTO);
}

static mrb_value m_rule_get_target(mrb_state *mrb, mrb_value self) {
  mrb_value handle;
  struct xtc_handle *h;
  const char *target;

  mrb_get_args(mrb, "o", &handle);
  h = unwrap_xtc_handle(mrb, handle);
  target = iptc_get_target(unwrap_entry(mrb, self), h);
  if (target == NULL) {
    return mrb_nil_value();
  } else {
    return mrb_str_new_cstr(mrb, target);
  }
}

static mrb_value capture_match_args(mrb_state *mrb,
                                    const struct xtables_match *match,
                                    const struct ipt_ip *ip,
                                    const struct ipt_entry_match *entry_match) {
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

static int push_match(const struct ipt_entry_match *match, mrb_state *mrb,
                      mrb_value matches, const struct ipt_ip *ip) {
  const struct xtables_match *m;
  struct RClass *match_class =
      mrb_class_get_under(mrb, mrb_module_get(mrb, "Libip4tc"), "Match");

  xtables_set_nfproto(NFPROTO_IPV4);
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
  const struct ipt_entry *entry;
  mrb_value matches = mrb_ary_new(mrb);

  entry = unwrap_entry(mrb, self);
  IPT_MATCH_ITERATE(entry, push_match, mrb, matches, &entry->ip);

  return matches;
}

void mrb_mruby_libip4tc_gem_init(mrb_state *mrb) {
  struct RClass *module = mrb_define_module(mrb, "Libip4tc");
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
  mrb_define_method(mrb, rule, "frag?", m_rule_frag_p, MRB_ARGS_NONE());
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
