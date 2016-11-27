#include <arpa/inet.h>
#include <errno.h>
#include <libiptc/libiptc.h>
#include <mruby.h>
#include <mruby/class.h>
#include <mruby/data.h>
#include <mruby/string.h>

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

  MRB_SET_INSTANCE_TT(rule, MRB_TT_DATA);
  mrb_undef_class_method(mrb, rule, "new");
  mrb_define_method(mrb, rule, "pcnt", m_rule_pcnt, MRB_ARGS_NONE());
  mrb_define_method(mrb, rule, "bcnt", m_rule_bcnt, MRB_ARGS_NONE());
  mrb_define_method(mrb, rule, "src", m_rule_src, MRB_ARGS_NONE());
  mrb_define_method(mrb, rule, "dst", m_rule_dst, MRB_ARGS_NONE());
  mrb_define_method(mrb, rule, "get_target", m_rule_get_target,
                    MRB_ARGS_REQ(1));
}
