#include <mruby.h>
#include <xtables.h>
#include <mruby/variable.h>

static struct xtables_globals mruby_libxtables_globals = {
    .compat_rev = xtables_compatible_revision,
};

static mrb_value m_s_init(mrb_state *mrb, mrb_value self) {
  mrb_value initialized;
  mrb_int proto;
  mrb_sym iv = mrb_intern_lit(mrb, "initialized_proto");

  initialized = mrb_iv_get(mrb, self, iv);
  if (!mrb_nil_p(initialized)) {
    mrb_raisef(mrb, E_RUNTIME_ERROR, "Libxtables is already initialized with %S", initialized);
  }

  mrb_get_args(mrb, "i", &proto);
  xtables_init_all(&mruby_libxtables_globals, proto);
  mrb_iv_set(mrb, self, iv, mrb_fixnum_value(proto));

  return mrb_nil_value();
}

void mrb_mruby_libxtables_gem_init(mrb_state *mrb) {
  struct RClass *module = mrb_define_module(mrb, "Libxtables");

  mrb_define_const(mrb, module, "NFPROTO_UNSPEC", mrb_fixnum_value(NFPROTO_UNSPEC));
  mrb_define_const(mrb, module, "NFPROTO_INET", mrb_fixnum_value(NFPROTO_INET));
  mrb_define_const(mrb, module, "NFPROTO_IPV4", mrb_fixnum_value(NFPROTO_IPV4));
  mrb_define_const(mrb, module, "NFPROTO_ARP", mrb_fixnum_value(NFPROTO_ARP));
  mrb_define_const(mrb, module, "NFPROTO_NETDEV", mrb_fixnum_value(NFPROTO_NETDEV));
  mrb_define_const(mrb, module, "NFPROTO_BRIDGE", mrb_fixnum_value(NFPROTO_BRIDGE));
  mrb_define_const(mrb, module, "NFPROTO_IPV6", mrb_fixnum_value(NFPROTO_IPV6));
  mrb_define_const(mrb, module, "NFPROTO_DECNET", mrb_fixnum_value(NFPROTO_DECNET));
  mrb_define_singleton_method(mrb, (struct RObject *)module, "init", m_s_init, MRB_ARGS_REQ(1));
}
