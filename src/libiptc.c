#include <mruby.h>
#include <xtables.h>

void mrb_mruby_libip4tc_gem_init(mrb_state *mrb);
void mrb_mruby_libip6tc_gem_init(mrb_state *mrb);

static struct xtables_globals mruby_libiptc_globals = {
    .compat_rev = xtables_compatible_revision,
};

void mrb_mruby_libiptc_gem_init(mrb_state *mrb) {
  mrb_mruby_libip4tc_gem_init(mrb);
  mrb_mruby_libip6tc_gem_init(mrb);

  xtables_init();
  xtables_set_params(&mruby_libiptc_globals);
}

void mrb_mruby_libiptc_gem_final(mrb_state *mrb) {
}
