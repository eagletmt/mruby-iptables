# mruby-iptables

## Usage
See [examples](examples).

## Caution
### Stability
This mrbgem uses libiptc and libxtables, but they are not meant to be used as a public interface.

See also: https://www.netfilter.org/documentation/FAQ/netfilter-faq-4.html#ss4.5

### libxtables
You have to call `Libxtables.init` before using libxtables features like `Rule#matches`.
