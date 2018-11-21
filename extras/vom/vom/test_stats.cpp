#include <vom/om.hpp>
#include <vom/hw.hpp>
#include <vom/types.hpp>
#include <vom/prefix.hpp>
#include <vom/tap_interface.hpp>

class listener : public VOM::interface::stat_listener
{
public:
  listener() {}
  ~listener() {}
  void handle_interface_stat(const VOM::interface& itf)
  {
    std::cout << itf.name() << " " << itf.get_stats();
  }
};

/**
 * Run VPP on another terminal before running vom_stats_test
 */
int main()
{
  uint8_t i = 5;
  listener *listen = new listener();

  VOM::HW::init(new VOM::HW::cmd_q());
  VOM::OM::init();

  while (VOM::HW::connect() != true)
    ;

  VOM::tap_interface itf("tap0", VOM::interface::admin_state_t::UP, VOM::route::prefix_t::ZERO);
  VOM::OM::write("__TAP__", itf);

  std::shared_ptr<VOM::tap_interface> intf = itf.singular();


  VOM::tap_interface itf1("tap1", VOM::interface::admin_state_t::UP, VOM::route::prefix_t::ZERO);
  VOM::OM::write("__TAP__", itf1);

  std::shared_ptr<VOM::tap_interface> intf1 = itf1.singular();

  VOM::tap_interface itf2("tap2", VOM::interface::admin_state_t::UP, VOM::route::prefix_t::ZERO);
  VOM::OM::write("__TAP__", itf2);

  std::shared_ptr<VOM::tap_interface> intf2 = itf2.singular();

  if (VOM::handle_t::INVALID == intf->handle() || VOM::handle_t::INVALID == intf1->handle()
      || VOM::handle_t::INVALID == intf2->handle())
    {
      std::cout << "Interface index is INVALID" << std::endl;
      VOM::HW::disconnect();

      return 0;
    }
  else
    {
      std::cout << "Interface #1 index is " << intf->handle().value() << std::endl;
      std::cout << "Interface #2 index is " << intf1->handle().value() << std::endl;
      std::cout << "Interface #3 index is " << intf2->handle().value() << std::endl;
    }

  intf->enable_stats(listen);
  intf1->enable_stats(listen);
  intf2->enable_stats(listen);

  while (i--)
    {
      sleep(3);
      std::cout << "stats # " << std::to_string(i) << std::endl;
      VOM::HW::read_stats();

      if (i == 2)
        intf->disable_stats();

    }

  intf1->disable_stats();
  intf2->disable_stats();

  intf.reset();
  intf1.reset();
  intf2.reset();

  VOM::OM::remove("__TAP__");

  delete listen;
  sleep(2);
  VOM::HW::disconnect();

  return 0;
}
