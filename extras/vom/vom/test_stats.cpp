#include <vom/om.hpp>
#include <vom/hw.hpp>
#include <vom/types.hpp>
#include <vom/prefix.hpp>
#include <vom/tap_interface.hpp>
#include <vom/stat_reader.hpp>

/**
 * Run VPP on another terminal before running vom_stats_test
 */

int main()
{

  uint8_t i = 5;

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

  intf->enable_stats();
  intf1->enable_stats();
  intf2->enable_stats();

  while (i--)
    {
      sleep(3);
      std::cout << "stats # " << std::to_string(i) << std::endl; 
      VOM::stat_reader::get_stats();

      if (i == 2)
        intf->disable_stats();
      else
        std::cout << intf->get_stats_print();

      std::cout << intf1->get_stats_print()
                << intf2->get_stats_print();
    }

  intf.reset();
  intf1.reset();
  intf2.reset();

  VOM::OM::remove("__TAP__");

  sleep(10);
  VOM::HW::disconnect();

  return 0;
}
