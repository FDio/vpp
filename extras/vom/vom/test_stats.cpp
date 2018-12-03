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

  if (VOM::handle_t::INVALID == intf->handle())
    {
      std::cout << "Interface index is INVALID" << std::endl;
      VOM::HW::disconnect();

      return 0;
    }
  else
    {
      std::cout << "Interface index is " << intf->handle().value() << std::endl;
    }

  intf->enable_stats();

  while (i--)
    {
      sleep(3);
      std::cout << "stats # " << std::to_string(i) << std::endl; 
      VOM::stat_reader::get_stats();

      if (i == 1)
        intf->disable_stats();
    }

  intf.reset();

  sleep(10);
  VOM::HW::disconnect();

  return 0;
}
