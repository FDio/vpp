#include <stdio.h>

#include <vlibmemory/api.h>
#include <vpp/api/vpe_msg_enum.h>
#include <vlibapi/api.h>

#define vl_typedefs
#define vl_endianfun
#include <vpp/api/vpe_all_api_h.h>
#undef vl_typedefs
#undef vl_endianfun

int main(int argc, char *argv[])
{
	printf("Hello, VPP World!\n");

	return 0;
}
