package main

import (
	. "fd.io/hs-test/infra"
)

func init() {
	RegisterKindTests(KindIperfVclTest)
}

func KindIperfVclTest(s *KindSuite) {
	vclPath := "/vcl.conf"
	ldpPath := "/usr/lib/libvcl_ldpreload.so"

	// temporary workaround
	symLink := "for file in /usr/lib/*.so; do\n" +
		"if [ -e \"$file\" ]; then\n" +
		"base=$(basename \"$file\")\n" +
		"newlink=\"/usr/lib/${base}.25.06\"\n" +
		"ln -s \"$file\" \"$newlink\"\n" +
		"fi\n" +
		"done"

	vclConf := "echo \"vcl {\n" +
		"rx-fifo-size 4000000\n" +
		"tx-fifo-size 4000000\n" +
		"app-scope-local\n" +
		"app-scope-global\n" +
		"app-socket-api abstract:vpp/session\n" +
		"}\" > /vcl.conf"

	s.Exec(s.ClientName, s.ClientName, s.Namespace, []string{"/bin/bash", "-c", symLink})
	s.Exec(s.ServerName, s.ServerName, s.Namespace, []string{"/bin/bash", "-c", symLink})

	_, err := s.Exec(s.ClientName, s.ClientName, s.Namespace, []string{"/bin/bash", "-c", vclConf})
	s.AssertNil(err)
	_, err = s.Exec(s.ServerName, s.ServerName, s.Namespace, []string{"/bin/bash", "-c", vclConf})
	s.AssertNil(err)

	_, err = s.Exec(s.ServerName, s.ServerName, s.Namespace, []string{"/bin/bash", "-c",
		"VCL_CONFIG=" + vclPath + " LD_PRELOAD=" + ldpPath + " iperf3 -s -D -4"})
	s.AssertNil(err)
	output, err := s.Exec(s.ClientName, s.ClientName, s.Namespace, []string{"/bin/bash", "-c",
		"VCL_CONFIG=" + vclPath + " LD_PRELOAD=" + ldpPath + " iperf3 -c " + s.ServerIp})
	s.Log(output)
	s.AssertNil(err)
}
