
AddressInfo(mac_local 1:1:1:1:1:1, mac_remote 2:2:2:2:2:2);

p1 :: ICMPPingSource(1.0.0.2, 1.0.0.1)
pr1 :: IPPrint(p1)
ms :: Queue;
uq :: Unqueue;
pr2 :: IPPrint(p2)
p3 :: Discard;
c :: Counter;

p1 -> c -> pr1 -> ms -> uq -> pr2 -> p3;


StaticThreadSched(p1 1, uq 0);

//ControlSocket(TCP, 7777);
