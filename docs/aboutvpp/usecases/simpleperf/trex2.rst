.. _trex2:

TRex Stateless Mode
===================

TRex can also be run in a stateless mode. For a detailed description of TRex stateless support
please refer to `TRex Stateless Support <https://trex-tgn.cisco.com/trex/doc/trex_stateless.html>`_.

In this section we show some simple examples using TRex stateless mode. These examples use
the configuration as shown in the section :ref:`trex`. These examples we will be using VMWare VMs.

To use TRex stateless mode we use 2 terminals on the TRex traffic generator node.  One terminal will
be used for the TRex console and one to monitor the traffic.

In one of terminals start TRex in stateless mode.  Use *Ctrl-C* to stop.

.. code-block:: console

    # cd v2.46/
    # ./trex -i
    -Per port stats table 
          ports |               0 |               1 |               2 |               3 
     -----------------------------------------------------------------------------------------
       opackets |               0 |               0 |               0 |               0 
         obytes |               0 |               0 |               0 |               0 
       ipackets |               6 |               6 |               5 |               5 
         ibytes |             384 |             384 |             320 |             320 
        ierrors |               0 |               0 |               0 |               0 
        oerrors |               0 |               0 |               0 |               0 
          Tx Bw |       0.00  bps |       0.00  bps |       0.00  bps |       0.00  bps 
    
    -Global stats enabled 
     Cpu Utilization : 0.0  %
     Platform_factor : 1.0  
     Total-Tx        :       0.00  bps  
     Total-Rx        :     238.30  bps  
     Total-PPS       :       0.00  pps  
     Total-CPS       :       0.00  cps  
    
     Expected-PPS    :       0.00  pps  
     Expected-CPS    :       0.00  cps  
     Expected-BPS    :       0.00  bps  
    
     Active-flows    :        0  Clients :        0   Socket-util : 0.0000 %    
     Open-flows      :        0  Servers :        0   Socket :        0 Socket/Clients :  -nan 
     drop-rate       :       0.00  bps   
     current time    : 21.4 sec  
     test duration   : 0.0 sec  
     *** TRex is shutting down - cause: 'CTRL + C detected'
     All cores stopped !! 

In the other terminal start the TRex console. With this console we will execute the TRex commands.

.. code-block:: console

    # cd v2.46/
    # ./trex -console
    
    Using 'python' as Python interpreter
    
    
    Connecting to RPC server on localhost:4501                   [SUCCESS]
    
    
    Connecting to publisher server on localhost:4500             [SUCCESS]
    
    
    Acquiring ports [0, 1, 2, 3]:                                [SUCCESS]
    
    
    Server Info:
    
    Server version:   v2.46 @ STL
    Server mode:      Stateless
    Server CPU:       2 x Intel(R) Xeon(R) CPU E5-2680 v2 @ 2.80GHz
    Ports count:      4 x 10Gbps @ VMXNET3 Ethernet Controller	
    
    -=TRex Console v3.0=-
    
    Type 'help' or '?' for supported actions
    trex>

Start some traffic using the **stl/imix.py** traffic profile.

.. code-block:: console

    trex>start -f ./stl/imix.py -p 0 1 2 3 -m 9475mbps
    
    Removing all streams from port(s) [0, 1, 2, 3]:              [SUCCESS]
    
    
    Attaching 3 streams to port(s) [0]:                          [SUCCESS]
    
    
    Attaching 3 streams to port(s) [1]:                          [SUCCESS]
    
    
    Attaching 3 streams to port(s) [2]:                          [SUCCESS]
    
    
    Attaching 3 streams to port(s) [3]:                          [SUCCESS]
    
    
    Starting traffic on port(s) [0, 1, 2, 3]:                    [SUCCESS]
    
    80.94 [ms]
    
    trex>

The **-f ./stl/imix.py** argument specifies the file that is used to create the
traffic profile. The argument **-p 0 1 2 3** specifies the ports to be used.
The argument **-m 9475mbps** the number of packets/sec to be used.
All the arguments can be displayed with the **-h** argument.

In the other terminal the display shows the statistics related the traffic flows.

.. code-block:: console

    -Per port stats table 
          ports |               0 |               1 |               2 |               3
     -----------------------------------------------------------------------------------------
       opackets |       789907304 |       789894738 |       790017701 |       790017132 
         obytes |    285397726750 |    285392406754 |    285406864578 |    285405883070 
       ipackets |      1563501970 |              45 |      1563504693 |              44 
         ibytes |    564870783050 |            2880 |    564873491682 |            2816 
        ierrors |        15728759 |               0 |        15732451 |               0 
        oerrors |               0 |               0 |               0 |               0 
          Tx Bw |     606.55 Mbps |     606.19 Mbps |     606.25 Mbps |     606.51 Mbps 

    -Global stats enabled 
     Cpu Utilization : 100.0  %  2.4 Gb/core 
     Platform_factor : 1.0  
     Total-Tx        :       2.43 Gbps  
     Total-Rx        :       2.40 Gbps  
     Total-PPS       :     841.44 Kpps  
     Total-CPS       :       0.00  cps  
    
     Expected-PPS    :       0.00  pps  
     Expected-CPS    :       0.00  cps  
     Expected-BPS    :       0.00  bps  
    
     Active-flows    :        0  Clients :        0   Socket-util : 0.0000 %    
     Open-flows      :        0  Servers :        0   Socket :        0 Socket/Clients :  -nan 
     Total_queue_full : 6529970196         
     drop-rate       :       0.00  bps   
     current time    : 4016.8 sec  
     test duration   : 0.0 sec  
    
More statistics can be displayed on the TRex console using the **tui** command.

.. code-block:: console

    trex>tui
    
    Global Statistics
    
    connection   : localhost, Port 4501                  total_tx_L2  : 2.45 Gb/sec                    
    version      : STL @ v2.46                           total_tx_L1  : 2.59 Gb/sec                    
    cpu_util.    : 99.89% @ 2 cores (1 per port)         total_rx     : 2.42 Gb/sec                    
    rx_cpu_util. : 4.03% / 837.39 Kpkt/sec               total_pps    : 846.96 Kpkt/sec                
    async_util.  : 0.05% / 1.76 KB/sec                   drop_rate    : 0 b/sec                        
                                                         queue_full   : 42,750,771 pkts                
    
    Port Statistics
    
       port    |         0         |         1         |         2         |         3         |       total       
    -----------+-------------------+-------------------+-------------------+-------------------+------------------
    owner      |              root |              root |              root |              root |                   
    link       |                UP |                UP |                UP |                UP |                   
    state      |      TRANSMITTING |      TRANSMITTING |      TRANSMITTING |      TRANSMITTING |                   
    speed      |           10 Gb/s |           10 Gb/s |           10 Gb/s |           10 Gb/s |                   
    CPU util.  |            99.89% |            99.89% |            99.89% |            99.89% |                   
    --         |                   |                   |                   |                   |                   
    Tx bps L2  |       612.76 Mbps |       613.07 Mbps |       612.52 Mbps |       612.77 Mbps |         2.45 Gbps 
    Tx bps L1  |       646.64 Mbps |       646.96 Mbps |        646.4 Mbps |       646.64 Mbps |         2.59 Gbps 
    Tx pps     |       211.72 Kpps |        211.8 Kpps |       211.73 Kpps |       211.71 Kpps |       846.96 Kpps 
    Line Util. |            6.47 % |            6.47 % |            6.46 % |            6.47 % |                   
    ---        |                   |                   |                   |                   |                   
    Rx bps     |         1.21 Gbps |     \u25bc\u25bc\u25bc 23.03 bps |         1.21 Gbps |          5.94 bps |         2.42 G    bps 
    Rx pps     |       418.59 Kpps |          0.04 pps |       418.77 Kpps |          0.01 pps |       837.36 Kpps 
    ----       |                   |                   |                   |                   |                   
    opackets   |           5227126 |           5227271 |           5432528 |           5432354 |          21319279 
    ipackets   |          10526000 |                 5 |          10527054 |                 4 |          21053063 
    obytes     |        1890829910 |        1891039152 |        1965259162 |        1965124338 |        7712252562 
    ibytes     |        3807894454 |               320 |        3808149896 |               256 |        7616044926 
    tx-pkts    |        5.23 Mpkts |        5.23 Mpkts |        5.43 Mpkts |        5.43 Mpkts |       21.32 Mpkts 
    rx-pkts    |       10.53 Mpkts |            5 pkts |       10.53 Mpkts |            4 pkts |       21.05 Mpkts 
    tx-bytes   |           1.89 GB |           1.89 GB |           1.97 GB |           1.97 GB |           7.71 GB 
    rx-bytes   |           3.81 GB |             320 B |           3.81 GB |             256 B |           7.62 GB 
    -----      |                   |                   |                   |                   |                   
    oerrors    |                 0 |                 0 |                 0 |                 0 |                 0 
    ierrors    |           133,370 |                 0 |           132,529 |                 0 |           265,899 
