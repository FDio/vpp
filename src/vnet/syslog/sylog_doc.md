# Syslog protocol support {#syslog_doc}

VPP provides [RFC5424](https://tools.ietf.org/html/rfc5424) syslog protocol
logging, which is used to transport event messages across network. VPP
currently suports UDP transport based on
[RFC5426](https://tools.ietf.org/html/rfc5426).

The syslog message has the following format:
* header
* structured data
* free-form message

The header contains, priority, version, timestamp, hostname, application,
process id and message id. It is followed by structured data, which  provides
a mechanism to express event data in easily parsable format. Structured data
can contain zero, one or multiple structured data elements. Structured data
element contains name-value pairs. Structured data can by followed by free-form
message.

Following example explains how to use the internal APIs to genrate syslog
message:
```{.c}
   #include <vnet/syslog/syslog.h>

   ...

   syslog_msg_t syslog_msg;

   /* Check if syslog logging is enabled */
   if (!syslog_is_enabled ())
     return;

   /* Severity filer test */
   if (syslog_severity_filter_block (severity))
     return;

   /* Initialize syslog message header */
   syslog_msg_init (&syslog_msg, facility, severity, "NAT", "SADD");

   /* Create structured data element */
   syslog_msg_sd_init (&syslog_msg, "nsess");
   /* Add structured data element parameters (name-value pairs) */
   syslog_msg_add_sd_param (&syslog_msg, "SSUBIX", "%d", ssubix);
   syslog_msg_add_sd_param (&syslog_msg, "SVLAN", "%d", svlan);
   syslog_msg_add_sd_param (&syslog_msg, "IATYP", "IPv4");
   syslog_msg_add_sd_param (&syslog_msg, "ISADDR", "%U",
                            format_ip4_address, isaddr);
   syslog_msg_add_sd_param (&syslog_msg, "ISPORT", "%d", isport);
   syslog_msg_add_sd_param (&syslog_msg, "XATYP", "IPv4");
   syslog_msg_add_sd_param (&syslog_msg, "XSADDR", "%U",
                            format_ip4_address, xsaddr);
   syslog_msg_add_sd_param (&syslog_msg, "XSPORT", "%d", xsport);
   syslog_msg_add_sd_param (&syslog_msg, "PROTO", "%d", proto);

   /* Send syslog message */
   syslog_msg_send (&syslog_msg);
```

Example above produces following syslog message:
   <134>1 2018-11-12T11:25:30.252715Z 172.16.4.1 NAT 5901 SADD [nsess SSUBIX="0" SVLAN="0" IATYP="IPv4" ISADDR="172.16.1.2" ISPORT="6303" XATYP="IPv4" XSADDR="10.0.0.3" XSPORT="16253" PROTO="6"]

To add free-form message use:
```{.c}
   syslog_msg_add_msg (&syslog_msg, "event log entry");
```
