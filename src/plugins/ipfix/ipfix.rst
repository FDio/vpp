.. _ipfix:

IPFIX support
=============

VPP includes a high-performance IP Flow Information Export (IPFIX)
provider. Plugins can register reports with the provider while retaining an
optional runtime dependency on ``ipfix_plugin.so``.

Consumer contract
-----------------

The IPFIX plugin exposes two symbols to consumers:

* ``ipfix_main`` is the stable provider object. Consumers cache its address,
  but must not cache exporter, report, or stream pointers from its mutable
  pools.
* ``ipfix_report_add_del`` registers or removes a report.

Resolve both symbols once during the consumer's initialization. Do not call
``vlib_get_plugin_symbol()`` from packet or event processing paths.

.. code:: c

   #include <ipfix/ipfix.h>
   #include <vlib/unix/plugin.h>

   typedef struct
   {
     ipfix_main_t *ipfix_main;
     ipfix_report_add_del_fn_t *ipfix_report_add_del;
     u32 stream_index;
   } my_main_t;

   extern my_main_t my_main;

   static clib_error_t *
   my_init (vlib_main_t *vm)
   {
     my_main_t *mm = &my_main;

     (void) vm;

     mm->ipfix_main =
       vlib_get_plugin_symbol (IPFIX_PLUGIN_SO, IPFIX_MAIN_SYMBOL);
     mm->ipfix_report_add_del = vlib_get_plugin_symbol (
       IPFIX_PLUGIN_SO, IPFIX_REPORT_ADD_DEL_SYMBOL);

     if (!!mm->ipfix_main != !!mm->ipfix_report_add_del)
       {
         clib_warning ("ipfix plugin symbols are inconsistent");
         mm->ipfix_main = 0;
         mm->ipfix_report_add_del = 0;
       }

     return 0;
   }

   VLIB_INIT_FUNCTION (my_init);

The missing-provider case is expected and must not fail consumer
initialization. A feature enable operation should return
``VNET_API_ERROR_FEATURE_DISABLED`` when either cached dependency is absent.
Removal can be a no-op when that matches the consumer's existing semantics.

Registering a report
--------------------

An ``ipfix_report_add_del_args_t`` describes the report's callbacks, fields,
stream, and opaque consumer data. The consumer owns both callbacks.

.. code:: c

   static ipfix_report_element_t my_elements[] = {
     { sourceIPv4Address, 4 },
     { destinationIPv4Address, 4 },
     { sourceTransportPort, 2 },
     { destinationTransportPort, 2 },
     { protocolIdentifier, 1 },
   };

   static int
   my_report_add_del (bool is_add)
   {
     my_main_t *mm = &my_main;
     ipfix_report_add_del_args_t args = {
       .rewrite_callback = my_template_rewrite,
       .data_callback = my_data_callback,
       .report_elements = my_elements,
       .n_report_elements = ARRAY_LEN (my_elements),
       .is_add = is_add,
       .domain_id = 1,
       .src_port = UDP_DST_PORT_ipfix,
       .stream_indexp = &mm->stream_index,
     };
     ipfix_exporter_t *exp;
     u16 template_id;

     if (!mm->ipfix_main || !mm->ipfix_report_add_del)
       return is_add ? VNET_API_ERROR_FEATURE_DISABLED : 0;

     exp = pool_elt_at_index (mm->ipfix_main->exporters, 0);
     return mm->ipfix_report_add_del (exp, &args, &template_id);
   }

The exporter at pool index zero is retained for compatibility with the
single-exporter API. Derive it from the cached main object when needed rather
than retaining the pool element across configuration changes.

Template callback
-----------------

The rewrite callback builds the IP, UDP, IPFIX, and template headers. Its
signature is:

.. code:: c

   u8 *
   my_template_rewrite (ipfix_exporter_t *exp, ipfix_report_t *report,
                        u16 collector_port,
                        ipfix_report_element_t *elements, u32 n_elements,
                        u32 *stream_index);

The provider associates the report with a stream during registration. The
callback reads ``report->stream_index``, stores it through ``stream_index``,
allocates the rewrite vector, and fills the template fields. Use
``ipfix_version_length()``, ``ipfix_set_id_length()``, and
``ipfix_id_count()`` when encoding IPFIX headers. The implementations in
``flowprobe``, ``nat``, and ``ioam`` provide complete examples.

Data callback
-------------

The provider invokes the data callback when a report should flush pending
records. The callback receives both provider and exporter state:

.. code:: c

   vlib_frame_t *
   my_data_callback (ipfix_main_t *im, ipfix_exporter_t *exp,
                     ipfix_report_t *report, vlib_frame_t *frame,
                     u32 *to_next, u32 node_index)
   {
     my_flush_records (im, exp, report);
     return frame;
   }

Per-thread buffers and frames remain the consumer's responsibility. Mark
generated buffers with ``VNET_BUFFER_F_IPFIX``, use the report's stream and
template identifiers, and update the stream sequence number according to RFC
7011. Consumers must synchronize any shared stream mutation separately from
the cached provider dependency.
