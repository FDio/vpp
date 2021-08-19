Web applications with VPP
=========================

Vpp includes a versatile http/https “static” server plugin. We quote the
word static in the previous sentence because the server is easily
extended. This note describes how to build a Hugo site which includes
both monitoring and control functions.

Let’s assume that we have a vpp data-plane plugin which needs a
monitoring and control web application. Here’s how to build one.

Step 1: Add URL handlers
------------------------

Individual URL handlers are pretty straightforward. You can return just
about anything you like, but as we work through the example you’ll see
why returning data in .json format tends to work out pretty well.

::

       static int
       handle_get_status (http_builtin_method_type_t reqtype,
                        u8 * request, http_session_t * hs)
       {
         my_main_t *mm = &my_main;
         u8 *s = 0;

         /* Construct a .json reply */
         s = format (s, "{\"status\": {");
         s = format (s, "   \"thing1\": \"%s\",", mm->thing1_value_string);
         s = format (s, "   \"thing2\": \"%s\",", mm->thing2_value_string);
         /* ... etc ... */
         s = format (s, "   \"lastthing\": \"%s\"", mm->last_value_string);
         s = format (s, "}}");

         /* And tell the static server plugin how to send the results */
         hs->data = s;
         hs->data_offset = 0;
         hs->cache_pool_index = ~0;
         hs->free_data = 1; /* free s when done with it, in the framework */
         return 0;
       }

Words to the Wise: Chrome has a very nice set of debugging tools. Select
“More Tools -> Developer Tools”. Right-hand sidebar appears with html
source code, a javascript debugger, network results including .json
objects, and so on.

Note: .json object format is **intolerant** of both missing and extra
commas, missing and extra curly-braces. It’s easy to waste a
considerable amount of time debugging .json bugs.

Step 2: Register URL handlers with the server
---------------------------------------------

Call http_static_server_register_builtin_handler() as shown. It’s likely
but not guaranteed that the static server plugin will be available.

::

       int
       plugin_url_init (vlib_main_t * vm)
       {
         void (*fp) (void *, char *, int);

         /* Look up the builtin URL registration handler */
         fp = vlib_get_plugin_symbol ("http_static_plugin.so",
                          "http_static_server_register_builtin_handler");

         if (fp == 0)
           {
             clib_warning ("http_static_plugin.so not loaded...");
             return -1;
           }

         (*fp) (handle_get_status, "status.json", HTTP_BUILTIN_METHOD_GET);
         (*fp) (handle_get_run, "run.json", HTTP_BUILTIN_METHOD_GET);
         (*fp) (handle_get_reset, "reset.json", HTTP_BUILTIN_METHOD_GET);
         (*fp) (handle_get_stop, "stop.json", HTTP_BUILTIN_METHOD_GET);
         return 0;
         }

Make sure to start the http static server **before** calling
plugin_url_init(…), or the registrations will disappear.

Step 3: Install Hugo, pick a theme, and create a site
-----------------------------------------------------

Please refer to the Hugo documentation.

See `the Hugo Quick Start
Page <https://gohugo.io/getting-started/quick-start>`__. Prebuilt binary
artifacts for many different environments are available on `the Hugo
release page <https://github.com/gohugoio/hugo/releases>`__.

To pick a theme, visit `the Hugo Theme
site <https://themes.gohugo.io>`__. Decide what you need your site to
look like. Stay away from complex themes unless you’re prepared to spend
considerable time tweaking and tuning.

The “Introduction” theme is a good choice for a simple site, YMMV.

Step 4: Create a “rawhtml” shortcode
------------------------------------

Once you’ve initialized your new site, create the directory
/layouts/shortcodes. Create the file “rawhtml.html” in that directory,
with the following contents:

::

       <!-- raw html -->
       {{.Inner}}

This is a key trick which allows a static Hugo site to include
javascript code.

Step 5: create Hugo content which interacts with vpp
----------------------------------------------------

Now it’s time to do some web front-end coding in javascript. Of course,
you can create static text, images, etc. as described in the Hugo
documentation. Nothing changes in that respect.

To include dynamically-generated data in your Hugo pages, splat down
some

.. raw:: html

   <div>

HTML tags, and define a few buttons:

::

       {{< rawhtml >}}
       <div id="Thing1"></div>
       <div id="Thing2"></div>
       <div id="Lastthing"></div>
       <input type="button" value="Run" onclick="runButtonClick()">
       <input type="button" value="Reset" onclick="resetButtonClick()">
       <input type="button" value="Stop" onclick="stopButtonClick()">
       <div id="Message"></div>
       {{< /rawhtml >}}

Time for some javascript code to interact with vpp:

::

   {{< rawhtml >}}
   <script>
   async function getStatusJson() {
       pump_url = location.href + "status.json";
       const json = await fetch(pump_url, {
           method: 'GET',
           mode: 'no-cors',
           cache: 'no-cache',
           headers: {
               'Content-Type': 'application/json',
           },
       })
       .then((response) => response.json())
       .catch(function(error) {
           console.log(error);
       });

       return json.status;
   };

   async function sendButton(which) {
       my_url = location.href + which + ".json";
       const json = await fetch(my_url, {
           method: 'GET',
           mode: 'no-cors',
           cache: 'no-cache',
           headers: {
               'Content-Type': 'application/json',
           },
       })
       .then((response) => response.json())
       .catch(function(error) {
           console.log(error);
       });
       return json.message;
   };

   async function getStatus() {
         const status = await getStatusJson();

         document.getElementById("Thing1").innerHTML = status.thing1;
         document.getElementById("Thing2").innerHTML = status.thing2;
         document.getElementById("Lastthing").innerHTML = status.lastthing;
   };

   async function runButtonClick() {
         const json = await sendButton("run");
         document.getElementById("Message").innerHTML = json.Message;
   }

   async function resetButtonClick() {
         const json = await sendButton("reset");
         document.getElementById("Message").innerHTML = json.Message;
   }
   async function stopButtonClick() {
         const json = await sendButton("stop");
         document.getElementById("Message").innerHTML = json.Message;
   }

   getStatus();

   </script>
   {{< /rawhtml >}}

At this level, javascript coding is pretty simple. Unless you know
exactly what you’re doing, please follow the async function / await
pattern shown above.

Step 6: compile the website
---------------------------

At the top of the website workspace, simply type “hugo”. The compiled
website lands in the “public” subdirectory.

You can use the Hugo static server - with suitable stub javascript code
- to see what your site will eventually look like. To start the hugo
static server, type “hugo server”. Browse to “http://localhost:1313”.

Step 7: configure vpp
---------------------

In terms of command-line args: you may wish to use poll-sleep-usec 100
to keep the load average low. Totally appropriate if vpp won’t be
processing a lot of packets or handling high-rate http/https traffic.

::

      unix {
        ...
        poll-sleep-usec 100
        startup-config ... see below ...
        ...
       }

If you wish to provide an https site, configure tls. The simplest tls
configuration uses a built-in test certificate - which will annoy Chrome
/ Firefox - but it’s sufficient for testing:

::

       tls {
           use-test-cert-in-ca
       }

vpp startup configuration
~~~~~~~~~~~~~~~~~~~~~~~~~

Enable the vpp static server by way of the startup config mentioned
above:

::

       http static server www-root /myhugosite/public uri tcp://0.0.0.0/2345 cache-size 5m fifo-size 8192

The www-root must be specified, and must correctly name the compiled
hugo site root. If your Hugo site is located at /myhugosite, specify
“www-root /myhugosite/public” in the “http static server” stanza. The
uri shown above binds to TCP port 2345.

If you’re using https, use a uri like “tls://0.0.0.0/443” instead of the
uri shown above.

You may want to add a Linux host interface to view the full-up site
locally:

::

       create tap host-if-name lstack host-ip4-addr 192.168.10.2/24
       set int ip address tap0 192.168.10.1/24
       set int state tap0 up
