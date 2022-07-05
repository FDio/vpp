First attempt to package the make test as a standalone entity using pyoxidizer

Requires the following tweak to Makefile:

iff --git a/test/Makefile b/test/Makefile
index 08c6eabe1..e58da2b7b 100644
--- a/test/Makefile
+++ b/test/Makefile
@@ -107,7 +107,7 @@ $(PIP_TOOLS_INSTALL_DONE):
 $(PYTHON_DEPENDS): requirements.txt
        @bash -c "source $(VENV_PATH)/bin/activate && \
                  CUSTOM_COMPILE_COMMAND='make test-refresh-deps (or update requirements.txt)' \
-                 python3 -m piptools compile -q --generate-hashes requirements.txt --output-file $@"
+                 python3 -m piptools compile -q --allow-unsafe --generate-hashes requirements.txt --output-file $@"
 


and consequently redoing the "make test-refresh-deps"


After that, the process is as follows:

on the build host:

1) install pyoxidizer and rust (see https://pyoxidizer.readthedocs.io/en/stable/pyoxidizer.html)
2) package the pyoxidized tests:

pyoxidizer build --path extras/pyoxidizer/vpp-make-test/

3) make a tarball with "everything"

(cd extras/pyoxidizer/vpp-make-test/; tar czvf vpp-make-test-pyox.tgz build)

4) copy out the tarball

scp ./extras/pyoxidizer/vpp-make-test/vpp-make-test-pyox.tgz


on the test host:

1) scp .../vpp-make-test-pyox.tgz

2) tar xzvf vpp-make-test-pyox.tgz

3) mkdir test # due to an "odd" behavior of run_test class that requires this directory to be present

4) sudo apt-get install vpp-plugin-devtools # unit-test plugin and such

5) ./build/x86_64-unknown-linux-gnu/debug/install/vpp-make-test --vpp /usr/bin/vpp --vpp-ws-dir ./ --vpp-tag vpp --vpp-install-dir /usr/share/vpp --vpp-plugin-dir /usr/lib/x86_64-linux-gnu/vpp_plugins/ --test-src-dir ./build/x86_64-unknown-linux-gnu/debug/install/vpptestfiles




./x86_64-unknown-linux-gnu/debug/install/vpp-make-test --vpp /usr/bin/vpp --vpp-ws-dir ./ --vpp-tag vpp --vpp-install-dir /usr/share/vpp --vpp-plugin-dir /usr/lib/x86_64-linux-gnu/vpp_plugins/ --test-src-dir ./x86_64-unknown-linux-gnu/debug/install/vpptestfiles/




