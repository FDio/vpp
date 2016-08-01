# Manipulate sys.path to allow tests be run inside the build environment.
import os, sys, glob
scriptdir = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.dirname(glob.glob(scriptdir+'/../../../build-root/install*/vpp-api/lib64/vpp_api.so')[0]))
sys.path.append(os.path.dirname(glob.glob(scriptdir+'/../../../build-root/install*/vlib-api/vlibmemory/memclnt.py')[0]))
sys.path.append(os.path.dirname(glob.glob(scriptdir+'/../../../build-root/install*/vpp/vpp-api/vpe.py')[0]))
sys.path.append(glob.glob(scriptdir+'/../../../build-root/install*/plugins/vpp_papi_plugins')[0])
