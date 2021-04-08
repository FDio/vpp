import os
import psutil

available_cpus = psutil.Process().cpu_affinity()
num_cpus = len(available_cpus)

max_vpp_cpus = os.getenv("MAX_VPP_CPUS", "auto").lower()

if max_vpp_cpus == "auto":
    max_vpp_cpus = num_cpus
else:
    try:
        max_vpp_cpus = int(max_vpp_cpus)
    except ValueError as e:
        raise ValueError("Invalid MAX_VPP_CPUS value specified, valid "
                         "values are a positive integer or 'auto'") from e
    if max_vpp_cpus <= 0:
        raise ValueError("Invalid MAX_VPP_CPUS value specified, valid "
                         "values are a positive integer or 'auto'")
    if max_vpp_cpus > num_cpus:
        max_vpp_cpus = num_cpus
