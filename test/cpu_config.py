import os
import psutil

available_cpus = psutil.Process().cpu_affinity()
num_cpus = len(available_cpus)

max_cpus = os.getenv("MAX_CPUS", "auto").lower()

if max_cpus == "auto":
    max_cpus = num_cpus
else:
    try:
        max_cpus = int(max_cpus)
    except ValueError as e:
        raise ValueError("Invalid MAX_CPUS value specified, valid "
                         "values are a positive integer or 'auto'") from e
    if max_cpus <= 0:
        raise ValueError("Invalid MAX_CPUS value specified, valid "
                         "values are a positive integer or 'auto'")
    if max_cpus > num_cpus:
        max_cpus = num_cpus
