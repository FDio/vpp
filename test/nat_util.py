from random import randint


def nat_rand_port(vpp_worker_count, thread_index):
    port_per_thread = int((0xffff-1024) / max(1, vpp_worker_count))
    result = 1024 + randint(1, port_per_thread)
    if vpp_worker_count > 0:
        result += port_per_thread * (thread_index - 1)
    return result
