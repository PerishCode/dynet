from __future__ import annotations

__all__ = [
    "tcp_flow_brief",
    "tcp_flow_rows",
    "workload_flow_brief",
    "workload_flow_rows",
]


def tcp_flow_brief(*args, **kwargs):
    from private_runtime_lib.tcp_flow.session import tcp_flow_brief as run

    return run(*args, **kwargs)


def tcp_flow_rows(*args, **kwargs):
    from private_runtime_lib.tcp_flow.session import tcp_flow_rows as run

    return run(*args, **kwargs)


def workload_flow_brief(*args, **kwargs):
    from private_runtime_lib.tcp_flow.workload import workload_flow_brief as run

    return run(*args, **kwargs)


def workload_flow_rows(*args, **kwargs):
    from private_runtime_lib.tcp_flow.workload import workload_flow_rows as run

    return run(*args, **kwargs)
