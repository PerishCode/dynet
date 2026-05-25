from __future__ import annotations


def tcp_slot_pressure_ok(report: dict, flow: dict, workload_probe_report: dict) -> bool:
    if int(report.get("tcpSlotPressureEvents") or 0) == 0:
        return True
    if not workload_all_success(workload_probe_report):
        return False
    successful_non_dns = sum(
        1
        for item in workload_probe_report.get("results", [])
        if isinstance(item, dict) and item.get("probe") != "dns" and item.get("ok") is True
    )
    return (
        int(flow.get("failedFlows") or 0) == 0
        and int(flow.get("lifecycleCompleteFlows") or 0) == int(flow.get("startedFlows") or 0)
        and int(flow.get("payloadBidirectionalFlows") or 0) >= successful_non_dns
    )


def workload_all_success(workload_probe_report: dict) -> bool:
    totals = workload_probe_report.get("totals", {})
    return (
        isinstance(totals, dict)
        and int(totals.get("count") or 0) > 0
        and int(totals.get("failure") or 0) == 0
    )
