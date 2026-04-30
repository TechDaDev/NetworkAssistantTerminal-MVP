from app.agent.task_chainer import build_task_chain, should_auto_run_followup


def test_scan_chains_to_show_devices():
    assert build_task_chain("scan my network", "scan_network") == ["scan_network", "show_devices"]


def test_scan_summary_chains_to_diagnose():
    assert build_task_chain("scan my network and summarize", "scan_network") == ["scan_network", "show_devices", "diagnose_network"]


def test_execution_never_auto_followup():
    assert not should_auto_run_followup("custom_plan_generate", "execute_plan", "execute this")
