from pathlib import Path

from app.qoderwork.agent import QoderWorkAgent


def test_qoderwork_autonomous_lifecycle_clean_workspace(tmp_path: Path):
    agent = QoderWorkAgent(workspace_root=tmp_path)
    report = agent.run_lifecycle()
    assert report.state == "Resolved"
    assert report.findings_count == 0
    assert report.resolved is True
    assert len(report.steps) == 1
    assert report.steps[0].step_name == "Trigger"


def test_qoderwork_autonomous_lifecycle_demo_vulnerable():
    fixture_dir = Path(__file__).parent.parent / "demo" / "vulnerable-agent"
    agent = QoderWorkAgent(workspace_root=fixture_dir)
    report = agent.run_lifecycle()
    assert report.findings_count > 0
    assert len(report.steps) == 4
    stage_names = [s.step_name for s in report.steps]
    assert stage_names == ["Trigger", "Investigate", "Action", "Resolved"]
    assert report.resolved is True
    assert report.redteam_passed is True
