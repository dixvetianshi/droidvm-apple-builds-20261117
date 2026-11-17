#!/usr/bin/env python3
"""Check local workflow syntax and reviewed source/destination boundaries."""
import json
from pathlib import Path
import yaml

root = Path(__file__).resolve().parents[1]
macos = yaml.load((root / ".github/workflows/macos.yml").read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
ipados = yaml.load((root / ".github/workflows/ipados.yml").read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
assert "workflow_dispatch" in macos["on"] and "workflow_dispatch" in ipados["on"]
assert len(macos["jobs"]) == 7
assert macos["env"]["GH_REPO"] == "${{ github.repository }}"
for job in macos["jobs"].values():
    checkouts = [step for step in job["steps"] if step.get("uses") == "actions/checkout@v4"]
    assert len(checkouts) == 1
    assert checkouts[0]["with"]["repository"] == "Droid-VM/macOS-DroidVM"
    assert checkouts[0]["with"]["ref"] == "524d27bf57ae92375aa39e3a81e11727c08973ff"
assert ipados["jobs"]["build"]["runs-on"] == "xcode-27"
assert ipados["jobs"]["build"]["env"]["DEVELOPER_DIR"] == "/Applications/Xcode_27.1.app/Contents/Developer"
ipados_steps = ipados["jobs"]["build"]["steps"]
diagnostics = next(step for step in ipados_steps if step.get("name") == "Upload task diagnostics")
assert diagnostics["if"] == "always()"
assert diagnostics["with"]["path"] == "verification/ipados-diagnostics/*.txt"
runtime_path = root / ".github/workflows/runtime.yml"
runtime = None
if runtime_path.is_file():
    runtime = yaml.load(runtime_path.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
    assert "workflow_dispatch" in runtime["on"]
    for job in runtime["jobs"].values():
        assert job["runs-on"] in {"ubuntu-latest", "ubuntu-24.04", "ubuntu-26.04", "ubuntu-24.04-arm", "ubuntu-26.04-arm"}
report = {
    "verification_scope": "static YAML structure, source pins and upload/destination boundaries only",
    "macos_jobs": list(macos["jobs"]),
    "ipados_runner": ipados["jobs"]["build"]["runs-on"],
    "yaml_parsed": True,
    "source_checkouts_pinned": True,
    "release_destination_is_calling_repository": True,
    "ipados_diagnostics_scope": "controlled runner output and explicitly redacted build console only",
    "runtime_workflow_checked_if_present": runtime is not None,
    "runner_availability_verified": False,
    "runner_toolchain_verified": False,
    "executed_cloud_build": False,
    "executed_guest_boot": False,
}
(root / "verification/workflows-checked.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
print(json.dumps(report))
