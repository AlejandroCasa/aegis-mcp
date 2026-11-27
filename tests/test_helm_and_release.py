"""Hardened Helm chart, release supply-chain workflow and v0.2.0 consistency.

Static checks always run. Rendering checks run ``helm template`` (and
``conftest`` / ``zizmor``) only when those binaries are installed, so the
suite stays deterministic on machines without them.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import tomllib
from pathlib import Path
from typing import Any

import pytest
import yaml

from app.main import app
from app.ocsf import PRODUCT_VERSION
from scripts import check_release_version as crv

ROOT = Path(__file__).resolve().parent.parent
CHART = ROOT / "deploy" / "helm" / "aegis-mcp"
TEMPLATES = CHART / "templates"
CI_VALUES = CHART / "ci" / "hardened-values.yaml"
RELEASE_WORKFLOW = ROOT / ".github" / "workflows" / "release.yml"
HELM_POLICY = ROOT / "policy" / "helm.rego"

HELM = shutil.which("helm")
CONFTEST = shutil.which("conftest")
ZIZMOR = shutil.which("zizmor")
needs_helm = pytest.mark.skipif(HELM is None, reason="helm binary not installed")

_PINNED_REF = re.compile(r"@(?:v\d+\.\d+\.\d+|[0-9a-f]{40})$")


def _load(path: Path) -> Any:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _template(name: str) -> str:
    return (TEMPLATES / name).read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def values() -> dict[str, Any]:
    loaded: dict[str, Any] = _load(CHART / "values.yaml")
    return loaded


@pytest.fixture(scope="module")
def workflow() -> dict[Any, Any]:
    loaded: dict[Any, Any] = _load(RELEASE_WORKFLOW)
    return loaded


# --------------------------------------------------------------------------
# Version consistency (v0.2.0 prep)
# --------------------------------------------------------------------------


def test_project_chart_and_runtime_versions_are_0_2_0() -> None:
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    chart = _load(CHART / "Chart.yaml")
    assert pyproject["project"]["version"] == "0.2.0"
    assert chart["apiVersion"] == "v2"
    assert chart["version"] == "0.2.0"
    assert chart["appVersion"] == "0.2.0"
    assert app.version == "0.2.0"
    assert PRODUCT_VERSION == "0.2.0"


def test_repository_release_versions_are_consistent() -> None:
    versions = crv.read_versions(ROOT)
    assert versions.changelog[:2] == ("Unreleased", "0.2.0")
    assert crv.check(versions) == []
    assert crv.check(versions, "v0.2.0") == []


def test_check_reports_every_mismatch() -> None:
    versions = crv.ReleaseVersions(
        pyproject="0.2.0", chart="0.1.0", app="0.3.0", changelog=("0.1.0",)
    )
    errors = crv.check(versions, "v0.2.0")
    assert len(errors) == 3
    assert any("Chart.yaml version" in e for e in errors)
    assert any("Chart.yaml appVersion" in e for e in errors)
    assert any("CHANGELOG.md has no '## [0.2.0]'" in e for e in errors)


def test_check_rejects_tag_ahead_of_sources() -> None:
    errors = crv.check(crv.read_versions(ROOT), "v9.9.9")
    assert len(errors) == 4


def _fake_repo(root: Path, chart_version: str) -> Path:
    (root / CHART_REL).parent.mkdir(parents=True)
    (root / "pyproject.toml").write_text('[project]\nversion = "1.2.3"\n')
    (root / CHART_REL).write_text(
        f"apiVersion: v2\nversion: {chart_version}  # chart\n" 'appVersion: "1.2.3"\n'
    )
    (root / "CHANGELOG.md").write_text("# Changelog\n\n## [1.2.3] - 2026-01-01\n")
    return root


CHART_REL = crv.CHART_PATH


def test_main_exit_codes(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    good = _fake_repo(tmp_path / "good", "1.2.3")
    assert crv.main(["--root", str(good), "--tag", "v1.2.3"]) == 0
    assert "consistent" in capsys.readouterr().out

    bad = _fake_repo(tmp_path / "bad", "1.2.4")
    assert crv.main(["--root", str(bad)]) == 1
    assert "Chart.yaml version is '1.2.4'" in capsys.readouterr().err


def test_chart_field_handles_quotes_comments_and_absence() -> None:
    doc = "version: 0.2.0 # c\nappVersion: '0.2.0'\n  nested: x\n"
    assert crv._chart_field(doc, "version") == "0.2.0"
    assert crv._chart_field(doc, "appVersion") == "0.2.0"
    assert crv._chart_field(doc, "nested") == ""


# --------------------------------------------------------------------------
# values.yaml hardened defaults
# --------------------------------------------------------------------------


def test_single_writer_and_scaling_disabled(values: dict[str, Any]) -> None:
    assert values["replicaCount"] == 1
    assert values["autoscaling"]["enabled"] is False
    assert values["autoscaling"]["maxReplicas"] == 1
    assert values["pdb"]["enabled"] is False
    raw = (CHART / "values.yaml").read_text(encoding="utf-8")
    assert "[persistence/postgres-ledger]" in raw
    assert "fork" in raw


def test_pod_security_standards_restricted(values: dict[str, Any]) -> None:
    pod = values["podSecurityContext"]
    assert pod["runAsNonRoot"] is True
    assert (pod["runAsUser"], pod["runAsGroup"], pod["fsGroup"]) == (10001,) * 3
    assert pod["seccompProfile"] == {"type": "RuntimeDefault"}
    container = values["securityContext"]
    assert container["allowPrivilegeEscalation"] is False
    assert container["readOnlyRootFilesystem"] is True
    assert container["privileged"] is False
    assert container["capabilities"] == {"drop": ["ALL"]}
    assert values["serviceAccount"]["automountServiceAccountToken"] is False


def test_persistence_probes_and_service(values: dict[str, Any]) -> None:
    assert values["persistence"]["enabled"] is True
    assert values["persistence"]["mountPath"] == "/data"
    assert values["config"]["dbFile"] == "aegis.db"
    assert values["service"]["port"] == 8000
    for probe in ("livenessProbe", "readinessProbe"):
        assert values[probe]["httpGet"]["path"] == "/healthz"
    assert values["config"]["environment"] == "prod"
    assert ":latest" not in values["image"]["repository"]


def test_network_policy_defaults_are_default_deny(values: dict[str, Any]) -> None:
    np = values["networkPolicy"]
    assert np["enabled"] is True
    assert np["egressUpstreams"] == []
    assert np["otlp"]["cidr"] == ""
    assert np["dns"]["enabled"] is True


# --------------------------------------------------------------------------
# Template sources (no helm required)
# --------------------------------------------------------------------------


def test_statefulset_template_wiring() -> None:
    sts = _template("statefulset.yaml")
    assert sts.startswith('{{- include "aegis-mcp.validate" . }}')
    assert "kind: StatefulSet" in sts
    assert "volumeClaimTemplates:" in sts
    assert "name: AEGIS_DB_PATH" in sts
    assert "automountServiceAccountToken: false" in sts
    assert "mountPath: /tmp" in sts
    assert "whenDeleted: Retain" in sts


def test_validate_helper_fails_closed() -> None:
    helpers = _template("_helpers.tpl")
    assert 'fail "replicaCount must be 1' in helpers
    assert 'fail "signingKey.existingSecret is required' in helpers


def test_scaling_templates_are_gated() -> None:
    assert "{{- if .Values.autoscaling.enabled }}" in _template("hpa.yaml")
    assert "{{- if .Values.pdb.enabled }}" in _template("pdb.yaml")


def test_networkpolicy_template_shape() -> None:
    np = _template("networkpolicy.yaml")
    assert "- Ingress" in np
    assert "- Egress" in np
    assert np.count("port: 53") == 2
    assert "protocol: UDP" in np
    assert "port: 8000" in np
    assert "egressUpstreams" in np
    assert "otlp.cidr" in np


def test_notes_and_service_account_exist() -> None:
    notes = _template("NOTES.txt")
    assert "cosign verify" in notes
    assert "postgres-ledger" in notes
    assert "automountServiceAccountToken" in _template("serviceaccount.yaml")
    assert "clusterIP: None" in _template("service.yaml")


def test_helm_rego_policy_covers_core_controls() -> None:
    rego = HELM_POLICY.read_text(encoding="utf-8")
    assert "import rego.v1" in rego
    for needle in (
        "runAsNonRoot",
        "readOnlyRootFilesystem",
        "allowPrivilegeEscalation",
        "RuntimeDefault",
        "replicas must be exactly 1",
        "volumeClaimTemplate",
        "policyTypes must include Egress",
        "port 8000",
        "0.0.0.0/0",
    ):
        assert needle in rego, needle


# --------------------------------------------------------------------------
# Release workflow (zizmor-style static checks)
# --------------------------------------------------------------------------


def _steps(workflow: dict[Any, Any]) -> list[dict[str, Any]]:
    return [s for job in workflow["jobs"].values() for s in job.get("steps", [])]


def _uses(workflow: dict[Any, Any]) -> list[str]:
    refs = [s["uses"] for s in _steps(workflow) if "uses" in s]
    refs += [j["uses"] for j in workflow["jobs"].values() if "uses" in j]
    return refs


def test_release_triggers_only_on_version_tags(workflow: dict[Any, Any]) -> None:
    # PyYAML (YAML 1.1) parses the bare ``on`` key as boolean True.
    triggers = workflow[True]
    assert triggers == {"push": {"tags": ["v*"]}}


def test_release_permissions_are_least_privilege(workflow: dict[Any, Any]) -> None:
    assert workflow["permissions"] == {}
    for name, job in workflow["jobs"].items():
        perms = job.get("permissions")
        assert isinstance(perms, dict) and perms, name
        assert "write-all" not in str(perms)
        assert perms.get("contents", "read") == "read", name


def test_release_actions_are_pinned(workflow: dict[Any, Any]) -> None:
    refs = _uses(workflow)
    assert refs
    for ref in refs:
        assert _PINNED_REF.search(ref), ref
        assert not ref.endswith(("@master", "@main"))


def test_release_has_no_template_injection_or_persisted_credentials(
    workflow: dict[Any, Any],
) -> None:
    for step in _steps(workflow):
        assert "${{" not in step.get("run", ""), step.get("name")
        if str(step.get("uses", "")).startswith("actions/checkout@"):
            assert step["with"]["persist-credentials"] is False


def test_release_supply_chain_steps(workflow: dict[Any, Any]) -> None:
    text = RELEASE_WORKFLOW.read_text(encoding="utf-8")
    image = workflow["jobs"]["image"]
    build = next(s for s in image["steps"] if s.get("id") == "build")
    assert build["with"]["platforms"] == "linux/amd64,linux/arm64"
    assert build["with"]["push"] is True
    assert image["permissions"]["id-token"] == "write"
    sbom = next(s for s in image["steps"] if "anchore/sbom-action" in s.get("uses", ""))
    assert sbom["with"]["format"] == "cyclonedx-json"
    assert 'cosign sign --yes "${IMAGE}@${DIGEST}"' in text
    assert "actions/attest-sbom@" in text
    provenance = workflow["jobs"]["provenance"]
    assert provenance["uses"].startswith(
        "slsa-framework/slsa-github-generator/.github/workflows/"
        "generator_container_slsa3.yml@v"
    )
    assert "--type slsaprovenance" in text
    assert "scripts.check_release_version" in text
    assert "policy/helm.rego" in text


# --------------------------------------------------------------------------
# Rendered manifests (requires helm; conftest/zizmor when available)
# --------------------------------------------------------------------------


def _helm_template(*args: str) -> subprocess.CompletedProcess[str]:
    assert HELM is not None
    return subprocess.run(
        [HELM, "template", "aegis", str(CHART), *args],
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )


def _render(*args: str) -> dict[str, list[dict[str, Any]]]:
    result = _helm_template("-f", str(CI_VALUES), *args)
    assert result.returncode == 0, result.stderr
    docs: dict[str, list[dict[str, Any]]] = {}
    for doc in yaml.safe_load_all(result.stdout):
        if doc:
            docs.setdefault(doc["kind"], []).append(doc)
    return docs


@needs_helm
def test_rendered_chart_is_hardened() -> None:
    docs = _render()
    assert set(docs) == {"StatefulSet", "Service", "ServiceAccount", "NetworkPolicy"}
    (sts,) = docs["StatefulSet"]
    assert sts["spec"]["replicas"] == 1
    pod = sts["spec"]["template"]["spec"]
    assert pod["automountServiceAccountToken"] is False
    (container,) = pod["containers"]
    env = {e["name"]: e.get("value") for e in container["env"]}
    assert env["AEGIS_DB_PATH"] == "/data/aegis.db"
    assert env["AEGIS_SIGNING_KEY_PATH"] == "/etc/aegis/signing/signing-key.pem"
    assert container["securityContext"]["readOnlyRootFilesystem"] is True
    mounts = {m["mountPath"] for m in container["volumeMounts"]}
    assert {"/data", "/tmp"} <= mounts
    assert sts["spec"]["volumeClaimTemplates"][0]["metadata"]["name"] == "data"
    (np,) = docs["NetworkPolicy"]
    egress_ports = {
        (p["port"], p["protocol"]) for r in np["spec"]["egress"] for p in r["ports"]
    }
    assert egress_ports == {(53, "UDP"), (53, "TCP"), (9000, "TCP"), (4318, "TCP")}
    assert [p["port"] for p in np["spec"]["ingress"][0]["ports"]] == [8000]


@needs_helm
def test_render_refuses_hash_chain_fork_and_missing_signing_key() -> None:
    forked = _helm_template("-f", str(CI_VALUES), "--set", "replicaCount=2")
    assert forked.returncode != 0
    assert "fork the audit hash chain" in forked.stderr
    unsigned = _helm_template()
    assert unsigned.returncode != 0
    assert "signingKey.existingSecret is required" in unsigned.stderr


@needs_helm
def test_scaling_resources_render_only_when_enabled() -> None:
    docs = _render("--set", "autoscaling.enabled=true", "--set", "pdb.enabled=true")
    assert "HorizontalPodAutoscaler" in docs
    assert "PodDisruptionBudget" in docs
    assert "replicas" not in docs["StatefulSet"][0]["spec"]


@needs_helm
@pytest.mark.skipif(CONFTEST is None, reason="conftest binary not installed")
def test_rendered_chart_passes_rego_policy(tmp_path: Path) -> None:
    result = _helm_template("-f", str(CI_VALUES))
    assert result.returncode == 0, result.stderr
    rendered = tmp_path / "rendered.yaml"
    rendered.write_text(result.stdout, encoding="utf-8")
    assert CONFTEST is not None
    policy = subprocess.run(
        [CONFTEST, "test", str(rendered), "--policy", str(HELM_POLICY)],
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    assert policy.returncode == 0, policy.stdout + policy.stderr


@pytest.mark.skipif(ZIZMOR is None, reason="zizmor binary not installed")
def test_release_workflow_has_no_zizmor_findings() -> None:
    assert ZIZMOR is not None
    result = subprocess.run(
        [
            ZIZMOR,
            "--offline",
            "--no-progress",
            "--config",
            str(ROOT / ".github" / "zizmor.yml"),
            str(RELEASE_WORKFLOW),
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    assert result.returncode == 0, result.stdout + result.stderr
