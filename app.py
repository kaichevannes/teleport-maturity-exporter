import json
import subprocess
import time
from urllib.parse import urlencode
from urllib.request import Request, urlopen
from prometheus_client import Gauge, start_http_server

PROMETHEUS_URL = (
    "http://kube-prometheus-stack-prometheus.monitoring.svc.cluster.local:9090"
)
LOKI_URL = "http://loki-gateway.monitoring.svc.cluster.local"

maturity_control = Gauge(
    "teleport_maturity_control",
    "Whether a Teleport maturity control is satisfied",
    ["level", "control", "display_name"],
)

maturity_resource_coverage = Gauge(
    "teleport_maturity_resource_coverage",
    "Enrollment coverage by resource type",
    ["type", "display_name"],
)

maturity_standing_access = Gauge(
    "teleport_maturity_standing_access",
    "Number of resources identities have standing access to",
    ["identity"],
)


maturity_score = Gauge("teleport_maturity_score", "Aggregated maturity level.")


def prometheus_query(expression):
    query = urlencode({"query": expression})

    with urlopen(f"{PROMETHEUS_URL}/api/v1/query?{query}", timeout=30) as response:
        data = json.load(response)

    results = data["data"]["result"]
    return float(results[0]["value"][1])


def loki_query(expression):
    query = urlencode({"query": expression})

    request = Request(
        f"{LOKI_URL}/loki/api/v1/query?{query}",
        headers={"X-Scope-OrgID": "teleport-audit"},
    )

    with urlopen(request, timeout=30) as response:
        data = json.load(response)

    results = data["data"]["result"]
    return float(results[0]["value"][1])


def tctl_get(resource):
    return subprocess.check_output(
        [
            "/usr/local/bin/tctl",
            "--auth-server=kaichevannes-teleport.uk:443",
            "--identity=/opt/machine-id/identity",
            "get",
            resource,
            "--format=json",
        ],
        text=True,
        timeout=30,
    )


def tctl_check(*args):
    try:
        result = subprocess.run(
            [
                "/usr/local/bin/tctl",
                "--auth-server=kaichevannes-teleport.uk:443",
                "--identity=/opt/machine-id/identity",
                *args,
            ],
            check=False,
            stdout=subprocess.DEVNULL,
            timeout=30,
        )
        return int(result.returncode == 0)
    except subprocess.TimeoutExpired:
        return 0


def coverage(resource, expected):
    if expected == 0:
        return 1

    resources = []
    for resource_kind in resource.split(","):
        resources += json.loads(tctl_get(resource_kind))

    deduplicated_resources = {item["metadata"]["name"] for item in resources}
    return len(deduplicated_resources) / expected


def calculate_score():
    controls = next(iter(maturity_control.collect())).samples
    score = 1

    for level in (2, 3, 4, 5):
        values = [
            control.value
            for control in controls
            if control.labels["level"] == str(level)
        ]

        if not all(values):
            return score + sum(values) / len(values)

        score = level

    return score


def main():
    start_http_server(8080)

    while True:
        with open("/etc/maturity-exporter/external-config.json") as file:
            config = json.load(file)

        inventory = config["inventory"]

        ## Level 2
        # SSO
        maturity_control.labels(
            level="2", control="sso", display_name="SSO Configured"
        ).set(int(bool(json.loads(tctl_get("connectors")))))

        ## Level 3
        # Audit events
        audit_activity = prometheus_query(
            "sum(increase(teleport_audit_emit_events[7d])) > bool 0"
        )
        maturity_control.labels(
            level="3",
            control="audit_activity",
            display_name="Audit Activity Observed (7d)",
        ).set(audit_activity)

        ## Level 4
        # Machine Identity
        maturity_control.labels(
            level="4", control="machine_id", display_name="Machine ID Configured"
        ).set(int(bool(json.loads(tctl_get("bot")))))

        # Workload Identity
        maturity_control.labels(
            level="4", control="workload_id", display_name="Workload ID Configured"
        ).set(int(bool(json.loads(tctl_get("workload_identity")))))

        # CI/CD
        ci_join_methods = {
            "azure_devops",
            "bitbucket",
            "circleci",
            "env0",
            "github",
            "gitlab",
            "spacelift",
            "terraform_cloud",
        }
        join_tokens = [
            token
            for token in json.loads(tctl_get("token"))
            if token["spec"].get("join_method") in ci_join_methods
        ]
        maturity_control.labels(
            level="4",
            control="devops_identity_configured",
            display_name="CI/CD Identity Configured",
        ).set(int(bool(join_tokens)))

        # Access Request activity
        request_count = loki_query(
            """
            sum(count_over_time(
                {job="teleport-audit"}
                | json
                | event="access_request.create"
                [7d]
            )) or vector(0)
            """
        )
        maturity_control.labels(
            level="4",
            control="access_request_activity",
            display_name="Access Requests Used (7d)",
        ).set(int(request_count > 0))

        ## Level 5
        # Access Graph Enabled
        maturity_control.labels(
            level="5",
            control="access_graph_enabled",
            display_name="Access Graph Configured",
        ).set(
            tctl_check(
                "access-review",
                "--query=SELECT * FROM access_path",
                "--no-activity",
                "--limit=1",
                "--format=json",
            )
        )

        # Identity Center Enabled
        maturity_control.labels(
            level="5",
            control="identity_center_enabled",
            display_name="Identity Center Configured",
        ).set(
            tctl_check(
                "investigate",
                "--from=1h",
                "--limit=1",
                "--format=text",
                "--no-all-facets",
                "--no-show-unmatched",
            )
        )

        # SSH Key Scanning Enabled
        try:
            access_graph_settings = json.loads(tctl_get("access_graph_settings"))
            scanning_enabled = int(
                any(
                    item["spec"].get("secrets_scan_config") == "enabled"
                    for item in access_graph_settings
                )
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            scanning_enabled = 0

        maturity_control.labels(
            level="5",
            control="ssh_key_scanning_enabled",
            display_name="SSH Key Scanning Configured",
        ).set(scanning_enabled)

        # No standing access
        maturity_standing_access.clear()
        try:
            response = json.loads(
                subprocess.check_output(
                    [
                        "/usr/local/bin/tctl",
                        "--auth-server=kaichevannes-teleport.uk:443",
                        "--identity=/opt/machine-id/identity",
                        "access-review",
                        "--query=SELECT * FROM access_path WHERE standing_privileges >= 1",
                        "--limit=10000",
                        "--no-activity",
                        "--format=json",
                    ],
                    text=True,
                    timeout=30,
                )
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            no_standing_access = 0
        else:
            for item in response["identities"]:
                identity = item["identity"]

                maturity_standing_access.labels(
                    identity=identity["name"],
                ).set(
                    len(
                        {
                            entry["resource"]["id"]
                            for entry in item["resources"]
                            if entry["level"] == "standing"
                        }
                    )
                )

            no_standing_access = int(not response["identities"])

        maturity_control.labels(
            level="5", control="no_standing_access", display_name="No Standing Access"
        ).set(no_standing_access)

        ## All levels
        # Resource coverage
        coverage_thresholds = {
            2: 0.5,
            3: 0.8,
            4: 0.9,
            5: 1.0,
        }

        resource_kinds = {
            "ssh": "node",
            "kubernetes": "kube_server",
            "databases": "db_server",
            "applications": "app_server,saml_idp_service_provider",
            "windows_desktop": "windows_desktop",
            "linux_desktop": "linux_desktop",
        }

        resource_display_names = {
            "ssh": "SSH",
            "kubernetes": "Kubernetes",
            "databases": "Database",
            "applicationss": "Application",
            "windows_desktop": "Windows Desktop",
            "linux_desktop": "Linux Desktop",
        }

        for resource, resource_kind in resource_kinds.items():
            value = coverage(resource_kind, inventory[resource])

            maturity_resource_coverage.labels(type=resource).set(value)

            for level, threshold in coverage_thresholds.items():
                maturity_control.labels(
                    level=str(level),
                    control=f"{resource}_coverage",
                    display_name=f"≥{threshold:.0%} {resource_display_names[resource]} Coverage",
                ).set(int(value >= threshold))

        maturity_score.set(calculate_score())

        time.sleep(60)


if __name__ == "__main__":
    main()
