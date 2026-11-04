import json
import subprocess
import time

from prometheus_client import Gauge, start_http_server

maturity_control = Gauge(
    "teleport_maturity_control",
    "Whether a Teleport maturity control is satisfied",
    ["level", "control"],
)

maturity_resource_coverage = Gauge(
    "teleport_maturity_resource_coverage",
    "Enrollment coverage by resource type",
    ["type"],
)


maturity_score = Gauge("teleport_maturity_score", "Aggregated maturity level.")


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


def coverage(resource, expected):
    if expected == 0:
        return 1

    deduplicated_resources = {
        item["metadata"]["name"] for item in json.loads(tctl_get(resource))
    }
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

        # SSO
        maturity_control.labels(
            level="2",
            control="sso",
        ).set(int(bool(json.loads(tctl_get("connectors")))))

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
            "applications": "app_server",
            "windows_desktop": "windows_desktop",
            "linux_desktop": "linux_desktop",
        }

        for resource, resource_kind in resource_kinds.items():
            value = coverage(resource_kind, inventory[resource])

            maturity_resource_coverage.labels(type=resource).set(value)

            for level, threshold in coverage_thresholds.items():
                maturity_control.labels(
                    level=str(level),
                    control=f"{resource}_coverage",
                ).set(int(value >= threshold))

        maturity_score.set(calculate_score())

        time.sleep(60)


if __name__ == "__main__":
    main()
