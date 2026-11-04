import json
import subprocess
import time

from prometheus_client import Gauge, start_http_server

maturity_control = Gauge(
    "teleport_maturity_control",
    "Whether a Teleport maturity control is satisfied",
    ["level", "control"],
)

maturity_score = Gauge("teleport_maturity_score", "Aggregated maturity level.")


def tctl_get(resource):
    return subprocess.check_output(
        [
            "/usr/local/bin/tctl",
            "--proxy=kaichevannes-teleport.uk:443",
            "--identity=/opt/machine-id/identity",
            "get",
            resource,
            "--format=json",
        ],
        text=True,
        timeout=30,
    )


def main() -> None:
    start_http_server(8080)

    while True:
        maturity_control.labels(
            level="2",
            control="sso",
        ).set(int(bool(json.loads(tctl_get("connectors")))))

        maturity_score.set(2.1)

        time.sleep(60)


if __name__ == "__main__":
    main()
