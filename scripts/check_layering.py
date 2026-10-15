#!/usr/bin/env python3
"""Check the production dependency closure and the concrete Inkson adapters."""

import argparse
import re
import subprocess
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--inkson-root", type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    for target, features in [("x86_64-pc-windows-msvc" if __import__("os").name == "nt" else "all", "native"),
                             ("wasm32-unknown-unknown", "wasm")]:
        result = subprocess.run(
            ["cargo", "tree", "--edges", "normal", "--prefix", "none", "--no-default-features",
             "--features", features, "--target", target],
            cwd=root, text=True, capture_output=True, timeout=1800, check=True,
        )
        forbidden = re.findall(r"^(?:openmls\S*|dioxus\S*|inkson)\s+v\S+", result.stdout, re.M)
        if forbidden:
            raise SystemExit(f"{target}: forbidden production dependencies: {forbidden}")
        print(f"PASS {target}: production closure has no OpenMLS, Dioxus or Inkson")
    if args.inkson_root:
        host = args.inkson_root
        checks = {
            "src/event_submit.rs": r"dioxus::|crate::app::|fn from_current_session|fn event_submission",
            "src/event_submit/metadata.rs": r"crate::views::",
            "src/identity/metadata.rs": r"crate::views::",
            "src/state/projection/sync.rs": r"crate::views::",
            "src/signal_receive_engine.rs": r"crate::views::",
            "src/mls/runtime/artifact_consumer.rs": r"enum MlsInstallOutcome",
        }
        for relative, pattern in checks.items():
            if re.search(pattern, (host / relative).read_text(encoding="utf-8")):
                raise SystemExit(f"host layering regression: {relative}")
        required = {
            "src/event_submit.rs": "garth::event_authoring::EventAuthoringSession",
            "src/mls/runtime/artifact_consumer.rs": "garth::mls::checkpoint_port::install_checkpoint",
            "src/realm_events_engine.rs": "garth::current_ingest::",
            "src/state/realm_membership.rs": "garth::mls::membership::admission_joined_members",
        }
        for relative, needle in required.items():
            if needle not in (host / relative).read_text(encoding="utf-8"):
                raise SystemExit(f"shared engine is disconnected: {relative}")
        if (host / "src/mls/accepted_artifact.rs").exists():
            raise SystemExit("host retains a second accepted-artifact parser")
        print("PASS Inkson: shared engines are connected and host/UI reverse dependencies are absent")


if __name__ == "__main__":
    main()
