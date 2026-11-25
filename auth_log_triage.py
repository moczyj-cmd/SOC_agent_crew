#!/usr/bin/env python3
"""
auth_log_triage.py (v2)
Offline Blue Team detection engine for Ubuntu /var/log/auth.log.

Detections:
  1. High-velocity sudo bursts (FBI ARTEX / MITRE T1548.003) using a true sliding window.
  2. SSH brute-force password guessing (MITRE T1110.001) per source IP.

Features:
  - Pandas time-based rolling windows (eliminates fixed-bucket boundary evasion)
  - Incident coalescing (prevents duplicate alert fatigue inside a single burst)
  - Narrow command-pattern allowlisting with transparent suppression counts
"""

import argparse
import re
from pathlib import Path
import pandas as pd


class AuthLogTriage:
    """Parses Ubuntu ISO-8601 auth.log entries and runs sliding-window SOC detections."""

    SUDO_PATTERN = re.compile(
        r"^(?P<timestamp>\S+)\s+"
        r"(?P<host>\S+)\s+sudo:\s+"
        r"(?P<user>\S+)\s*:.*?"
        r"TTY=(?P<tty>[^;]+?)\s*;.*?"
        r"PWD=(?P<pwd>[^;]+?)\s*;.*?"
        r"USER=(?P<target_user>[^;]+?)\s*;.*?"
        r"COMMAND=(?P<command>.+)$"
    )

    SSH_FAIL_PATTERN = re.compile(
        r"^(?P<timestamp>\S+)\s+"
        r"(?P<host>\S+)\s+sshd(?:-session)?\[\d+\]:\s+"
        r"Failed password for (?:invalid user )?(?P<target_user>\S+)\s+"
        r"from (?P<src_ip>\S+)\s+port\s+(?P<src_port>\d+)"
    )

    # Narrow command-level allowlist (never allowlist an entire user account)
    BENIGN_SUDO_PATTERNS = [
        re.compile(r"^/usr/sbin/usermod\s+-a\s+-G\s+(?:render|video|ollama)\s+\S+$"),
        re.compile(r"^/usr/bin/systemctl\s+(?:daemon-reload|restart\s+ollama|enable\s+ollama)$"),
    ]

    def __init__(self, log_path: str, use_allowlist: bool = True) -> None:
        self.log_path = Path(log_path)
        self.use_allowlist = use_allowlist
        self.sudo_df = pd.DataFrame()
        self.ssh_df = pd.DataFrame()
        self.suppressed_sudo_count = 0

    def _is_allowlisted(self, command: str) -> bool:
        return any(pattern.search(command) for pattern in self.BENIGN_SUDO_PATTERNS)

    def parse(self) -> tuple[pd.DataFrame, pd.DataFrame]:
        """Parse auth.log into structured sudo and failed-SSH DataFrames."""
        sudo_records = []
        ssh_records = []
        self.suppressed_sudo_count = 0

        with self.log_path.open("r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                sudo_match = self.SUDO_PATTERN.search(line)
                if sudo_match:
                    rec = sudo_match.groupdict()
                    rec["command"] = rec["command"].strip()
                    if self.use_allowlist and self._is_allowlisted(rec["command"]):
                        self.suppressed_sudo_count += 1
                        continue
                    sudo_records.append(rec)
                    continue

                ssh_match = self.SSH_FAIL_PATTERN.search(line)
                if ssh_match:
                    ssh_records.append(ssh_match.groupdict())

        self.sudo_df = self._finalize_df(
            sudo_records,
            ["timestamp", "host", "user", "tty", "pwd", "target_user", "command"],
        )
        self.ssh_df = self._finalize_df(
            ssh_records,
            ["timestamp", "host", "target_user", "src_ip", "src_port"],
        )
        return self.sudo_df, self.ssh_df

    @staticmethod
    def _finalize_df(records: list[dict], columns: list[str]) -> pd.DataFrame:
        if not records:
            return pd.DataFrame(columns=columns)
        df = pd.DataFrame(records)
        df["timestamp"] = pd.to_datetime(df["timestamp"], format="ISO8601", utc=True)
        return df.sort_values("timestamp").reset_index(drop=True)

    @staticmethod
    def _sliding_window_alerts(
        df: pd.DataFrame,
        group_cols: list[str],
        detail_col: str,
        window_seconds: int,
        threshold: int,
        mitre_id: str,
        alert_name: str,
    ) -> pd.DataFrame:
        """Detect threshold breaches over a true rolling time window and coalesce overlaps."""
        if df.empty:
            return pd.DataFrame()

        alerts = []
        window_delta = pd.Timedelta(seconds=window_seconds)

        for keys, group in df.groupby(group_cols, sort=False):
            if not isinstance(keys, tuple):
                keys = (keys,)

            g = group.sort_values("timestamp").reset_index(drop=True)
            g["_event"] = 1
            g["rolling_count"] = (
                g.set_index("timestamp")["_event"]
                .rolling(f"{window_seconds}s")
                .sum()
                .astype(int)
                .to_numpy()
            )

            triggers = g.loc[g["rolling_count"] >= threshold]
            if triggers.empty:
                continue

            # Coalesce overlapping triggers within window_seconds into one clean incident
            incidents = []
            for _, row in triggers.iterrows():
                t = row["timestamp"]
                cnt = int(row["rolling_count"])
                if not incidents or (t - incidents[-1]["end"]) > window_delta:
                    incidents.append(
                        {"start_bound": t - window_delta, "end": t, "peak_in_window": cnt}
                    )
                else:
                    incidents[-1]["end"] = t
                    incidents[-1]["peak_in_window"] = max(
                        incidents[-1]["peak_in_window"], cnt
                    )

            for inc in incidents:
                window_slice = g.loc[
                    (g["timestamp"] > inc["start_bound"])
                    & (g["timestamp"] <= inc["end"])
                ]
                record = {
                    "alert": alert_name,
                    "mitre": mitre_id,
                    "first_seen": window_slice["timestamp"].iloc[0].strftime("%Y-%m-%d %H:%M:%S UTC"),
                    "last_seen": window_slice["timestamp"].iloc[-1].strftime("%Y-%m-%d %H:%M:%S UTC"),
                }
                for col, val in zip(group_cols, keys):
                    record[col] = val
                record["event_count"] = len(window_slice)
                record["peak_in_window"] = inc["peak_in_window"]
                record["unique_items"] = int(window_slice[detail_col].nunique())
                record["samples"] = " | ".join(
                    window_slice[detail_col].drop_duplicates().head(3)
                )
                alerts.append(record)

        if not alerts:
            return pd.DataFrame()
        return pd.DataFrame(alerts).sort_values("last_seen", ascending=False).reset_index(drop=True)

    def detect_sudo_bursts(self, window_seconds: int = 5, threshold: int = 5) -> pd.DataFrame:
        return self._sliding_window_alerts(
            df=self.sudo_df,
            group_cols=["host", "user", "target_user"],
            detail_col="command",
            window_seconds=window_seconds,
            threshold=threshold,
            mitre_id="T1548.003",
            alert_name="ARTEX_SUDO_BURST",
        )

    def detect_ssh_bruteforce(self, window_seconds: int = 60, threshold: int = 5) -> pd.DataFrame:
        return self._sliding_window_alerts(
            df=self.ssh_df,
            group_cols=["host", "src_ip"],
            detail_col="target_user",
            window_seconds=window_seconds,
            threshold=threshold,
            mitre_id="T1110.001",
            alert_name="SSH_BRUTE_FORCE",
        )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Tier 2 sliding-window triage parser for Ubuntu /var/log/auth.log."
    )
    parser.add_argument("-f", "--file", default="/var/log/auth.log", help="Path to auth.log")
    parser.add_argument("--sudo-window", type=int, default=5, help="Sudo sliding window in seconds (default: 5)")
    parser.add_argument("--sudo-threshold", type=int, default=5, help="Sudo burst threshold (default: 5)")
    parser.add_argument("--ssh-window", type=int, default=60, help="SSH brute-force window in seconds (default: 60)")
    parser.add_argument("--ssh-threshold", type=int, default=5, help="Failed SSH threshold (default: 5)")
    parser.add_argument("--no-allowlist", action="store_true", help="Disable benign command allowlist for raw audit")
    parser.add_argument("--export", default=None, help="Optional CSV path to export all alerts")
    args = parser.parse_args()

    triage = AuthLogTriage(args.file, use_allowlist=not args.no_allowlist)
    sudo_df, ssh_df = triage.parse()

    print(f"\n[+] Target log: {args.file}")
    print(f"[+] Parsed {len(sudo_df)} sudo event(s) | {len(ssh_df)} failed SSH event(s)")
    if triage.suppressed_sudo_count:
        print(
            f"[i] Suppressed {triage.suppressed_sudo_count} allowlisted benign sudo event(s) "
            "(pass --no-allowlist to inspect raw)"
        )

    sudo_alerts = triage.detect_sudo_bursts(args.sudo_window, args.sudo_threshold)
    ssh_alerts = triage.detect_ssh_bruteforce(args.ssh_window, args.ssh_threshold)

    print(f"\n--- Sudo Burst Alerts (MITRE T1548.003 | >= {args.sudo_threshold} in {args.sudo_window}s sliding) ---")
    print("No sudo burst alerts." if sudo_alerts.empty else sudo_alerts.to_string(index=False))

    print(f"\n--- SSH Brute-Force Alerts (MITRE T1110.001 | >= {args.ssh_threshold} in {args.ssh_window}s sliding) ---")
    print("No SSH brute-force alerts." if ssh_alerts.empty else ssh_alerts.to_string(index=False))

    if args.export:
        combined = pd.concat([sudo_alerts, ssh_alerts], ignore_index=True)
        if not combined.empty:
            combined.to_csv(args.export, index=False)
            print(f"\n[+] Exported {len(combined)} alert(s) to {args.export}")
        else:
            print("\n[i] No alerts to export.")


if __name__ == "__main__":
    main()
