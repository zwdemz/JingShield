"""Deploy a built JingShield binary to an authorized Linux test node.

The SSH/sudo password is read from JINGSHIELD_SSH_PASSWORD and is never stored
in the repository. Requires paramiko in the local Python environment.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import shlex
import ssl
import time
import urllib.error
import urllib.request

import paramiko


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", required=True)
    parser.add_argument("--user", required=True)
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument("--binary", default="bin/jingshield-linux-amd64")
    parser.add_argument("--verify-only", action="store_true")
    args = parser.parse_args()

    password = os.environ.get("JINGSHIELD_SSH_PASSWORD")
    if not password:
        raise SystemExit("JINGSHIELD_SSH_PASSWORD is required")
    binary = pathlib.Path(args.binary).resolve()
    if not binary.is_file():
        raise SystemExit(f"binary not found: {binary}")

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(args.host, port=args.port, username=args.user, password=password, timeout=15)

    def run(command: str, sudo: bool = False) -> str:
        full = f"sudo -S -p '' {command}" if sudo else command
        stdin, stdout, stderr = client.exec_command(full, timeout=90)
        if sudo:
            stdin.write(password + "\n")
            stdin.flush()
        status = stdout.channel.recv_exit_status()
        output = stdout.read().decode("utf-8", "replace") + stderr.read().decode("utf-8", "replace")
        if status != 0:
            raise RuntimeError(f"remote command failed ({status}): {command}\n{output}")
        return output.strip()

    if args.verify_only:
        remote_scripts: list[str] = []
        try:
            repository_root = pathlib.Path(__file__).resolve().parents[1]
            script_paths = [
                repository_root / "deploy/linux/run.sh",
                repository_root / "deploy/linux/upgrade.sh",
                repository_root / "deploy/linux/install-remote-test.sh",
            ]
            with client.open_sftp() as sftp:
                for index, script_path in enumerate(script_paths):
                    remote_path = f"/home/{args.user}/.jingshield-syntax-{int(time.time())}-{index}.sh"
                    sftp.put(str(script_path), remote_path)
                    remote_scripts.append(remote_path)
            run("bash -n " + " ".join(shlex.quote(path) for path in remote_scripts))
            api_key = run(
                'mysql -NBe "SELECT config_value FROM jyj_ccpro.jyj_config WHERE config_key=\'api_key\'"',
                sudo=True,
            )
            if not api_key:
                raise RuntimeError("API Key is empty")
            context = ssl._create_unverified_context()
            request = urllib.request.Request(
                f"https://{args.host}:18443/openapi/v1/status",
                headers={"X-API-Key": api_key},
            )
            with urllib.request.urlopen(request, context=context, timeout=15) as response:
                data = json.load(response)
                if response.status != 200 or data.get("code") != 0 or data.get("data", {}).get("status") != "healthy":
                    raise RuntimeError(f"unexpected OpenAPI response: HTTP {response.status}")
            try:
                urllib.request.urlopen(f"https://{args.host}:18443/openapi/v1/status", context=context, timeout=15)
            except urllib.error.HTTPError as exc:
                if exc.code != 401:
                    raise
            else:
                raise RuntimeError("OpenAPI accepted a request without API Key")
            print(
                "scripts=bash-ok openapi=healthy authenticated=200 unauthenticated=401 "
                f"sites={data['data']['sites_enabled']}/{data['data']['sites_total']}"
            )
        finally:
            if remote_scripts:
                with client.open_sftp() as sftp:
                    for remote_path in remote_scripts:
                        try:
                            sftp.remove(remote_path)
                        except OSError:
                            pass
            client.close()
        return

    stage = f"/home/{args.user}/jingshield-{int(time.time())}.new"
    backup = f"/opt/jingshield/bin/jingshield.pre-api-{int(time.time())}"
    try:
        with client.open_sftp() as sftp:
            sftp.put(str(binary), stage)
        run(f"install -o root -g root -m 0755 {shlex.quote(stage)} /opt/jingshield/bin/jingshield.next", sudo=True)
        run("bash -c 'set -a; source /etc/jingshield/jingshield.env; set +a; /opt/jingshield/bin/jingshield.next migrate -c /etc/jingshield/config.yaml'", sudo=True)
        run(f"cp /opt/jingshield/bin/jingshield {shlex.quote(backup)}", sudo=True)
        run("systemctl stop jingshield", sudo=True)
        run("mv /opt/jingshield/bin/jingshield.next /opt/jingshield/bin/jingshield", sudo=True)
        try:
            run("systemctl start jingshield", sudo=True)
            status = run("systemctl is-active jingshield", sudo=True)
        except Exception:
            run(f"cp {shlex.quote(backup)} /opt/jingshield/bin/jingshield", sudo=True)
            run("systemctl start jingshield", sudo=True)
            raise
        print(f"deployed={binary.name} service={status} backup={backup}")
    finally:
        try:
            run(f"rm -f {shlex.quote(stage)}")
        except Exception:
            pass
        client.close()


if __name__ == "__main__":
    main()
