"""Deploy a built JingShield binary to an authorized Linux test node.

The SSH/sudo password is read from JINGSHIELD_SSH_PASSWORD and is never stored
in the repository. Requires paramiko in the local Python environment.
"""

from __future__ import annotations

import argparse
import hashlib
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
    action = parser.add_mutually_exclusive_group()
    action.add_argument("--verify-only", action="store_true")
    action.add_argument("--sync-scripts", action="store_true")
    action.add_argument("--inspect-only", action="store_true")
    action.add_argument("--cleanup-stale-candidate", action="store_true")
    parser.add_argument("--install-root", default="/opt/jingshield")
    args = parser.parse_args()

    password = os.environ.get("JINGSHIELD_SSH_PASSWORD")
    if not password:
        raise SystemExit("JINGSHIELD_SSH_PASSWORD is required")
    repository_root = pathlib.Path(__file__).resolve().parents[1]
    binary = pathlib.Path(args.binary).resolve()
    if not args.verify_only and not args.sync_scripts and not args.inspect_only and not binary.is_file():
        raise SystemExit(f"binary not found: {binary}")
    install_root = pathlib.PurePosixPath(args.install_root)
    if not install_root.is_absolute() or ".." in install_root.parts or str(install_root) == "/":
        raise SystemExit("--install-root must be a safe absolute directory")

    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
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

    if args.inspect_only:
        try:
            print(
                run(
                    "systemctl show jingshield.service --no-pager "
                    "--property=LoadState,ActiveState,SubState,FragmentPath,ExecStart,EnvironmentFiles"
                )
            )
            print("sites:")
            print(
                run(
                    'mysql -NBe "SELECT id,name,host,upstream,pass_host,tls_skip_verify,enabled '
                    'FROM jyj_ccpro.jyj_sites ORDER BY id"',
                    sudo=True,
                )
            )
            print("latest_attack_packet_summary:")
            print(
                run(
                    'mysql -NBe "SELECT id,COALESCE(event_id,\'\'),attack_type,CHAR_LENGTH(COALESCE(request_packet,\'\')),'
                    'LOCATE(\'%5BREDACTED%5D\',COALESCE(request_packet,\'\'))>0,'
                    'LOCATE(\'UNION+SELECT\',COALESCE(request_packet,\'\'))>0,'
                    'LOCATE(\'jingshield-packet-secret\',COALESCE(request_packet,\'\'))>0 '
                    'FROM jyj_ccpro.jyj_attack_log ORDER BY id DESC LIMIT 1"',
                    sudo=True,
                )
            )
            print("latest_event_references:")
            print(
                run(
                    'mysql -NBe "SELECT event_id,attack_log_id,occurred_at '
                    'FROM jyj_ccpro.jyj_attack_event_ref ORDER BY occurred_at DESC LIMIT 5"',
                    sudo=True,
                )
            )
        finally:
            client.close()
        return

    if args.cleanup_stale_candidate:
        candidate = str(install_root / ".jingshield.next")
        try:
            expected = hashlib.sha256(binary.read_bytes()).hexdigest()
            try:
                actual = run("sha256sum " + shlex.quote(candidate), sudo=True).split()[0].lower()
            except RuntimeError as exc:
                if "No such file or directory" in str(exc):
                    print(f"stale_candidate=absent path={candidate}")
                    return
                raise
            if actual != expected:
                raise RuntimeError("refusing to remove stale candidate with an unexpected SHA-256")
            run("rm -f -- " + shlex.quote(candidate), sudo=True)
            print(f"stale_candidate=removed hash={actual} path={candidate}")
        finally:
            client.close()
        return

    if args.sync_scripts:
        script_paths = [repository_root / "run.sh", repository_root / "upgrade.sh"]
        for script_path in script_paths:
            if not script_path.is_file():
                raise SystemExit(f"deployment script not found: {script_path}")
        remote_scripts: list[str] = []
        try:
            remote_home = run('printf %s "$HOME"')
            if not remote_home.startswith("/") or "\n" in remote_home or "\r" in remote_home:
                raise RuntimeError("remote account returned an invalid home directory")
            stamp = int(time.time())
            with client.open_sftp() as sftp:
                for script_path in script_paths:
                    remote_path = f"{remote_home}/.jingshield-{script_path.name}-{stamp}.new"
                    sftp.put(str(script_path), remote_path)
                    sftp.chmod(remote_path, 0o700)
                    remote_scripts.append(remote_path)
            run("bash -n " + " ".join(shlex.quote(path) for path in remote_scripts))
            install_command = "set -e; " + "; ".join(
                [
                    f"test -d {shlex.quote(str(install_root))}",
                    *[
                        "install -o root -g root -m 0755 "
                        + shlex.quote(remote_path)
                        + " "
                        + shlex.quote(str(install_root / (script_path.name + ".next")))
                        for remote_path, script_path in zip(remote_scripts, script_paths)
                    ],
                    *[
                        "mv -f "
                        + shlex.quote(str(install_root / (script_path.name + ".next")))
                        + " "
                        + shlex.quote(str(install_root / script_path.name))
                        for script_path in script_paths
                    ],
                ]
            )
            run("bash -c " + shlex.quote(install_command), sudo=True)
            remote_hashes = run(
                "sha256sum "
                + " ".join(shlex.quote(str(install_root / script_path.name)) for script_path in script_paths),
                sudo=True,
            ).splitlines()
            expected = [hashlib.sha256(path.read_bytes()).hexdigest() for path in script_paths]
            actual = [line.split()[0].lower() for line in remote_hashes]
            if actual != expected:
                raise RuntimeError("remote deployment script SHA-256 does not match local files")
            print(
                "scripts=synchronized syntax=bash-ok hashes=verified "
                + "paths="
                + ",".join(str(install_root / path.name) for path in script_paths)
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

    if args.verify_only:
        remote_scripts: list[str] = []
        try:
            script_paths = [
                repository_root / "run.sh",
                repository_root / "upgrade.sh",
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
    try:
        with client.open_sftp() as sftp:
            sftp.put(str(binary), stage)
        remote_upgrade = str(install_root / "upgrade.sh")
        output = run(
            "bash " + shlex.quote(remote_upgrade) + " " + shlex.quote(stage),
            sudo=True,
        )
        print(f"deployed={binary.name}")
        print(output)
    finally:
        try:
            run(f"rm -f {shlex.quote(stage)}")
        except Exception:
            pass
        client.close()


if __name__ == "__main__":
    main()
