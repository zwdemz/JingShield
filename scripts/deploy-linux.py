"""Install or upgrade JingShield on an authorized Linux host over SSH.

The complete release archive is uploaded, SHA-256 verified, and executed through
its run.sh or upgrade.sh entry point. Passwords are read from environment
variables and are never placed in command-line arguments or repository files.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import pathlib
import shlex
import tarfile
import time
import uuid

try:
    import paramiko
except ImportError as exc:  # pragma: no cover - operator dependency
    raise SystemExit("paramiko is required; create .venv and install requirements-deploy.txt") from exc


SECRET_KEYS = (
    "JINGSHIELD_DB_ADMIN_PASS",
    "JINGSHIELD_DB_PASS",
    "JINGSHIELD_SESSION_KEY",
    "JINGSHIELD_DB_HOST",
    "JINGSHIELD_DB_PORT",
    "JINGSHIELD_DB_USER",
    "JINGSHIELD_DB_NAME",
    "JINGSHIELD_UPSTREAM",
    "JINGSHIELD_LISTEN",
    "JINGSHIELD_TLS_LISTEN",
    "JINGSHIELD_TLS_CERT_FILE",
    "JINGSHIELD_TLS_KEY_FILE",
)


def inspect_package(package: pathlib.Path) -> str:
    if not package.is_file() or not package.name.endswith(".tar.gz"):
        raise SystemExit(f"complete Linux package not found: {package}")
    with tarfile.open(package, "r:gz") as archive:
        members = archive.getmembers()
        if not members:
            raise SystemExit("release archive is empty")
        for member in members:
            parts = pathlib.PurePosixPath(member.name).parts
            if member.name.startswith("/") or ".." in parts or member.issym() or member.islnk():
                raise SystemExit(f"unsafe archive member: {member.name}")
        roots = {pathlib.PurePosixPath(member.name).parts[0] for member in members if member.name}
        if len(roots) != 1:
            raise SystemExit("release archive must contain exactly one top-level directory")
        root = next(iter(roots))
        names = {member.name.rstrip("/") for member in members}
        required = {
            f"{root}/run.sh",
            f"{root}/upgrade.sh",
            f"{root}/SHA256SUMS",
            f"{root}/payload/jingshield",
            f"{root}/config/config.yaml",
            f"{root}/systemd/jingshield.service",
        }
        missing = required - names
        if missing:
            raise SystemExit("incomplete release archive: " + ", ".join(sorted(missing)))
        return root


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description="Deploy a complete JingShield Linux package")
    parser.add_argument("--host", required=True)
    parser.add_argument("--user", required=True)
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument("--package", required=True)
    parser.add_argument("--action", choices=("install", "upgrade"), default="install")
    parser.add_argument("--key-file")
    parser.add_argument("--known-hosts", default=str(pathlib.Path.home() / ".ssh" / "known_hosts"))
    parser.add_argument("--accept-new-host-key", action="store_true")
    parser.add_argument("--admin-user")
    parser.add_argument("--admin-email", default="")
    parser.add_argument("--db-admin-user", default="root")
    parser.add_argument("--install-root", default="/opt/jingshield")
    parser.add_argument("--skip-db-provision", action="store_true")
    parser.add_argument("--force-config", action="store_true")
    parser.add_argument("--no-start", action="store_true")
    args = parser.parse_args()

    if args.action == "install" and not args.admin_user:
        parser.error("--admin-user is required for a non-interactive remote installation")
    if not args.install_root.startswith("/") or any(part in ("", "..") for part in args.install_root.split("/")[1:]):
        parser.error("--install-root must be a normalized absolute path")

    package = pathlib.Path(args.package).resolve()
    package_root = inspect_package(package)
    local_digest = sha256_file(package)
    ssh_password = os.environ.get("JINGSHIELD_SSH_PASSWORD")
    sudo_password = os.environ.get("JINGSHIELD_SUDO_PASSWORD", ssh_password or "")

    client = paramiko.SSHClient()
    known_hosts = pathlib.Path(args.known_hosts).expanduser()
    client.load_system_host_keys()
    if known_hosts.is_file():
        client.load_host_keys(str(known_hosts))
    if args.accept_new_host_key:
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    else:
        client.set_missing_host_key_policy(paramiko.RejectPolicy())

    connect_options: dict[str, object] = {
        "hostname": args.host,
        "port": args.port,
        "username": args.user,
        "timeout": 20,
        "banner_timeout": 20,
        "auth_timeout": 20,
        "allow_agent": True,
        "look_for_keys": True,
    }
    if ssh_password:
        connect_options["password"] = ssh_password
    if args.key_file:
        connect_options["key_filename"] = str(pathlib.Path(args.key_file).expanduser())
    client.connect(**connect_options)

    if args.accept_new_host_key:
        known_hosts.parent.mkdir(parents=True, exist_ok=True)
        client.save_host_keys(str(known_hosts))

    def run(command: str, *, sudo: bool = False, timeout: int = 600) -> str:
        if sudo:
            if sudo_password:
                command = "sudo -S -p '' -- " + command
            else:
                command = "sudo -n -- " + command
        stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
        if sudo and sudo_password:
            stdin.write(sudo_password + "\n")
            stdin.flush()
        status = stdout.channel.recv_exit_status()
        output = stdout.read().decode("utf-8", "replace")
        error = stderr.read().decode("utf-8", "replace")
        if status != 0:
            raise RuntimeError(f"remote command failed ({status}):\n{error or output}")
        return output + error

    remote_stage = ""
    try:
        remote_home = run("printf '%s' \"$HOME\"").strip()
        if not remote_home.startswith("/") or "\n" in remote_home or "\r" in remote_home:
            raise RuntimeError("remote account returned an invalid home directory")
        remote_stage = f"{remote_home}/.jingshield-deploy-{uuid.uuid4().hex}"
        remote_archive = f"{remote_stage}/{package.name}"
        remote_extract = f"{remote_stage}/unpacked"
        remote_secrets = f"{remote_stage}/deployment.values"
        run(f"mkdir -m 700 -- {shlex.quote(remote_stage)} {shlex.quote(remote_extract)}")

        with client.open_sftp() as sftp:
            sftp.put(str(package), remote_archive)

        remote_digest = run(f"sha256sum -- {shlex.quote(remote_archive)}").split()[0].lower()
        if remote_digest != local_digest:
            raise RuntimeError("uploaded package SHA-256 does not match the local archive")
        run(f"tar -xzf {shlex.quote(remote_archive)} -C {shlex.quote(remote_extract)}")

        remote_root = f"{remote_extract}/{package_root}"
        if args.action == "install":
            values: list[str] = []
            for key in SECRET_KEYS:
                value = os.environ.get(key)
                if value is None:
                    continue
                if "\n" in value or "\r" in value:
                    raise SystemExit(f"{key} must not contain a newline")
                values.append(f"{key}={value}\n")
            if values:
                with client.open_sftp() as sftp:
                    with sftp.file(remote_secrets, "w") as target:
                        target.write("".join(values))
                    sftp.chmod(remote_secrets, 0o600)

            install_args = ["bash", "./run.sh", "--admin-user", args.admin_user]
            if args.admin_email:
                install_args.extend(("--admin-email", args.admin_email))
            install_args.extend(("--db-admin-user", args.db_admin_user))
            if values:
                install_args.extend(("--secrets-file", remote_secrets, "--consume-secrets"))
            if args.skip_db_provision:
                install_args.append("--skip-db-provision")
            if args.force_config:
                install_args.append("--force-config")
            if args.no_start:
                install_args.append("--no-start")
            command = (
                "cd "
                + shlex.quote(remote_root)
                + " && env JINGSHIELD_INSTALL_ROOT="
                + shlex.quote(args.install_root)
                + " "
                + shlex.join(install_args)
            )
        else:
            command = (
                "cd "
                + shlex.quote(remote_root)
                + " && env JINGSHIELD_INSTALL_ROOT="
                + shlex.quote(args.install_root)
                + " bash ./upgrade.sh"
            )

        output = run(command, sudo=True)
        print(f"package_sha256={local_digest}")
        print(output.rstrip())
    finally:
        if remote_stage:
            try:
                run(f"rm -rf -- {shlex.quote(remote_stage)}")
            except Exception:
                pass
        client.close()


if __name__ == "__main__":
    main()
