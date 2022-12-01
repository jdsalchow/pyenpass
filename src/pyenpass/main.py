#!/usr/bin/env python3
import subprocess
import argparse
from . import enpass
from pathlib import Path


def password_from_osx_keychain(account: str, service: str = "pyenpass"):
    return subprocess.run(["/usr/bin/security", "find-generic-password", "-s", service, "-a", account, "-w"],
                          capture_output=True, text=True).stdout[:-1]


def run():
    parser = argparse.ArgumentParser(
        prog="enpass_cli",
        description='Read-only command line interface to enpass vaults',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    parser.add_argument("-n", help='Do not print the trailing newline character.',
                        action=argparse.BooleanOptionalAction)

    parser.add_argument("--vault_directory",
                        help="directory in which to look for enpass vaults",
                        default=Path.home().joinpath(".enpass/Enpass/Vaults").as_posix(), type=str)
    parser.add_argument("--vault_name",
                        help="name of the vault, absolute or relative to vault directory", default="primary", type=str)

    parser.add_argument("item_name", type=str)
    parser.add_argument("field_name", type=str, nargs='?')

    args = parser.parse_args()

    vault = enpass.Vault(args.vault_name if Path(args.vault_name).is_absolute()
                         else Path(args.vault_directory).joinpath(args.vault_name),
                         password_from_osx_keychain(account=args.vault_name))

    if args.field_name is None:
        items = vault.retrieve_fields(args.item_name).items()
        max_length = max(map(lambda item: len(item[0]), items))
        for field_name, value in items:
            print(f"{field_name.ljust(max_length)} | {value}")
    else:
        print(vault.retrieve_field(args.item_name, args.field_name), end='' if args.n else '\n')
