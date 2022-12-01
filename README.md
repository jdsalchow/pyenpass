# pyenpass

Simple python tool to read enpass vaults. Assumes that the master password is stored in the osx keychain with service
`pyenpass` and account 'vault name'.

```
enpass-cli -h
usage: enpass_cli [-h] [-n] [--vault_directory VAULT_DIRECTORY] [--vault_name VAULT_NAME] item_name [field_name]

Read-only command line interface to enpass vaults

positional arguments:
  item_name
  field_name

optional arguments:
  -h, --help            show this help message and exit
  -n                    Do not print the trailing newline character. (default: None)
  --vault_directory VAULT_DIRECTORY
                        directory in which to look for enpass vaults (default: ~/.enpass/Enpass/Vaults)
  --vault_name VAULT_NAME
                        name of the vault, absolute or relative to vault directory (default: primary)
```