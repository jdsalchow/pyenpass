from pysqlcipher3 import dbapi2 as sqlite
from Crypto.Cipher import AES
import hashlib
from pathlib import Path
import os
import json


class Vault:
    def __init__(self, vaults_dir: str, vault_name: str, master_password: str):
        def vault_json(vault_dir):
            with open(os.path.join(vault_dir, "vault.json"), 'r') as vaultJson:
                return json.load(vaultJson)

        vaults = {os.path.join(vaults_dir, name): vault_json(os.path.join(vaults_dir, name))
                  for name in os.listdir(vaults_dir)
                  if os.path.isdir(os.path.join(vaults_dir, name))
                  and os.path.isfile(os.path.join(vaults_dir, name, "vault.json"))}

        vault_dir = [directory for directory, metadata in vaults.items() if metadata.get('vault_name') == vault_name][0]

        self.vault_file = Path(vault_dir).joinpath("vault.enpassdb").as_posix()
        self.hash_name = 'sha512'
        self.salt = open(self.vault_file, 'rb').read(16)
        self.pbkdf2_rounds = 100_000
        self.key = self.__database_key__(master_password)

    def __database_key__(self, master_password: str):
        return hashlib.pbkdf2_hmac(self.hash_name, str.encode(master_password),
                                   self.salt,
                                   self.pbkdf2_rounds).hex()[:64]

    def __connection__(self):
        db = sqlite.connect(self.vault_file)

        cursor = db.cursor()
        cursor.row_factory = sqlite.Row
        cursor.execute(f"PRAGMA key=\"x'{self.key}'\";")
        cursor.execute("PRAGMA cipher_compatibility = 3;")
        cursor.row_factory = sqlite.Row

        return db, cursor

    @staticmethod
    def name(row):
        return row['type'] if row['label'] == '' else f"{row['label']} ({row['type']})"

    def retrieve_items(self):
        db, cursor = self.__connection__()
        with db:
            result = cursor.execute("""select title from item""")
            return [row['title'] for row in result.fetchall()]

    def retrieve_fields(self, item_name: str):
        db, cursor = self.__connection__()
        with db:
            result = cursor.execute(
                """select * from item, itemfield
                            where item.uuid = itemfield.item_uuid and item.title = ? and itemfield.deleted = 0""",
                [item_name])
            return {self.name(row): (row['value'] if row['type'] != 'password'
                                     else decrypt_password(row['value'], row['key'], row['uuid']))
                    for row in result.fetchall()}

    def retrieve_field(self, item_name: str, field_name: str):
        db, cursor = self.__connection__()
        with db:
            result = cursor.execute(
                f"""select * from item, itemfield
                        where item.uuid = itemfield.item_uuid 
                            and item.title = ?
                            and ? in (itemfield.type, itemfield.label)
                            and itemfield.deleted = 0                
                            """,
                (item_name, field_name))

            row = result.fetchone()
            return (row['value'] if row['type'] != 'password'
                    else decrypt_password(row['value'], row['key'], row['uuid']))


def decrypt_password(value_tag: str, key_nonce: bytearray, uuid: str):
    key = key_nonce[:32]
    nonce = key_nonce[32:]

    value = bytearray.fromhex(value_tag[:-32])

    header = uuid.replace('-', '')

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(bytearray.fromhex(header))
    return cipher.decrypt(value).decode('utf-8')
