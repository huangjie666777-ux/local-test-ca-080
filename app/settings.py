import os
from dataclasses import dataclass


CA_KEY_NAME = "ca.key.pem"
CA_CERT_NAME = "ca.cert.pem"
DB_NAME = "ca.sqlite3"
CRL_NAME = "crl.pem"


@dataclass(frozen=True)
class Settings:
    data_dir: str

    @property
    def ca_key_path(self) -> str:
        return os.path.join(self.data_dir, CA_KEY_NAME)

    @property
    def ca_cert_path(self) -> str:
        return os.path.join(self.data_dir, CA_CERT_NAME)

    @property
    def db_path(self) -> str:
        return os.path.join(self.data_dir, DB_NAME)

    @property
    def crl_path(self) -> str:
        return os.path.join(self.data_dir, CRL_NAME)


def get_settings() -> Settings:
    return Settings(os.environ.get("CA_DATA_DIR", os.path.join(os.getcwd(), "data")))
