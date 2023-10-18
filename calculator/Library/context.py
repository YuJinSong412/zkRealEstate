from __future__ import annotations
from Library.cli_constants import CLIENT_CONFIG_FILE
from Library.constants import CLIENT_PATH
from typing import Optional, Dict, Any
import json


class ClientConfig:
    """
    Context for users of these client tools
    """

    def __init__(
            self,
            env: Optional[str],
            instance_file: str,
            token_instance_file: str,
            address_file: str,
            audit_address_file: str,
            wallet_dir: str,
            depth: str,
            hash: str,
            zksnark: str,
            ec: str):
        self.env = env
        self.instance_file = instance_file
        self.token_instance_file = token_instance_file
        self.address_file = address_file
        self.audit_address_file = audit_address_file
        self.wallet_dir = wallet_dir
        self.depth = depth
        self.hash = hash
        self.zksnark = zksnark
        self.ec = ec

    def to_json(self) -> str:
        return json.dumps(self._to_json_dict())

    def _to_json_dict(self) -> Dict[str, Any]:
        return {
            "env": self.env,
            "instance_file": self.instance_file,
            "token_instance_file": self.token_instance_file,
            "address_file": self.address_file,
            "audit_address_file": self.audit_address_file,
            "wallet_dir": self.wallet_dir,
            "depth": self.depth,
            "hash": self.hash,
            "zksnark": self.zksnark,
            "ec": self.ec
        }

    def show(self) -> None:
        client_config_dict = self._to_json_dict()

        print(f"CLIENT CONFIGURATION: ")
        print('   --{0: <20}    {1}'.format('env', client_config_dict["env"]))
        print('   --{0: <20}    {1}'.format('instance_file', client_config_dict["instance_file"]))
        print('   --{0: <20}    {1}'.format('token_instance_file', client_config_dict["token_instance_file"]))
        print('   --{0: <20}    {1}'.format('address_file', client_config_dict["address_file"]))
        print('   --{0: <20}    {1}'.format('audit_address_file', client_config_dict["audit_address_file"]))
        print('   --{0: <20}    {1}'.format('wallet_dir', client_config_dict["wallet_dir"]))
        print('   --{0: <20}    {1}'.format('depth', client_config_dict["depth"]))
        print('   --{0: <20}    {1}'.format('hash', client_config_dict["hash"]))
        print('   --{0: <20}    {1}'.format('zksnark', client_config_dict["zksnark"]))
        print('   --{0: <20}    {1}\n'.format('ec', client_config_dict["ec"]))

        print(' {0: <20}    {1}'.format('Config file path: ', CLIENT_PATH))
        print(' {0: <20}    {1}'.format('Config file name: ', CLIENT_CONFIG_FILE))

    @staticmethod
    def from_json(client_config_json: str) -> ClientConfig:
        return ClientConfig._from_json_dict(json.loads(client_config_json))

    @staticmethod
    def _from_json_dict(client_config_dict: Dict[str, Any]) -> ClientConfig:
        return ClientConfig(
            env=client_config_dict["env"],
            instance_file=client_config_dict["instance_file"],
            token_instance_file=client_config_dict["token_instance_file"],
            address_file=client_config_dict["address_file"],
            audit_address_file=client_config_dict["audit_address_file"],
            wallet_dir=client_config_dict["wallet_dir"],
            depth=client_config_dict["depth"],
            hash=client_config_dict["hash"],
            zksnark=client_config_dict["zksnark"],
            ec=client_config_dict["ec"]
        )


class NetworkConfig:
    """
    Simple description of a network. Name (may be used in some cases to
    understand the type of network) and endpoint URL.
    """

    def __init__(
            self,
            name: str,
            endpoint: str,
            certificate: Optional[str] = None,
            insecure: bool = False):
        self.name = name
        self.endpoint = endpoint
        self.certificate = certificate
        self.insecure = insecure

    def to_json(self) -> str:
        json_dict: Dict[str, Any] = {
            "name": self.name,
            "endpoint": self.endpoint,
        }
        if self.certificate:
            json_dict["certificate"] = self.certificate
        if self.insecure:
            json_dict["insecure"] = self.insecure
        return json.dumps(json_dict)

    @staticmethod
    def from_json(network_config_json: str) -> NetworkConfig:
        json_dict = json.loads(network_config_json)
        return NetworkConfig(
            name=json_dict["name"],
            endpoint=json_dict["endpoint"],
            certificate=json_dict.get("certificate", None),
            insecure=json_dict.get("insecure", None))
