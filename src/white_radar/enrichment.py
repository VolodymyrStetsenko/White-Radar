from __future__ import annotations

import os
from typing import Any

from white_radar.config import EnrichmentConfig
from white_radar.http import HttpError, request_json
from white_radar.models import ContractMetadata
from white_radar.rpc import JsonRpcClient

EIP1967_SLOTS = {
    "implementation": "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc",
    "admin": "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103",
    "beacon": "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50",
}


def storage_word_to_address(value: str | None) -> str | None:
    if not value or not value.startswith("0x"):
        return None
    raw = value[2:].rjust(64, "0")
    if int(raw, 16) == 0:
        return None
    return "0x" + raw[-40:].lower()


class ContractEnricher:
    def __init__(
        self,
        config: EnrichmentConfig,
        *,
        timeout: int,
        retries: int,
    ) -> None:
        self._config = config
        self._timeout = timeout
        self._retries = retries

    def enrich(
        self,
        rpc: JsonRpcClient,
        *,
        chain_id: int,
        address: str,
    ) -> ContractMetadata:
        proxy = self._proxy_metadata(rpc, address)
        verified = False
        source: str | None = None
        name: str | None = None

        if self._config.sourcify_enabled:
            verified, name = self._sourcify(chain_id, address)
            if verified:
                source = "Sourcify"
        if not verified and self._config.etherscan_enabled:
            verified, name, explorer_proxy, explorer_implementation = self._etherscan(
                chain_id, address
            )
            if verified:
                source = "Etherscan"
            if explorer_proxy and not proxy["implementation"]:
                proxy["implementation"] = explorer_implementation

        return ContractMetadata(
            verified=verified,
            verification_source=source,
            contract_name=name,
            is_proxy=bool(proxy["implementation"] or proxy["beacon"]),
            implementation=proxy["implementation"],
            admin=proxy["admin"],
            beacon=proxy["beacon"],
        )

    def _proxy_metadata(self, rpc: JsonRpcClient, address: str) -> dict[str, str | None]:
        result: dict[str, str | None] = {}
        for name, slot in EIP1967_SLOTS.items():
            try:
                result[name] = storage_word_to_address(rpc.storage_at(address, slot))
            except Exception:
                result[name] = None
        return result

    def _sourcify(self, chain_id: int, address: str) -> tuple[bool, str | None]:
        url = f"https://sourcify.dev/server/v2/contract/{chain_id}/{address}?fields=all"
        try:
            data = request_json(
                "GET",
                url,
                timeout=self._timeout,
                retries=1,
                allow_not_found=True,
            )
        except HttpError:
            return False, None
        if not isinstance(data, dict):
            return False, None
        name = data.get("compilation", {}).get("name")
        if not name:
            name = data.get("contractName") or data.get("name")
        return True, str(name) if name else None

    def _etherscan(self, chain_id: int, address: str) -> tuple[bool, str | None, bool, str | None]:
        key = os.getenv("ETHERSCAN_API_KEY", "").strip()
        if not key:
            return False, None, False, None
        try:
            data = request_json(
                "GET",
                "https://api.etherscan.io/v2/api",
                timeout=self._timeout,
                retries=self._retries,
                params={
                    "chainid": chain_id,
                    "module": "contract",
                    "action": "getsourcecode",
                    "address": address,
                    "apikey": key,
                },
            )
        except HttpError:
            return False, None, False, None
        if not isinstance(data, dict) or not isinstance(data.get("result"), list):
            return False, None, False, None
        records: list[Any] = data["result"]
        if not records or not isinstance(records[0], dict):
            return False, None, False, None
        record = records[0]
        source = str(record.get("SourceCode") or "")
        verified = bool(source and record.get("ABI") != "Contract source code not verified")
        name = str(record.get("ContractName") or "") or None
        is_proxy = str(record.get("Proxy") or "0") == "1"
        implementation = str(record.get("Implementation") or "").lower() or None
        return verified, name, is_proxy, implementation
