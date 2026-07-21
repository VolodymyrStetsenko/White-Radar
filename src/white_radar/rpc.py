from __future__ import annotations

import itertools
import threading
from typing import Any

from white_radar.http import request_json

READ_ONLY_RPC_METHODS = frozenset(
    {
        "eth_blockNumber",
        "eth_call",
        "eth_chainId",
        "eth_getBlockByNumber",
        "eth_getCode",
        "eth_getLogs",
        "eth_getStorageAt",
        "eth_getTransactionByHash",
        "eth_getTransactionReceipt",
        "debug_traceTransaction",
    }
)


class RpcError(RuntimeError):
    """A JSON-RPC endpoint returned an error."""


class ReadOnlyViolation(RpcError):
    """A caller attempted to use a state-changing or unapproved RPC method."""


def hex_to_int(value: str | None) -> int:
    return int(value or "0x0", 16)


def int_to_hex(value: int) -> str:
    return hex(value)


class JsonRpcClient:
    """Minimal EVM JSON-RPC client that cannot broadcast transactions."""

    def __init__(self, url: str, *, timeout: int = 20, retries: int = 3) -> None:
        if not url.startswith(("http://", "https://")):
            raise RpcError("RPC URL must use http:// or https://")
        self._url = url
        self._timeout = timeout
        self._retries = retries
        self._counter = itertools.count(1)
        self._lock = threading.Lock()

    def call(self, method: str, params: list[object]) -> Any:
        if method not in READ_ONLY_RPC_METHODS:
            raise ReadOnlyViolation(f"RPC method is not permitted in read-only mode: {method}")
        with self._lock:
            request_id = next(self._counter)
        response = request_json(
            "POST",
            self._url,
            timeout=self._timeout,
            retries=self._retries,
            payload={"jsonrpc": "2.0", "id": request_id, "method": method, "params": params},
        )
        if not isinstance(response, dict):
            raise RpcError(f"Malformed JSON-RPC response for {method}")
        if response.get("error"):
            error = response["error"]
            if isinstance(error, dict):
                code = error.get("code", "unknown")
                message = error.get("message", "RPC error")
                raise RpcError(f"{method} failed ({code}): {message}")
            raise RpcError(f"{method} failed: {error}")
        return response.get("result")

    def chain_id(self) -> int:
        return hex_to_int(self.call("eth_chainId", []))

    def block_number(self) -> int:
        return hex_to_int(self.call("eth_blockNumber", []))

    def block(self, number: int, *, full_transactions: bool = True) -> dict[str, Any] | None:
        result = self.call("eth_getBlockByNumber", [int_to_hex(number), full_transactions])
        return result if isinstance(result, dict) else None

    def transaction(self, tx_hash: str) -> dict[str, Any] | None:
        result = self.call("eth_getTransactionByHash", [tx_hash])
        return result if isinstance(result, dict) else None

    def receipt(self, tx_hash: str) -> dict[str, Any] | None:
        result = self.call("eth_getTransactionReceipt", [tx_hash])
        return result if isinstance(result, dict) else None

    def code(self, address: str, block: str = "latest") -> str:
        result = self.call("eth_getCode", [address, block])
        return str(result or "0x")

    def storage_at(self, address: str, slot: str, block: str = "latest") -> str:
        result = self.call("eth_getStorageAt", [address, slot, block])
        return str(result or "0x")

    def logs(
        self,
        *,
        from_block: int,
        to_block: int,
        topics: list[object],
        addresses: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        log_filter: dict[str, object] = {
            "fromBlock": int_to_hex(from_block),
            "toBlock": int_to_hex(to_block),
            "topics": topics,
        }
        if addresses:
            log_filter["address"] = addresses
        result = self.call("eth_getLogs", [log_filter])
        return [item for item in (result or []) if isinstance(item, dict)]

    def trace_transaction(self, tx_hash: str) -> dict[str, Any] | None:
        result = self.call(
            "debug_traceTransaction",
            [
                tx_hash,
                {
                    "tracer": "callTracer",
                    "tracerConfig": {"onlyTopCall": False, "withLog": False},
                },
            ],
        )
        return result if isinstance(result, dict) else None
