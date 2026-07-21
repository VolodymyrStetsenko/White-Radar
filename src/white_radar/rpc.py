from __future__ import annotations

import itertools
import threading
from typing import Any

from white_radar.http import HttpError, request_json

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
        "debug_traceCall",
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
    """Minimal EVM JSON-RPC client with transport failover and no broadcast methods."""

    def __init__(self, url: str | tuple[str, ...], *, timeout: int = 20, retries: int = 3) -> None:
        urls = (url,) if isinstance(url, str) else tuple(url)
        if not urls:
            raise RpcError("At least one RPC URL is required")
        if any(not item.startswith(("http://", "https://")) for item in urls):
            raise RpcError("RPC URLs must use http:// or https://")
        if len(set(urls)) != len(urls):
            raise RpcError("Duplicate RPC URLs are not permitted")
        self._urls = urls
        self._timeout = timeout
        self._retries = retries
        self._counter = itertools.count(1)
        self._lock = threading.Lock()
        self._active_endpoint = 0

    @property
    def endpoint_count(self) -> int:
        return len(self._urls)

    @property
    def active_endpoint_index(self) -> int:
        return self._active_endpoint

    def call(self, method: str, params: list[object]) -> Any:
        if method not in READ_ONLY_RPC_METHODS:
            raise ReadOnlyViolation(f"RPC method is not permitted in read-only mode: {method}")
        with self._lock:
            request_id = next(self._counter)
        request_payload = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
            "params": params,
        }
        last_transport_error: Exception | None = None
        for offset in range(len(self._urls)):
            endpoint_index = (self._active_endpoint + offset) % len(self._urls)
            try:
                response = request_json(
                    "POST",
                    self._urls[endpoint_index],
                    timeout=self._timeout,
                    retries=self._retries,
                    payload=request_payload,
                )
            except HttpError as exc:
                last_transport_error = exc
                continue
            if not isinstance(response, dict):
                last_transport_error = RpcError(f"Malformed JSON-RPC response for {method}")
                continue
            if response.get("error"):
                error = response["error"]
                if isinstance(error, dict):
                    code = error.get("code", "unknown")
                    message = error.get("message", "RPC error")
                    if code == -32601 and offset + 1 < len(self._urls):
                        continue
                    raise RpcError(f"{method} failed ({code}): {message}")
                raise RpcError(f"{method} failed: {error}")
            self._active_endpoint = endpoint_index
            return response.get("result")
        detail = type(last_transport_error).__name__ if last_transport_error else "unknown"
        raise RpcError(
            f"All {len(self._urls)} RPC endpoint(s) failed for {method}; last error: {detail}"
        )

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

    def eth_call(self, transaction: dict[str, object], block: str = "latest") -> str:
        result = self.call("eth_call", [transaction, block])
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

    def trace_call(
        self,
        transaction: dict[str, object],
        block: str,
    ) -> dict[str, Any] | None:
        result = self.call(
            "debug_traceCall",
            [
                transaction,
                block,
                {
                    "tracer": "callTracer",
                    "timeout": "5s",
                    "tracerConfig": {"onlyTopCall": False, "withLog": False},
                },
            ],
        )
        return result if isinstance(result, dict) else None
