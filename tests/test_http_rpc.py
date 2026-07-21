from __future__ import annotations

import io
import unittest
import urllib.error
from unittest.mock import patch

from white_radar.http import HttpError, redact_url, request_json
from white_radar.rpc import JsonRpcClient, RpcError, hex_to_int, int_to_hex


class FakeResponse:
    def __init__(self, body: bytes) -> None:
        self.body = body

    def __enter__(self) -> FakeResponse:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def read(self) -> bytes:
        return self.body


class HttpTests(unittest.TestCase):
    def test_redacts_provider_and_telegram_credentials(self) -> None:
        self.assertEqual(
            redact_url("https://eth.example/v2/secret-key?x=1"),
            "https://eth.example/v2/<redacted>",
        )
        self.assertNotIn(
            "123:secret",
            redact_url("https://api.telegram.org/bot123:secret/sendMessage"),
        )

    def test_json_request_success_and_retry(self) -> None:
        with patch(
            "urllib.request.urlopen",
            side_effect=[urllib.error.URLError("temporary"), FakeResponse(b'{"ok":true}')],
        ):
            result = request_json(
                "POST",
                "https://example.invalid/api",
                timeout=1,
                retries=2,
                params={"chainid": 1},
                payload={"hello": "world"},
            )
        self.assertEqual(result, {"ok": True})

    def test_allowed_not_found(self) -> None:
        error = urllib.error.HTTPError(
            "https://example.invalid",
            404,
            "not found",
            {},
            io.BytesIO(),
        )
        with patch("urllib.request.urlopen", side_effect=error):
            self.assertIsNone(
                request_json(
                    "GET",
                    "https://example.invalid",
                    timeout=1,
                    retries=1,
                    allow_not_found=True,
                )
            )

    def test_raises_sanitized_error(self) -> None:
        with (
            patch("urllib.request.urlopen", side_effect=urllib.error.URLError("offline")),
            self.assertRaises(HttpError) as raised,
        ):
            request_json(
                "GET",
                "https://example.invalid/v2/private-key",
                timeout=1,
                retries=1,
            )
        self.assertNotIn("private-key", str(raised.exception))


class RpcResponseTests(unittest.TestCase):
    def test_convenience_methods_parse_responses(self) -> None:
        responses = {
            "eth_chainId": "0x1",
            "eth_blockNumber": "0xa",
            "eth_getBlockByNumber": {"number": "0xa"},
            "eth_getTransactionByHash": {"hash": "0xabc"},
            "eth_getTransactionReceipt": {"status": "0x1"},
            "eth_getCode": "0x6000",
            "eth_getStorageAt": "0x00",
            "eth_getLogs": [{"address": "0x1"}],
            "eth_call": "0x01",
            "debug_traceCall": {"type": "CALL"},
        }

        def fake_request(_method: str, _url: str, **kwargs: object) -> object:
            payload = kwargs["payload"]
            assert isinstance(payload, dict)
            method = payload["method"]
            assert isinstance(method, str)
            return {"jsonrpc": "2.0", "id": payload["id"], "result": responses[method]}

        rpc = JsonRpcClient("https://example.invalid")
        with patch("white_radar.rpc.request_json", side_effect=fake_request):
            self.assertEqual(rpc.chain_id(), 1)
            self.assertEqual(rpc.block_number(), 10)
            self.assertEqual(rpc.block(10), {"number": "0xa"})
            self.assertEqual(rpc.transaction("0xabc"), {"hash": "0xabc"})
            self.assertEqual(rpc.receipt("0xabc"), {"status": "0x1"})
            self.assertEqual(rpc.code("0x1"), "0x6000")
            self.assertEqual(rpc.storage_at("0x1", "0x0"), "0x00")
            self.assertEqual(len(rpc.logs(from_block=1, to_block=2, topics=[])), 1)
            self.assertEqual(rpc.eth_call({"to": "0x1"}, "0xa"), "0x01")
            self.assertEqual(rpc.trace_call({"to": "0x1"}, "0xa"), {"type": "CALL"})

    def test_fails_over_between_read_only_http_endpoints(self) -> None:
        calls: list[str] = []

        def fake_request(_method: str, url: str, **kwargs: object) -> object:
            calls.append(url)
            if len(calls) == 1:
                raise HttpError("temporary transport failure")
            payload = kwargs["payload"]
            assert isinstance(payload, dict)
            return {"jsonrpc": "2.0", "id": payload["id"], "result": "0x1"}

        rpc = JsonRpcClient(("https://primary.invalid", "https://secondary.invalid"))
        with patch("white_radar.rpc.request_json", side_effect=fake_request):
            self.assertEqual(rpc.chain_id(), 1)
        self.assertEqual(calls, ["https://primary.invalid", "https://secondary.invalid"])
        self.assertEqual(rpc.active_endpoint_index, 1)
        self.assertEqual(rpc.endpoint_count, 2)

    def test_rejects_bad_url_and_rpc_errors(self) -> None:
        with self.assertRaises(RpcError):
            JsonRpcClient("wss://example.invalid")
        rpc = JsonRpcClient("https://example.invalid")
        with (
            patch(
                "white_radar.rpc.request_json",
                return_value={"error": {"code": -32000, "message": "failure"}},
            ),
            self.assertRaises(RpcError),
        ):
            rpc.chain_id()
        with (
            patch("white_radar.rpc.request_json", return_value=[]),
            self.assertRaises(RpcError),
        ):
            rpc.chain_id()

    def test_hex_helpers(self) -> None:
        self.assertEqual(hex_to_int(None), 0)
        self.assertEqual(hex_to_int("0xff"), 255)
        self.assertEqual(int_to_hex(255), "0xff")


if __name__ == "__main__":
    unittest.main()
