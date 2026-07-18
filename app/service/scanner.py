from __future__ import annotations

import asyncio
import json
import logging
import socket
import subprocess
import tempfile
from pathlib import Path

import asyncpg

logger = logging.getLogger(__name__)


async def process_scan(db: asyncpg.Pool, payload: dict, rate: int, ports: str) -> None:
    scan_id = payload.get("scan_id")
    tenant_id = payload.get("tenant_id")
    target = payload.get("target")

    if not target or not tenant_id:
        logger.warning("missing target or tenant_id in payload")
        return

    resolved = await _resolve_target(target)
    if not resolved:
        logger.warning("could not resolve target %s", target)
        if scan_id:
            await _finish(db, scan_id, 0, 0)
        return

    logger.info("masscan target=%s resolved=%s ports=%s rate=%d", target, resolved, ports, rate)
    results = await asyncio.get_event_loop().run_in_executor(
        None, _run_masscan, resolved, ports, rate
    )
    logger.info("masscan returned %d open ports for %s", len(results), target)

    by_ip: dict[str, list[dict]] = {}
    for r in results:
        by_ip.setdefault(r["ip"], []).append(r)

    assets_count = 0
    ports_count = 0
    for ip, open_ports in by_ip.items():
        asset_id = await _upsert_asset(db, tenant_id, ip, target)
        if not asset_id:
            continue
        assets_count += 1
        for p in open_ports:
            if await _upsert_port(db, asset_id, p["port"], p.get("proto", "tcp")):
                ports_count += 1

    logger.info("target %s: %d assets, %d open ports stored", target, assets_count, ports_count)

    if scan_id:
        await db.execute(
            "UPDATE scan_jobs SET assets_found = $1, ports_found = $2 WHERE id = $3",
            assets_count,
            ports_count,
            scan_id,
        )


async def _resolve_target(target: str) -> str | None:
    try:
        socket.inet_aton(target)
        return target
    except OSError:
        pass
    if "/" in target:
        return target
    try:
        loop = asyncio.get_event_loop()
        info = await loop.run_in_executor(None, socket.getaddrinfo, target, None, socket.AF_INET)
        return info[0][4][0] if info else None
    except Exception:
        return None


def _run_masscan(target: str, ports: str, rate: int) -> list[dict]:
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        out_path = f.name
    try:
        subprocess.run(
            [
                "masscan",
                target,
                f"-p{ports}",
                f"--rate={rate}",
                "--output-format", "json",
                "-oJ", out_path,
            ],
            capture_output=True,
            timeout=600,
            check=False,
        )
        raw = Path(out_path).read_text().strip()
        if not raw or raw in ("[]", ""):
            return []
        data = json.loads(raw)
        results = []
        for entry in data:
            ip = entry.get("ip")
            for port_info in entry.get("ports", []):
                results.append({
                    "ip": ip,
                    "port": port_info.get("port"),
                    "proto": port_info.get("proto", "tcp"),
                })
        return results
    except Exception as exc:
        logger.error("masscan failed: %s", exc)
        return []
    finally:
        Path(out_path).unlink(missing_ok=True)


async def _upsert_asset(db: asyncpg.Pool, tenant_id: str, ip: str, hostname: str) -> str | None:
    try:
        row = await db.fetchrow(
            """
            INSERT INTO assets (tenant_id, ip, hostname, asset_type)
            VALUES ($1, $2::inet, $3, 'ip')
            ON CONFLICT (tenant_id, ip) DO UPDATE
                SET hostname = EXCLUDED.hostname, last_seen = NOW(), updated_at = NOW()
            RETURNING id
            """,
            tenant_id,
            ip,
            hostname,
        )
        return str(row["id"]) if row else None
    except Exception as exc:
        logger.warning("asset upsert failed %s: %s", ip, exc)
        return None


async def _upsert_port(db: asyncpg.Pool, asset_id: str, port: int, proto: str) -> bool:
    try:
        await db.execute(
            """
            INSERT INTO ports (asset_id, port, protocol, state)
            VALUES ($1, $2, $3, 'open')
            ON CONFLICT (asset_id, port, protocol) DO UPDATE
                SET state = 'open', last_seen = NOW()
            """,
            asset_id,
            port,
            proto,
        )
        return True
    except Exception as exc:
        logger.warning("port upsert failed %s:%d: %s", asset_id, port, exc)
        return False


async def _finish(db: asyncpg.Pool, scan_id: str, assets: int, ports: int) -> None:
    await db.execute(
        "UPDATE scan_jobs SET assets_found = $1, ports_found = $2 WHERE id = $3",
        assets,
        ports,
        scan_id,
    )
