import asyncio
import datetime
import ipaddress
import json
import pathlib
import socket
import ssl
import time
import urllib.request

CF_CIDRS = [
    "104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13", "162.158.0.0/15",
    "198.41.128.0/17", "197.234.240.0/22", "188.114.96.0/20", "190.93.240.0/20",
    "108.162.192.0/18", "141.101.64.0/18", "103.21.244.0/22", "103.22.200.0/22",
    "103.31.4.0/22", "173.245.48.0/20"
]
CF_NETS = [ipaddress.ip_network(c) for c in CF_CIDRS]

def is_non_cf_ipv4(ip_str: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip_str.strip())
        if ip_obj.version != 4 or ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved:
            return False
        return not any(ip_obj in net for net in CF_NETS)
    except ValueError:
        return False

def collect_candidates() -> list[str]:
    raw_items = set()
    cand_file = pathlib.Path("candidates.txt")
    if cand_file.exists():
        for line in cand_file.read_text(encoding="utf-8").splitlines():
            clean = line.strip().split(":")[0]
            if clean and not clean.startswith("#"):
                raw_items.add(clean)

    src_file = pathlib.Path("sources.txt")
    if src_file.exists():
        for url in src_file.read_text(encoding="utf-8").splitlines():
            url = url.strip()
            if not url or url.startswith("#"):
                continue
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
                with urllib.request.urlopen(req, timeout=8) as resp:
                    text = resp.read().decode("utf-8", errors="ignore")
                    for line in text.splitlines():
                        clean = line.strip().split(":")[0].split("#")[0].strip()
                        if clean:
                            raw_items.add(clean)
            except Exception:
                pass

    resolved_ips = set()
    for item in raw_items:
        if is_non_cf_ipv4(item):
            resolved_ips.add(item)
            continue
        try:
            infos = socket.getaddrinfo(item, 443, family=socket.AF_INET, type=socket.SOCK_STREAM)
            for info in infos:
                ip = info[4][0]
                if is_non_cf_ipv4(ip):
                    resolved_ips.add(ip)
        except Exception:
            pass

    return sorted(resolved_ips)[:450]

async def verify_hub(ip: str, sem: asyncio.Semaphore, ssl_ctx: ssl.SSLContext):
    async with sem:
        t0 = time.perf_counter()
        writer = None
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, 443, ssl=ssl_ctx, server_hostname="speed.cloudflare.com"),
                timeout=2.5
            )
            payload = (
                b"GET /cdn-cgi/trace HTTP/1.1\r\n"
                b"Host: speed.cloudflare.com\r\n"
                b"User-Agent: Mozilla/5.0\r\n"
                b"Connection: close\r\n\r\n"
            )
            writer.write(payload)
            await asyncio.wait_for(writer.drain(), timeout=1.5)
            data = await asyncio.wait_for(reader.read(2048), timeout=2.0)
            text = data.decode("utf-8", errors="ignore")
            if "200 OK" in text and "colo=" in text:
                rtt_ms = int((time.perf_counter() - t0) * 1000)
                colo = "UNK"
                for line in text.splitlines():
                    if line.startswith("colo="):
                        colo = line.split("=", 1)[1].strip()
                        break
                return {"ip": ip, "rtt_ms": rtt_ms, "colo": colo}
        except Exception:
            pass
        finally:
            if writer is not None:
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass
        return None

async def main():
    candidates = collect_candidates()
    sem = asyncio.Semaphore(40)
    ssl_ctx = ssl.create_default_context()
    results = await asyncio.gather(*(verify_hub(ip, sem, ssl_ctx) for ip in candidates))
    healthy = [r for r in results if r is not None]
    healthy.sort(key=lambda x: x["rtt_ms"])
    top_hubs = healthy[:15]

    output = {
        "updated_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "checked_candidates": len(candidates),
        "count": len(top_hubs),
        "hubs": top_hubs
    }
    pathlib.Path("hubs.json").write_text(json.dumps(output, indent=2), encoding="utf-8")
    print(f"Verified {len(top_hubs)} healthy non-CF hubs out of {len(candidates)} candidates.")

if __name__ == "__main__":
    asyncio.run(main())
