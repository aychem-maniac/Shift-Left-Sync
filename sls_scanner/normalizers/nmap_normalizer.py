# sls_scanner/normalizers/nmap_normalizer.py

def normalize_nmap_result(raw_nmap_result: dict) -> list[dict]:
    print("[INFO] Nmap normalization started")
    port_results = []
    try:
        raw_result = raw_nmap_result.get("raw_result", {})
        for host, host_data in raw_result.items():
            for protocol, ports in host_data.items():
                for port, port_data in ports.items():
                    port_results.append({
                        "host": host,
                        "port": int(port),
                        "protocol": protocol,
                        "service": port_data.get("name", ""),
                        "state": port_data.get("state", ""),
                        "product": port_data.get("product", ""),
                        "version": port_data.get("version", "")
                    })
        print(f"[INFO] Nmap normalization completed: {len(port_results)} ports found")
        return port_results

    except Exception as e:
        print(f"[ERROR] Nmap normalization failed: {e}")
        return []