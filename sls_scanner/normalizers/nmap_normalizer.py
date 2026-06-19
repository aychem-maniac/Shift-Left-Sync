# sls_scanner/normalizers/nmap_normalizer.py

# Nmap 원본 결과를 리포트/후속 처리에서 쓰기 쉬운 포트 목록 형태로 변환한다.
def normalize_nmap_result(raw_nmap_result: dict) -> list[dict]:
    print("[INFO] Nmap normalization started")
    port_results = []
    try:
        # 입력은 raw_result -> host -> protocol -> port 구조를 전제로 한다.
        raw_result = raw_nmap_result.get("raw_result", {})
        # 호스트별 TCP/UDP 포트 정보를 순회하며 서비스 식별 정보를 꺼낸다.
        for host, host_data in raw_result.items():
            for protocol, ports in host_data.items():
                for port, port_data in ports.items():
                    # 각 포트 결과를 공통 dict 형태로 맞춰 리포트 생성 단계에서 동일하게 처리한다.
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
        # Nmap 결과 파싱 실패가 전체 스캔 중단으로 번지지 않도록 빈 목록을 반환한다.
        print(f"[ERROR] Nmap normalization failed: {e}")
        return []
