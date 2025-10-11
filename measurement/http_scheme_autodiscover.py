import json
import csv

input_file = "/home/wzq/scan-website/cmd/filtered_http_redirects_autodiscover.jsonl"#统计http最终获得的数量
output_csv = "/home/wzq/scan-website/cmd/autodiscover_scheme_summary.csv"  # 可选

def summarize_schemes(input_file, output_csv=None):
    # domain -> {"http": bool, "https": bool}
    domain_schemes = {}

    with open(input_file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue

            domain = obj.get("domain")
            scheme = (obj.get("final_scheme") or "").lower()
            is_http_flag = obj.get("is_http", None)

            if not domain:
                continue

            if domain not in domain_schemes:
                domain_schemes[domain] = {"http": False, "https": False}

            # 优先使用 final_scheme 字段判断
            if scheme == "http":
                domain_schemes[domain]["http"] = True
            elif scheme == "https":
                domain_schemes[domain]["https"] = True
            else:
                # fallback: 如果没有 final_scheme，但有 is_http 布尔字段
                if is_http_flag is True:
                    domain_schemes[domain]["http"] = True
                elif is_http_flag is False:
                    domain_schemes[domain]["https"] = True

    total = len(domain_schemes)
    http_any = sum(1 for v in domain_schemes.values() if v["http"])
    https_any = sum(1 for v in domain_schemes.values() if v["https"])
    both = sum(1 for v in domain_schemes.values() if v["http"] and v["https"])
    http_only = sum(1 for v in domain_schemes.values() if v["http"] and not v["https"])
    https_only = sum(1 for v in domain_schemes.values() if v["https"] and not v["http"])
    neither = sum(1 for v in domain_schemes.values() if not v["http"] and not v["https"])

    def pct(x): 
        return (x / total * 100) if total else 0

    print("🔍 Autodiscover 最终协议统计")
    print(f"总域名数: {total}")
    print(f"至少存在 HTTP 路径的域名数 (不安全判定): {http_any} ({pct(http_any):.2f}%)")
    print(f"至少存在 HTTPS 路径的域名数: {https_any} ({pct(https_any):.2f}%)")
    print(f"同时存在 HTTP 与 HTTPS 的域名数: {both} ({pct(both):.2f}%)")
    print(f"仅 HTTP 的域名数: {http_only} ({pct(http_only):.2f}%)")
    print(f"仅 HTTPS 的域名数: {https_only} ({pct(https_only):.2f}%)")
    print(f"既没有 HTTP 也没有 HTTPS 标记的域名数（异常/丢失数据）: {neither} ({pct(neither):.2f}%)")

    if output_csv:
        with open(output_csv, "w", newline="", encoding="utf-8") as csvf:
            writer = csv.writer(csvf)
            writer.writerow(["domain", "has_http", "has_https"])
            for d, v in sorted(domain_schemes.items()):
                writer.writerow([d, int(v["http"]), int(v["https"])])

    return domain_schemes

if __name__ == "__main__":
    summarize_schemes(input_file, output_csv)
