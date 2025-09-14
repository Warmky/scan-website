import json
from urllib.parse import urlparse

#重定向路径提取最后一条，看最终是通过http/https获取的配置信息
input_file = "/home/wzq/scan-website/cmd/init.jsonl"
output_file = "/home/wzq/scan-website/cmd/filtered_http_redirects_autodiscover.jsonl"

def extract_http_usage(input_file, output_file):
    with open(input_file, "r", encoding="utf-8") as f, open(output_file, "w", encoding="utf-8") as out_f:
        for line in f:
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as e:
                print(f"❌ JSON 解析失败: {e}")
                continue
            
            domain = obj.get("domain")
            extracted_info = []

            for entry in obj.get("autodiscover", []):
                redirects = entry.get("redirects", [])
                if redirects:
                    # 获取重定向链中的状态码
                    chainlast_autodiscover_code = redirects[-1].get("Status")
                    
                    # 筛选状态码在 200 到 299 之间的且没有解析错误的重定向链
                    if (200 <= chainlast_autodiscover_code < 300 and 
                        not entry.get("error", "").startswith("failed to unmarshal") and 
                        not entry.get("error", "").startswith("failed to read response body")):
                        # 取最后一个跳转的 URL
                        last_url = redirects[-1].get("URL", "")
                        last_scheme = urlparse(last_url).scheme.lower()

                        if last_scheme in ["http", "https"]:
                            redirect_info = {
                                "domain": domain,
                                "final_url": last_url,
                                "final_scheme": last_scheme,
                                "is_http": last_scheme == "http"  # True 表示最后落在 http
                            }
                            extracted_info.append(json.dumps(redirect_info))

                
                

            if extracted_info:
                out_f.write("\n".join(extracted_info) + "\n")

extract_http_usage(input_file, output_file)
