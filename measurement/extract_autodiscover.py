import ijson
import json
from urllib.parse import urlparse
import tldextract
'''
用来从原始的配置记录文件init.jsonl中提取出重定向有关的信息，生成.jsonl文件 01
'''
input_file = "/home/wzq/scan-website/cmd/init.jsonl"
output_file = "filtered_redirects_autodiscover.jsonl"  # 存储符合条件的重定向链信息

# 函数：标准化为注册域名
def normalize_domain(domain):
    # 提取注册域名
    return tldextract.extract(domain).registered_domain

import json

def extract_redirect_info(input_file, output_file):
    with open(input_file, "r", encoding="utf-8") as f, open(output_file, "a", encoding="utf-8") as out_f:
        for line in f:
            try:
                obj = json.loads(line)  # 逐行解析 JSON 对象
            except json.JSONDecodeError as e:
                print(f"❌ JSON 解析失败，可能是文件格式有问题: {e}")
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
                        # 标准化域名
                        normalized_redirects = [normalize_domain(redirect["URL"]) for redirect in redirects]

                        # 如果重定向链中第一个和最后一个标准化域名相同，则去除环
                        if normalized_redirects[0] == normalized_redirects[-1] :
                            if normalized_redirects[0]!=normalize_domain(domain): #查询的domain和重定向路径的第一个就不一样（如srv-post）
                                normalized_redirects_new = [normalize_domain(domain), normalized_redirects[0]]
                                redirect_info = {
                                    "domain": domain,
                                    "redirects": normalized_redirects_new,
                                }
                            else:
                                normalized_redirects_new = ["preself"+ normalized_redirects[0], normalized_redirects[0]]
                                redirect_info = {
                                    "domain": domain,
                                    "redirects": normalized_redirects_new,
                                }
                        else:
                            redirect_info = {
                                "domain": domain,
                                "redirects": normalized_redirects,
                            }
                        
                        extracted_info.append(json.dumps(redirect_info))

            # 批量写入，减少文件 I/O
            if extracted_info:
                out_f.write("\n".join(extracted_info) + "\n")

extract_redirect_info("/home/wzq/scan-website/cmd/init.jsonl", "/home/wzq/scan-website/cmd/filtered_redirects_autodiscover.jsonl")




