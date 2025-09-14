# import json
# from collections import defaultdict

# '''
# 从check_results.jsonl中提取Server(及供给的那些域名)、port、protocol到`clusters.json`中，再由try.sh生成对应的.csv,为实际连接测试准备
# '''
# # 定义聚类结果
# clusters = defaultdict(lambda: defaultdict(set))

# with open("check_results2.jsonl", "r", encoding="utf-8") as f:
#     for line in f:
#         data = json.loads(line) # 使用ijson?
#         domain = data.get("Domain")
        
#         for check in ["AutoconfigCheckResult", "AutodiscoverCheckResult", "SRVCheckResult"]:
#             result = data.get(check)
#             if result is None or result.get("Protocols") is None:
#                 continue  # 如果 result 或 Protocols 为 None 跳过该条记录
#             #if result and result.get("OverallCheck") == "Valid":
#             for proto in result.get("Protocols", []):
#                 if proto is None:  # 如果 Protocols 为 None 跳过
#                     continue
#                 proto_type = proto.get("Type", "").lower()
#                 server = proto.get("Server", "").rstrip(".")
#                 port = str(proto.get("Port") or "").strip()
#                 if not (proto_type and server and port):
#                     continue
#                 cluster_key = f"{proto_type}-{port}"
#                 clusters[cluster_key][server].add(domain)


# # 转换 set 为 list 方便 JSON 输出
# output = {
#     cluster: {host: list(domains) for host, domains in hosts.items()}
#     for cluster, hosts in clusters.items()
# }

# # 保存结果
# with open("clusters.json", "w", encoding="utf-8") as out_f:
#     json.dump(output, out_f, indent=4)


import json
from collections import defaultdict

'''
从check_results.jsonl中提取Server(及供给的那些域名)、port、protocol到`clusters.json`中，
再由try.sh生成对应的.csv,为实际连接测试准备
'''

# 定义聚类结果
clusters = defaultdict(lambda: defaultdict(set))


def process_result(result, domain):
    """处理单个 MethodConfig 对象"""
    if not result or not result.get("Protocols"):
        return
    for proto in result.get("Protocols", []):
        if proto is None:
            continue
        proto_type = proto.get("Type", "").lower()
        server = proto.get("Server", "").rstrip(".")
        port = str(proto.get("Port") or "").strip()
        if not (proto_type and server and port):
            continue
        cluster_key = f"{proto_type}-{port}"
        clusters[cluster_key][server].add(domain)


with open("/home/wzq/scan-website/cmd/check_results914_onlysome.jsonl", "r", encoding="utf-8") as f:
    for line in f:
        data = json.loads(line)
        domain = data.get("Domain")

        # Autoconfig / Autodiscover → 数组
        for check in ["AutoconfigCheckResult", "AutodiscoverCheckResult"]:
            result_list = data.get(check)
            if not result_list:  # None 或 空数组
                continue
            for result in result_list:  # 遍历数组里的 MethodConfig
                process_result(result, domain)

        # SRV → 单对象
        srv_result = data.get("SRVCheckResult")
        if srv_result:
            process_result(srv_result, domain)


# 转换 set 为 list 方便 JSON 输出
output = {
    cluster: {host: list(domains) for host, domains in hosts.items()}
    for cluster, hosts in clusters.items()
}

# 保存结果
with open("./clusters.json", "w", encoding="utf-8") as out_f:
    json.dump(output, out_f, indent=4)
