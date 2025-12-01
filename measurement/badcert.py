# import json

# input_file = "/home/wzq/scan-website/cmd/certreal/smtp-587_starttls2_certs.jsonl"
# output_file = "/home/wzq/scan-website/cmd/smtp-587_starttls2_bad_issuers.txt"

# bad_issuers = set()

# with open(input_file, "r", encoding="utf-8") as f:
#     for line in f:
#         line = line.strip()
#         if not line:
#             continue
#         try:
#             data = json.loads(line)
#         except json.JSONDecodeError:
#             continue
        
#         if (
#             data.get("expired") is True
#             or data.get("self_signed") is True
#             or data.get("browser_trusted") is False
#             or data.get("matches_domain") is False
#         ):
#             issuer = data.get("issuer")
#             if issuer:
#                 bad_issuers.add(issuer)

# # 写入结果文件
# with open(output_file, "w", encoding="utf-8") as f:
#     for issuer in sorted(bad_issuers):
#         f.write(issuer + "\n")

# print(f"✅ 已提取 {len(bad_issuers)} 个异常证书的颁发机构，写入 {output_file}")
import json

input_file = "/home/wzq/scan-website/cmd/certreal/smtp-587_starttls2_certs.jsonl"
output_file = "/home/wzq/scan-website/cmd/certreal/smtp-587_starttls2_bad_hosts.txt"

bad_hosts = set()

with open(input_file, "r", encoding="utf-8") as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue
        
        if (
            data.get("expired") is True
            or data.get("self_signed") is True
            or data.get("browser_trusted") is False
            or data.get("matches_domain") is False
        ):
            host = data.get("host")
            if host:
                bad_hosts.add(host)

# 写入文件
with open(output_file, "w", encoding="utf-8") as f:
    for host in sorted(bad_hosts):
        f.write(host + "\n")

print(f"✅ 已提取 {len(bad_hosts)} 个存在证书问题的邮件主机，结果已写入 {output_file}")
