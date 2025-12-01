# import json

# # ======== 输入文件路径 ========
# cluster_file = "/home/wzq/scan-website/clusters.json"
# bad_hosts_file = "/home/wzq/scan-website/cmd/certreal/imap-993_imaps_bad_hosts.txt"
# output_file = "/home/wzq/scan-website/cmd/all/imap-993_imaps_bad_mapping.txt"

# # ======== 读取坏主机列表 ========
# with open(bad_hosts_file, "r", encoding="utf-8") as f:
#     bad_hosts = set(line.strip() for line in f if line.strip())

# print(f"加载坏主机数量: {len(bad_hosts)}")

# # ======== 读取 cluster.json ========
# with open(cluster_file, "r", encoding="utf-8") as f:
#     cluster_data = json.load(f)

# # ======== 结果容器 ========
# result_lines = []

# # 遍历协议端口
# for proto_port, host_map in cluster_data.items():
#     # 遍历每个邮件主机
#     for host, domains in host_map.items():
#         if host in bad_hosts:
#             result_lines.append(f"[{proto_port}] {host}  ({len(domains)} domains)")
#             for d in domains:
#                 result_lines.append(f"    - {d}")
#             result_lines.append("")  # 空行分隔

# # ======== 输出结果 ========
# if result_lines:
#     with open(output_file, "w", encoding="utf-8") as f:
#         f.write("\n".join(result_lines))
#     print(f"已写入 {len(result_lines)} 行结果到: {output_file}")
# else:
#     print("未找到匹配的坏主机。")


#!/usr/bin/env python3
import json
import glob
import os
import re

# ====== 配置区 ======
cluster_file = "/home/wzq/scan-website/clusters.json"
bad_hosts_dir = "/home/wzq/scan-website/cmd/certreal"   # 包含 *_bad_hosts.txt 的目录
out_dir = "/home/wzq/scan-website/cmd/all"
os.makedirs(out_dir, exist_ok=True)

# ====== 辅助函数 ======
def normalize_host(h):
    """标准化主机名：去空格、转小写、去掉末尾点、去掉 :port"""
    if not h:
        return h
    h = h.strip().lower()
    if h.endswith('.'):
        h = h[:-1]
    # 去掉可能的 :993 或 /path
    h = re.sub(r':\d+$', '', h)
    h = re.sub(r'/.*$', '', h)
    return h

# ====== 读取 cluster.json ======
with open(cluster_file, "r", encoding="utf-8") as f:
    cluster = json.load(f)

# 预处理 cluster：构建映射 proto_port -> normalized host -> domains
cluster_norm = {}
for proto_port, host_map in cluster.items():
    cluster_norm.setdefault(proto_port, {})
    for host, domains in host_map.items():
        nh = normalize_host(host)
        # 确保 domains 是列表
        doms = domains if isinstance(domains, list) else [domains]
        cluster_norm[proto_port][nh] = doms

# ====== 读取所有 bad_hosts 文件 ======
bad_files = glob.glob(os.path.join(bad_hosts_dir, "*_bad_hosts.txt"))
if not bad_files:
    print("⚠️ 未找到任何 *_bad_hosts.txt 文件于:", bad_hosts_dir)

all_bad_hosts = set()
badfile_map = {}  # filename -> set(hosts)
for bf in bad_files:
    with open(bf, "r", encoding="utf-8") as f:
        hs = set(normalize_host(line) for line in f if line.strip())
    badfile_map[os.path.basename(bf)] = hs
    all_bad_hosts.update(hs)

print(f"加载 {len(badfile_map)} 个 bad-hosts 文件，合计 {len(all_bad_hosts)} 个去重后的坏主机（标准化后）")

# ====== 建立映射：proto_port -> host -> domains (只包含坏主机) ======
mapping = {}  # proto_port -> host -> domains
matched_bad_hosts = set()

for proto_port, hosts in cluster_norm.items():
    for host, domains in hosts.items():
        if host in all_bad_hosts:
            mapping.setdefault(proto_port, {})[host] = domains
            matched_bad_hosts.add(host)

# ====== 输出可读文本文件 ======
readable_path = os.path.join(out_dir, "bad_mapping_readable.txt")
with open(readable_path, "w", encoding="utf-8") as f:
    for proto_port in sorted(mapping.keys()):
        f.write(f"=== [{proto_port}] ===\n")
        for host, domains in sorted(mapping[proto_port].items()):
            f.write(f"{host}  ({len(domains)} domains)\n")
            for d in domains:
                f.write(f"    - {d}\n")
            f.write("\n")
print("✅ 已写可读输出:", readable_path)

# ====== 输出结构化 JSON 汇总 ======
summary = {
    "meta": {
        "cluster_file": cluster_file,
        "bad_hosts_dir": bad_hosts_dir,
        "bad_files_count": len(badfile_map),
        "bad_hosts_total": len(all_bad_hosts),
        "matched_bad_hosts": len(matched_bad_hosts)
    },
    "mapping": mapping,
    "bad_files": {k: sorted(list(v)) for k, v in badfile_map.items()},
    "unmatched_bad_hosts": sorted(list(all_bad_hosts - matched_bad_hosts))
}
json_path = os.path.join(out_dir, "bad_mapping_summary.json")
with open(json_path, "w", encoding="utf-8") as f:
    json.dump(summary, f, indent=2, ensure_ascii=False)
print("✅ 已写结构化 JSON:", json_path)

# ====== 未匹配 bad hosts 列表（便于排查） ======
unmatched_path = os.path.join(out_dir, "unmatched_bad_hosts.txt")
with open(unmatched_path, "w", encoding="utf-8") as f:
    for h in sorted(all_bad_hosts - matched_bad_hosts):
        f.write(h + "\n")
print("✅ 未在 cluster.json 中找到的坏主机已写入:", unmatched_path)

# ====== 简短统计输出 ======
print("---- 统计 ----")
print("bad files:", len(badfile_map))
print("bad hosts total:", len(all_bad_hosts))
print("matched bad hosts:", len(matched_bad_hosts))
print("unmatched bad hosts:", len(all_bad_hosts - matched_bad_hosts))
print("输出目录:", out_dir)
