import json
import pandas as pd
from collections import defaultdict
'''
成功结合gTLDs生成了redirects_tld_statistics.csv,得到sanky图 03_2
'''
# 读取 redirects_statistics.json 文件
with open("/home/wzq/scan-website/cmd/redirects_statistics_autoconfig.json", "r", encoding="utf-8") as f:
    redirect_stats = json.load(f)

# 定义常见的 TLD
common_tlds = ['.com', '.org', '.net', '.edu', '.gov', '.co', '.io', '.cn']
other_tld = "others"

# 用于存储生成的 source, target 和 value
source = []
target = []
value = []

# 遍历每个 provider
for provider, customers in redirect_stats.items():
    tld_count = defaultdict(int)  # 记录每个 TLD 的数量
    total_customers = len(customers)  # 获取当前 provider 的客户数量

    # 判断是否是 small_provider
    is_small_provider = total_customers < 1 # 10

    for customer in customers:
        # 检查每个 customer 的顶级域名
        matched = False
        for tld in common_tlds:
            if customer.endswith(tld):
                tld_count[tld] += 1
                matched = True
                break
        # 如果没有匹配到常见的 TLD，归类为 others
        if not matched:
            tld_count[other_tld] += 1
    
    # 将每个 TLD 聚类为一行
    for tld, count in tld_count.items():
        if is_small_provider:
            # 如果是 small_provider，则 target 为 small_provider
            existing_idx = None
            # 检查是否已经有 "source = tld" 和 "target = small_provider"
            for i, s in enumerate(source):
                if s == tld and target[i] == "small_provider":
                    existing_idx = i
                    break
            if existing_idx is not None:
                value[existing_idx] += count  # 更新 value
            else:
                source.append(tld)
                target.append("small_provider")
                value.append(count)
        else:
            # 如果不是 small_provider，则每个 customer 单独聚类
            source.append(tld)
            target.append(provider)
            value.append(count)

# 创建 DataFrame 并保存为 CSV
df = pd.DataFrame({"source": source, "target": target, "value": value})
df.to_csv("/home/wzq/scan-website/cmd/redirects_tld_statistics_autoconfig_nosmall.csv", index=False, encoding="utf-8")

print("新CSV文件已生成：redirects_tld_statistics_320_autoconfig.csv")
