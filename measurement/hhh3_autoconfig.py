import json
import csv
'''
通过前面生成的redirects_statistics_320_autoconfig.json(不包含preself前缀)，生成了small_providers_320_autoconfig.csv，看看那些small_provider具体是哪些，以及其提供服务的域名里是否包含自己
'''
# 读取 JSON 文件
with open("/home/wzq/scan-website/cmd/redirects_statistics_autoconfig.json", "r", encoding="utf-8") as f:
    redirect_stats = json.load(f)

# 存储 small_provider 信息
small_providers = []

# 遍历每个 provider
for provider, customers in redirect_stats.items():
    total_customers = len(customers)  # 获取当前 provider 的客户数量

    # 判断是否是 small_provider
    if total_customers < 2:
        contains_self = provider in customers  # 检查 provider 是否也在其 customers 列表中
        small_providers.append((provider, total_customers, contains_self))

# 按客户数量排序（从小到大）
small_providers.sort(key=lambda x: x[1])

# 写入 CSV 文件
output_file = "/home/wzq/scan-website/cmd/small_providers_2_autoconfig.csv"
with open(output_file, "w", newline="", encoding="utf-8") as f:
    writer = csv.writer(f)
    writer.writerow(["Provider", "Customers", "Contains_Self"])  # 写入表头
    writer.writerows(small_providers)  # 写入数据

print(f"small_provider 结果已保存至 {output_file}")
