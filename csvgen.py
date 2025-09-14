import csv

input_file = "domains.txt"   # 你的txt文件
output_file = "domains.csv"  # 输出的csv

with open(input_file, "r", encoding="utf-8") as f:
    domains = [line.strip() for line in f if line.strip()]

with open(output_file, "w", newline="", encoding="utf-8") as f:
    writer = csv.writer(f)
    for idx, domain in enumerate(domains, start=1):
        writer.writerow([idx, domain])

print(f"CSV 已生成: {output_file}")
