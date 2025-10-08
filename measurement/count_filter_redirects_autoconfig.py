import json
from collections import defaultdict

'''
用来生成.json文件表明一个provider会作为重定向链的最后一环提供服务给哪些域名。也就是说，只关注了起始域名和重定向链的最后域名，没有关注中间域名。02
'''
input_file = "/home/wzq/scan-website/cmd/filtered_redirects_autoconfig.jsonl"  # 输入文件
output_file = "/home/wzq/scan-website/cmd/redirects_statistics_autoconfig.json"  # 存储统计结果的文件

# 创建一个字典，键是最后一个域名，值是一个集合，包含所有重定向到该域名的域名
redirect_stats = defaultdict(set)

def analyze_redirects(input_file, output_file):
    # 使用正确的缩进方式来初始化 redirect_stats
    redirect_stats = defaultdict(set)
    
    with open(input_file, "r", encoding="utf-8") as f:
        for line in f:
            obj = json.loads(line.strip())  # 解析每一行 JSON 数据
            domain = obj.get("domain")
            redirects = obj.get("redirects", [])

            # 打印调试信息
            print(f"Processing domain: {domain}, redirects: {redirects}")

            # 获取重定向链的最后一个域名
            if redirects:
                last_redirect = redirects[-1]
                
                # 打印调试信息
                print(f"Last redirect for {domain}: {last_redirect}")

                # 将该域名（domain）加入字典中对应最后一个域名的集合
                redirect_stats[last_redirect].add(domain)
            else:
                print(f"No redirects for {domain}")

    # 将统计结果保存为 JSON 文件
    # 将所有的 set 转换为 list，因为 JSON 不支持直接序列化 set
    redirect_stats = {key: list(value) for key, value in redirect_stats.items()}

    with open(output_file, "w", encoding="utf-8") as out_f:
        json.dump(redirect_stats, out_f, indent=4, ensure_ascii=False)

    print(f"Redirect statistics saved to {output_file}")

# 执行统计分析并保存结果
analyze_redirects(input_file, output_file)
