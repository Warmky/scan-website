#!/bin/bash

# 结果文件所在目录
RESULT_DIR="/home/wzq/scan-website/zgrab2/real"
# 输出文件路径
OUTPUT_FILE="/home/wzq/scan-website/all_success.csv"

echo "🔍 查找所有连接成功的结果..." > "$OUTPUT_FILE"
echo "Domain,Protocol,Port,Extra" >> "$OUTPUT_FILE"  # CSV 文件头

# 遍历所有 JSONL 结果文件
for file in "$RESULT_DIR"/*.jsonl; do
    proto=$(basename "$file" | cut -d'_' -f1)     # 提取协议+端口，如 imap-443
    base_proto=$(echo "$proto" | cut -d'-' -f1)   # 协议名，如 imap
    port=$(echo "$proto" | cut -d'-' -f2)         # 端口号，如 443

    # 获取文件名中的 _ 后的部分并去掉 .jsonl 后缀
    extra=$(basename "$file" | cut -d'_' -f2- | sed 's/.jsonl//')

    echo "🔹 扫描文件: $file"

    # 针对不同协议查找成功的连接
    case "$base_proto" in
        "imap")
            jq -r 'select(.data.imap.status=="success") | .domain' "$file" | while read -r domain; do
                echo "$(echo $domain | sed 's/\"//g'),$base_proto,$port,$extra" >> "$OUTPUT_FILE"
            done
            ;;
        "pop3")
            jq -r 'select(.data.pop3.status=="success") | .domain' "$file" | while read -r domain; do
                echo "$(echo $domain | sed 's/\"//g'),$base_proto,$port,$extra" >> "$OUTPUT_FILE"
            done
            ;;
        "smtp")
            jq -r 'select(.data.smtp.status=="success") | .domain' "$file" | while read -r domain; do
                echo "$(echo $domain | sed 's/\"//g'),$base_proto,$port,$extra" >> "$OUTPUT_FILE"
            done
            ;;
        *)
            echo "⚠️ 未处理的协议: $base_proto"
            ;;
    esac
done

echo "✅ 查找完成！结果保存在 $OUTPUT_FILE"
