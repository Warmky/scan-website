#!/bin/bash

# 结果文件所在目录
RESULT_DIR="/home/wzq/scan-website/zgrab2/real"
# 输出文件路径
OUTPUT_FILE="/home/wzq/scan-website/non_standard_success.csv"

# 定义邮件协议的标准端口
declare -A STANDARD_PORTS=(
    ["imap"]="143 993"
    ["smtp"]="25 465 587 2525"
    ["pop3"]="110 995"
    ["imaps"]="143 993"
    ["smtps"]="25 465 587 2525"
    ["pop3s"]="110 995"
)

echo "🔍 查找非常规端口的成功连接..." > "$OUTPUT_FILE"
echo "Domain,Config,Extra" >> "$OUTPUT_FILE"  # CSV 文件头，添加 Extra 列

# 遍历所有 JSONL 结果文件
for file in "$RESULT_DIR"/*.jsonl; do
    proto=$(basename "$file" | cut -d'_' -f1)  # 提取协议，如 imap-443_plain.jsonl -> imap-443
    base_proto=$(echo "$proto" | cut -d'-' -f1) # 取协议名，如 imap

    port=$(echo "$proto" | cut -d'-' -f2) # 取端口号，如 443
    if [[ -z "$port" || -z "$base_proto" ]]; then
        continue  # 解析失败跳过
    fi

    # 检查是否是非常规端口
    if [[ " ${STANDARD_PORTS[$base_proto]} " =~ " $port " ]]; then
        continue  # 是标准端口，跳过
    fi

    # 获取文件名中的 _ 后的部分并去掉 .jsonl 后缀
    extra=$(basename "$file" | cut -d'_' -f2- | sed 's/.jsonl//')  # 提取 _ 后面的部分并去掉 .jsonl 后缀

    echo "🔹 发现 $proto 端口 ($file) 结果"

    # 针对不同协议进行处理
    case "$base_proto" in
        "imap")
            # 查找 imap status 为 success 的记录并输出到文件（只输出 domain 和配置）
            jq -r 'select(.data.imap.status=="success") | .domain' "$file" | while read -r domain; do
                # 去掉 domain 中的双引号，并输出到 CSV
                echo "$(echo $domain | sed 's/"//g'),$proto,$extra" >> "$OUTPUT_FILE"
            done
            ;;
        "pop3")
            # 查找 pop3 status 为 success 的记录并输出到文件（只输出 domain 和配置）
            jq -r 'select(.data.pop3.status=="success") | .domain' "$file" | while read -r domain; do
                # 去掉 domain 中的双引号，并输出到 CSV
                echo "$(echo $domain | sed 's/"//g'),$proto,$extra" >> "$OUTPUT_FILE"
            done
            ;;
        "smtp")
            # 查找 smtp status 为 success 的记录并输出到文件（只输出 domain 和配置）
            jq -r 'select(.data.smtp.status=="success") | .domain' "$file" | while read -r domain; do
                # 去掉 domain 中的双引号，并输出到 CSV
                echo "$(echo $domain | sed 's/"//g'),$proto,$extra" >> "$OUTPUT_FILE"
            done
            ;;
        *)
            # 如果是其他协议，可以在这里扩展
            echo "⚠️ 未处理的协议: $base_proto"
            ;;
    esac
done

echo "✅ 查找完成！结果保存在 $OUTPUT_FILE"
