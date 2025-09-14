#!/bin/bash

# 定义 JSON 文件路径
JSON_FILE="/home/wzq/scan-website/clusters.json"
OUTPUT_DIR="real"

# 确保输出目录存在
mkdir -p "$OUTPUT_DIR"

# 循环处理每个协议
protocols=$(jq -r 'keys_unsorted[]' "$JSON_FILE")

for proto in $protocols; do
    # 分离协议和端口
    protocol=$(echo "$proto" | cut -d'-' -f1)
    port=$(echo "$proto" | cut -d'-' -f2)

    # 生成 CSV 文件
    csv_file="${OUTPUT_DIR}/${proto}.csv"
    echo "name" > "$csv_file"
    jq -r --arg p "$proto" '.[$p] | keys_unsorted[]' "$JSON_FILE" >> "$csv_file"
    echo "✅ 已生成 CSV 文件: $csv_file"

    # 多轮协议处理
    if [[ "$protocol" =~ ^(imap|imaps)$ ]]; then
        scan_name="imap"
        # 1️⃣ plain
        output_plain="${OUTPUT_DIR}/${proto}_plain.jsonl"
        cmd_plain="./zgrab2 -f \"$csv_file\" -o \"$output_plain\" $scan_name --port \"$port\""
        echo "🔹 执行: $cmd_plain"
        eval $cmd_plain

        # 2️⃣ starttls
        output_starttls="${OUTPUT_DIR}/${proto}_starttls.jsonl"
        cmd_starttls="./zgrab2 -f \"$csv_file\" -o \"$output_starttls\" $scan_name --port \"$port\" --starttls"
        echo "🔹 执行: $cmd_starttls"
        eval $cmd_starttls

        # 3️⃣ imaps
        output_imaps="${OUTPUT_DIR}/${proto}_imaps.jsonl"
        cmd_imaps="./zgrab2 -f \"$csv_file\" -o \"$output_imaps\" $scan_name --port \"$port\" --imaps"
        echo "🔹 执行: $cmd_imaps"
        eval $cmd_imaps

        echo "✅ $proto 三种方式扫描完成"

    elif [[ "$protocol" =~ ^(smtp|smtps)$ ]]; then
        scan_name="smtp"
        # 1️⃣ plain
        output_plain="${OUTPUT_DIR}/${proto}_plain.jsonl"
        cmd_plain="./zgrab2 -f \"$csv_file\" -o \"$output_plain\" $scan_name --port \"$port\""
        echo "🔹 执行: $cmd_plain"
        eval $cmd_plain

        # 2️⃣ starttls
        output_starttls="${OUTPUT_DIR}/${proto}_starttls.jsonl"
        cmd_starttls="./zgrab2 -f \"$csv_file\" -o \"$output_starttls\" $scan_name --port \"$port\" --starttls"
        echo "🔹 执行: $cmd_starttls"
        eval $cmd_starttls

        # 3️⃣ smtps
        output_smtps="${OUTPUT_DIR}/${proto}_smtps.jsonl"
        cmd_smtps="./zgrab2 -f \"$csv_file\" -o \"$output_smtps\" $scan_name --port \"$port\" --smtps"
        echo "🔹 执行: $cmd_smtps"
        eval $cmd_smtps

        echo "✅ $proto 三种方式扫描完成"

    elif [[ "$protocol" =~ ^(pop3|pop3s)$ ]]; then
        scan_name="pop3"
        # 1️⃣ plain
        output_plain="${OUTPUT_DIR}/${proto}_plain.jsonl"
        cmd_plain="./zgrab2 -f \"$csv_file\" -o \"$output_plain\" $scan_name --port \"$port\""
        echo "🔹 执行: $cmd_plain"
        eval $cmd_plain

        # 2️⃣ starttls
        output_starttls="${OUTPUT_DIR}/${proto}_starttls.jsonl"
        cmd_starttls="./zgrab2 -f \"$csv_file\" -o \"$output_starttls\" $scan_name --port \"$port\" --starttls"
        echo "🔹 执行: $cmd_starttls"
        eval $cmd_starttls

        # 3️⃣ pop3s
        output_pop3s="${OUTPUT_DIR}/${proto}_pop3s.jsonl"
        cmd_pop3s="./zgrab2 -f \"$csv_file\" -o \"$output_pop3s\" $scan_name --port \"$port\" --pop3s"
        echo "🔹 执行: $cmd_pop3s"
        eval $cmd_pop3s

        echo "✅ $proto 三种方式扫描完成"

    else
        # 其他协议单轮处理
        if [[ "$protocol" =~ s$ ]]; then
            scan_protocol="${protocol::-1}"
        else
            scan_protocol="$protocol"
        fi

        output_file="${OUTPUT_DIR}/${proto}.jsonl"
        cmd="./zgrab2 -f \"$csv_file\" -o \"$output_file\" \"$scan_protocol\" --port \"$port\""
        echo "🔹 执行: $cmd"
        eval $cmd

        echo "✅ $proto 扫描完成"
    fi
done

echo "🎉 全部协议扫描完成！"
