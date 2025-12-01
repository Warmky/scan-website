# import json
# import datetime
# from pathlib import Path

# jsonl_file = "/home/wzq/scan-website/zgrab2/real/imap-993_imaps.jsonl"

# def parse_cert_details(cert_data):
#     parsed = cert_data.get("parsed", {})
#     validation = parsed.get("validation", {})

#     version = parsed.get("version")
#     serial = parsed.get("serial_number")
#     sig_alg = parsed.get("signature_algorithm", {}).get("name")

#     issuer = parsed.get("issuer_dn")
#     subject = parsed.get("subject_dn")

#     validity = parsed.get("validity", {})
#     not_before = validity.get("start")
#     not_after = validity.get("end")

#     self_signed = parsed.get("self_signed", False)
#     browser_trusted = validation.get("browser_trusted", False)
#     matches_domain = validation.get("matches_domain", False)

#     # 判断是否过期
#     expired = False
#     if not_after:
#         try:
#             end_time = datetime.datetime.fromisoformat(not_after.replace("Z", "+00:00"))
#             expired = end_time < datetime.datetime.now(datetime.timezone.utc)
#         except Exception:
#             expired = None

#     return {
#         "version": version,
#         "serial_number": serial,
#         "signature_algorithm": sig_alg,
#         "issuer": issuer,
#         "subject": subject,
#         "valid_from": not_before,
#         "valid_to": not_after,
#         "expired": expired,
#         "self_signed": self_signed,
#         "browser_trusted": browser_trusted,
#         "matches_domain": matches_domain,
#     }

# def process_tls_details(entry):
#     data = entry.get("data", {})
#     for proto in ["imap", "smtp", "pop3"]:
#         proto_data = data.get(proto)
#         if proto_data and proto_data.get("status") == "success":
#             host = entry.get("domain") or entry.get("host") or entry.get("ip")
#             port = proto_data.get("port")
#             print(f"\n✅ 成功连接: {host}:{port}")

#             # ===== 提取证书 =====
#             cert_chain = (
#                 proto_data.get("result", {})
#                 .get("tls", {})
#                 .get("handshake_log", {})
#                 .get("server_certificates", {})
#                 .get("certificate", {})
#             )

#             if not cert_chain:
#                 print("⚠️ 未找到证书信息")
#                 continue

#             cert_info = parse_cert_details(cert_chain)
#             print(f"🔹 证书版本: {cert_info['version']}")
#             print(f"🔹 序列号: {cert_info['serial_number']}")
#             print(f"🔹 签名算法: {cert_info['signature_algorithm']}")
#             print(f"🔹 签发者: {cert_info['issuer']}")
#             print(f"🔹 主体: {cert_info['subject']}")
#             print(f"🔹 有效期: {cert_info['valid_from']} → {cert_info['valid_to']}")
#             print(f"🔹 是否过期: {cert_info['expired']}")
#             print(f"🔹 是否自签名: {cert_info['self_signed']}")
#             print(f"🔹 浏览器信任: {cert_info['browser_trusted']}")
#             print(f"🔹 域名匹配: {cert_info['matches_domain']}")

#             print("-" * 80)

# def main():
#     with open(jsonl_file, "r", encoding="utf-8") as f:
#         for line in f:
#             line = line.strip()
#             if not line:
#                 continue
#             try:
#                 entry = json.loads(line)
#             except json.JSONDecodeError:
#                 continue
#             process_tls_details(entry)

# if __name__ == "__main__":
#     main()


# import json
# import datetime
# from pathlib import Path

# # ===== 输入与输出路径 =====
# # jsonl_file = "/home/wzq/scan-website/zgrab2/real/imap-993_imaps.jsonl"
# # output_file = "/home/wzq/scan-website/cmd/certreal/imap-993_certs.jsonl"

# jsonl_file = "/home/wzq/scan-website/zgrab2/real/pop3-995_pop3s.jsonl"
# output_file = "/home/wzq/scan-website/cmd/certreal/pop3-995_certs.jsonl"


# # def parse_cert_details(cert_data):
# #     parsed = cert_data.get("parsed", {})
# #     validation = parsed.get("validation", {})

# #     version = parsed.get("version")
# #     serial = parsed.get("serial_number")
# #     sig_alg = parsed.get("signature_algorithm", {}).get("name")

# #     issuer = parsed.get("issuer_dn")
# #     subject = parsed.get("subject_dn")

# #     validity = parsed.get("validity", {})
# #     not_before = validity.get("start")
# #     not_after = validity.get("end")

# #     # self_signed = parsed.get("self_signed", False)
# #     self_signed = parsed.get("signature").get("self_signed")
# #     browser_trusted = validation.get("browser_trusted", False)
# #     matches_domain = validation.get("matches_domain", False)

# #     # 判断是否过期
# #     expired = False
# #     if not_after:
# #         try:
# #             end_time = datetime.datetime.fromisoformat(not_after.replace("Z", "+00:00"))
# #             expired = end_time < datetime.datetime.now(datetime.timezone.utc)
# #         except Exception:
# #             expired = None

# #     return {
# #         "version": version,
# #         "serial_number": serial,
# #         "signature_algorithm": sig_alg,
# #         "issuer": issuer,
# #         "subject": subject,
# #         "valid_from": not_before,
# #         "valid_to": not_after,
# #         "expired": expired,
# #         "self_signed": self_signed,
# #         "browser_trusted": browser_trusted,
# #         "matches_domain": matches_domain,
# #     }

# def parse_cert_details(cert_data):
#     parsed = cert_data.get("parsed", {})
#     signature_info = cert_data.get("signature", {})

#     version = parsed.get("version")
#     serial = parsed.get("serial_number")
#     sig_alg = parsed.get("signature_algorithm", {}).get("name")
#     issuer = parsed.get("issuer_dn")
#     subject = parsed.get("subject_dn")

#     validity = parsed.get("validity", {})
#     not_before = validity.get("start")
#     not_after = validity.get("end")

#     # self_signed 优先 parsed 下的字段，没有再用 signature 下的
#     self_signed = parsed.get("self_signed")
#     if self_signed is None:
#         self_signed = signature_info.get("self_signed", False)

#     validation = cert_data.get("validation", {})
#     browser_trusted = validation.get("browser_trusted", False)
#     matches_domain = validation.get("matches_domain", False)

#     # 判断是否过期
#     expired = None
#     if not_after:
#         try:
#             end_time = datetime.datetime.fromisoformat(not_after.replace("Z", "+00:00"))
#             expired = end_time < datetime.datetime.now(datetime.timezone.utc)
#         except Exception:
#             expired = None

#     return {
#         "version": version,
#         "serial_number": serial,
#         "signature_algorithm": sig_alg,
#         "issuer": issuer,
#         "subject": subject,
#         "valid_from": not_before,
#         "valid_to": not_after,
#         "expired": expired,
#         "self_signed": self_signed,
#         "browser_trusted": browser_trusted,
#         "matches_domain": matches_domain,
#     }

# def process_tls_details(entry):
#     results = []
#     data = entry.get("data", {})
#     for proto in ["imap", "smtp", "pop3"]:
#         proto_data = data.get(proto)
#         if proto_data and proto_data.get("status") == "success":
#             host = entry.get("domain") or entry.get("host") or entry.get("ip")
#             port = proto_data.get("port")
#             print(f"\n✅ 成功连接: {host}:{port}")

#             cert_chain = (
#                 proto_data.get("result", {})
#                 .get("tls", {})
#                 .get("handshake_log", {})
#                 .get("server_certificates", {})
#                 .get("certificate", {})
#             )

#             if not cert_chain:
#                 print("⚠️ 未找到证书信息")
#                 continue

#             cert_info = parse_cert_details(cert_chain)
#             result = {
#                 "host": host,
#                 "port": port,
#                 "protocol": proto,
#                 **cert_info,
#             }

#             # 打印到控制台
#             print(f"🔹 证书版本: {cert_info['version']}")
#             print(f"🔹 序列号: {cert_info['serial_number']}")
#             print(f"🔹 签名算法: {cert_info['signature_algorithm']}")
#             print(f"🔹 签发者: {cert_info['issuer']}")
#             print(f"🔹 主体: {cert_info['subject']}")
#             print(f"🔹 有效期: {cert_info['valid_from']} → {cert_info['valid_to']}")
#             print(f"🔹 是否过期: {cert_info['expired']}")
#             print(f"🔹 是否自签名: {cert_info['self_signed']}")
#             print(f"🔹 浏览器信任: {cert_info['browser_trusted']}")
#             print(f"🔹 域名匹配: {cert_info['matches_domain']}")
#             print("-" * 80)

#             results.append(result)
#     return results


# def main():
#     output_path = Path(output_file)
#     if output_path.exists():
#         output_path.unlink()  # 若已存在则清空

#     with open(jsonl_file, "r", encoding="utf-8") as f_in, open(output_file, "a", encoding="utf-8") as f_out:
#         for line in f_in:
#             line = line.strip()
#             if not line:
#                 continue
#             try:
#                 entry = json.loads(line)
#             except json.JSONDecodeError:
#                 continue

#             results = process_tls_details(entry)
#             for r in results:
#                 f_out.write(json.dumps(r, ensure_ascii=False) + "\n")

#     print(f"\n✅ 所有结果已保存至: {output_file}")


# if __name__ == "__main__":
#     main()


# import json
# import datetime
# from pathlib import Path

# # ===== 输入与输出路径 =====
# jsonl_file = "/home/wzq/scan-website/zgrab2/real/pop3-995_pop3s.jsonl"
# output_file = "/home/wzq/scan-website/cmd/certreal/pop3-995_certs.jsonl"

# def parse_cert_details(cert_data):
#     parsed = cert_data.get("parsed", {})
    
#     # 修正：validation 应该在 parsed 里面
#     validation = parsed.get("validation", {})
    
#     version = parsed.get("version")
#     serial = parsed.get("serial_number")
#     sig_alg = parsed.get("signature_algorithm", {}).get("name")
    
#     # 修正：使用更友好的显示格式
#     issuer = parsed.get("issuer", {}).get("common_name", [""])[0] or parsed.get("issuer_dn", "")
#     subject = parsed.get("subject", {}).get("common_name", [""])[0] or parsed.get("subject_dn", "")
    
#     validity = parsed.get("validity", {})
#     not_before = validity.get("start")
#     not_after = validity.get("end")
    
#     # 修正：直接从 parsed 获取 self_signed
#     self_signed = parsed.get("self_signed", False)
    
#     # 修正：从正确的 validation 中获取
#     browser_trusted = validation.get("browser_trusted", False)
#     matches_domain = validation.get("matches_domain", False)
    
#     # 获取主题备用名称
#     extensions = parsed.get("extensions", {})
#     subject_alt_names = extensions.get("subject_alt_name", {}).get("dns_names", [])
    
#     # 判断是否过期
#     expired = False
#     if not_after:
#         try:
#             end_time = datetime.datetime.fromisoformat(not_after.replace("Z", "+00:00"))
#             expired = end_time < datetime.datetime.now(datetime.timezone.utc)
#         except Exception:
#             expired = None

#     return {
#         "version": version,
#         "serial_number": serial,
#         "signature_algorithm": sig_alg,
#         "issuer": issuer,
#         "subject": subject,
#         "valid_from": not_before,
#         "valid_to": not_after,
#         "expired": expired,
#         "self_signed": self_signed,
#         "browser_trusted": browser_trusted,
#         "matches_domain": matches_domain,
#         "subject_alt_names": subject_alt_names,  # 新增：主题备用名称
#     }

# def process_tls_details(entry):
#     results = []
#     data = entry.get("data", {})
#     for proto in ["imap", "smtp", "pop3"]:
#         proto_data = data.get(proto)
#         if proto_data and proto_data.get("status") == "success":
#             host = entry.get("domain") or entry.get("host") or entry.get("ip")
#             port = proto_data.get("port")
#             print(f"\n✅ 成功连接: {host}:{port}")

#             # ===== 修正：更安全的证书提取路径 =====
#             cert_chain = (
#                 proto_data.get("result", {})
#                 .get("tls", {})
#                 .get("handshake_log", {})
#                 .get("server_certificates", {})
#             )
            
#             # 先检查 server_certificates 是否存在
#             if not cert_chain:
#                 print("⚠️ 未找到 server_certificates 信息")
#                 continue
                
#             # 然后获取 certificate
#             certificate = cert_chain.get("certificate", {})
#             if not certificate:
#                 print("⚠️ 未找到 certificate 信息")
#                 continue

#             cert_info = parse_cert_details(certificate)
#             result = {
#                 "host": host,
#                 "port": port,
#                 "protocol": proto,
#                 **cert_info,
#             }

#             # 打印到控制台
#             print(f"🔹 证书版本: {cert_info['version']}")
#             print(f"🔹 序列号: {cert_info['serial_number']}")
#             print(f"🔹 签名算法: {cert_info['signature_algorithm']}")
#             print(f"🔹 签发者: {cert_info['issuer']}")
#             print(f"🔹 主体: {cert_info['subject']}")
#             print(f"🔹 有效期: {cert_info['valid_from']} → {cert_info['valid_to']}")
#             print(f"🔹 是否过期: {cert_info['expired']}")
#             print(f"🔹 是否自签名: {cert_info['self_signed']}")
#             print(f"🔹 浏览器信任: {cert_info['browser_trusted']}")
#             print(f"🔹 域名匹配: {cert_info['matches_domain']}")
#             print(f"🔹 主题备用名称: {cert_info['subject_alt_names']}")
#             print("-" * 80)

#             results.append(result)
#     return results

# def main():
#     output_path = Path(output_file)
#     if output_path.exists():
#         output_path.unlink()  # 若已存在则清空

#     with open(jsonl_file, "r", encoding="utf-8") as f_in, open(output_file, "a", encoding="utf-8") as f_out:
#         for line in f_in:
#             line = line.strip()
#             if not line:
#                 continue
#             try:
#                 entry = json.loads(line)
#             except json.JSONDecodeError:
#                 continue

#             results = process_tls_details(entry)
#             for r in results:
#                 f_out.write(json.dumps(r, ensure_ascii=False) + "\n")

#     print(f"\n✅ 所有结果已保存至: {output_file}")

# if __name__ == "__main__":
#     main()


# import json
# import datetime
# from pathlib import Path

# # ===== 输入与输出路径 =====
# jsonl_file = "/home/wzq/scan-website/zgrab2/real/pop3-995_pop3s.jsonl"
# output_file = "/home/wzq/scan-website/cmd/certreal/pop3-995_certs.jsonl"

# def parse_cert_details(cert_data, server_certificates_data):
#     parsed = cert_data.get("parsed", {})
    
#     # 修正：validation 在 server_certificates 的同级，不是在 certificate 里面
#     validation = server_certificates_data.get("validation", {})
    
#     version = parsed.get("version")
#     serial = parsed.get("serial_number")
#     sig_alg = parsed.get("signature_algorithm", {}).get("name")
    
#     # 使用更友好的显示格式
#     issuer = parsed.get("issuer", {}).get("common_name", [""])[0] or parsed.get("issuer_dn", "")
#     subject = parsed.get("subject", {}).get("common_name", [""])[0] or parsed.get("subject_dn", "")
    
#     validity = parsed.get("validity", {})
#     not_before = validity.get("start")
#     not_after = validity.get("end")
    
#     # 直接从 parsed 获取 self_signed
#     self_signed = parsed.get("self_signed", False)
    
#     # 修正：从正确的 validation 中获取
#     browser_trusted = validation.get("browser_trusted", False)
#     matches_domain = validation.get("matches_domain", False)
    
#     # 获取主题备用名称
#     extensions = parsed.get("extensions", {})
#     subject_alt_names = extensions.get("subject_alt_name", {}).get("dns_names", [])
    
#     # 判断是否过期
#     expired = False
#     if not_after:
#         try:
#             end_time = datetime.datetime.fromisoformat(not_after.replace("Z", "+00:00"))
#             expired = end_time < datetime.datetime.now(datetime.timezone.utc)
#         except Exception:
#             expired = None

#     return {
#         "version": version,
#         "serial_number": serial,
#         "signature_algorithm": sig_alg,
#         "issuer": issuer,
#         "subject": subject,
#         "valid_from": not_before,
#         "valid_to": not_after,
#         "expired": expired,
#         "self_signed": self_signed,
#         "browser_trusted": browser_trusted,
#         "matches_domain": matches_domain,
#         "subject_alt_names": subject_alt_names,
#     }

# def process_tls_details(entry):
#     results = []
#     data = entry.get("data", {})
#     for proto in ["imap", "smtp", "pop3"]:
#         proto_data = data.get(proto)
#         if proto_data and proto_data.get("status") == "success":
#             host = entry.get("domain") or entry.get("host") or entry.get("ip")
#             port = proto_data.get("port")
#             print(f"\n✅ 成功连接: {host}:{port}")

#             # ===== 修正：获取整个 server_certificates 对象 =====
#             server_certificates = (
#                 proto_data.get("result", {})
#                 .get("tls", {})
#                 .get("handshake_log", {})
#                 .get("server_certificates", {})
#             )
            
#             # 先检查 server_certificates 是否存在
#             if not server_certificates:
#                 print("⚠️ 未找到 server_certificates 信息")
#                 continue
                
#             # 然后获取 certificate
#             certificate = server_certificates.get("certificate", {})
#             if not certificate:
#                 print("⚠️ 未找到 certificate 信息")
#                 continue

#             # 修正：传递 server_certificates 数据来获取 validation
#             cert_info = parse_cert_details(certificate, server_certificates)
#             result = {
#                 "host": host,
#                 "port": port,
#                 "protocol": proto,
#                 **cert_info,
#             }

#             # 打印到控制台
#             print(f"🔹 证书版本: {cert_info['version']}")
#             print(f"🔹 序列号: {cert_info['serial_number']}")
#             print(f"🔹 签名算法: {cert_info['signature_algorithm']}")
#             print(f"🔹 签发者: {cert_info['issuer']}")
#             print(f"🔹 主体: {cert_info['subject']}")
#             print(f"🔹 有效期: {cert_info['valid_from']} → {cert_info['valid_to']}")
#             print(f"🔹 是否过期: {cert_info['expired']}")
#             print(f"🔹 是否自签名: {cert_info['self_signed']}")
#             print(f"🔹 浏览器信任: {cert_info['browser_trusted']}")
#             print(f"🔹 域名匹配: {cert_info['matches_domain']}")
#             print(f"🔹 主题备用名称: {cert_info['subject_alt_names']}")
#             print("-" * 80)

#             results.append(result)
#     return results

# def main():
#     output_path = Path(output_file)
#     if output_path.exists():
#         output_path.unlink()  # 若已存在则清空

#     with open(jsonl_file, "r", encoding="utf-8") as f_in, open(output_file, "a", encoding="utf-8") as f_out:
#         for line in f_in:
#             line = line.strip()
#             if not line:
#                 continue
#             try:
#                 entry = json.loads(line)
#             except json.JSONDecodeError:
#                 continue

#             results = process_tls_details(entry)
#             for r in results:
#                 f_out.write(json.dumps(r, ensure_ascii=False) + "\n")

#     print(f"\n✅ 所有结果已保存至: {output_file}")

# if __name__ == "__main__":
#     main()




import json
import datetime
from pathlib import Path

# ===== 输入与输出路径 =====
# jsonl_file = "/home/wzq/scan-website/zgrab2/real/pop3-995_pop3s.jsonl"
# output_file = "/home/wzq/scan-website/cmd/certreal/pop3-995_pop3s_certs.jsonl"
# jsonl_file = "/home/wzq/scan-website/zgrab2/real/imap-993_imaps.jsonl"
# output_file = "/home/wzq/scan-website/cmd/certreal/imap-993_imaps_certs.jsonl"
# jsonl_file = "/home/wzq/scan-website/zgrab2/real/smtp-465_smtps.jsonl"
# output_file = "/home/wzq/scan-website/cmd/certreal/smtp-465_smtps_certs.jsonl"
# jsonl_file = "/home/wzq/scan-website/zgrab2/real/imap-143_starttls.jsonl"
# output_file = "/home/wzq/scan-website/cmd/certreal/imap-143_starttls_certs.jsonl"
# jsonl_file = "/home/wzq/scan-website/zgrab2/real/pop3-110_starttls.jsonl"
# output_file = "/home/wzq/scan-website/cmd/certreal/pop3-110_starttls_certs.jsonl"
jsonl_file = "/home/wzq/scan-website/zgrab2/realv2/smtp-587_starttls2.jsonl"
output_file = "/home/wzq/scan-website/cmd/certreal/smtp-587_starttls2_certs.jsonl"


def parse_cert_details(cert_data, server_certificates_data):
    parsed = cert_data.get("parsed", {})
    
    # 修正：validation 在 server_certificates 的同级
    validation = server_certificates_data.get("validation", {})
    
    version = parsed.get("version")
    serial = parsed.get("serial_number")
    sig_alg = parsed.get("signature_algorithm", {}).get("name")
    
    # 使用更友好的显示格式
    issuer = parsed.get("issuer", {}).get("common_name", [""])[0] or parsed.get("issuer_dn", "")
    subject = parsed.get("subject", {}).get("common_name", [""])[0] or parsed.get("subject_dn", "")
    
    validity = parsed.get("validity", {})
    not_before = validity.get("start")
    not_after = validity.get("end")
    
    # 修正：self_signed 的正确路径是 certificate.parsed.signature.self_signed
    signature_info = parsed.get("signature", {})
    self_signed = signature_info.get("self_signed", False)
    
    # 从正确的 validation 中获取
    browser_trusted = validation.get("browser_trusted", False)
    matches_domain = validation.get("matches_domain", False)
    
    # 获取主题备用名称
    extensions = parsed.get("extensions", {})
    subject_alt_names = extensions.get("subject_alt_name", {}).get("dns_names", [])
    
    # 判断是否过期
    expired = False
    if not_after:
        try:
            end_time = datetime.datetime.fromisoformat(not_after.replace("Z", "+00:00"))
            expired = end_time < datetime.datetime.now(datetime.timezone.utc)
        except Exception:
            expired = None

    return {
        "version": version,
        "serial_number": serial,
        "signature_algorithm": sig_alg,
        "issuer": issuer,
        "subject": subject,
        "valid_from": not_before,
        "valid_to": not_after,
        "expired": expired,
        "self_signed": self_signed,
        "browser_trusted": browser_trusted,
        "matches_domain": matches_domain,
        "subject_alt_names": subject_alt_names,
    }

def process_tls_details(entry):
    results = []
    data = entry.get("data", {})
    for proto in ["imap", "smtp", "pop3"]:
        proto_data = data.get(proto)
        if proto_data and proto_data.get("status") == "success":
            host = entry.get("domain") or entry.get("host") or entry.get("ip")
            port = proto_data.get("port")
            print(f"\n✅ 成功连接: {host}:{port}")

            # 获取整个 server_certificates 对象
            server_certificates = (
                proto_data.get("result", {})
                .get("tls", {})
                .get("handshake_log", {})
                .get("server_certificates", {})
            )
            
            # 先检查 server_certificates 是否存在
            if not server_certificates:
                print("⚠️ 未找到 server_certificates 信息")
                continue
                
            # 然后获取 certificate
            certificate = server_certificates.get("certificate", {})
            if not certificate:
                print("⚠️ 未找到 certificate 信息")
                continue

            # 传递 server_certificates 数据来获取 validation
            cert_info = parse_cert_details(certificate, server_certificates)
            result = {
                "host": host,
                "port": port,
                "protocol": proto,
                **cert_info,
            }

            # 打印到控制台
            print(f"🔹 证书版本: {cert_info['version']}")
            print(f"🔹 序列号: {cert_info['serial_number']}")
            print(f"🔹 签名算法: {cert_info['signature_algorithm']}")
            print(f"🔹 签发者: {cert_info['issuer']}")
            print(f"🔹 主体: {cert_info['subject']}")
            print(f"🔹 有效期: {cert_info['valid_from']} → {cert_info['valid_to']}")
            print(f"🔹 是否过期: {cert_info['expired']}")
            print(f"🔹 是否自签名: {cert_info['self_signed']}")
            print(f"🔹 浏览器信任: {cert_info['browser_trusted']}")
            print(f"🔹 域名匹配: {cert_info['matches_domain']}")
            print(f"🔹 主题备用名称: {cert_info['subject_alt_names']}")
            print("-" * 80)

            results.append(result)
    return results

def main():
    output_path = Path(output_file)
    if output_path.exists():
        output_path.unlink()  # 若已存在则清空

    with open(jsonl_file, "r", encoding="utf-8") as f_in, open(output_file, "a", encoding="utf-8") as f_out:
        for line in f_in:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue

            results = process_tls_details(entry)
            for r in results:
                f_out.write(json.dumps(r, ensure_ascii=False) + "\n")

    print(f"\n✅ 所有结果已保存至: {output_file}")

if __name__ == "__main__":
    main()