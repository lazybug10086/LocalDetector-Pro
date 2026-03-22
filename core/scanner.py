import os
import regex as re
from concurrent.futures import ThreadPoolExecutor, as_completed
import yara
from core.entropy import calculate_shannon_entropy

# 1. 企业级规则库 (正则引擎)
RULES = {
    "Email": re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b'),
    "Phone (China)": re.compile(r'\b1[3-9]\d{9}\b'),
    "IPv4 Address": re.compile(
        r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'),
    # 增加了一个极简单的测试规则，如果你在代码里写 HACK_ME_NOW，它必中
    "Debug_Test": re.compile(r'HACK_ME_NOW'),
    "Potential Pwd/Key": re.compile(
        r'(?i)(?:pwd|password|secret|token|auth|key)\s*[:=]\s*["\']([^"\'\.\+\$]{5,64})["\']'),
}

# 2. 遍历黑名单（这些文件夹里的东西会被直接忽略）
EXCLUDE_DIRS = {'.git', 'node_modules', 'target', 'build', 'dist', '.venv', 'venv', '.idea', '__pycache__'}
# 3. 允许扫描的文件后缀
INCLUDE_EXTS = {'.java', '.js', '.py', '.vue', '.yml', '.yaml', '.properties', '.sql', '.txt'}

# 精准降噪：白名单
WHITELIST_IPS = {"127.0.0.1", "0.0.0.0", "localhost"}


class ScanWorker:
    def __init__(self, yara_rules_dir=None):
        self.yara_scanner = None

        # 批量加载整个文件夹的 YARA 规则
        if yara_rules_dir and os.path.exists(yara_rules_dir):
            rule_files = {}
            for root, _, files in os.walk(yara_rules_dir):
                for file in files:
                    if file.endswith('.yar') or file.endswith('.yara'):
                        file_path = os.path.join(root, file)
                        rule_files[file] = file_path

            if rule_files:
                try:
                    # 编译 YARA 规则
                    self.yara_scanner = yara.compile(filepaths=rule_files)
                except Exception as e:
                    print(f"[!] YARA 编译失败: {e}")

    def scan_file(self, file_path):
        """线程执行的文件扫描逻辑"""
        findings = []
        try:
            # 调试信息：你可以取消下面这行的注释来查看程序是否真的读取了该文件
            # print(f"--- 正在审计文件: {os.path.basename(file_path)} ---")

            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            if not content: return []
            seen_in_file = set()

            # --- A. 正则引擎 ---
            for rule_name, pattern in RULES.items():
                for match in pattern.findall(content):
                    if isinstance(match, tuple): match = match[0]

                    # 过滤逻辑
                    if rule_name == "IPv4 Address" and (
                            match in WHITELIST_IPS or match.startswith("10.") or match.startswith("192.168.")): continue

                    unique_key = f"Regex:{rule_name}:{match}"
                    if unique_key not in seen_in_file:
                        seen_in_file.add(unique_key)
                        findings.append(("Regex", rule_name, file_path, match))

            # --- B. 启发式引擎 (信息熵) ---
            # 匹配 16-64 位的随机字符串
            potential_secrets = re.findall(r'[\'"]([A-Za-z0-9+/=_-]{16,64})[\'"]', content)
            for secret in potential_secrets:
                ent_val = calculate_shannon_entropy(secret)
                if ent_val > 4.5:  # 稍微调低了一点点门槛
                    unique_key = f"Entropy:{secret}"
                    if unique_key not in seen_in_file:
                        seen_in_file.add(unique_key)
                        findings.append(("Heuristic", f"High Entropy (Val: {round(ent_val, 2)})", file_path, secret))

                        # --- C. YARA 引擎 ---
                        if self.yara_scanner:
                            try:
                                # 直接传 content 给 YARA 匹配
                                matches = self.yara_scanner.match(data=content)
                                for match in matches:
                                    risk_name = match.meta.get('description', match.rule) if hasattr(match,
                                                                                                     'meta') else match.rule

                                    # 安全提取匹配到的危险字符串 (防崩溃机制)
                                    match_text = "YARA Matched"
                                    if match.strings:
                                        s = match.strings[0]
                                        # 兼容不同版本的 yara-python 返回格式
                                        if isinstance(s, tuple) and len(s) >= 3:
                                            match_text = s[2].decode('utf-8', errors='ignore') if isinstance(s[2],
                                                                                                             bytes) else str(
                                                s[2])
                                        else:
                                            match_text = str(s)

                                    unique_key = f"YARA:{match.rule}:{match_text}"
                                    if unique_key not in seen_in_file:
                                        seen_in_file.add(unique_key)
                                        findings.append(("YARA", f"Rule: {risk_name}", file_path, match_text))
                            except Exception as yara_err:
                                # 如果 YARA 内部报错，强制打印到后台终端，不再默默吞掉
                                print(f"[!] YARA 解析出错 ({file_path}): {yara_err}")

        except Exception:
            pass  # 忽略读取权限等问题

        return findings


def start_multi_process_scan(target_path, log_callback, progress_callback, yara_rules_dir):
    """主控函数：使用多线程 ThreadPoolExecutor"""
    log_callback(f"[*] 启动审计引擎 (路径: {target_path})", "INFO")

    # 1. 极速遍历文件
    files_to_scan = []
    for root, dirs, files in os.walk(target_path):
        # 实时剔除排除目录
        dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
        for file in files:
            # 检查后缀名是否在允许列表内
            if any(file.lower().endswith(ext) for ext in INCLUDE_EXTS):
                files_to_scan.append(os.path.join(root, file))

    total_files = len(files_to_scan)
    log_callback(f"[*] 索引完成！发现 {total_files} 个有效待扫文件。", "INFO")

    if total_files == 0:
        log_callback(f"[!] 未发现任何符合后缀名的文件，请检查路径和后缀配置。", "WARNING")
        return []

    # 2. 初始化加载器
    worker_instance = ScanWorker(yara_rules_dir)
    if worker_instance.yara_scanner:
        log_callback(f"[*] YARA 规则库加载成功，已进入深度审计模式。", "SUCCESS")

    all_findings = []
    files_processed = 0

    # 3. 启动线程池（Windows 下线程池比进程池更稳定且支持 YARA）
    with ThreadPoolExecutor(max_workers=os.cpu_count() or 4) as executor:
        future_to_file = {executor.submit(worker_instance.scan_file, f): f for f in files_to_scan}

        for future in as_completed(future_to_file):
            try:
                result = future.result()
                if result:
                    all_findings.extend(result)
                    for f_type, r_type, f_path, match_text in result:
                        tag = "YARA" if f_type == "YARA" else "WARNING"
                        log_callback(f"[{f_type}] {r_type} -> {os.path.basename(f_path)}", tag)
            except Exception as e:
                log_callback(f"[!] 扫描出错: {e}", "WARNING")

            files_processed += 1
            progress_callback(files_processed / total_files, files_processed, total_files)

    log_callback("-" * 30, "INFO")
    log_callback(f"[*] 审计结束，共发现 {len(all_findings)} 处潜在风险。", "SUCCESS")
    return all_findings