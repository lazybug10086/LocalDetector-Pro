# -*- coding: utf-8 -*-
"""
LocalDetector Pro - 核心扫描引擎 (Core Scanner Engine)
======================================================
该模块实现了多线程/多进程驱动的混合安全审计逻辑。
包含三大核心引擎：
1. 启发式信息熵引擎 (Heuristic Entropy Engine)
2. 深度正则特征引擎 (Deep Regex Pattern Engine)
3. YARA 二进制与结构化特征引擎 (YARA Rule Engine)

Author: LocalDetector Security Team
Version: 1.0.0
"""

import os
import re
import math
import fnmatch
import logging
from typing import List, Tuple, Set, Dict, Optional
import concurrent.futures

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False


# =====================================================================
# [配置区] 全局默认忽略目录与后缀 (防干扰降噪系统)
# =====================================================================
DEFAULT_IGNORE_DIRS = {
    '.git', '.svn', '.hg', '.idea', '.vscode', 'node_modules',
    'venv', '.venv', 'env', '__pycache__', 'dist', 'build', 'target',
    'vendor', 'bower_components', 'logs', 'tmp', 'temp', 'cache'
}

DEFAULT_IGNORE_EXTS = {
    # 图像与媒体
    '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.ico', '.svg', '.webp',
    '.mp3', '.mp4', '.avi', '.mov', '.wav', '.flv',
    # 压缩包与二进制文件
    '.zip', '.tar', '.gz', '.rar', '.7z', '.bz2', '.iso',
    '.exe', '.dll', '.so', '.dylib', '.bin', '.dat', '.db', '.sqlite',
    # 办公文档与字体
    '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
    '.ttf', '.otf', '.woff', '.woff2', '.eot'
}

# =====================================================================
# [规则区] 企业级云原生与第三方 API 凭证正则库 (Regex Vault)
# 包含目前市面上主流云服务、SaaS 平台的硬编码特征库
# =====================================================================
REGEX_VAULT: Dict[str, re.Pattern] = {
    # ---- 1. 基础网络与凭证特征 ----
    "IPv4 Address": re.compile(
        r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    ),
    "Email Address": re.compile(
        r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b'
    ),
    "Phone Number (China)": re.compile(
        r'\b(?:(?:\+|00)86)?1[3-9]\d{9}\b'
    ),
    "Generic Password/Secret Key": re.compile(
        r'(?i)(?:password|passwd|pwd|secret|token|api_key|apikey|access_key)[\s]*[:=]+[\s]*["\']([^"\']{6,})["\']'
    ),

    # ---- 2. 国际主流云服务 (AWS/Azure/GCP) ----
    "AWS Access Key ID": re.compile(r'(?i)\b(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b'),
    "AWS Secret Access Key": re.compile(r'(?i)(?:aws_secret|aws_secret_access_key)[\s]*[:=][\s]*["\']?[A-Za-z0-9/+=]{40}["\']?'),
    "Google Cloud API Key": re.compile(r'(?i)\bAIza[0-9A-Za-z\\-_]{35}\b'),
    "Google OAuth Client ID": re.compile(r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com'),
    "Azure Storage Account Key": re.compile(r'(?i)AccountKey=[a-zA-Z0-9+/=]{80,120}'),
    
    # ---- 3. 国内主流云服务 (Alibaba/Tencent/Baidu) ----
    "Alibaba Cloud AccessKey ID": re.compile(r'(?i)\bLTAI[A-Za-z0-9]{20}\b'),
    "Alibaba Cloud SecretKey": re.compile(r'(?i)(?:aliyun|alibaba).*?(?:secret|key)[\s]*[:=][\s]*["\']?[A-Za-z0-9]{30}["\']?'),
    "Tencent Cloud SecretId": re.compile(r'(?i)\bAKID[A-Za-z0-9]{32}\b'),
    "Baidu Cloud Access Key": re.compile(r'(?i)\b(?:bd|baidu).*?(?:ak|access_key)[\s]*[:=][\s]*["\']?[A-Za-z0-9]{32}["\']?'),

    # ---- 4. 代码托管与协作平台 (GitHub/GitLab/Slack) ----
    "GitHub Personal Access Token": re.compile(r'(?i)\bgh[pousr]_[A-Za-z0-9_]{36,255}\b'),
    "GitHub OAuth Access Token": re.compile(r'(?i)\bgho_[a-zA-Z0-9]{36}\b'),
    "GitLab Personal Access Token": re.compile(r'(?i)\bglpat-[a-zA-Z0-9\-=_]{20,22}\b'),
    "Slack Bot Token": re.compile(r'(?i)xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}'),
    "Slack Webhook URL": re.compile(r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8,10}/[a-zA-Z0-9_]{24}'),

    # ---- 5. 支付与通讯服务 (Stripe/Twilio/Mailgun) ----
    "Stripe Standard API Key": re.compile(r'(?i)sk_(?:live|test)_[0-9a-zA-Z]{24}'),
    "Stripe Restricted API Key": re.compile(r'(?i)rk_(?:live|test)_[0-9a-zA-Z]{24,99}'),
    "Twilio API Key": re.compile(r'(?i)SK[0-9a-fA-F]{32}'),
    "Mailgun API Key": re.compile(r'(?i)key-[0-9a-zA-Z]{32}'),
    "SendGrid API Key": re.compile(r'(?i)SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}'),

    # ---- 6. 身份验证与加密基础设施 (RSA/PGP/JWT) ----
    "RSA Private Key Base64 Block": re.compile(r'-----BEGIN RSA PRIVATE KEY-----[a-zA-Z0-9\+/\n\r=]+-----END RSA PRIVATE KEY-----'),
    "OpenSSH Private Key Block": re.compile(r'-----BEGIN OPENSSH PRIVATE KEY-----[a-zA-Z0-9\+/\n\r=]+-----END OPENSSH PRIVATE KEY-----'),
    "PGP Private Key Block": re.compile(r'-----BEGIN PGP PRIVATE KEY BLOCK-----[a-zA-Z0-9\+/\n\r=]+-----END PGP PRIVATE KEY BLOCK-----'),
    "JSON Web Token (JWT)": re.compile(r'\beyJ[a-zA-Z0-9\-_]+\.eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\b')
}


# =====================================================================
# [引擎模块] 启发式信息熵分析器
# =====================================================================
class EntropyAnalyzer:
    """
    高级信息熵分析器 (Advanced Entropy Analyzer)。
    通过数学统计方法（香农熵）检测代码中隐藏的高随机性加密凭证。
    能够有效识别脱离了标准上下文、未被正则捕获的 Base64 Token 或 Hex 密钥。
    """

    @staticmethod
    def calculate_shannon_entropy(data: str) -> float:
        """
        计算给定字符串的香农信息熵。
        熵值越高，代表字符串越混乱、越随机，是加密密钥或哈希值的概率越大。
        
        公式: H = - Σ P(x) * log2(P(x))
        
        Args:
            data (str): 需要计算熵值的字符串
            
        Returns:
            float: 计算得出的熵值 (通常在 0 到 8 之间)
        """
        if not data:
            return 0.0
            
        entropy = 0.0
        length = len(data)
        char_counts = {}
        
        # 统计字符频次
        for char in data:
            char_counts[char] = char_counts.get(char, 0) + 1
            
        # 套用香农熵公式
        for count in char_counts.values():
            probability = count / length
            entropy -= probability * math.log2(probability)
            
        return entropy

    @classmethod
    def analyze_line(cls, line: str, threshold: float = 4.8) -> Optional[Tuple[float, str]]:
        """
        对单行代码进行结构切分，提取连续的纯字符序列并计算其信息熵。
        
        Args:
            line (str): 代码行
            threshold (float): 报警阈值，默认 4.8 适合抓取 Base64 和长 Hex。
            
        Returns:
            Optional[Tuple[float, str]]: 如果发现高危熵值字符串，返回 (熵值, 危险字符串片段)，否则返回 None。
        """
        # 使用正则提取长度大于 20 的类 Base64/Hex 连续字母数字序列
        # 排除包含空格、中文字符等明显属于注释或自然语言的段落
        words = re.findall(r'[A-Za-z0-9+/=]{20,}', line)
        
        for word in words:
            entropy_val = cls.calculate_shannon_entropy(word)
            if entropy_val > threshold:
                # 排除一些极度重复但熵值异常的情况 (如 aaaaaaaaaaaaaaaaaaaa)
                unique_chars = len(set(word))
                if unique_chars > 12: 
                    return round(entropy_val, 2), word
        return None


# =====================================================================
# [引擎模块] 核心本地扫描调度器
# =====================================================================
class LocalScanner:
    """
    混合式本地代码安全扫描器。
    协调文件 I/O、路径过滤、多线程调度以及三种安全分析引擎的执行。
    """

    def __init__(self, target_dir: str, rules_dir: str, log_callback=None):
        """
        初始化扫描器。
        
        Args:
            target_dir (str): 需要扫描的目标项目根目录绝对路径
            rules_dir (str): YARA 规则文件所在目录
            log_callback (callable): UI 层的日志回显回调函数
        """
        self.target_dir = os.path.abspath(target_dir)
        self.rules_dir = os.path.abspath(rules_dir)
        self.log_callback = log_callback
        
        self.yara_scanner = None
        self.ignore_patterns: List[str] = []
        
        # 扫描统计与结果收集
        self.findings: List[Tuple[str, str, str, str]] = [] # [(Engine, RiskType, FilePath, Snippet)]
        self.scanned_files_count = 0
        
        self._initialize_engines()

    def _log(self, message: str):
        """内部日志路由"""
        if self.log_callback:
            self.log_callback(message)
        else:
            print(message)

    def _initialize_engines(self):
        """
        引擎启动前的初始化流水线。
        1. 解析 .scanignore 白名单配置
        2. 编译并加载 YARA 规则库
        """
        self._log("[*] 引擎初始化流水线启动...")
        self._parse_ignore_file()
        self._load_yara_rules()

    def _parse_ignore_file(self):
        """
        尝试在目标根目录下寻找并解析 .scanignore 文件。
        兼容类似于 .gitignore 的通配符语法。
        """
        ignore_path = os.path.join(self.target_dir, '.scanignore')
        if os.path.exists(ignore_path):
            self._log(f"[*] 发现自定义白名单配置: {ignore_path}")
            try:
                with open(ignore_path, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            self.ignore_patterns.append(line)
            except Exception as e:
                self._log(f"[!] 读取 .scanignore 失败: {e}")
        else:
            self._log("[*] 未发现 .scanignore，将采用系统默认严格降噪模式。")

    def _load_yara_rules(self):
        """
        加载并预编译 rules 目录下的所有 .yar / .yara 规则。
        """
        if not YARA_AVAILABLE:
            self._log("[!] 严重警告: yara-python 库未安装，YARA 深度特征引擎将被禁用！")
            return

        rule_files = {}
        if not os.path.exists(self.rules_dir):
            self._log(f"[!] 找不到规则目录: {self.rules_dir}")
            return

        for root_dir, _, files in os.walk(self.rules_dir):
            for file in files:
                if file.endswith('.yar') or file.endswith('.yara'):
                    file_path = os.path.join(root_dir, file)
                    # 命名空间处理，防止多文件规则冲突
                    namespace = os.path.splitext(file)[0]
                    rule_files[namespace] = file_path

        if not rule_files:
            self._log(f"[!] 警告: 在 {self.rules_dir} 中没有找到任何有效的 YARA 规则文件。")
            return

        try:
            self.yara_scanner = yara.compile(filepaths=rule_files)
            self._log(f"[*] YARA 引擎加载成功！共载入 {len(rule_files)} 个规则集。")
        except yara.SyntaxError as e:
            self._log(f"[!] YARA 规则语法编译错误:\n{e}")
        except Exception as e:
            self._log(f"[!] YARA 引擎初始化出现未知异常:\n{e}")

    def is_file_ignored(self, file_path: str, file_name: str) -> bool:
        """
        综合路径拦截器。判断某文件是否应当被排除在扫描之外。
        
        Args:
            file_path (str): 文件的完整绝对路径
            file_name (str): 仅文件名称
            
        Returns:
            bool: True 表示应被忽略，False 表示放行扫描
        """
        # 1. 基础扩展名黑名单过滤
        ext = os.path.splitext(file_name)[1].lower()
        if ext in DEFAULT_IGNORE_EXTS:
            return True
            
        # 2. 基础目录黑名单过滤 (路径中包含非法目录名)
        path_parts = set(file_path.replace('\\', '/').split('/'))
        if path_parts.intersection(DEFAULT_IGNORE_DIRS):
            return True
            
        # 3. 用户自定义 .scanignore 规则过滤
        rel_path = os.path.relpath(file_path, self.target_dir).replace('\\', '/')
        for pattern in self.ignore_patterns:
            if fnmatch.fnmatch(rel_path, pattern) or fnmatch.fnmatch(file_name, pattern):
                return True
                
        return False

    def build_scan_index(self) -> List[str]:
        """
        遍历目标项目，构建待扫描文件索引表。
        
        Returns:
            List[str]: 所有符合扫描要求的绝对路径列表
        """
        target_files = []
        for root_dir, dirs, files in os.walk(self.target_dir):
            # 动态修改 dirs 列表，防止 os.walk 进入被忽略的目录，极大提升索引速度
            dirs[:] = [d for d in dirs if d not in DEFAULT_IGNORE_DIRS]
            
            for file in files:
                full_path = os.path.join(root_dir, file)
                if not self.is_file_ignored(full_path, file):
                    target_files.append(full_path)
                    
        return target_files

    def analyze_single_file(self, file_path: str) -> List[Tuple[str, str, str, str]]:
        """
        审计引擎调度核心。对单一文件依次执行正则、信息熵与 YARA 匹配。
        
        Args:
            file_path (str): 待扫描文件路径
            
        Returns:
            List: 发现的安全隐患列表
        """
        local_findings = []
        seen_fingerprints = set() # 防止同一行代码触发多次相同的报警
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                
            if not content.strip():
                return local_findings

            lines = content.splitlines()

            # ==========================================
            # 引擎 A: 正则表达式匹配引擎 (Line by Line)
            # ==========================================
            for line_no, line in enumerate(lines, 1):
                # 过滤掉过长的行 (如前端压缩后的代码)，防止正则 ReDoS 拒绝服务攻击
                if len(line) > 1000:
                    continue
                    
                for risk_name, pattern in REGEX_VAULT.items():
                    matches = pattern.findall(line)
                    for match in matches:
                        # 格式化匹配内容
                        if isinstance(match, tuple):
                            match_str = match[0]
                        else:
                            match_str = match
                            
                        # 截取危险上下文用于报告展示
                        snippet = match_str[:100] + "..." if len(match_str) > 100 else match_str
                        fingerprint = f"Regex:{risk_name}:{snippet}"
                        
                        if fingerprint not in seen_fingerprints:
                            seen_fingerprints.add(fingerprint)
                            local_findings.append(("Regex", risk_name, f"{file_path} (Line {line_no})", snippet))

            # ==========================================
            # 引擎 B: 启发式信息熵分析 (Line by Line)
            # ==========================================
            for line_no, line in enumerate(lines, 1):
                if len(line) > 1000:
                    continue
                    
                entropy_result = EntropyAnalyzer.analyze_line(line)
                if entropy_result:
                    entropy_val, bad_str = entropy_result
                    snippet = bad_str[:50] + "..." if len(bad_str) > 50 else bad_str
                    fingerprint = f"Entropy:{snippet}"
                    
                    if fingerprint not in seen_fingerprints:
                        seen_fingerprints.add(fingerprint)
                        local_findings.append(
                            ("Heuristic", f"High Entropy (Val: {entropy_val})", f"{file_path} (Line {line_no})", snippet)
                        )

            # ==========================================
            # 引擎 C: YARA 二进制结构匹配 (Whole File)
            # ==========================================
            if self.yara_scanner:
                try:
                    # YARA 直接扫描文件整体内容，便于处理多行结构或二进制魔数
                    yara_matches = self.yara_scanner.match(data=content)
                    for match in yara_matches:
                        # 提取规则名称或描述
                        risk_name = match.meta.get('description', match.rule) if hasattr(match, 'meta') else match.rule
                        
                        # 安全提取匹配到底层的危险字符串
                        match_text = "YARA Struct Matched"
                        if match.strings:
                            first_string = match.strings[0]
                            if isinstance(first_string, tuple) and len(first_string) >= 3:
                                raw_bytes = first_string[2]
                                match_text = raw_bytes.decode('utf-8', errors='ignore') if isinstance(raw_bytes, bytes) else str(raw_bytes)
                            else:
                                match_text = str(first_string)
                                
                        snippet = match_text[:100] + "..." if len(match_text) > 100 else match_text
                        fingerprint = f"YARA:{match.rule}:{snippet}"
                        
                        if fingerprint not in seen_fingerprints:
                            seen_fingerprints.add(fingerprint)
                            local_findings.append(("YARA", f"Rule: {risk_name}", file_path, snippet))
                            
                except Exception as yara_err:
                    self._log(f"[!] YARA 引擎在解析 {file_path} 时发生内部错误: {yara_err}")

        except Exception as e:
            # 捕获文件读取权限或特殊编码错误
            self._log(f"[!] 无法读取文件 {file_path}: {e}")
            
        return local_findings

    def start_scan(self):
        """
        触发完整扫描任务。
        使用动态线程池架构并发处理文件 I/O，极大提升扫描吞吐量。
        """
        self._log(f"[*] 正在构建文件索引... 路径: {self.target_dir}")
        target_files = self.build_scan_index()
        self.scanned_files_count = len(target_files)
        
        if not target_files:
            self._log("[-] 未发现需要扫描的文件。可能是目录为空，或全部被忽略规则过滤。")
            return

        self._log(f"[*] 索引完成！共发现 {self.scanned_files_count} 个有效待扫文件。")
        self._log(f"[*] 多线程并发引擎启动，配置最大 Worker 数量: {os.cpu_count()}")
        self._log("-" * 50)

        # 根据 CPU 核心数动态分配线程池
        max_workers = min(32, (os.cpu_count() or 1) * 4)
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            # 将分析任务分发到线程池
            future_to_file = {executor.submit(self.analyze_single_file, path): path for path in target_files}
            
            for future in concurrent.futures.as_completed(future_to_file):
                file_path = future_to_file[future]
                try:
                    file_findings = future.result()
                    if file_findings:
                        self.findings.extend(file_findings)
                        # 实时回显报警信息
                        for engine, risk, path, _ in file_findings:
                            # 简化路径显示，避免终端过长
                            display_path = os.path.relpath(path.split(' (Line')[0], self.target_dir)
                            line_info = ""
                            if " (Line " in path:
                                line_info = path.split(" (Line ")[1].replace(")", "")
                                line_info = f":{line_info}"
                            self._log(f"[{engine}] {risk} -> {display_path}{line_info}")
                            
                except Exception as exc:
                    self._log(f"[!] 线程调度异常 {file_path} generated an exception: {exc}")

        self._log("-" * 50)
        self._log(f"[*] 审计任务结束。共耗时极短，发现 {len(self.findings)} 处潜在安全风险。")
