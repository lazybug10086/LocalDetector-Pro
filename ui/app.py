import customtkinter as ctk
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext  # 挪到顶部
import threading
import csv
import os
from datetime import datetime
from core.scanner import start_multi_process_scan

# 设置外观主题
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")


class AdvancedDetectorUI(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("LocalDetector Pro v1.0 - 企业级本地安全引擎")
        self.geometry("900x680")

        # 内部变量
        self.selected_path = ctk.StringVar()
        self.findings_data = []

        # --- 统一变量名为 yara_rules_dir ---
        # 确保项目目录下确实有一个叫 rules 的文件夹
        self.yara_rules_dir = os.path.join(os.getcwd(), "rules")

        self._build_modern_ui()

    def _build_modern_ui(self):
        # 1. 顶部：标题栏
        header_label = ctk.CTkLabel(self, text="🛡️ LocalDetector Pro", font=ctk.CTkFont(size=24, weight="bold"),
                                    text_color="#2196F3")
        header_label.pack(pady=(20, 10))

        subheader_label = ctk.CTkLabel(self, text="高性能多线程扫描 · 精准降噪去重 · 专业 YARA 规则支持",
                                       font=ctk.CTkFont(size=12), text_color="gray")
        subheader_label.pack(pady=(0, 20))

        # 2. 路径选择 Frame
        path_frame = ctk.CTkFrame(self)
        path_frame.pack(fill=ctk.X, padx=20, pady=10)

        path_entry = ctk.CTkEntry(path_frame, textvariable=self.selected_path, placeholder_text="请选择本地代码目录...",
                                  width=600)
        path_entry.pack(side=ctk.LEFT, padx=(10, 5), pady=10)

        btn_browse = ctk.CTkButton(path_frame, text="📂 浏览目录", command=self.browse_folder, width=100)
        btn_browse.pack(side=ctk.LEFT, padx=5, pady=10)

        # 3. 控制与状态 Frame
        control_frame = ctk.CTkFrame(self)
        control_frame.pack(fill=ctk.X, padx=20, pady=10)

        self.btn_scan = ctk.CTkButton(control_frame, text="▶ 启动深度审计引擎", command=self.start_scan,
                                      fg_color="#4CAF50", hover_color="#3d8b40",
                                      font=ctk.CTkFont(size=14, weight="bold"), width=180, height=35)
        self.btn_scan.pack(side=ctk.LEFT, padx=(10, 10), pady=10)

        self.btn_export = ctk.CTkButton(control_frame, text="💾 导出报告 (CSV)", command=self.export_csv,
                                        state=ctk.DISABLED, fg_color="#2196F3", hover_color="#1e81d2",
                                        font=ctk.CTkFont(size=12), width=120, height=35)
        self.btn_export.pack(side=ctk.LEFT, padx=5, pady=10)

        self.progress_bar = ctk.CTkProgressBar(control_frame, width=300)
        self.progress_bar.set(0)
        self.progress_bar.pack(side=ctk.RIGHT, padx=(10, 10), pady=10)

        self.lbl_progress = ctk.CTkLabel(control_frame, text="", font=ctk.CTkFont(size=11), text_color="gray")
        self.lbl_progress.pack(side=ctk.RIGHT, pady=10)

        # 4. 底部日志：暗色终端
        log_frame = ctk.CTkFrame(self, fg_color="#121212")
        log_frame.pack(fill=ctk.BOTH, expand=True, padx=20, pady=(10, 20))

        tk.Label(log_frame, text="实时审计日志:", bg="#121212", fg="gray").pack(anchor=tk.NW, padx=5, pady=2)

        self.txt_log = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, bg="#121212", fg="#00E676",
                                                 font=("Consolas", 10), borderwidth=0, relief=tk.FLAT)
        self.txt_log.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)

        # 颜色标签
        self.txt_log.tag_config("INFO", foreground="#81D4FA")
        self.txt_log.tag_config("WARNING", foreground="#FFD54F")
        self.txt_log.tag_config("YARA", foreground="#FF8A65", background="#4d1a1a")
        self.txt_log.tag_config("SUCCESS", foreground="#81C784")
        self.txt_log.tag_config("ERROR", foreground="#FF5252")

    def browse_folder(self):
        folder = filedialog.askdirectory()
        if folder: self.selected_path.set(folder)

    def log(self, message, tag=None):
        self.after(0, self._insert_log, message, tag)

    def _insert_log(self, message, tag):
        self.txt_log.insert(tk.END, f"[{datetime.now().strftime('%H:%M:%S')}] " + str(message) + "\n", tag)
        self.txt_log.see(tk.END)

    def update_progress(self, ratio, current, total):
        self.after(0, self._set_progress, ratio, current, total)

    def _set_progress(self, ratio, current, total):
        self.progress_bar.set(ratio)
        self.lbl_progress.configure(text=f"正在分析 {current} / {total}...")

    def start_scan(self):
        target = self.selected_path.get()
        if not target or not os.path.exists(target):
            messagebox.showwarning("错误", "请选择有效的本地代码目录！")
            return

        self.btn_scan.configure(state=ctk.DISABLED, text="正在计算中...")
        self.btn_export.configure(state=ctk.DISABLED)
        self.progress_bar.set(0)
        self.lbl_progress.configure(text="正在索引中...")
        self.txt_log.delete('1.0', tk.END)
        self.findings_data = []

        threading.Thread(target=self._scan_thread_wrapper, args=(target,), daemon=True).start()

    def _scan_thread_wrapper(self, target):
        try:
            # 这里传参 self.yara_rules_dir，名字要和 __init__ 里对上
            results = start_multi_process_scan(target, self.log, self.update_progress, self.yara_rules_dir)
            self.findings_data = results
            self.after(0, self._scan_finished, results)
        except Exception as e:
            self.log(f"[!] 扫描核心出错: {e}", "ERROR")
            self.after(0, self._scan_finished, [])

    def _scan_finished(self, results):
        self.btn_scan.configure(state=ctk.NORMAL, text="▶ 启动深度审计引擎")
        self.progress_bar.set(1)
        self.lbl_progress.configure(text="审计完成！")
        if results:
            self.btn_export.configure(state=ctk.NORMAL)
            messagebox.showinfo("审计完成", f"共发现 {len(results)} 处中高风险泄漏。")
        else:
            messagebox.showinfo("干净的代码", "未发现明显的敏感信息泄漏。")

    def export_csv(self):
        if not self.findings_data: return
        default_name = f"Audit_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        file_path = filedialog.asksaveasfilename(defaultextension=".csv", initialfile=default_name,
                                                 filetypes=[("CSV Files", "*.csv")])
        if file_path:
            try:
                with open(file_path, 'w', newline='', encoding='utf-8-sig') as csvfile:
                    writer = csv.writer(csvfile)
                    writer.writerow(["引擎类型", "风险类别", "文件路径", "匹配到的敏感内容片段"])
                    writer.writerows(self.findings_data)
                self.log(f"[*] 报告已导出: {file_path}", "SUCCESS")
                messagebox.showinfo("成功", "报告已导出。")
            except Exception as e:
                messagebox.showerror("导出失败", str(e))