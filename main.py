# main.py - 应用入口启动文件
import sys
import os

# 确保能找到 core 和 ui 模块
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from ui.app import AdvancedDetectorUI

if __name__ == "__main__":
    # CustomTkinter 建议在这里设置应用
    app = AdvancedDetectorUI()
    app.mainloop()