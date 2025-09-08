import argparse
import asyncio
import ipaddress
import socket
import sys
import os

# 兼容 PyInstaller 资源查找
def resource_path(relative_path):
    if hasattr(sys, '_MEIPASS'):
        return os.path.join(sys._MEIPASS, relative_path)
    return os.path.join(os.path.abspath("."), relative_path)
import urllib.request
import json
import concurrent.futures
from typing import List, Optional
import tkinter as tk
from tkinter import ttk, messagebox
import threading
import platform
import time
import random
import pystray
from PIL import Image, ImageDraw



def get_default_net() -> str:
    """自动检测本机 IP 的前两位，返回类似 '10.87.0.0/16' 的网段字符串。"""
    try:
        # 获取本机 IP（排除回环地址）
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        local_ip = s.getsockname()[0]
        s.close()
    except Exception:
        local_ip = "127.0.0.1"
    parts = local_ip.split('.')
    if len(parts) >= 2 and parts[0] != "127":
        net = f"{parts[0]}.{parts[1]}.0.0/16"
    else:
        net = "10.87.0.0/16"  # 回退默认
    return net

DEFAULT_NET = get_default_net()
DEFAULT_PORT = 7890

async def check_host(ip: str, port: int, timeout: float, sem: asyncio.Semaphore) -> Optional[str]:
    """尝试 TCP 连接 ip:port，成功返回 IP 字符串，失败返回 None。"""
    try:
        async with sem:
            conn = asyncio.open_connection(ip, port)
            reader, writer = await asyncio.wait_for(conn, timeout=timeout)
            writer.close()
            # Python 3.7+ 的正确关闭方式
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return ip
    except Exception:
        return None

def check_host_sync(ip: str, port: int, timeout: float) -> bool:
    """同步检测端口是否开放，成功返回 True，否则 False。"""
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except Exception:
        return False

def iter_ips(start: Optional[str], end: Optional[str]) -> List[str]:
    """生成需要扫描的 IP 列表，并随机打乱顺序。"""
    if start and end:
        start_ip = int(ipaddress.IPv4Address(start))
        end_ip = int(ipaddress.IPv4Address(end))
        if start_ip > end_ip:
            start_ip, end_ip = end_ip, start_ip
        ip_list = [str(ipaddress.IPv4Address(i)) for i in range(start_ip, end_ip + 1)]
    else:
        net_str = get_default_net()
        net = ipaddress.IPv4Network(net_str, strict=False)
        ip_list = [str(ip) for ip in net.hosts()]
    random.shuffle(ip_list)
    return ip_list

async def scan_ips(ips: List[str], port: int, concurrency: int, timeout: float) -> List[str]:
    sem = asyncio.Semaphore(concurrency)
    tasks = [asyncio.create_task(check_host(ip, port, timeout, sem)) for ip in ips]
    open_hosts: List[str] = []
    total = len(tasks)
    # 使用 tqdm 显示进度条
    iterator = asyncio.as_completed(tasks)
    for fut in iterator:
        res = await fut
        if res:
            open_hosts.append(res)
    return sorted(open_hosts, key=lambda ip: tuple(map(int, ip.split('.'))))

def test_proxy(ip: str, port: int, timeout: float = 3.0):
    """尝试用 ip:port 作为 HTTP 代理访问 ip-api.com，成功返回 (公网IP, 地理位置)，失败返回 None。"""
    proxy_handler = urllib.request.ProxyHandler({
        'http': f'http://{ip}:{port}',
        'https': f'http://{ip}:{port}',
    })
    opener = urllib.request.build_opener(proxy_handler)
    opener.addheaders = [('User-Agent', 'Mozilla/5.0')]
    try:
        with opener.open('http://ip-api.com/json', timeout=timeout) as resp:
            data = resp.read()
            info = json.loads(data)
            if info.get('status') == 'success':
                ip_addr = info.get('query', '')
                country = info.get('country', '')
                region = info.get('regionName', '')
                city = info.get('city', '')
                location = f"{country} {region} {city}".strip()
                return ip_addr, location
    except Exception:
        return None

def parse_args():
    p = argparse.ArgumentParser(description="扫描 10.87.*.* 的 TCP 7890 端口")
    p.add_argument("--start", help="起始 IP（含），如 10.87.0.0", default=None)
    p.add_argument("--end", help="结束 IP（含），如 10.87.255.255", default=None)
    p.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"端口（默认 {DEFAULT_PORT}）")
    p.add_argument("--concurrency", type=int, default=600, help="最大并发（默认 600）")
    p.add_argument("--timeout", type=float, default=0.8, help="连接超时秒（默认 0.8）")
    p.add_argument("-o", "--output", help="将开放主机写入文件", default=None)
    return p.parse_args()

if platform.system() == "Windows":
    import winreg

class ScanApp:
    def __init__(self, master):
        self.master = master
        master.title("7890 Scanner")
        master.geometry("800x600")

        # 参数区
        frm_top = tk.Frame(master)
        frm_top.pack(fill=tk.X, padx=10, pady=5)

        # 删除起始IP和结束IP输入框，只显示扫描网段
        tk.Label(frm_top, text=f"扫描网段: {DEFAULT_NET}").pack(side=tk.LEFT, padx=5)
        tk.Label(frm_top, text="端口:").pack(side=tk.LEFT)
        self.port_entry = tk.Entry(frm_top, width=6)
        self.port_entry.insert(0, str(DEFAULT_PORT))
        self.port_entry.pack(side=tk.LEFT)
        tk.Label(frm_top, text="并发:").pack(side=tk.LEFT)
        self.conc_entry = tk.Entry(frm_top, width=6)
        self.conc_entry.insert(0, "600")
        self.conc_entry.pack(side=tk.LEFT)
        tk.Label(frm_top, text="超时:").pack(side=tk.LEFT)
        self.timeout_entry = tk.Entry(frm_top, width=6)
        self.timeout_entry.insert(0, "0.5")
        self.timeout_entry.pack(side=tk.LEFT)

        self.scan_btn = tk.Button(frm_top, text="开始扫描", command=self.start_scan)
        self.scan_btn.pack(side=tk.LEFT, padx=10)

        # 结果区（Treeview三列表格，height=6）
        frm_mid = tk.Frame(master)
        frm_mid.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        columns = ("proxy", "pubip", "location")
        self.result_tree = ttk.Treeview(frm_mid, columns=columns, show="headings", height=6)
        self.result_tree.heading("proxy", text="代理地址")
        self.result_tree.heading("pubip", text="公网IP")
        self.result_tree.heading("location", text="地理位置")
        self.result_tree.column("proxy", width=180, anchor="center")
        self.result_tree.column("pubip", width=140, anchor="center")
        self.result_tree.column("location", width=320, anchor="w")
        self.result_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar = tk.Scrollbar(frm_mid, command=self.result_tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.result_tree.config(yscrollcommand=scrollbar.set)

        # 右键菜单
        self.proxy_menu = tk.Menu(self.result_tree, tearoff=0)
        self.proxy_menu.add_command(label="设为代理", command=self.set_selected_proxy)

        self.result_tree.bind("<Button-3>", self.show_proxy_menu)

        # 进度条
        frm_prog = tk.Frame(master)
        frm_prog.pack(fill=tk.X, padx=10, pady=2)
        self.progress = ttk.Progressbar(frm_prog, orient="horizontal", length=400, mode="determinate")
        self.progress.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.progress["value"] = 0
        self.progress["maximum"] = 100
        self.progress_label = tk.Label(frm_prog, text="进度: 0%")
        self.progress_label.pack(side=tk.LEFT, padx=10)

        # 状态栏（仅显示扫描状态）
        self.status_var = tk.StringVar()
        self.status_var.set("准备就绪")
        status_bar = tk.Label(master, textvariable=self.status_var, anchor="w")
        status_bar.pack(fill=tk.X, padx=10, pady=2)

        # 代理控制按钮区
        frm_proxy = tk.Frame(master)
        frm_proxy.pack(fill=tk.X, padx=10, pady=2)
        self.start_proxy_btn = tk.Button(frm_proxy, text="启动代理", command=self.enable_proxy, state=tk.DISABLED)
        self.start_proxy_btn.pack(side=tk.LEFT, padx=5)
        self.stop_proxy_btn = tk.Button(frm_proxy, text="停止代理", command=self.disable_proxy, state=tk.DISABLED)
        self.stop_proxy_btn.pack(side=tk.LEFT, padx=5)
        self.auto_scan_running = False
        self.auto_scan_btn = tk.Button(frm_proxy, text="自动扫挂", command=self.toggle_auto_scan)
        self.auto_scan_btn.pack(side=tk.LEFT, padx=5)
        self.hide_btn = tk.Button(frm_proxy, text="隐藏到菜单栏", command=self.hide_to_tray)
        self.hide_btn.pack(side=tk.LEFT, padx=5)
        self.current_proxy = None

        # 新增：倒计时标签
        self.countdown_var = tk.StringVar()
        self.countdown_var.set("")
        countdown_label = tk.Label(frm_proxy, textvariable=self.countdown_var, anchor="w", fg="red")
        countdown_label.pack(side=tk.LEFT, padx=15)

        # 新增：代理选择标签
        self.proxy_var = tk.StringVar()
        self.proxy_var.set("未选择代理")
        proxy_label = tk.Label(frm_proxy, textvariable=self.proxy_var, anchor="w", fg="blue")
        proxy_label.pack(side=tk.LEFT, padx=15)

        # 新增：代理状态标签
        self.proxy_status_var = tk.StringVar()
        self.proxy_status_var.set("")
        proxy_status_label = tk.Label(frm_proxy, textvariable=self.proxy_status_var, anchor="w", fg="green")
        proxy_status_label.pack(side=tk.LEFT, padx=15)

        self.results = []

    def show_proxy_menu(self, event):
        item = self.result_tree.identify_row(event.y)
        if item:
            self.result_tree.selection_set(item)
            self.proxy_menu.post(event.x_root, event.y_root)

    def set_selected_proxy(self):
        selected = self.result_tree.selection()
        if not selected:
            return
        values = self.result_tree.item(selected[0], "values")
        proxy_addr = values[0]
        self.current_proxy = proxy_addr
        self.start_proxy_btn.config(state=tk.NORMAL)
        self.stop_proxy_btn.config(state=tk.NORMAL)
        self.proxy_var.set(f"已选择代理: {proxy_addr}")

    def enable_proxy(self):
        if not self.current_proxy:
            messagebox.showinfo("提示", "请先选择代理")
            return
        if platform.system() == "Windows":
            try:
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                    r"Software\Microsoft\Windows\CurrentVersion\Internet Settings", 0, winreg.KEY_SET_VALUE)
                winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1)
                winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, self.current_proxy)
                winreg.CloseKey(key)
                self.proxy_status_var.set(f"已启动系统代理: {self.current_proxy}")
            except Exception as e:
                messagebox.showerror("代理设置失败", str(e))
        else:
            messagebox.showinfo("提示", "仅支持 Windows 系统代理设置")

    def disable_proxy(self):
        if platform.system() == "Windows":
            try:
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                    r"Software\Microsoft\Windows\CurrentVersion\Internet Settings", 0, winreg.KEY_SET_VALUE)
                winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 0)
                winreg.CloseKey(key)
                self.proxy_status_var.set("已停止系统代理")
            except Exception as e:
                messagebox.showerror("代理关闭失败", str(e))
        else:
            messagebox.showinfo("提示", "仅支持 Windows 系统代理设置")

    def start_scan(self):
        if getattr(self, 'scan_thread', None) and self.scan_thread.is_alive():
            # 终止扫描
            self.stop_scan = True
            self.status_var.set("正在终止扫描...")
            return
        self.result_tree.delete(*self.result_tree.get_children())
        self.status_var.set("正在扫描...")
        self.scan_btn.config(text="终止扫描", state=tk.NORMAL)
        self.auto_scan_btn.config(state=tk.DISABLED)
        self.progress["value"] = 0
        self.progress_label.config(text="进度: 0%")
        self.results = []
        self.stop_scan = False
        self.scan_thread = threading.Thread(target=self.scan_and_test_batch_thread, daemon=True)
        self.scan_thread.start()

    def scan_and_test_batch_thread(self):
        # 扫描前清空列表
        self.result_tree.delete(*self.result_tree.get_children())
        self.results = []
        try:
            port = int(self.port_entry.get())
            concurrency = int(self.conc_entry.get())
            timeout = float(self.timeout_entry.get())
        except Exception:
            self.status_var.set("参数错误")
            self.scan_btn.config(state=tk.NORMAL)
            return

        try:
            ips = iter_ips(None, None)
        except Exception as e:
            self.status_var.set(f"IP范围错误: {e}")
            self.scan_btn.config(state=tk.NORMAL)
            return

        total = len(ips)
        self.status_var.set(f"正在分批扫描和测试代理...（目标数：{total}）")
        self.progress["value"] = 0
        self.progress_label.config(text="进度: 0%")

        batch_size = concurrency
        batches = [ips[i:i+batch_size] for i in range(0, total, batch_size)]
        done = 0
        batch_timeout = 30  # 每批最大等待秒数

        for batch in batches:
            if getattr(self, 'stop_scan', False):
                break
            # 先同步检测端口开放
            open_ips = []
            with concurrent.futures.ThreadPoolExecutor(max_workers=batch_size) as executor:
                future_map = {executor.submit(check_host_sync, ip, port, timeout): ip for ip in batch}
                finished, unfinished = concurrent.futures.wait(
                    future_map.keys(), timeout=batch_timeout, return_when=concurrent.futures.ALL_COMPLETED
                )
                for fut in finished:
                    done += 1
                    percent = int(done / total * 100) if total else 0
                    self.progress["value"] = percent
                    self.progress_label.config(text=f"进度: {percent}%")
                    ip = future_map[fut]
                    if fut.done() and fut.result():
                        open_ips.append(ip)
                for fut in unfinished:
                    fut.cancel()
                percent = int(done / total * 100) if total else 0
                self.progress["value"] = percent
                self.progress_label.config(text=f"进度: {percent}%")

            # 再并发检测代理
            if open_ips:
                with concurrent.futures.ThreadPoolExecutor(max_workers=batch_size) as executor:
                    proxy_futures = {executor.submit(test_proxy, ip, port): ip for ip in open_ips}
                    for pfut in concurrent.futures.as_completed(proxy_futures):
                        ip = proxy_futures[pfut]
                        res = pfut.result()
                        if res:
                            pub_ip, location = res
                            proxy_addr = f"{ip}:{port}"
                            self.results.append(f"{proxy_addr}  {pub_ip}  {location}")
                            self.result_tree.insert("", tk.END, values=(proxy_addr, pub_ip, location))

        self.progress["value"] = 100
        self.progress_label.config(text="进度: 100%")

        if self.results:
            self.status_var.set(f"可用代理主机数：{len(self.results)}")
        else:
            self.status_var.set("未发现可用代理主机")
        self.scan_btn.config(text="开始扫描", state=tk.NORMAL)
        self.auto_scan_btn.config(state=tk.NORMAL)

    def check_google(self, proxy_addr=None, timeout=5):
        """检测能否访问Google，支持代理（如有）"""
        try:
            if proxy_addr:
                proxy_handler = urllib.request.ProxyHandler({
                    'http': f'http://{proxy_addr}',
                    'https': f'http://{proxy_addr}',
                })
                opener = urllib.request.build_opener(proxy_handler)
            else:
                opener = urllib.request.build_opener()
            opener.addheaders = [('User-Agent', 'Mozilla/5.0')]
            with opener.open('http://www.google.com', timeout=timeout) as resp:
                if resp.status == 200:
                    return True
        except Exception:
            return False
        return False

    def toggle_auto_scan(self):
        if not self.auto_scan_running:
            self.auto_scan_running = True
            self.auto_scan_btn.config(text="停止自动扫挂")
            threading.Thread(target=self.auto_scan_thread, daemon=True).start()
        else:
            self.auto_scan_running = False
            self.auto_scan_btn.config(text="自动扫挂")
            self.status_var.set("已停止自动扫挂")

    def get_system_proxy(self):
        """获取当前系统代理（仅Windows）"""
        if platform.system() == "Windows":
            try:
                import winreg
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                     r"Software\Microsoft\Windows\CurrentVersion\Internet Settings", 0, winreg.KEY_READ)
                enabled, _ = winreg.QueryValueEx(key, "ProxyEnable")
                proxy, _ = winreg.QueryValueEx(key, "ProxyServer")
                winreg.CloseKey(key)
                if enabled and proxy:
                    return proxy
            except Exception:
                return None
        return None

    def auto_scan_thread(self):
        self.status_var.set("自动扫挂已启动")
        google_success_count = 0
        max_success_needed = 30  # 连续成功访问Google次数
        while self.auto_scan_running:
            # 检查当前系统代理能否访问Google
            proxy_addr = self.get_system_proxy()
            ok = self.check_google(proxy_addr)
            if ok and google_success_count < max_success_needed:
                google_success_count += 1
                self.status_var.set(f"Google可访问，等待10秒后重试（成功{google_success_count}/{max_success_needed}次后更换代理）")
                for sec in range(10, 0, -1):
                    self.countdown_var.set(f"倒计时：{sec}秒")
                    time.sleep(1)
                    if not self.auto_scan_running:
                        break
                self.countdown_var.set("")
                # 连续2次成功访问Google也触发扫挂
                if google_success_count >= max_success_needed:
                    self.status_var.set(f"连续{max_success_needed}次成功访问Google，强制开始扫描代理")
            else:
                google_success_count = 0
                if not ok:
                    self.status_var.set("Google不可访问，开始扫描代理")
                else:
                    self.status_var.set(f"触发强制更换代理")
                self.countdown_var.set("")
                self.scan_btn.config(state=tk.DISABLED)
                # 扫描前清空列表
                self.result_tree.delete(*self.result_tree.get_children())
                self.results = []
                found_proxy = None

                # 扫描并自动挂代理
                try:
                    port = int(self.port_entry.get())
                    concurrency = int(self.conc_entry.get())
                    timeout = float(self.timeout_entry.get())
                except Exception:
                    self.status_var.set("参数错误")
                    self.scan_btn.config(state=tk.NORMAL)
                    break

                try:
                    ips = iter_ips(None, None)
                except Exception as e:
                    self.status_var.set(f"IP范围错误: {e}")
                    self.scan_btn.config(state=tk.NORMAL)
                    break

                total = len(ips)
                batch_size = concurrency
                batches = [ips[i:i+batch_size] for i in range(0, total, batch_size)]
                done = 0
                batch_timeout = 30

                scan_stop = False
                for batch in batches:
                    if scan_stop or not self.auto_scan_running:
                        break
                    open_ips = []
                    with concurrent.futures.ThreadPoolExecutor(max_workers=batch_size) as executor:
                        future_map = {executor.submit(check_host_sync, ip, port, timeout): ip for ip in batch}
                        finished, unfinished = concurrent.futures.wait(
                            future_map.keys(), timeout=batch_timeout, return_when=concurrent.futures.ALL_COMPLETED
                        )
                        for fut in finished:
                            done += 1
                            ip = future_map[fut]
                            if fut.done() and fut.result():
                                open_ips.append(ip)
                        for fut in unfinished:
                            fut.cancel()

                    if open_ips:
                        with concurrent.futures.ThreadPoolExecutor(max_workers=batch_size) as executor:
                            proxy_futures = {executor.submit(test_proxy, ip, port): ip for ip in open_ips}
                            for pfut in concurrent.futures.as_completed(proxy_futures):
                                ip = proxy_futures[pfut]
                                res = pfut.result()
                                if res:
                                    pub_ip, location = res
                                    proxy_addr = f"{ip}:{port}"
                                    self.results.append(f"{proxy_addr}  {pub_ip}  {location}")
                                    self.result_tree.insert("", tk.END, values=(proxy_addr, pub_ip, location))
                                    # 自动挂代理
                                    self.current_proxy = proxy_addr
                                    self.proxy_var.set(f"已选择代理: {proxy_addr}")
                                    self.enable_proxy()
                                    self.status_var.set(f"已自动挂代理: {proxy_addr}")
                                    scan_stop = True
                                    break
                    # 强制刷新进度
                    percent = int(done / total * 100) if total else 0
                    self.progress["value"] = percent
                    self.progress_label.config(text=f"进度: {percent}%")

                self.progress["value"] = 100
                self.progress_label.config(text="进度: 100%")
                self.scan_btn.config(state=tk.NORMAL)
                # 挂上代理后等待10秒再检测Google
                for sec in range(10, 0, -1):
                    self.countdown_var.set(f"倒计时：{sec}秒")
                    time.sleep(1)
                    if not self.auto_scan_running:
                        break
                self.countdown_var.set("")
        self.status_var.set("自动扫挂已停止")
        self.countdown_var.set("")

    def hide_to_tray(self):
        if pystray is None:
            messagebox.showerror("缺少依赖", "请先安装 pystray 和 pillow 库")
            return
        self.master.withdraw()
        image = self._create_tray_icon()
        # 托盘菜单增加自动扫挂选项
        self.tray_menu_auto_scan_item = pystray.MenuItem(
            '启动自动扫挂' if not self.auto_scan_running else '停止自动扫挂',
            self.tray_toggle_auto_scan
        )
        menu = pystray.Menu(
            pystray.MenuItem('显示窗口', self.show_window),
            self.tray_menu_auto_scan_item,
            pystray.MenuItem('退出', self.exit_app)
        )
        self.tray_icon = pystray.Icon("ipscan", image, "7890 Scanner", menu)
        threading.Thread(target=self.tray_icon.run, daemon=True).start()

    def tray_toggle_auto_scan(self, icon, item):
        # 切换自动扫挂状态
        self.master.after(0, self.toggle_auto_scan)
        # 动态更新菜单项文本
        if self.tray_icon:
            # 重新设置菜单（pystray不支持直接修改MenuItem文本，只能重建菜单）
            self.tray_menu_auto_scan_item = pystray.MenuItem(
                '启动自动扫挂' if not self.auto_scan_running else '停止自动扫挂',
                self.tray_toggle_auto_scan
            )
            self.tray_icon.menu = pystray.Menu(
                pystray.MenuItem('显示窗口', self.show_window),
                self.tray_menu_auto_scan_item,
                pystray.MenuItem('退出', self.exit_app)
            )

    def _create_tray_icon(self):
        # 使用 icon.png 作为托盘图标
        try:
            img = Image.open(resource_path("icon.png"))
            # pystray 推荐 64x64，必要时缩放
            img = img.resize((64, 64))
            return img
        except Exception as e:
            # 失败时仍返回默认图标
            img = Image.new('RGB', (64, 64), color='white')
            d = ImageDraw.Draw(img)
            d.rectangle([8, 8, 56, 56], outline='blue', width=4)
            d.text((16, 24), "IP", fill='blue')
            return img

    def show_window(self, icon, item):
        self.master.after(0, self._restore_window)

    def _restore_window(self):
        self.master.deiconify()
        if self.tray_icon:
            self.tray_icon.stop()
            self.tray_icon = None

    def exit_app(self, icon, item):
        if self.tray_icon:
            self.tray_icon.stop()
        self.master.quit()
        sys.exit(0)

def main():
    args = parse_args()

    # 建议参数（可在命令行覆盖）
    if args.timeout == 0.8:
        args.timeout = 0.1  # 推荐更短超时
    if args.concurrency == 600:
        args.concurrency = 1200  # 推荐更高并发

    try:
        ips = iter_ips(args.start, args.end)
    except Exception as e:
        print(f"[!] 无效的 IP 或范围: {e}", file=sys.stderr)
        sys.exit(2)

    print(f"[+] 目标数：{len(ips)}  |  端口：{args.port}  |  并发：{args.concurrency}  |  超时：{args.timeout}s")
    if args.start and args.end:
        print(f"[+] 范围：{args.start} 〜 {args.end}")
    else:
        print(f"[+] 范围：{get_default_net()}（主机地址）")

    try:
        open_hosts = asyncio.run(scan_ips(ips, args.port, args.concurrency, args.timeout))
    except KeyboardInterrupt:
        print("\n[!] 已中断")
        sys.exit(130)

    if open_hosts:
        print(f"\n[+] 端口开放的主机（共 {len(open_hosts)}）：")
        for ip in open_hosts:
            print(ip)
        if args.output:
            try:
                with open(args.output, "w", encoding="utf-8") as f:
                    f.write("\n".join(open_hosts) + "\n")
                print(f"\n[+] 已写入：{args.output}")
            except Exception as e:
                print(f"[!] 写入文件失败：{e}", file=sys.stderr)
    else:
        print("\n[-] 未发现开放主机。")

    # 新增：代理检测并发加速
    valid_proxies = []
    print("\n[+] 正在检测代理功能和地理位置...")

    def proxy_task(ip):
        res = test_proxy(ip, args.port)
        if res:
            pub_ip, location = res
            return f"{ip}:{args.port}  {pub_ip}  {location}"
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=64) as executor:
        results = list(executor.map(proxy_task, open_hosts))

    for ip, line in zip(open_hosts, results):
        if line:
            valid_proxies.append(line)
            print(f"[√] {line}")
        else:
            print(f"[×] {ip}:{args.port}  不可用代理")

    if valid_proxies:
        print(f"\n[+] 可用代理主机（共 {len(valid_proxies)}）：")
        for line in valid_proxies:
            print(line)
        if args.output:
            try:
                with open(args.output, "w", encoding="utf-8") as f:
                    f.write("\n".join(valid_proxies) + "\n")
                print(f"\n[+] 已写入：{args.output}")
            except Exception as e:
                print(f"[!] 写入文件失败：{e}", file=sys.stderr)
    else:
        print("\n[-] 未发现可用代理主机。")

if __name__ == "__main__":
    root = tk.Tk()
    # 设置窗口图标为 icon.png
    try:
        from PIL import Image, ImageTk
        icon_img = Image.open(resource_path("icon.png"))
        icon_photo = ImageTk.PhotoImage(icon_img)
        root.iconphoto(True, icon_photo)
    except Exception as e:
        pass
    app = ScanApp(root)
    root.mainloop()
    # with concurrent.futures.ThreadPoolExecutor(max_workers=64) as executor:
    #     results = list(executor.map(proxy_task, open_hosts))

    # for ip, line in zip(open_hosts, results):
    #     if line:
    #         valid_proxies.append(line)
    #         print(f"[√] {line}")
    #     else:
    #         print(f"[×] {ip}:{args.port}  不可用代理")

    # if valid_proxies:
    #     print(f"\n[+] 可用代理主机（共 {len(valid_proxies)}）：")
    #     for line in valid_proxies:
    #         print(line)
    #     if args.output:
    #         try:
    #             with open(args.output, "w", encoding="utf-8") as f:
    #                 f.write("\n".join(valid_proxies) + "\n")
    #             print(f"\n[+] 已写入：{args.output}")
    #         except Exception as e:
    #             print(f"[!] 写入文件失败：{e}", file=sys.stderr)
    #
