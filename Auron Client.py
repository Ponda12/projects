import flet as ft
from tkinter.filedialog import askopenfilename
import os, json, pyperclip, time, psutil, datetime, pyautogui
import win32api, win32gui, win32con, win32process
import ctypes
from ctypes import wintypes, WinDLL, windll
import uuid, platform, subprocess, hashlib, base64, requests
import mss, struct, threading


# variables
running = False
pid = None
h_proc = None
address = None
window = None
value = None
chat_id = None

# links
pastebin_link = "https://pastebin.com/raw/6ZkW9GgH"
bot_token = "8537133653:AAGkmkp07fl2tIJlmrZstINj7hfNP0l0JRs"

# coordinates
buy = (1636, 446)
confirm = (951, 693)
upd = (717, 367)
upd_nakl = (1009,367)
skin = (1033, 463)
cancel = (1818,99)
size = (1920, 1080)


# ctypes + oop
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
ntdll = ctypes.WinDLL('ntdll')

PROCESS_ALL_ACCESS = 0x1F0FFF
MEM_COMMIT = 0x1000
PAGE_READWRITE = 0x04
PAGE_READONLY = 0x02
PAGE_WRITECOPY = 0x08
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80

OpenProcess = kernel32.OpenProcess
VirtualQueryEx = kernel32.VirtualQueryEx
ReadProcessMemory = kernel32.ReadProcessMemory

class RECT(ctypes.Structure):
    _fields_ = [('left', ctypes.c_long), ('top', ctypes.c_long), ('right', ctypes.c_long), ('bottom', ctypes.c_long)]

class SECURITY_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("nLength", wintypes.DWORD),
        ("lpSecurityDescriptor", wintypes.LPVOID),
        ("bInheritHandle", wintypes.BOOL)
    ]

class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_ulonglong),
        ("AllocationBase", ctypes.c_ulonglong),
        ("AllocationProtect", wintypes.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]

# Functions
def load_cfg(e, page):
    global address, chat_id

    config_file = askopenfilename(title="Выберите нужный файл (.json)", filetypes=[('json file', '*.json'), ('all files', '*.*')])

    with open(config_file, "r", encoding="utf-8") as f:
        config = json.load(f)
    address = int(config["address"], 16)
    chat_id = config["chat_id"]

    PRIMARY_COLOR = ft.Colors.CYAN_400
    SECONDARY_COLOR = ft.Colors.GREY_400
    CARD_COLOR = ft.Colors.GREY_900
    TEXT_COLOR = ft.Colors.WHITE

    close_button = ft.Container(
        content=ft.Text("Закрыть", color=TEXT_COLOR, weight=ft.FontWeight.BOLD),
        width=170,
        height=48,
        border_radius=14,
        alignment=ft.alignment.center,


        bgcolor=PRIMARY_COLOR,

        on_click=lambda e: close_dialog(dialog, page),

        shadow=ft.BoxShadow(
            blur_radius=18,
            spread_radius=1,
            color=ft.Colors.with_opacity(0.4, PRIMARY_COLOR),
            offset=ft.Offset(0, 0),
        ),
    )

    dialog_card = ft.Container(
        content=ft.Column(
            [
                # Заголовок
                ft.Row(
                    [
                        ft.Container(
                            content=ft.Icon(ft.Icons.CHECK_CIRCLE, size=38, color=PRIMARY_COLOR),
                            padding=ft.padding.all(10),
                            border_radius=50,
                            bgcolor=ft.Colors.with_opacity(0.15, PRIMARY_COLOR),
                        ),
                        ft.Text(
                            "Конфиг успешно загружен",
                            size=16,
                            weight=ft.FontWeight.BOLD,
                            color=TEXT_COLOR,
                        ),
                    ],
                    alignment=ft.MainAxisAlignment.CENTER,
                    spacing=10,
                ),


                ft.Container(
                    content=ft.Column(
                        [
                            ft.Text(f"Адрес: {config['address']}", color=ft.Colors.GREY_300, size=14),
                            ft.Text(
                                "Проверьте данные перед запуском.",
                                color=ft.Colors.GREY_500,
                                size=12,
                                italic=True
                            ),
                        ],
                        spacing=6,
                        horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                    ),
                    padding=ft.padding.all(10),
                ),
            ],
            spacing=12,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
        ),

        padding=25,
        border_radius=20,


        bgcolor=ft.LinearGradient(
            begin=ft.Alignment(-1, -1),
            end=ft.Alignment(1, 1),
            colors=[
                ft.Colors.with_opacity(0.18, ft.Colors.BLACK),
                ft.Colors.with_opacity(0.10, ft.Colors.GREY_900),
            ],
        ),


        shadow=ft.BoxShadow(
            blur_radius=32,
            spread_radius=2,
            color=ft.Colors.with_opacity(0.45, ft.Colors.BLACK),
            offset=ft.Offset(0, 6),
        ),
    )

    dialog = ft.AlertDialog(
        modal=True,
        bgcolor=ft.Colors.with_opacity(0.05, ft.Colors.BLACK),


        content=ft.Container(
            content=ft.Column(
                [dialog_card],
                alignment=ft.MainAxisAlignment.CENTER,

            ),
            width=380,
        ),
        actions=[close_button],
        inset_padding=ft.padding.all(25),
    )

    page.overlay.append(dialog)
    dialog.open = True
    page.update()


def auto_pid():
    target_processes = ['Ld9BoxHeadless.exe', 'HD-Player.exe']
    latest_process = None
    latest_start_time = None

    for proc in psutil.process_iter(['pid', 'name', 'create_time']):
        if proc.info['name'] in target_processes:
            try:
                create_time = proc.info['create_time']
                if latest_start_time is None or create_time > latest_start_time:
                    latest_process = proc.info
                    latest_start_time = create_time
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    if latest_process:
        return latest_process['pid'], latest_process['name']

    return None, None


def auto_hwnd(pid, process_name):
    def callback(hwnd, hwnds):
        if win32gui.IsWindowVisible(hwnd):
            _, found_pid = win32process.GetWindowThreadProcessId(hwnd)
            if found_pid == target_pid:
                window_title = win32gui.GetWindowText(hwnd)
                hwnds.append((hwnd, window_title))
        return True

    target_process = None

    if process_name == 'Ld9BoxHeadless.exe':
        target_process = 'dnplayer.exe'
    elif process_name == 'HD-Player.exe':
        target_process = 'HD-Player.exe'

    target_pid = None
    for proc in psutil.process_iter(['pid', 'name']):
        if proc.info['name'] == target_process:
            target_pid = proc.info['pid']
            break

    if not target_pid:
        return None



    hwnds = []
    win32gui.EnumWindows(callback, hwnds)

    if not hwnds:
        return None

    hwnd, window_title = hwnds[0]

    if process_name == 'Ld9BoxHeadless.exe' and window_title:
        parent_hwnd = win32gui.FindWindow(None, window_title)
        if parent_hwnd == 0:
            return hwnd

        child_hwnd = win32gui.FindWindowEx(parent_hwnd, None, None, None)
        if child_hwnd:
            return child_hwnd
        else:
            return parent_hwnd

    return hwnd

def window_rect(hwnd):
    rect = RECT()
    user32 = ctypes.windll.user32
    user32.GetWindowRect(hwnd, ctypes.byref(rect))
    return rect

def cords(rect, x, y, original_size):
    window_width = rect.right - rect.left
    window_height = rect.bottom - rect.top
    normalized_x = x / original_size[0]
    normalized_y = y / original_size[1]
    proportional_x = int(normalized_x * window_width)
    proportional_y = int(normalized_y * window_height)
    return proportional_x, proportional_y

def click(hwnd, x, y) -> None:
    lParam = win32api.MAKELONG(x, y)
    win32api.PostMessage(hwnd, 513, 0, lParam)
    win32api.PostMessage(hwnd,514, 0, lParam)

def read(h_process, address):
    buf = ctypes.create_string_buffer(2)
    bytes_read = ctypes.c_size_t()
    ok = ReadProcessMemory(h_process, ctypes.c_void_p(address), buf, 2, ctypes.byref(bytes_read))
    if not ok or bytes_read.value != 2:
        return None
    return struct.unpack("<H", buf.raw)[0]

def scan_for_value2(h_process, target_value):
    found = []
    CHUNK = 4 * 1024 * 1024


    pattern = struct.pack("<H", target_value)

    addr = 0
    mbi = MEMORY_BASIC_INFORMATION()

    while VirtualQueryEx(h_process, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)) == ctypes.sizeof(mbi):
        if mbi.State == MEM_COMMIT:
            prot = mbi.Protect
            readable = (prot & PAGE_READONLY) or (prot & PAGE_READWRITE) or (prot & PAGE_WRITECOPY) or \
                       (prot & PAGE_EXECUTE_READ) or (prot & PAGE_EXECUTE_READWRITE) or (prot & PAGE_EXECUTE_WRITECOPY)

            if readable:
                base = mbi.BaseAddress
                region_size = mbi.RegionSize
                offset = 0

                while offset < region_size:
                    to_read = min(CHUNK, region_size - offset)
                    if to_read < 2:
                        break

                    buf = ctypes.create_string_buffer(to_read)
                    bytes_read = ctypes.c_size_t()

                    ok = ReadProcessMemory(h_process, ctypes.c_void_p(base + offset),
                                           buf, to_read, ctypes.byref(bytes_read))

                    if ok and bytes_read.value >= 2:
                        raw = buf.raw[:bytes_read.value]

                        start = 0
                        while True:
                            idx = raw.find(pattern, start)
                            if idx == -1:
                                break
                            if (base + offset + idx) % 2 == 0:
                                found.append(base + offset + idx)
                            start = idx + 2

                    offset += to_read

        addr = mbi.BaseAddress + mbi.RegionSize
        if addr >= 0x7FFFFFFFFFFF:
            break

    return found


def bag_pd(h_process, hwnd, initial_addresses, buy_coord, up_coord, pause=0.5):
    addresses = list(initial_addresses)

    click(hwnd, *up_coord)
    time.sleep(pause)
    click(hwnd, *up_coord)
    time.sleep(pause)

    click(hwnd, *buy_coord)
    time.sleep(pause)
    addresses = [addr for addr in addresses if read(h_process, addr) == 257]

    click(hwnd, *buy_coord)
    time.sleep(pause)
    addresses = [addr for addr in addresses if read(h_process, addr) == 1]

    click(hwnd, *up_coord)
    time.sleep(pause)
    click(hwnd, *up_coord)
    time.sleep(pause)

    click(hwnd, *buy_coord)
    time.sleep(pause)
    addresses = [addr for addr in addresses if read(h_process, addr) == 257]

    click(hwnd, *buy_coord)
    time.sleep(pause)
    addresses = [addr for addr in addresses if read(h_process, addr) == 1]

    click(hwnd, *buy_coord)
    time.sleep(pause)
    addresses = [addr for addr in addresses if read(h_process, addr) == 257]


    addresses_ending_with_8 = []
    for addr in addresses:
        hex_str = f"{addr:X}"
        if hex_str.endswith('8'):
            addresses_ending_with_8.append((addr, hex_str))

    normalized_addresses = []
    for addr, hex_str in addresses_ending_with_8:
        if len(hex_str) < 11:
            normalized_hex = '0' * (11 - len(hex_str)) + hex_str
        else:
            normalized_hex = hex_str
        normalized_addresses.append((addr, normalized_hex))

    groups = {}
    for addr, hex_str in normalized_addresses:
        prefix = hex_str[:8]
        if prefix not in groups:
            groups[prefix] = []
        groups[prefix].append((addr, hex_str))

    final_addresses = []
    pair_count = 0

    for prefix, addrs in sorted(groups.items()):
        if 2 <= len(addrs) <= 3:
            pair_count += 1
            for i, (addr, hex_str) in enumerate(addrs):
                val = read(h_process, addr)
                final_addresses.append(addr)


    return final_addresses


def auto_settings2(page):
    pid, process_name = auto_pid()
    hwnd = auto_hwnd(pid, process_name)

    h_process = OpenProcess(0x1F0FFF, False, pid)

    rect = window_rect(hwnd)
    up_coord = cords(rect, upd[0], upd[1], size)
    buy_coord = cords(rect, buy[0], buy[1], size)

    click(hwnd, *buy_coord)
    time.sleep(0.9)

    addresses = scan_for_value2(h_process, 257)
    click(hwnd, *buy_coord)
    time.sleep(1)
    filtered = bag_pd(h_process, hwnd, addresses, buy_coord, up_coord)

    show_results_dialog(filtered, h_process, page)


def show_results_dialog(filtered_addresses, h_process, page):
    PRIMARY_COLOR = ft.Colors.CYAN_400
    TEXT_COLOR = ft.Colors.WHITE

    def copy_address(e, address_to_copy):
        pyperclip.copy(address_to_copy)
        snackbar = ft.SnackBar(
            content=ft.Row(
                controls=[
                    ft.Icon(ft.Icons.CHECK_CIRCLE_OUTLINE, color=ft.Colors.WHITE, size=20),
                    ft.Text(f"Адрес {address_to_copy} скопирован!", color=ft.Colors.WHITE, weight=ft.FontWeight.BOLD)
                ],
                alignment=ft.MainAxisAlignment.CENTER,
                spacing=10
            ),
            bgcolor=ft.Colors.GREEN_600,
            duration=2000,
        )
        page.overlay.append(snackbar)
        snackbar.open = True
        page.update()

    def close_dialog(e):
        dialog.open = False
        page.update()

    def address_tile(addr_hex, value):
        return ft.Container(
            content=ft.Row(
                [
                    ft.Column(
                        [
                            ft.Text(addr_hex,
                                    color=ft.Colors.WHITE,
                                    size=14,
                                    weight=ft.FontWeight.W_500),
                            ft.Text(f"Значение: {value}",
                                    color=ft.Colors.GREY_400,
                                    size=12),
                        ],
                        spacing=2,
                    ),
                    ft.Container(
                        content=ft.Icon(ft.Icons.CONTENT_COPY, size=18, color=PRIMARY_COLOR),
                        on_click=lambda e, addr=addr_hex: copy_address(e, addr),
                        padding=ft.padding.all(8),
                        border=ft.border.all(1, PRIMARY_COLOR),
                        border_radius=10,
                        tooltip="Копировать адрес"
                    )
                ],
                alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
            ),
            padding=12,
            bgcolor=ft.Colors.with_opacity(0.08, ft.Colors.WHITE),
            border_radius=12,
        )

    address_content = []
    if filtered_addresses:
        for i, addr in enumerate(filtered_addresses):
            val = read(h_process, addr)
            hex_str = f"{addr:X}"
            address_content.append(address_tile(hex_str, val))
            address_content.append(ft.Container(height=6))
    else:
        address_content = [
            ft.Container(
                content=ft.Column(
                    [
                        ft.Icon(ft.Icons.WARNING, color=ft.Colors.ORANGE_400, size=32),
                        ft.Text("Адреса не найдены",
                                color=ft.Colors.GREY_300,
                                size=14,
                                text_align=ft.TextAlign.CENTER),
                    ],
                    horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                    spacing=10,
                ),
                padding=20,
            )
        ]

    address_scrollable = ft.Container(
        content=ft.Column(
            address_content,
            spacing=0,
            scroll=ft.ScrollMode.ADAPTIVE,
        ),
        height=min(len(filtered_addresses) * 70, 400),
        width=350,
    )

    content_column = ft.Column(
        [
            ft.Container(
                content=ft.Row(
                    [
                        ft.Icon(ft.Icons.MEMORY, color=PRIMARY_COLOR, size=32),
                        ft.Text(
                            "Результат автопоиска",
                            size=18,
                            weight=ft.FontWeight.BOLD,
                            color=TEXT_COLOR,
                        ),
                    ],
                    alignment=ft.MainAxisAlignment.CENTER,
                    spacing=10,
                ),
                padding=ft.padding.only(bottom=10),
            ),

            ft.Text(
                f"Найдено адресов: {len(filtered_addresses)}",
                color=ft.Colors.GREY_400,
                size=13,
                text_align=ft.TextAlign.CENTER,
            ),

            ft.Container(height=15),

            address_scrollable,

            ft.Container(height=10),

            ft.Text(
                "Нажмите на значок копирования, чтобы скопировать адрес",
                color=ft.Colors.GREY_500,
                size=11,
                text_align=ft.TextAlign.CENTER,
                italic=True
            ),
        ],
        horizontal_alignment=ft.CrossAxisAlignment.CENTER,
        spacing=4,
    )

    dialog_card = ft.Container(
        content=content_column,
        padding=30,
        width=400,  # Немного шире для лучшего отображения
        bgcolor=ft.LinearGradient(
            begin=ft.Alignment(-1, -1),
            end=ft.Alignment(1, 1),
            colors=[
                ft.Colors.with_opacity(0.25, ft.Colors.BLACK),
                ft.Colors.with_opacity(0.1, ft.Colors.GREY_900),
            ],
        ),
        border_radius=20,
        shadow=ft.BoxShadow(
            spread_radius=1,
            blur_radius=25,
            color=ft.Colors.with_opacity(0.4, ft.Colors.BLACK),
            offset=ft.Offset(0, 6),
        ),
    )

    close_button = ft.FilledButton(
        "Закрыть",
        icon=ft.Icons.CLOSE,
        on_click=close_dialog,
        style=ft.ButtonStyle(
            bgcolor=PRIMARY_COLOR,
            color=ft.Colors.WHITE,
            shape=ft.RoundedRectangleBorder(radius=14),
            padding=ft.padding.symmetric(horizontal=26, vertical=14),
        )
    )

    dialog = ft.AlertDialog(
        modal=True,
        content=dialog_card,
        actions=[close_button],
        actions_padding=20,
        inset_padding=ft.padding.all(25),
    )

    page.overlay.append(dialog)
    dialog.open = True
    page.update()




def read_dword(h_process, address):
    buf = ctypes.create_string_buffer(8)
    bytes_read = ctypes.c_size_t()
    ok = ReadProcessMemory(h_process, ctypes.c_void_p(address), buf, 8, ctypes.byref(bytes_read))
    if not ok or bytes_read.value != 8:
        return None
    return struct.unpack("<Q", buf.raw)[0]

def enum_memory_regions(h_process):
    start_addr = 0x30000000
    end_addr = 0x120000000
    address = start_addr
    mbi = MEMORY_BASIC_INFORMATION()
    regions = []

    while address < end_addr:
        res = VirtualQueryEx(h_process, ctypes.c_void_p(address),
                             ctypes.byref(mbi), ctypes.sizeof(mbi))
        if not res:
            address += 0x1000
            continue

        base = mbi.BaseAddress
        region_size = mbi.RegionSize

        if base + region_size < start_addr or base >= end_addr:
            address = base + region_size
            continue

        if base + region_size > end_addr:
            region_size = end_addr - base

        if mbi.State != MEM_COMMIT:
            address = base + mbi.RegionSize
            continue

        if not (mbi.Protect & PAGE_READWRITE):
            address = base + mbi.RegionSize
            continue

        if mbi.Type != 0x20000:
            address = base + mbi.RegionSize
            continue

        if region_size > 8:
            regions.append((base, region_size))

        address = base + mbi.RegionSize

    return regions

def scan_for_value(h_process, target_value):
    found = []
    regions = enum_memory_regions(h_process)
    pattern = struct.pack("<Q", target_value)
    chunk_size = 0x2000000

    for base, size in regions:
        offset = 0
        while offset < size - 8:
            to_read = min(chunk_size, size - offset)
            buf = ctypes.create_string_buffer(to_read)
            bytes_read = ctypes.c_size_t()

            ok = ReadProcessMemory(h_process, ctypes.c_void_p(base + offset), buf, to_read, ctypes.byref(bytes_read))
            if not ok or bytes_read.value == 0:
                offset += to_read
                continue

            raw = buf.raw[:bytes_read.value]
            start = 0
            while True:
                idx = raw.find(pattern, start)
                if idx == -1:
                    break
                addr = base + offset + idx
                if (addr & 0xF) == 0:
                    found.append(addr)
                start = idx + 1

            offset += to_read

    return found

def barrier(h_process, hwnd, up_coord, sk_coord, cancel_coord,up_nakl, initial_addresses,
                               target_count=10, max_iterations=30, pause=0.5):
    addresses = list(initial_addresses)
    expected = 0
    iteration = 0


    while len(addresses) > target_count and iteration < max_iterations and addresses:
        iteration += 1
        click(hwnd, *up_coord)
        time.sleep(pause)

        new_addresses = []
        for addr in addresses:
            val = read_dword(h_process, addr)
            if val == expected:
                new_addresses.append(addr)

        addresses = new_addresses
        expected = 1 if expected == 0 else 0


    ones = sum(1 for a in addresses if read_dword(h_process, a) == 1)
    zeros = len(addresses) - ones

    if ones > zeros:
        click(hwnd, *up_coord)
        time.sleep(0.5)
        click(hwnd, *sk_coord)
    else:
        click(hwnd, *sk_coord)

    time.sleep(2)
    click(hwnd, *cancel_coord)
    click(hwnd, *cancel_coord)
    time.sleep(1)

    zero_addrs = [a for a in addresses if read_dword(h_process, a) == 0]
    time.sleep(0.3)
    click(hwnd, *up_coord)
    time.sleep(0.7)

    one_addrs = [a for a in zero_addrs if read_dword(h_process, a) == 1]

    start_vals = {a: read_dword(h_process, a) for a in one_addrs}
    time.sleep(1)

    final = []
    for a in one_addrs:
        val = read_dword(h_process, a)
        if val == start_vals[a]:
            final.append(a)

    start_vals = {a: read_dword(h_process, a) for a in final}
    click(hwnd, *up_nakl)
    time.sleep(0.2)
    click(hwnd, *up_nakl)
    time.sleep(0.5)
    final = [a for a in final if read_dword(h_process, a) == start_vals[a]]

    final = [a for a in final if (a & 0xF) == 0]


    return final


def auto_settings(e, page):
    PRIMARY_COLOR = ft.Colors.CYAN_400
    SECONDARY_COLOR = ft.Colors.GREY_400
    CARD_COLOR = ft.Colors.GREY_900
    TEXT_COLOR = ft.Colors.WHITE

    pid, process_name = auto_pid()
    hwnd = auto_hwnd(pid, process_name)
    snackbar = ft.SnackBar(
        content=ft.Row([
            ft.Icon(ft.Icons.CHECK_CIRCLE_OUTLINE, color=ft.Colors.WHITE, size=20),
            ft.Text("Авто настройка начата. Ожидайте", color=ft.Colors.WHITE, weight=ft.FontWeight.BOLD)
        ], alignment=ft.MainAxisAlignment.CENTER, spacing=10),
        bgcolor=ft.Colors.GREEN_600,
        duration=3000
    )
    page.overlay.append(snackbar)
    snackbar.open = True
    page.update()

    h_process = OpenProcess(0x1F0FFF, False, pid)

    rect = window_rect(hwnd)
    up = cords(rect, upd[0], upd[1], size)
    sk_coord = cords(rect, skin[0], skin[1], size)
    cancel_coord = cords(rect, cancel[0], cancel[1], size)
    up_nakl = cords(rect, upd_nakl[0], upd_nakl[1], size)
    time.sleep(1)
    click(hwnd, up[0], up[1])
    time.sleep(0.9)
    addresses = scan_for_value(h_process, 1)
    filtered = barrier(h_process, hwnd, up, sk_coord, cancel_coord, up_nakl, addresses)

    def copy_address(e, address_to_copy):
        pyperclip.copy(address_to_copy)
        snackbar = ft.SnackBar(
            content=ft.Row(
                controls=[
                    ft.Icon(ft.Icons.CHECK_CIRCLE_OUTLINE, color=ft.Colors.WHITE, size=20),
                    ft.Text(f"Адрес {address_to_copy} скопирован!", color=ft.Colors.WHITE, weight=ft.FontWeight.BOLD)
                ],
                alignment=ft.MainAxisAlignment.CENTER,
                spacing=10
            ),
            bgcolor=ft.Colors.GREEN_600,
            duration=2000,
        )
        page.overlay.append(snackbar)
        snackbar.open = True
        page.update()

    def close_dialog_auto(e):
        dialog.open = False
        page.update()

        def delayed_click():
            time.sleep(2)
            click(hwnd, up[0], up[1])

        def run_auto_settings2():
            time.sleep(3)
            auto_settings2(page)

        threading.Thread(target=delayed_click, daemon=True).start()
        threading.Thread(target=run_auto_settings2, daemon=True).start()



    def address_tile(addr_hex):
        return ft.Container(
            content=ft.Row(
                [
                    ft.Text(addr_hex,
                            color=ft.Colors.WHITE,
                            size=15,
                            weight=ft.FontWeight.W_500,
                            expand=True),
                    ft.Container(
                        content=ft.Icon(ft.Icons.CONTENT_COPY, size=18, color=PRIMARY_COLOR),
                        on_click=lambda e, addr=addr_hex: copy_address(e, addr),
                        padding=ft.padding.all(8),
                        border=ft.border.all(1, PRIMARY_COLOR),
                        border_radius=10,
                        tooltip="Копировать адрес"
                    )
                ],
                alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
            ),
            padding=12,
            bgcolor=ft.Colors.with_opacity(0.08, ft.Colors.WHITE),
            border_radius=12,
        )

    if filtered:
        address_content = []
        for i, addr in enumerate(filtered[:3]):
            hex_str = f"{addr:08X}"
            address_content.append(address_tile(hex_str))
            address_content.append(ft.Container(height=6))
    else:
        address_content = [
            ft.Text("Адреса не найдены", color=ft.Colors.RED_300, size=14)
        ]

    close_button = ft.FilledButton(
        "Закрыть",
        icon=ft.Icons.CLOSE,
        on_click=close_dialog_auto,
        style=ft.ButtonStyle(
            bgcolor=PRIMARY_COLOR,
            color=ft.Colors.WHITE,
            shape=ft.RoundedRectangleBorder(radius=14),
            padding=ft.padding.symmetric(horizontal=26, vertical=14),
        )
    )
    address_scrollable = ft.Container(
        content=ft.Column(
            address_content,
            spacing=0,
            scroll=ft.ScrollMode.ADAPTIVE,
        ),
        height=min(len(filtered) * 60, 300),
    )

    content_column = ft.Column(
        [
            ft.Container(
                content=ft.Row(
                    [
                        ft.Icon(ft.Icons.SEARCH, color=PRIMARY_COLOR, size=32),
                        ft.Text(
                            "Результат автопоиска",
                            size=18,
                            weight=ft.FontWeight.BOLD,
                            color=TEXT_COLOR,
                        ),
                    ],
                    alignment=ft.MainAxisAlignment.CENTER,
                    spacing=10,
                ),
                padding=ft.padding.only(bottom=10),
            ),

            ft.Text(
                f"Найдено адресов: {len(filtered)}",
                color=ft.Colors.GREY_400,
                size=13,
                text_align=ft.TextAlign.CENTER,
            ),

            ft.Container(height=10),

            address_scrollable,

            ft.Container(height=10),

            ft.Text(
                "Нажмите на значок, чтобы скопировать адрес.",
                color=ft.Colors.GREY_500,
                size=11,
                text_align=ft.TextAlign.CENTER,
                italic=True
            ),
        ],
        horizontal_alignment=ft.CrossAxisAlignment.CENTER,
        spacing=4,
    )

    dialog_card = ft.Container(
        content=content_column,
        padding=30,
        width=380,
        bgcolor=ft.LinearGradient(
            begin=ft.Alignment(-1, -1),
            end=ft.Alignment(1, 1),
            colors=[
                ft.Colors.with_opacity(0.25, ft.Colors.BLACK),
                ft.Colors.with_opacity(0.1, ft.Colors.GREY_900),
            ],
        ),
        border_radius=20,
        shadow=ft.BoxShadow(
            spread_radius=1,
            blur_radius=25,
            color=ft.Colors.with_opacity(0.4, ft.Colors.BLACK),
            offset=ft.Offset(0, 6),
        ),
    )

    dialog = ft.AlertDialog(
        modal=True,
        content=dialog_card,
        actions=[close_button],
        actions_padding=20,
        inset_padding=ft.padding.all(25),
    )

    page.overlay.append(dialog)
    dialog.open = True
    page.update()

def read_mem(h_proc, address):
    global running, value
    address_ptr = ctypes.c_void_p(address)
    buffer = ctypes.create_string_buffer(1)
    while running:
        ntdll.NtReadVirtualMemory(h_proc, address_ptr, buffer, 1, None)
        value = buffer[0]

    time.sleep(0.0001)


def update(hwnd, u, update_time):
    while running:
        click(hwnd, u[0], u[1])
        time.sleep(update_time)


def send_telegram(image_path, caption=""):
    if not chat_id:
        return
    url = f"https://api.telegram.org/bot{bot_token}/sendPhoto"
    with open(image_path, "rb") as img:
        files = {"photo": img}
        data = {"chat_id": chat_id, "caption": caption, "parse_mode": "html"}
        try:
            requests.post(url, files=files, data=data, timeout=5)
        except requests.RequestException as e:
            print("Ошибка отправки в Telegram:", e)


def main_l(hwnd, buy_l, conf_l, u, stickers):
    global running, value
    while running:
        if value >= stickers:
            win32api.PostMessage(hwnd, 513, 0, buy_l)
            win32api.PostMessage(hwnd,514, 0, buy_l)
            win32api.PostMessage(hwnd, 513, 0, conf_l)
            win32api.PostMessage(hwnd, 514, 0, conf_l)
            threading.Thread(target=notify, args=value, daemon=True).start()
            click(hwnd, u[0], u[1])
            click(hwnd, u[0], u[1])
    time.sleep(0.0001)


def notify(stickers_count):
    global window

    hwnd = win32gui.FindWindow(None, window)
    if hwnd == 0:
        return
    hwnd = win32gui.FindWindowEx(hwnd, None, None, None)

    rect = window_rect(hwnd)
    with mss.mss() as sct:
        monitor = {
            "left": rect.left,
            "top": rect.top,
            "width": rect.right - rect.left,
            "height": rect.bottom - rect.top
        }
        screenshot = sct.grab(monitor)
        path = os.path.join(os.path.dirname(__file__), f"screenshot_{int(time.time())}.png")
        mss.tools.to_png(screenshot.rgb, screenshot.size, output=path)

    send_telegram(path,
                  caption=f"𝘼𝙪𝙧𝙤𝙣 𝘾𝙡𝙞𝙚𝙣𝙩 | 𝙃𝙖𝙡𝙛-𝘼𝙥𝙞\n<b>🟢 Скин успешно куплен\nКол-во наклеек: {sticker_count}\nПродолжаю работу....</b>")
    try:
        os.remove(path)
    except:
        pass


def start(delay, stickers, update_time):
    global running, h_proc, address

    pid, process_name = auto_pid()
    hwnd = auto_hwnd(pid, process_name)

    if h_proc is None:
        h_proc = kernel32.OpenProcess(0x1F0FFF, False, pid)

    rect = window_rect(hwnd)

    buy_button = cords(rect, buy[0], buy[1], size)
    conf = cords(rect, confirm[0], confirm[1], size)
    u = cords(rect, upd[0], upd[1], size)
    buy_l = win32api.MAKELONG(buy_button[0], buy_button[1])
    conf_l = win32api.MAKELONG(conf[0], conf[1])

    if not running:
        running = True
        read = threading.Thread(target=read_mem, args=(h_proc, address))
        main = threading.Thread(target=main_l_optimized, args=(hwnd, buy_l, conf_l, u, stickers), daemon=True)
        update_ = threading.Thread(target=update, args=(hwnd, u, update_time), daemon=True)

        read.start()
        main.start()
        update_.start()

        current_process = psutil.Process()
        current_process.nice(psutil.HIGH_PRIORITY_CLASS)

def stop():
    global running, h_proc

    running = False
    time.sleep(0.1)

    if h_proc:
        kernel32.CloseHandle(h_proc)

    h_proc = None

# GUI
def login_page(page: ft.Page):
    icon_path = os.path.join(os.path.dirname(__file__), "icon.ico")
    page.window.icon = icon_path
    page.title = "𝘼𝙪𝙧𝙤𝙣 𝘾𝙡𝙞𝙚𝙣𝙩 | 𝙃𝙖𝙡𝙛-𝘼𝙥𝙞"
    page.theme_mode = ft.ThemeMode.DARK
    page.window.width = 400
    page.window.height = 540
    page.window.resizable = False
    page.window.center()

    PRIMARY_COLOR = ft.Colors.CYAN_400
    SECONDARY_COLOR = ft.Colors.TEAL_400
    BACKGROUND_COLOR = ft.Colors.GREY_900
    CARD_COLOR = ft.Colors.GREY_800
    TEXT_COLOR = ft.Colors.WHITE
    page.bgcolor = BACKGROUND_COLOR

    def check_subscription(hwid):
        try:
            resp = requests.get(pastebin_link, timeout=3)
            resp.raise_for_status()
            data = json.loads(resp.text)

            if "dev" in data and hwid in data["dev"]:
                return {"valid": True}
            elif "users" in data and hwid in data["users"]:
                expiry_str = data["users"][hwid]
                expiry_date = datetime.datetime.strptime(expiry_str, "%Y-%m-%d")

                if datetime.datetime.now() < expiry_date:
                    return {"valid": True}
                else:
                    return {"valid": False, "error": "subscription_expired"}

            return {"valid": False, "error": "hwid_not_found"}

        except Exception as e:
            return {"valid": False, "error": "connection_error"}

    def get_hwid() -> str:
        data = {
            "node": platform.node(),
            "platform": platform.system()
        }

        if data['platform'].lower().startswith("win"):
            cpu_id = subprocess.getoutput("wmic cpu get ProcessorId /value").replace("ProcessorId=", "").strip()
            data['cpu'] = cpu_id

        canon = json.dumps(data, sort_keys=True, ensure_ascii=False).encode('utf-8')
        hwid = hashlib.sha256(canon).hexdigest()

        token = base64.b64encode(hwid.encode('utf-8')).decode('utf-8')

        return token

    def copy_hwid(e):
        hwid = get_hwid()
        pyperclip.copy(hwid)

        snackbar = ft.SnackBar(
            content=ft.Row(
                controls=[
                    ft.Icon(ft.Icons.CHECK_CIRCLE_OUTLINE, color=ft.Colors.WHITE, size=20),
                    ft.Text("Успешно скопировано!", color=ft.Colors.WHITE, weight=ft.FontWeight.BOLD)
                ],
                alignment=ft.MainAxisAlignment.CENTER,
                spacing=10
            ),
            bgcolor=ft.Colors.GREEN_600,
            duration=2000,
            shape=ft.RoundedRectangleBorder(radius=12),
            elevation=5
        )

        page.overlay.append(snackbar)
        snackbar.open = True
        page.update()

    def sign_in(e) -> bool:
        hwid = get_hwid()
        sub_info = check_subscription(hwid)
        if sub_info["valid"]:
            main_page(page)
        else:
            error_messages = {
                "hwid_not_found": "HWID не найден в базе данных",
                "subscription_expired": "Подписка истекла",
                "connection_error": "Ошибка подключения к серверу"
            }
            error_msg = error_messages.get(sub_info.get("error"), "Ошибка авторизации")

            snackbar = ft.SnackBar(
                content=ft.Row([
                    ft.Icon(ft.Icons.CANCEL, color=ft.Colors.WHITE, size=20),
                    ft.Text(error_msg, color=ft.Colors.WHITE, weight=ft.FontWeight.BOLD)
                ], alignment=ft.MainAxisAlignment.CENTER, spacing=10),
                bgcolor=ft.Colors.RED_600,
                duration=2000
            )
            page.overlay.append(snackbar)
            snackbar.open = True
            page.update()


    login = ft.Container(
        content=ft.Column(
            controls=[
                ft.Container(
                    content=ft.Column(
                        [
                            ft.Icon(ft.Icons.SECURITY, size=80, color=PRIMARY_COLOR),
                            ft.Text(
                                "𝘼𝙪𝙧𝙤𝙣 𝘾𝙡𝙞𝙚𝙣𝙩",
                                size=32,
                                weight=ft.FontWeight.BOLD,
                                color=PRIMARY_COLOR,
                            ),
                            ft.Text(
                                "𝙃𝙖𝙡𝙛 - 𝘼𝙥𝙞",
                                size=16,
                                color=SECONDARY_COLOR,
                                weight=ft.FontWeight.W_500,
                            ),
                        ],
                        horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                        spacing=10,
                    ),
                    margin=ft.margin.only(bottom=40),
                ),
                ft.Container(
                    content=ft.Column(
                        [
                            ft.Container(
                                content=ft.Row(
                                    [
                                        ft.Icon(
                                            ft.Icons.LOGIN, color=ft.Colors.WHITE, size=20
                                        ),
                                        ft.Text(
                                            "𝐒𝐢𝐠𝐧 𝐈𝐧",
                                            color=ft.Colors.WHITE,
                                            weight=ft.FontWeight.BOLD,
                                            size=16,
                                        ),
                                    ],
                                    alignment=ft.MainAxisAlignment.CENTER,
                                    spacing=10,
                                ),
                                width=200,
                                height=50,
                                border_radius=12,
                                gradient=ft.LinearGradient(
                                    begin=ft.alignment.top_left,
                                    end=ft.alignment.bottom_right,
                                    colors=[PRIMARY_COLOR, SECONDARY_COLOR],
                                ),
                                shadow=ft.BoxShadow(
                                    spread_radius=1,
                                    blur_radius=15,
                                    color=PRIMARY_COLOR,
                                    offset=ft.Offset(0, 0),
                                    blur_style=ft.ShadowBlurStyle.OUTER,
                                ),
                                on_click=sign_in,
                                animate=300,
                            ),
                            ft.Container(height=20),
                            ft.Container(
                                content=ft.Row(
                                    [
                                        ft.Icon(
                                            ft.Icons.CONTENT_COPY,
                                            color=PRIMARY_COLOR,
                                            size=18,
                                        ),
                                        ft.Text(
                                            "𝐂𝐨𝐩𝐲 𝐇𝐖𝐈𝐃",
                                            color=PRIMARY_COLOR,
                                            weight=ft.FontWeight.BOLD,
                                            size=14,
                                        ),
                                    ],
                                    alignment=ft.MainAxisAlignment.CENTER,
                                    spacing=10,
                                ),
                                width=200,
                                height=45,
                                border_radius=10,
                                border=ft.border.all(2, PRIMARY_COLOR),
                                on_click=copy_hwid,
                                animate=200,
                            ),
                        ],
                        horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                        spacing=0,
                    ),
                ),
                ft.Container(
                    content=ft.Column(
                        [
                            ft.Divider(color=ft.Colors.GREY_700),
                            ft.Text(
                                "Ваш HWID будет автоматически скопирован при нажатии на кнопку Copy HWID",
                                size=12,
                                color=ft.Colors.GREY_500,
                                text_align=ft.TextAlign.CENTER,
                            ),
                        ],
                        horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                        spacing=10,
                    ),
                    margin=ft.margin.only(top=30),
                ),
            ],
            alignment=ft.MainAxisAlignment.CENTER,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
        ),
        padding=40,
        bgcolor=BACKGROUND_COLOR,
    )

    page.add(login)

def main_page(page: ft.Page):
    global running
    page.clean()
    icon_path = os.path.join(os.path.dirname(__file__), "icon.ico")
    page.window.icon = icon_path
    page.title = "𝘼𝙪𝙧𝙤𝙣 𝘾𝙡𝙞𝙚𝙣𝙩 | 𝙃𝙖𝙡𝙛-𝘼𝙥𝙞"
    page.theme_mode = ft.ThemeMode.DARK
    page.window.width = 550
    page.window.height = 380
    page.window.resizable = False

    PRIMARY_COLOR = ft.Colors.CYAN_400
    SECONDARY_COLOR = ft.Colors.TEAL_400
    BACKGROUND_COLOR = ft.Colors.GREY_900
    CARD_COLOR = ft.Colors.GREY_800
    TEXT_COLOR = ft.Colors.WHITE
    page.bgcolor = BACKGROUND_COLOR


    start_stop = ft.Container(
        content=ft.Row([
            ft.Icon(ft.Icons.PLAY_ARROW if not running else ft.Icons.STOP,
                    color=ft.Colors.WHITE, size=20),
            ft.Text("𝙎𝙩𝙖𝙧𝙩‌" if not running else "𝙎𝙩𝙤𝙥",
                    color=ft.Colors.WHITE, weight=ft.FontWeight.BOLD)
        ], alignment=ft.MainAxisAlignment.CENTER, spacing=8),
        width=160,
        height=55,
        border_radius=12,
        gradient=ft.LinearGradient(
            begin=ft.alignment.top_left,
            end=ft.alignment.bottom_right,
            colors=[PRIMARY_COLOR, SECONDARY_COLOR] if not running else [ft.Colors.RED_500, ft.Colors.ORANGE_500]
        ),
        shadow=ft.BoxShadow(
            spread_radius=1,
            blur_radius=15,
            color=PRIMARY_COLOR if not running else ft.Colors.RED_500,
            offset=ft.Offset(0, 0),
            blur_style=ft.ShadowBlurStyle.OUTER
        ),
        on_click=lambda e: toggle(),
        animate=300
    )

    def toggle():
        global running

        delay = float(delay_txt.value)
        stickers = int(stickers_txt.value)
        update_time = float(update.value)

        if not running:
            start(delay, stickers, update_time)
            start_stop.gradient = ft.LinearGradient(
                begin=ft.alignment.top_left,
                end=ft.alignment.bottom_right,
                colors=[ft.Colors.RED_500, ft.Colors.ORANGE_500]
            )
            start_stop.shadow.color = ft.Colors.RED_500
            start_stop.content.controls[0].name = ft.Icons.STOP
            start_stop.content.controls[1].value = "𝙎𝙩𝙤𝙥"
        else:
            stop()
            start_stop.gradient = ft.LinearGradient(
                begin=ft.alignment.top_left,
                end=ft.alignment.bottom_right,
                colors=[PRIMARY_COLOR, SECONDARY_COLOR]
            )
            start_stop.shadow.color = PRIMARY_COLOR
            start_stop.content.controls[0].name = ft.Icons.PLAY_ARROW
            start_stop.content.controls[1].value = "𝙎𝙩𝙖𝙧𝙩‌"

        start_stop.update()

    settings_button = ft.ElevatedButton(
        "𝘼𝙪𝙩𝙤 𝙎𝙚𝙩𝙩𝙞𝙣𝙜𝙨",
        width=160,
        height=50,
        style=ft.ButtonStyle(
            shape=ft.RoundedRectangleBorder(radius=10),
            color=ft.Colors.WHITE,
            bgcolor=ft.Colors.TRANSPARENT,
            overlay_color=ft.Colors.GREY_700,
            side=ft.BorderSide(color=ft.Colors.GREY_600, width=1),
        ),
        on_click= lambda e: auto_settings(e, page)
    )

    config_button = ft.ElevatedButton(
        "𝙇𝙤𝙖𝙙 𝘾𝙤𝙣𝙛𝙞𝙜",
        width=160,
        height=50,
        style=ft.ButtonStyle(
            shape=ft.RoundedRectangleBorder(radius=10),
            color=ft.Colors.WHITE,
            bgcolor=ft.Colors.TRANSPARENT,
            overlay_color=ft.Colors.GREY_700,
            side=ft.BorderSide(color=ft.Colors.GREY_600, width=1),
        ),
        on_click= lambda e: load_cfg(e, page)
    )

    def create_text_field(label, icon):
        return ft.TextField(
            label=label,
            prefix_icon=icon,
            width=160,
            height=45,
            border_color=ft.Colors.GREY_600,
            focused_border_color=PRIMARY_COLOR,
            border_radius=10,
            cursor_color=PRIMARY_COLOR,
            label_style=ft.TextStyle(color=ft.Colors.GREY_400),
            text_style=ft.TextStyle(color=TEXT_COLOR),
            filled=True,
            fill_color=CARD_COLOR,
        )

    delay_txt = create_text_field("ᴅᴇʟᴀʏ", ft.Icons.TIMER)
    stickers_txt = create_text_field("sᴛɪᴄᴋᴇʀs", ft.Icons.EMOJI_EMOTIONS)
    update = create_text_field("ᴜᴘᴅᴀᴛᴇ ᴛɪᴍᴇ", ft.Icons.UPDATE)

    left_column = ft.Container(
        content=ft.Column(
            controls=[
                start_stop,
                config_button,
                settings_button,
            ],
            spacing=15,
        ),
        padding=10
    )

    right_column = ft.Container(
        content=ft.Column(
            controls=[
                delay_txt,
                stickers_txt,
                update,
            ],
            spacing=20,
        ),
        padding=10
    )

    def create_sell_field(label, value):
        return ft.Container(
            content=ft.Column([
                ft.Text(label, size=12, color=ft.Colors.GREY_400),
                ft.TextField(
                    value=value,
                    width=120,
                    height=40,
                    border_color=ft.Colors.GREY_600,
                    focused_border_color=SECONDARY_COLOR,
                    border_radius=8,
                    text_style=ft.TextStyle(color=TEXT_COLOR, size=14),
                    filled=True,
                    fill_color=CARD_COLOR,
                    content_padding=ft.padding.all(10),
                )
            ], spacing=5)
        )

    to = create_sell_field("оᴛ 2 нᴀᴋᴧᴇᴇᴋ", "")
    tri = create_sell_field("оᴛ 3 нᴀᴋᴧᴇᴇᴋ", "")
    cit = create_sell_field("оᴛ 4 нᴀᴋᴧᴇᴇᴋ", "")

    auto_sell = ft.Switch(
        value=False,
        active_color=SECONDARY_COLOR,
        active_track_color=ft.Colors.CYAN_200,
        thumb_color=ft.Colors.WHITE,
    )

    def update_sell_fields(e=None):
        disabled = not auto_sell.value
        for field in [to.content.controls[1], tri.content.controls[1], cit.content.controls[1]]:
            field.disabled = disabled

    auto_sell.on_change = lambda e: [update_sell_fields(), page.update()]

    home = ft.Container(
        content=ft.Column(
            controls=[
                ft.Container(
                    content=ft.Row(
                        controls=[
                            left_column,
                            ft.VerticalDivider(width=1, color=ft.Colors.GREY_700),
                            right_column,
                        ],
                        alignment=ft.MainAxisAlignment.SPACE_EVENLY,
                    ),
                    bgcolor=CARD_COLOR,
                    border_radius=15,
                    padding=15,
                    shadow=ft.BoxShadow(
                        spread_radius=1,
                        blur_radius=10,
                        color=ft.Colors.BLACK,
                        offset=ft.Offset(0, 2),
                    )
                )
            ],
            spacing=20,
        ),
        padding=10
    )

    settings = ft.Container(
        content=ft.Column(
            controls=[
                ft.Container(
                    content=ft.Column([
                        ft.Row(
                            controls=[
                                ft.Row([
                                    ft.Icon(ft.Icons.SHOPPING_CART, color=SECONDARY_COLOR, size=20),
                                    ft.Text("ᴇɴᴀʙʟᴇ ᴀᴜᴛᴏ sᴇʟʟ", size=16, color=TEXT_COLOR),
                                ], spacing=8),
                                auto_sell,
                            ],
                            alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                        ),
                        ft.Divider(height=20, thickness=1, color=ft.Colors.GREY_700),
                        ft.Row(
                            controls=[to, tri, cit],
                            spacing=15,
                            alignment=ft.MainAxisAlignment.SPACE_EVENLY,
                        ),
                    ]),
                    bgcolor=CARD_COLOR,
                    border_radius=15,
                    padding=20,
                    shadow=ft.BoxShadow(
                        spread_radius=1,
                        blur_radius=10,
                        color=ft.Colors.BLACK,
                        offset=ft.Offset(0, 2),
                    )
                )
            ],
            spacing=20,
            alignment=ft.MainAxisAlignment.CENTER,
        ),
        padding=10,
        expand=True,
    )

    tabs = ft.Tabs(
        animation_duration=400,
        indicator_color=PRIMARY_COLOR,
        label_color=PRIMARY_COLOR,
        unselected_label_color=ft.Colors.GREY_500,
        indicator_border_radius=10,
        indicator_padding=ft.padding.all(2),
        tabs=[
            ft.Tab(
                icon=ft.Icons.HOME,
                content=home
            ),
            ft.Tab(
                icon=ft.Icons.SETTINGS,
                content=settings
            ),
        ],
        expand=True
    )

    page.add(tabs)

    update_sell_fields()
    page.update()

if __name__ == "__main__":
    ft.app(login_page)