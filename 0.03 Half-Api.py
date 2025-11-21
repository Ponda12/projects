import time, re, random
import flet as ft
import pymemoryapi
from tkinter import messagebox
import ctypes
from ctypes import wintypes
import psutil, struct
import win32gui, win32process, win32con, win32api
import threading, asyncio
from os import abort
import os
import hashlib, subprocess, requests
import uuid
import telebot
import pyautogui, mss
from telebot import types

_colors = getattr(ft, "colors", None) or getattr(ft, "Colors", None)
_icons = getattr(ft, "icons", None) or getattr(ft, "Icons", None)


pastebin_link = "https://pastebin.com/raw/1a6s7cpE"

key_file = "key.json"


PROCESS_ALL_ACCESS = 0x1F0FFF
MEM_COMMIT = 0x1000
PAGE_READWRITE = 0x04

running = False
selected_mode = "Default"
opened_settings = None
start_button = None

request_addr = None
balance_addr = None
lot_addr = None
input_addr = None
min_change = 0.005
max_price = 1000000.0

await_time = 2.0
anti_full_threshold = 0.15

request_value = ft.Ref[ft.Text]()
balance_value = ft.Ref[ft.Text]()
lot_value = ft.Ref[ft.Text]()

zp1 = (1661, 186)
zp2 = (951, 693)
size = (1920, 1080)
vvod = (981, 446)
cancel = (1660, 279)


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_ulonglong),
        ("AllocationBase", ctypes.c_ulonglong),
        ("AllocationProtect", wintypes.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD)
    ]


kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
OpenProcess = kernel32.OpenProcess
OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
OpenProcess.restype = wintypes.HANDLE

VirtualQueryEx = kernel32.VirtualQueryEx
VirtualQueryEx.argtypes = [wintypes.HANDLE, wintypes.LPCVOID,
                           ctypes.POINTER(MEMORY_BASIC_INFORMATION), ctypes.c_size_t]
VirtualQueryEx.restype = ctypes.c_size_t

ReadProcessMemory = kernel32.ReadProcessMemory
ReadProcessMemory.argtypes = [wintypes.HANDLE, wintypes.LPCVOID,
                              wintypes.LPVOID, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
ReadProcessMemory.restype = wintypes.BOOL


class RECT(ctypes.Structure):
    _fields_ = [('left', ctypes.c_long), ('top', ctypes.c_long), ('right', ctypes.c_long), ('bottom', ctypes.c_long)]


def window_rect(hwnd):
    rect = wintypes.RECT()
    ctypes.windll.user32.GetWindowRect(hwnd, ctypes.byref(rect))
    return rect


def cords(rect, x, y, original_size):
    ww, wh = rect.right - rect.left, rect.bottom - rect.top
    nx, ny = x / original_size[0], y / original_size[1]
    return int(nx * ww), int(ny * wh)


def click(hwnd, x, y):
    lparam = win32api.MAKELONG(x, y)
    win32gui.SendMessage(hwnd, win32con.WM_MOUSEMOVE, 0, lparam)
    win32gui.SendMessage(hwnd, win32con.WM_LBUTTONDOWN, win32con.MK_LBUTTON, lparam)
    win32gui.SendMessage(hwnd, win32con.WM_LBUTTONUP, 0, lparam)


def get_process_pid(proc_name, window_number=1):
    proc_num = 0
    for proc in sorted(psutil.process_iter(['pid', 'name', 'create_time']),
                       key=lambda p: p.info.get('create_time', 0)):
        if proc.info['name'] == proc_name:
            proc_num += 1
            if proc_num == window_number:
                return proc.pid
    return None


def enum_window_callback(hwnd, pid):
    tid, current_pid = win32process.GetWindowThreadProcessId(hwnd)
    if pid == current_pid and win32gui.IsWindowVisible(hwnd):
        windows.append(hwnd)


def read_float(process_handle, address):
    float_value = ctypes.c_float()
    bytes_read = ctypes.c_size_t()
    addr = ctypes.c_void_p(address)
    success = ctypes.windll.kernel32.ReadProcessMemory(process_handle, addr, ctypes.byref(float_value),
                                                       ctypes.sizeof(float_value), ctypes.byref(bytes_read))
    if not success:
        ctypes.windll.user32.MessageBoxW(None, f"Ошибка чтения памяти по адресу {hex(address)}!", "Ошибка", 0)
        abort()
    return float_value.value


def write_float(process_handle, address, value):
    float_value = ctypes.c_float(value)
    bytes_written = ctypes.c_size_t()
    addr = ctypes.c_void_p(address)
    success = ctypes.windll.kernel32.WriteProcessMemory(process_handle, addr, ctypes.byref(float_value),
                                                        ctypes.sizeof(float_value), ctypes.byref(bytes_written))
    if not success:
        ctypes.windll.user32.MessageBoxW(None, f"Ошибка записи памяти по адресу {hex(address)}!", "Ошибка", 0)
        abort()


def scan_memory():
    process_name = "Ld9BoxHeadless.exe"
    window_process_name = "dnplayer.exe"
    window_number = 1

    pid = get_process_pid(process_name, window_number)
    if not pid:
        raise Exception("Процесс Ld9BoxHeadless.exe не найден! Запусти игру!")

    global windows
    windows = []
    window_pid = get_process_pid(window_process_name, window_number)
    if not window_pid:
        raise Exception("Процесс dnplayer.exe не найден!")

    win32gui.EnumWindows(enum_window_callback, window_pid)
    if not windows:
        raise Exception("Окно dnplayer.exe не найдено!")

    h_process = ctypes.windll.kernel32.OpenProcess(0x0010 | 0x0020 | 0x0400, False, pid)
    if not h_process:
        raise Exception("Не удалось открыть процесс Ld9BoxHeadless.exe!")

    process = pymemoryapi.Process(pid=pid)
    results = []

    signatures = [
        ("баланс", "FF FF FF FF 65 00 00 00 00 00 ?? ?? 66 00 00 00 FF FF FF FF 66"),
        ("запрос", "12 1C 1A 18 1A 16 0A 14 08 ?? ?? ?? 10 ?? 18 ?? ?? ?? 25 ?? ??")
    ]

    for name, signature in signatures:
        address = process.pattern_scan(
            return_first_found=True,
            start_address=0x0,
            end_address=0x120000000,
            pattern=signature
        )
        if address is None:
            raise Exception(f"Адрес {name} не найден!")

        addressz = address + 0x18
        float_value = read_float(h_process, addressz)
        results.append((name, addressz, float_value))

    return results, pid


def find_input_address():
    global input_addr
    process_name = "Ld9BoxHeadless.exe"
    window_number = 1
    value = 1488.52
    pid = get_process_pid(process_name, window_number)
    h_process = OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not h_process:
        raise Exception("Не удалось открыть процесс для сканирования!")

    addr = 0
    mbi = MEMORY_BASIC_INFORMATION()
    size_mbi = ctypes.sizeof(mbi)
    pattern = struct.pack('f', value)

    while addr < 0x7FFFFFFFFFFF:
        if not VirtualQueryEx(h_process, addr, ctypes.byref(mbi), size_mbi):
            addr += 0x1000
            continue

        base = int(mbi.BaseAddress)
        region_size = int(mbi.RegionSize)

        if mbi.State == MEM_COMMIT and mbi.Protect == PAGE_READWRITE:
            buffer = (ctypes.c_char * region_size)()
            bytesRead = ctypes.c_size_t()
            if ReadProcessMemory(h_process, base, buffer, region_size, ctypes.byref(bytesRead)):
                raw = buffer.raw[:bytesRead.value]

                idx = raw.find(pattern)
                if idx != -1:
                    input_addr = base + idx
                    return input_addr

        addr = base + region_size

    raise Exception("Адрес ввода не найден!")


def autosetprice(price=None):
    try:
        price = float(price)
    except (TypeError, ValueError):
        return False

    okrugprice = round(price, 2)
    nenorm = r'^\d+(\.\d{1,2})?$'

    if 10 < okrugprice <= 100000.00 and re.match(nenorm, f"{okrugprice}"):
        return True
    return False


def find_request_addr(base_addr):
    process_name = "Ld9BoxHeadless.exe"
    window_number = 1
    pid = get_process_pid(process_name, window_number)
    h_process = OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not h_process:
        raise Exception("Не удалось открыть процесс для сканирования!")

    base_nibble = request_addr & ~0xF

    for last_digit in (6, 7, 8, 9):
        candidate = base_nibble | last_digit
        try:
            val = read_float(h_process, candidate)
        except Exception:
            continue

        if autosetprice(val):
            return candidate, round(val, 2)

    return None


def auto_settings(e=None):
    global request_addr, balance_addr, lot_addr, input_addr

    value = 1488.52

    hwnd = win32gui.FindWindow(None, "LDPlayer")
    if hwnd == 0:
        return
    hwnd = win32gui.FindWindowEx(hwnd, None, None, None)

    rect = window_rect(hwnd)
    zp1_in = cords(rect, zp1[0], zp1[1], size)
    zp2_in = cords(rect, zp2[0], zp2[1], size)
    vvod_in = cords(rect, vvod[0], vvod[1], size)
    cancel_in = cords(rect, cancel[0], cancel[1], size)

    click(hwnd, zp1_in[0], zp1_in[1])
    time.sleep(0.3)
    click(hwnd, vvod_in[0], vvod_in[1])
    time.sleep(0.3)
    for ch in "0.03":
        win32api.PostMessage(hwnd, win32con.WM_CHAR, ord(ch), 0)
        time.sleep(0.09)
    time.sleep(0.2)
    click(hwnd, zp2_in[0], zp2_in[1])
    time.sleep(0.5)
    click(hwnd, cancel_in[0], cancel_in[1])

    try:
        results, pid = scan_memory()
    except Exception as ex:
        messagebox.showerror("Ошибка", str(ex))
        return

    try:
        click(hwnd, zp1_in[0], zp1_in[1])
        time.sleep(0.3)
        click(hwnd, vvod_in[0], vvod_in[1])
        time.sleep(0.3)
        for ch in str(value):
            if ch == '.':
                win32api.PostMessage(hwnd, win32con.WM_CHAR, ord('.'), 0)
            else:
                win32api.PostMessage(hwnd, win32con.WM_CHAR, ord(ch), 0)
            time.sleep(0.09)

        win32api.PostMessage(hwnd, win32con.WM_KEYDOWN, win32con.VK_RETURN, 0)
        win32api.PostMessage(hwnd, win32con.WM_KEYUP, win32con.VK_RETURN, 0)
        time.sleep(0.1)
        input_addr = find_input_address()

    except Exception as ex:
        messagebox.showerror("Ошибка", f"Не удалось найти адрес ввода: {ex}")
        return

    msg = ""
    for name, addressz, float_value in results:
        msg += f"{name}: {hex(addressz)}, значение: {float_value:.2f}\n"
        if "запрос" in name:
            request_addr = addressz
            lot_addr = addressz - 5
        elif "баланс" in name:
            balance_addr = addressz

    msg += f"ввод: {hex(input_addr)}, значение: 1488.52"

    try:
        pm = pymemoryapi.Process(pid=pid)
    except Exception as ex:
        messagebox.showerror("Ошибка", f"Не удалось открыть процесс: {ex}")
        return

    messagebox.showinfo("Авто настройка прошла успешно!", msg)



async def auto_update(page, request_value, balance_value, lot_value):
    global request_addr, balance_addr, lot_addr
    process_name = "Ld9BoxHeadless.exe"
    window_number = 1
    pid = get_process_pid(process_name, window_number)
    h_process = OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not h_process:
        raise Exception("Не удалось открыть процесс для сканирования!")
    last_req = None
    last_lot = None
    last_bal = None

    while True:
        try:
            if not all([request_addr, balance_addr, lot_addr]):
                await asyncio.sleep(0.5)
                continue

            req = read_float(h_process, request_addr)
            bal = read_float(h_process, balance_addr)
            lot = read_float(h_process, lot_addr)

            if req is not None and req != 0 and -1e-08 < req < max_price:
                last_req = req
            if lot is not None and lot != 0 and -1e-08 < lot < max_price:
                last_lot = lot
            if bal is not None and bal != 0 and -1e-08 < bal < max_price:
                last_bal = bal

            if request_value.current:
                request_value.current.value = f"{last_req:.2f}" if last_req is not None else "--"
            if balance_value.current:
                balance_value.current.value = f"{last_bal:.2f}" if last_bal is not None else "--"
            if lot_value.current:
                lot_value.current.value = f"{last_lot:.2f}" if last_lot is not None else "--"

            page.update()


        except Exception as ex:
            if request_value.current:
                request_value.current.value = "--"
            if balance_value.current:
                balance_value.current.value = "--"
            if lot_value.current:
                lot_value.current.value = "--"

        await asyncio.sleep(0.5)

def take_screen():
    with mss.mss() as sct:
        filename = f"screen_{int(time.time())}.png"
        sct.shot(output=filename)



def def_mode():
    global request_addr, balance_addr, lot_addr, input_addr, running

    hwnd = win32gui.FindWindow(None, "LDPlayer")
    if hwnd == 0:
        return
    hwnd = win32gui.FindWindowEx(hwnd, None, None, None)

    rect = window_rect(hwnd)
    zp1_in = cords(rect, zp1[0], zp1[1], size)
    zp2_in = cords(rect, zp2[0], zp2[1], size)
    vvod_in = cords(rect, vvod[0], vvod[1], size)
    cancel_in = cords(rect, cancel[0], cancel[1], size)
    process_name = "Ld9BoxHeadless.exe"
    window_number = 1
    pid = get_process_pid(process_name, window_number)
    h_process = OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not h_process:
        raise Exception("Не удалось открыть процесс для сканирования!")
    click(hwnd, zp1_in[0], zp1_in[1])

    running = True
    last_req = None
    last_lot = None
    init_req = read_float(h_process, request_addr)
    init_lot = read_float(h_process, lot_addr)
    if init_req is not None and init_lot is not None:
        last_req = round(init_req, 2)
        last_lot = round(init_lot, 2)

    while running:
        req = read_float(h_process, request_addr)
        lot = read_float(h_process, lot_addr)

        if req == 0.0 or abs(req) < 1e-06:
            continue

        if lot == 0.0 or abs(lot) < 1e-06:
            continue

        if req > max_price or lot > max_price:
            continue

        req_r = round(req, 2)
        lot_r = round(lot, 2)

        if last_req is None:
            last_req = req_r
            last_lot = lot_r
            continue

        if req_r == 0.0 or (last_req == 0 and req_r > 0):
            last_req = req_r
            continue

        if abs(req_r - last_req) < min_change:
            continue

        if req_r + 0.01 <= lot_r - 0.01 and req_r > last_req:
            new_req = round(req_r + 0.01, 2)
            time.sleep(0.1)
            write_float(h_process, input_addr, new_req)
            print("Поставил новый запрос", new_req)
            click(hwnd, zp2_in[0], zp2_in[1])
            time.sleep(2)
            click(hwnd, cancel_in[0], cancel_in[1])
            time.sleep(0.3)
            click(hwnd, zp1_in[0], zp1_in[1])

        last_req = req_r
        last_lot = lot_r

    time.sleep(0.005)


def full_mode():
    global request_addr, balance_addr, lot_addr, input_addr, running

    hwnd = win32gui.FindWindow(None, "LDPlayer")
    if hwnd == 0:
        return
    hwnd = win32gui.FindWindowEx(hwnd, None, None, None)

    rect = window_rect(hwnd)
    zp1_in = cords(rect, zp1[0], zp1[1], size)
    zp2_in = cords(rect, zp2[0], zp2[1], size)
    vvod_in = cords(rect, vvod[0], vvod[1], size)
    cancel_in = cords(rect, cancel[0], cancel[1], size)
    process_name = "Ld9BoxHeadless.exe"
    window_number = 1
    pid = get_process_pid(process_name, window_number)
    h_process = OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not h_process:
        raise Exception("Не удалось открыть процесс для сканирования!")
    click(hwnd, zp1_in[0], zp1_in[1])

    running = True
    last_req = None
    last_lot = None
    last_bal = None
    init_req = read_float(h_process, request_addr)
    init_lot = read_float(h_process, lot_addr)
    init_bal = read_float(h_process, balance_addr)
    if init_req is not None and init_lot is not None:
        last_req = round(init_req, 2)
        last_lot = round(init_lot, 2)
        last_bal = round(init_bal, 2)

    while running:
        req = read_float(h_process, request_addr)
        lot = read_float(h_process, lot_addr)
        bal = read_float(h_process, balance_addr)

        if req == 0.0 or abs(req) < 1e-06:
            continue

        if lot == 0.0 or abs(lot) < 1e-06:
            continue

        if req > max_price or lot > max_price:
            continue

        req_r = round(req, 2)
        lot_r = round(lot, 2)

        if last_req is None:
            last_req = req_r
            last_lot = lot_r
            continue

        if req_r == 0.0 or (last_req == 0 and req_r > 0):
            last_req = req_r
            continue

        if abs(req_r - last_req) < min_change:
            continue

        if req_r + 0.01 <= lot_r - 0.01 and req_r > last_req:
            new_req = round(lot_r - 0.01, 2)
            time.sleep(0.01)
            write_float(h_process, input_addr, new_req)
            click(hwnd, zp2_in[0], zp2_in[1])
            time.sleep(2)
            click(hwnd, cancel_in[0], cancel_in[1])
            time.sleep(0.3)
            click(hwnd, zp1_in[0], zp1_in[1])
            time.sleep(0.2)
            if (last_bal - bal) > 0.02:
                take_screen()


        last_req = req_r
        last_lot = lot_r

    time.sleep(0.005)


def double_request_mode():
    global request_addr, balance_addr, lot_addr, input_addr, running

    hwnd = win32gui.FindWindow(None, "LDPlayer")
    if hwnd == 0:
        return
    hwnd = win32gui.FindWindowEx(hwnd, None, None, None)

    rect = window_rect(hwnd)
    zp1_in = cords(rect, zp1[0], zp1[1], size)
    zp2_in = cords(rect, zp2[0], zp2[1], size)
    vvod_in = cords(rect, vvod[0], vvod[1], size)
    cancel_in = cords(rect, cancel[0], cancel[1], size)
    process_name = "Ld9BoxHeadless.exe"
    window_number = 1
    pid = get_process_pid(process_name, window_number)
    h_process = OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not h_process:
        raise Exception("Не удалось открыть процесс для сканирования!")
    click(hwnd, zp1_in[0], zp1_in[1])

    running = True
    last_req = None
    last_lot = None
    init_req = read_float(h_process, request_addr)
    init_lot = read_float(h_process, lot_addr)
    if init_req is not None and init_lot is not None:
        last_req = round(init_req, 2)
        last_lot = round(init_lot, 2)

    while running:
        req = read_float(h_process, request_addr)
        lot = read_float(h_process, lot_addr)

        if req == 0.0 or abs(req) < 1e-06:
            continue

        if lot == 0.0 or abs(lot) < 1e-06:
            continue

        if req > max_price or lot > max_price:
            continue

        req_r = round(req, 2)
        lot_r = round(lot, 2)

        if last_req is None:
            last_req = req_r
            last_lot = lot_r
            continue

        if req_r == 0.0 or (last_req == 0 and req_r > 0):
            last_req = req_r
            continue

        if abs(req_r - last_req) < min_change:
            continue

        if req_r + 0.01 <= lot_r - 0.01 and req_r > last_req:
            new_req = round(req_r + 0.01, 2)
            if new_req >= lot_r:
                new_req = round(lot_r - 0.01, 2)

            time.sleep(0.01)
            write_float(h_process, input_addr, new_req)
            click(hwnd, zp2_in[0], zp2_in[1])
            time.sleep(2)
            click(hwnd, cancel_in[0], cancel_in[1])
            time.sleep(0.5)
            click(hwnd, zp1_in[0], zp1_in[1])
            time.sleep(0.1)

            write_float(h_process, input_addr, new_req)
            click(hwnd, zp2_in[0], zp2_in[1])
            time.sleep(2)
            click(hwnd, cancel_in[0], cancel_in[1])
            time.sleep(0.5)
            click(hwnd, zp1_in[0], zp1_in[1])
            time.sleep(2)

        last_req = req_r
        last_lot = lot_r

    time.sleep(0.005)


def await_mode():
    global request_addr, balance_addr, lot_addr, input_addr, running, await_time

    hwnd = win32gui.FindWindow(None, "LDPlayer")
    if hwnd == 0:
        return
    hwnd = win32gui.FindWindowEx(hwnd, None, None, None)

    rect = window_rect(hwnd)
    zp1_in = cords(rect, zp1[0], zp1[1], size)
    zp2_in = cords(rect, zp2[0], zp2[1], size)
    vvod_in = cords(rect, vvod[0], vvod[1], size)
    cancel_in = cords(rect, cancel[0], cancel[1], size)
    process_name = "Ld9BoxHeadless.exe"
    window_number = 1
    pid = get_process_pid(process_name, window_number)
    h_process = OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not h_process:
        raise Exception("Не удалось открыть процесс для сканирования!")
    click(hwnd, zp1_in[0], zp1_in[1])

    running = True
    last_req = None
    last_lot = None
    init_req = read_float(h_process, request_addr)
    init_lot = read_float(h_process, lot_addr)
    if init_req is not None and init_lot is not None:
        last_req = round(init_req, 2)
        last_lot = round(init_lot, 2)

    while running:
        req = read_float(h_process, request_addr)
        lot = read_float(h_process, lot_addr)

        if req == 0.0 or abs(req) < 1e-06:
            continue

        if lot == 0.0 or abs(lot) < 1e-06:
            continue

        if req > max_price or lot > max_price:
            continue

        req_r = round(req, 2)
        lot_r = round(lot, 2)

        if last_req is None:
            last_req = req_r
            last_lot = lot_r
            continue

        if req_r == 0.0 or (last_req == 0 and req_r > 0):
            last_req = req_r
            continue

        if abs(req_r - last_req) < min_change:
            continue

        if req_r + 0.01 <= lot_r - 0.01 and req_r > last_req:
            time.sleep(await_time)
            new_req = round(req_r + 0.01, 2)
            if new_req >= lot_r:
                new_req = round(lot_r - 0.01, 2)

            time.sleep(0.01)
            write_float(h_process, input_addr, new_req)
            click(hwnd, zp2_in[0], zp2_in[1])
            time.sleep(0.5)
            click(hwnd, cancel_in[0], cancel_in[1])
            time.sleep(0.3)
            click(hwnd, zp1_in[0], zp1_in[1])

        last_req = req_r
        last_lot = lot_r

    time.sleep(0.005)


def anti_full_mode():
    global request_addr, balance_addr, lot_addr, input_addr, running, anti_full_threshold

    hwnd = win32gui.FindWindow(None, "LDPlayer")
    if hwnd == 0:
        return
    hwnd = win32gui.FindWindowEx(hwnd, None, None, None)

    rect = window_rect(hwnd)
    zp1_in = cords(rect, zp1[0], zp1[1], size)
    zp2_in = cords(rect, zp2[0], zp2[1], size)
    vvod_in = cords(rect, vvod[0], vvod[1], size)
    cancel_in = cords(rect, cancel[0], cancel[1], size)
    process_name = "Ld9BoxHeadless.exe"
    window_number = 1
    pid = get_process_pid(process_name, window_number)
    h_process = OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not h_process:
        raise Exception("Не удалось открыть процесс для сканирования!")
    click(hwnd, zp1_in[0], zp1_in[1])

    running = True
    last_req = None
    last_lot = None
    init_req = read_float(h_process, request_addr)
    init_lot = read_float(h_process, lot_addr)
    if init_req is not None and init_lot is not None:
        last_req = round(init_req, 2)
        last_lot = round(init_lot, 2)

    while running:
        req = read_float(h_process, request_addr)
        lot = read_float(h_process, lot_addr)

        if req == 0.0 or abs(req) < 1e-06:
            continue

        if lot == 0.0 or abs(lot) < 1e-06:
            continue

        if req > max_price or lot > max_price:
            continue

        req_r = round(req, 2)
        lot_r = round(lot, 2)

        if last_req is None:
            last_req = req_r
            last_lot = lot_r
            continue

        if req_r == 0.0 or (last_req == 0 and req_r > 0):
            last_req = req_r
            continue

        if abs(req_r - last_req) < min_change:
            continue

        difference = lot_r - req_r
        if difference <= anti_full_threshold:
            last_req = req_r
            last_lot = lot_r
            continue

        if req_r + 0.01 <= lot_r - 0.01 and req_r > last_req:
            new_req = round(req_r + 0.01, 2)
            time.sleep(0.1)
            write_float(h_process, input_addr, new_req)
            click(hwnd, zp2_in[0], zp2_in[1])
            time.sleep(2)
            click(hwnd, cancel_in[0], cancel_in[1])
            time.sleep(0.3)
            click(hwnd, zp1_in[0], zp1_in[1])

        last_req = req_r
        last_lot = lot_r

    time.sleep(0.005)


def api_mode():
    global request_addr, balance_addr, lot_addr, input_addr, running

    hwnd = win32gui.FindWindow(None, "LDPlayer")
    if hwnd == 0:
        return
    hwnd = win32gui.FindWindowEx(hwnd, None, None, None)

    rect = window_rect(hwnd)
    zp1_in = cords(rect, zp1[0], zp1[1], size)
    zp2_in = cords(rect, zp2[0], zp2[1], size)
    vvod_in = cords(rect, vvod[0], vvod[1], size)
    cancel_in = cords(rect, cancel[0], cancel[1], size)
    process_name = "Ld9BoxHeadless.exe"
    window_number = 1
    pid = get_process_pid(process_name, window_number)
    h_process = OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not h_process:
        raise Exception("Не удалось открыть процесс для сканирования!")
    click(hwnd, zp1_in[0], zp1_in[1])

    running = True
    last_req = None
    last_lot = None
    last = None

    init_req = read_float(h_process, request_addr)
    init_lot = read_float(h_process, lot_addr)
    if init_req is not None and init_lot is not None:
        last_req = round(init_req, 2)
        last_lot = round(init_lot, 2)

    while running:
        req = read_float(h_process, request_addr)
        lot = read_float(h_process, lot_addr)

        if req == 0.0 or abs(req) < 1e-06:
            continue

        if lot == 0.0 or abs(lot) < 1e-06:
            continue

        if req > max_price or lot > max_price:
            continue

        req_r = round(req, 2)
        lot_r = round(lot, 2)

        if last_req is None:
            last_req = req_r
            last_lot = lot_r
            continue

        if last is not None and req_r > last:
            new_req = round(req_r + 0.01, 2)

            if new_req >= lot_r - 0.01:
                last = None
                last_req = req_r
                continue

            time.sleep(0.01)
            write_float(h_process, input_addr, new_req)
            click(hwnd, zp2_in[0], zp2_in[1])
            time.sleep(1)
            click(hwnd, cancel_in[0], cancel_in[1])
            time.sleep(0.3)
            click(hwnd, zp1_in[0], zp1_in[1])

            last = new_req
            last_req = req_r
            continue

        if req_r + 0.01 <= lot_r - 0.01 and req_r > last_req:
            new_req = round(req_r + 0.01, 2)
            if new_req >= lot_r - 0.01:
                last_req = req_r
                continue

            time.sleep(0.01)
            write_float(h_process, input_addr, new_req)
            click(hwnd, zp2_in[0], zp2_in[1])
            time.sleep(1)
            click(hwnd, cancel_in[0], cancel_in[1])
            time.sleep(0.3)
            click(hwnd, zp1_in[0], zp1_in[1])

            last = new_req
            last_req = req_r

        last_req = req_r
        last_lot = lot_r

    time.sleep(0.005)


def half_mode():
    global request_addr, balance_addr, lot_addr, input_addr, running

    hwnd = win32gui.FindWindow(None, "LDPlayer")
    if hwnd == 0:
        return
    hwnd = win32gui.FindWindowEx(hwnd, None, None, None)

    rect = window_rect(hwnd)
    zp1_in = cords(rect, zp1[0], zp1[1], size)
    zp2_in = cords(rect, zp2[0], zp2[1], size)
    vvod_in = cords(rect, vvod[0], vvod[1], size)
    cancel_in = cords(rect, cancel[0], cancel[1], size)
    process_name = "Ld9BoxHeadless.exe"
    window_number = 1
    pid = get_process_pid(process_name, window_number)
    h_process = OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not h_process:
        raise Exception("Не удалось открыть процесс для сканирования!")
    click(hwnd, zp1_in[0], zp1_in[1])

    running = True
    last_req = None
    last_lot = None
    init_req = read_float(h_process, request_addr)
    init_lot = read_float(h_process, lot_addr)
    if init_req is not None and init_lot is not None:
        last_req = round(init_req, 2)
        last_lot = round(init_lot, 2)

    while running:
        req = read_float(h_process, request_addr)
        lot = read_float(h_process, lot_addr)

        if req == 0.0 or abs(req) < 1e-06:
            continue

        if lot == 0.0 or abs(lot) < 1e-06:
            continue

        if req > max_price or lot > max_price:
            continue

        req_r = round(req, 2)
        lot_r = round(lot, 2)

        if last_req is None:
            last_req = req_r
            last_lot = lot_r
            continue

        if req_r == 0.0 or (last_req == 0 and req_r > 0):
            last_req = req_r
            continue

        if abs(req_r - last_req) < min_change:
            continue

        if req_r + 0.01 <= lot_r - 0.01 and req_r > last_req:
            half = req_r + (lot_r - req_r) / 2
            new_req = round(req_r + half, 2)

            if new_req >= lot_r:
                new_req = round(lot_r - 0.01, 2)
            elif new_req <= req_r:
                new_req = round(req_r + 0.01, 2)

            time.sleep(0.01)
            write_float(h_process, input_addr, new_req)
            click(hwnd, zp2_in[0], zp2_in[1])
            time.sleep(2)
            click(hwnd, cancel_in[0], cancel_in[1])
            time.sleep(0.3)
            click(hwnd, zp1_in[0], zp1_in[1])

        last_req = req_r
        last_lot = lot_r

    time.sleep(0.005)


def custom_mode():
    global request_addr, balance_addr, lot_addr, input_addr, running

    hwnd = win32gui.FindWindow(None, "LDPlayer")
    if hwnd == 0:
        return
    hwnd = win32gui.FindWindowEx(hwnd, None, None, None)

    rect = window_rect(hwnd)
    zp1_in = cords(rect, zp1[0], zp1[1], size)
    zp2_in = cords(rect, zp2[0], zp2[1], size)
    vvod_in = cords(rect, vvod[0], vvod[1], size)
    cancel_in = cords(rect, cancel[0], cancel[1], size)
    process_name = "Ld9BoxHeadless.exe"
    window_number = 1
    pid = get_process_pid(process_name, window_number)
    h_process = OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not h_process:
        raise Exception("Не удалось открыть процесс для сканирования!")
    click(hwnd, zp1_in[0], zp1_in[1])

    running = True
    last_req = None

    custom_amount = get_custom()

    while running:
        req = read_float(h_process, request_addr)
        lot = read_float(h_process, lot_addr)

        if req == 0.0 or lot == 0.0:
            continue

        req_r = round(req, 2)
        lot_r = round(lot, 2)

        if last_req is None:
            last_req = req_r
            continue

        if req_r > last_req and req_r + custom_amount < lot_r:
            new_req = round(req_r + custom_amount, 2)

            write_float(h_process, input_addr, new_req)
            click(hwnd, zp2_in[0], zp2_in[1])
            time.sleep(1.5)
            click(hwnd, cancel_in[0], cancel_in[1])
            time.sleep(0.3)
            click(hwnd, zp1_in[0], zp1_in[1])

        last_req = req_r

    time.sleep(0.005)


custom = 0.05


def random_mode():
    global request_addr, balance_addr, lot_addr, input_addr, running

    hwnd = win32gui.FindWindow(None, "LDPlayer")
    if hwnd == 0:
        return
    hwnd = win32gui.FindWindowEx(hwnd, None, None, None)

    rect = window_rect(hwnd)
    zp1_in = cords(rect, zp1[0], zp1[1], size)
    zp2_in = cords(rect, zp2[0], zp2[1], size)
    vvod_in = cords(rect, vvod[0], vvod[1], size)
    cancel_in = cords(rect, cancel[0], cancel[1], size)
    process_name = "Ld9BoxHeadless.exe"
    window_number = 1
    pid = get_process_pid(process_name, window_number)
    h_process = OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not h_process:
        raise Exception("Не удалось открыть процесс для сканирования!")

    print("⚙️ Random Mode запущен")
    click(hwnd, zp1_in[0], zp1_in[1])

    running = True
    last_req = None

    min_val, max_val = get_random()

    while running:
        req = read_float(h_process, request_addr)
        lot = read_float(h_process, lot_addr)

        if req == 0.0 or lot == 0.0:
            continue

        req_r = round(req, 2)
        lot_r = round(lot, 2)

        if last_req is None:
            last_req = req_r
            continue

        if req_r > last_req:
            random_add = round(random.uniform(min_val, max_val), 2)
            new_req = round(req_r + random_add, 2)

            if new_req < lot_r - 0.01:
                write_float(h_process, input_addr, new_req)
                click(hwnd, zp2_in[0], zp2_in[1])
                time.sleep(1.5)
                click(hwnd, cancel_in[0], cancel_in[1])
                time.sleep(0.3)
                click(hwnd, zp1_in[0], zp1_in[1])

        last_req = req_r

    time.sleep(0.005)


rand_min = 0.01
rand_max = 0.10


def get_random():
    return rand_min, rand_max


def set_random_range(min_val, max_val):
    global rand_min, rand_max
    try:
        rand_min = float(min_val)
        rand_max = float(max_val)
        return True
    except:
        return False


def get_custom():
    return custom


def set_custom_bid_amount(value):
    global custom
    try:
        custom = float(value)
        return True
    except:
        return False


def set_await_time(value):
    global await_time
    try:
        await_time = float(value)
        return True
    except:
        return False


def set_anti_full_threshold(value):
    global anti_full_threshold
    try:
        anti_full_threshold = float(value)
        return True
    except:
        return False


def save_key_1(key_value):
    with open(key_file, "w", encoding="utf-8") as f:
        json.dump({"key": key_value}, f, indent=4)

def load_key():
    if os.path.exists(key_file):
        with open(key_file, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data.get("key", "")

    return ""


def get_hwid():
    try:
        output = subprocess.check_output(
            "wmic csproduct get uuid", shell=True, stderr=subprocess.DEVNULL
        ).decode(errors="ignore").split()
        hwid_source = output[-1] if len(output) > 1 else None
    except Exception:
        hwid_source = None

    if not hwid_source:
        try:
            hwid_source = subprocess.check_output(
                'powershell -Command "(Get-CimInstance Win32_ComputerSystemProduct).UUID"',
                shell=True, stderr=subprocess.DEVNULL
            ).decode(errors="ignore").strip()
        except Exception:
            hwid_source = None

    if not hwid_source:
        hwid_source = str(uuid.getnode())

    hwid = hashlib.md5(hwid_source.encode()).hexdigest()
    return hwid

def check_key(user_key: str) -> bool:
    hwid = get_hwid()
    resp = requests.get(pastebin_link, timeout=5)
    if resp.status_code != 200:
        return False
    for line in resp.text.strip().splitlines():
        stored_hwid, stored_key = line.split(":")
        if stored_hwid == hwid and stored_key == user_key:
            return True

    return False

def logging_page(page: ft.Page):
    page.window.width = 450
    page.window.height = 300
    page.title = "𝐀𝐮𝐭𝐡𝐨𝐫𝐢𝐳𝐚𝐭𝐢𝐨𝐧"
    page.window.resizable = False
    page.window.center()

    saved_key = load_key()

    def check_bd(e):
        if check_key(password.value.strip()):
            main_window(page)

        else:
            page.update()
            messagebox.showerror("Ошибка доступа", "Вас нет в базе данных для авторизации")

    def buy_key_logic(e):
        webbrowser.open("https://t.me/Traider_script")


    def save_key_btn(e):
        key_value = password.value.strip()
        if not key_value:
            messagebox.showerror("Ошибка в сохранении","Ввведите ключ перед сохранением")
            return

        save_key_1(key_value)
        messagebox.showinfo("Успех","Ваш ключ успешно сохранен")



    password = ft.TextField(
        label="𝐄𝐧𝐭𝐞𝐫 𝐲𝐨𝐮𝐫 𝐤𝐞𝐲",
        password=True,
        can_reveal_password=True,
        width= 275,
        height= 50,
        border_color=ft.Colors.GREY,
        focused_border_color=ft.Colors.BLUE,
        border_radius=6,
        value=saved_key,
    )

    signin_btn = ft.ElevatedButton(
        "𝐒𝐢𝐠𝐧 𝐈𝐧",
        width= 120,
        height= 50,
        on_click=check_bd,
        style=ft.ButtonStyle(
            shape=ft.RoundedRectangleBorder(radius=6),
            text_style=ft.TextStyle(size=18),
            side=ft.BorderSide(1, ft.Colors.GREY),
        ),
    )

    save_key = ft.ElevatedButton(
        "𝐒𝐚𝐯𝐞 𝐤𝐞𝐲",
        width= 120,
        height= 50,
        on_click=save_key_btn,
        style=ft.ButtonStyle(
            shape=ft.RoundedRectangleBorder(radius=6),
            text_style=ft.TextStyle(size=18),
            side=ft.BorderSide(1, ft.Colors.GREY),
        ),
    )

    welcome_lb = ft.Text(
        "𝐖𝐞𝐥𝐜𝐨𝐦𝐞 𝐔𝐬𝐞𝐫",
        size = 27,
        width= 200,
        height= 40,
    )

    buy_key = ft.TextButton(
        "нᴇᴛ ᴋᴧючᴀ?",
        on_click=buy_key_logic,
        width= 110,
        height= 40,
        style=ft.ButtonStyle(
            text_style=ft.TextStyle(size=18),
        )
    )


    row = ft.Row(
        [signin_btn, save_key],
        spacing=10,
        alignment= ft.MainAxisAlignment.CENTER,
        expand=True,
    )
    center_column = ft.Container(
        content=ft.Column([welcome_lb, password, row, buy_key],spacing=20,horizontal_alignment= ft.CrossAxisAlignment.CENTER),
        alignment=ft.alignment.center,
        expand= True
    )


    page.add(center_column)

def main_menu(page: ft.Page):
    global start_button
    title = ft.Row(controls=[ft.Icon(name=ft.Icons.HOME, size=23, color="white"), ft.Text("𝐌𝐞𝐧𝐮", size=23), ],
                   spacing=5, alignment="start", vertical_alignment="center")

    def start_app(e):
        global running, selected_mode, start_button
        if start_button.text == "🟢 𝐒𝐓𝐀𝐑𝐓":
            running = True
            process_name = "Ld9BoxHeadless.exe"
            pid = get_process_pid(process_name)
            h_process = OpenProcess(PROCESS_ALL_ACCESS, False, pid)
            if not h_process:
                messagebox.showerror("Ошибка", "Не удалось открыть процесс!")
                return

            req = read_float(h_process, request_addr)
            bal = read_float(h_process, balance_addr)

            if req > bal:
                messagebox.showerror("Недостаточно голды", "Запуск невозможен — запрос выше баланса!")
                return

            start_button.text = "🔴 𝐒𝐓𝐎𝐏"
            page.update()
            if selected_mode == "𝐅𝐮𝐥𝐥 𝐌𝐨𝐝":
                threading.Thread(target=full_mode, daemon=True).start()
            elif selected_mode == "𝐃𝐞𝐟𝐚𝐮𝐥𝐭":
                threading.Thread(target=def_mode, daemon=True).start()
            elif selected_mode == "𝐃𝐨𝐮𝐛𝐥𝐞 𝐑𝐞𝐪𝐮𝐞𝐬𝐭":
                threading.Thread(target=double_request_mode, daemon=True).start()
            elif selected_mode == "𝐀𝐰𝐚𝐢𝐭 𝐌𝐨𝐝𝐞":
                threading.Thread(target=await_mode, daemon=True).start()
            elif selected_mode == "𝐀𝐧𝐭𝐢 𝐅𝐮𝐥𝐥":
                threading.Thread(target=anti_full_mode, daemon=True).start()
            elif selected_mode == "𝐀𝐏𝐈 𝐌𝐨𝐝𝐞":
                threading.Thread(target=api_mode, daemon=True).start()
            elif selected_mode == "𝐇𝐚𝐥𝐟 𝐌𝐨𝐝𝐞":
                threading.Thread(target=half_mode, daemon=True).start()
            elif selected_mode == "𝐂𝐮𝐬𝐭𝐨𝐦 𝐎𝐯𝐞𝐫𝐛𝐢𝐝":
                threading.Thread(target=custom_mode, daemon=True).start()
            elif selected_mode == "𝐑𝐚𝐧𝐝𝐨𝐦 𝐌𝐨𝐝𝐞":
                threading.Thread(target=random_mode, daemon=True).start()
        else:
            start_button.text = "🟢 𝐒𝐓𝐀𝐑𝐓"
            page.update()
            running = False

    start_button = ft.ElevatedButton(
        "🟢 𝐒𝐓𝐀𝐑𝐓",
        width=190,
        height=60,
        on_click=start_app,
        style=ft.ButtonStyle(
            shape=ft.RoundedRectangleBorder(radius=6), text_style=ft.TextStyle(size=18),
            side=ft.BorderSide(1, ft.Colors.GREY)

        ),
    )

    autosettings_button = ft.ElevatedButton(
        "𝐀𝐮𝐭𝐨 𝐒𝐞𝐭𝐭𝐢𝐧𝐠𝐬",
        width=190,
        height=60,
        on_click=auto_settings,
        style=ft.ButtonStyle(
            shape=ft.RoundedRectangleBorder(radius=6), text_style=ft.TextStyle(size=18),
            side=ft.BorderSide(1, ft.Colors.GREY)
        ),
    )

    left_column = ft.Column(
        controls=[
            ft.Container(content=title, alignment=ft.alignment.top_left, padding=0),
            ft.Container(expand=True),
            ft.Row(controls=[start_button], alignment="start"),
            ft.Row(controls=[autosettings_button], alignment="end"),
            ft.Container(expand=True),
        ],
        expand=True,
    )

    left_container = ft.Container(
        content=left_column,
        width=170,
        padding=0,
    )

    right_container = ft.Container(
        content=ft.Column(
            controls=[
                ft.Row(
                    controls=[ft.Text("𝐕𝐀𝐋𝐔𝐄𝐒", size=20, weight="bold")],
                    alignment="center"
                ),
                ft.Divider(height=10, color=ft.Colors.GREY),
                ft.Row(
                    controls=[
                        ft.Text("𝐑𝐞𝐪𝐮𝐞𝐬𝐭:", size=20),
                        ft.Text("--", size=20, weight="bold", color="white", ref=request_value),
                    ],
                    alignment="spaceBetween",
                ),
                ft.Row(
                    controls=[
                        ft.Text("𝐋𝐨𝐭:", size=20),
                        ft.Text("--", size=20, weight="bold", color="white", ref=lot_value),
                    ],
                    alignment="spaceBetween",
                ),
                ft.Row(
                    controls=[
                        ft.Text("𝐁𝐚𝐥𝐚𝐧𝐜𝐞:", size=20),
                        ft.Text("--", size=20, weight="bold", color="white", ref=balance_value),
                    ],
                    alignment="spaceBetween",
                ),
            ],
            spacing=10,
            alignment="end",
        ),
        width=200,
        padding=10,
        border=ft.border.all(1, ft.Colors.GREY),
        border_radius=6,
        bgcolor=ft.Colors.with_opacity(0.05, ft.Colors.WHITE),
        margin=ft.margin.only(right=10),
    )

    outer = ft.Container(
        content=ft.Row(
            controls=[left_container, ft.Container(expand=True), right_container],
            expand=True,
            alignment="spaceBetween",
        ),
        padding=10,
        margin=10,
        border=ft.border.all(2, ft.Colors.GREY),
        border_radius=8,
        expand=True,
    )

    page.run_task(auto_update, page, request_value, balance_value, lot_value)
    return outer


def settings_menu(page: ft.Page):
    global pm, request_addr
    title = ft.Row(
        controls=[
            ft.Icon(name=ft.Icons.SETTINGS, size=23, color="white"),
            ft.Text("𝐒𝐞𝐭𝐭𝐢𝐧𝐠𝐬", size=23),
        ],
        spacing=5,
        alignment="start",
        vertical_alignment="center",
    )

    def on_change_skin(e):
        global request_addr, lot_addr

        process_name = "Ld9BoxHeadless.exe"
        window_number = 1
        pid = get_process_pid(process_name, window_number)
        h_process = OpenProcess(PROCESS_ALL_ACCESS, False, pid)
        if not h_process:
            raise Exception("Не удалось открыть процесс для сканирования!")

        if not request_addr:
            messagebox.showerror("Ошибка", "Сначала используй Auto Settings!")
            return

        res = find_request_addr(request_addr)
        if res:
            addr, val = res
            request_addr = addr
            lot_addr = addr - 5
            try:
                lot_val = read_float(h_process, lot_addr)
                lot_val = round(lot_val, 2)
            except Exception:
                lot_val = "--"
            messagebox.showinfo("Успех",
                                f"Новый адрес запроса: {hex(addr)} (значение: {round(val, 2)})")
        else:
            messagebox.showerror("Не найдено", "Валидный адрес не найден")

    change_button = ft.ElevatedButton(
        "𝐂𝐡𝐚𝐧𝐠𝐞 𝐒𝐤𝐢𝐧",
        width=180,
        height=100,
        on_click=on_change_skin,
        style=ft.ButtonStyle(
            shape=ft.RoundedRectangleBorder(radius=6),
            text_style=ft.TextStyle(size=18),
            side=ft.BorderSide(1, ft.Colors.GREY)
        )
    )

    cancelzp = ft.TextField(
        label="𝐂𝐚𝐧𝐜𝐞𝐥 𝐓𝐢𝐦𝐞",
        width=150,
        height=200,
        border_color=ft.Colors.GREY,
        focused_border_color=ft.Colors.BLUE,
    )

    field_row = ft.Row(
        controls=[cancelzp, change_button],
        spacing=75,
        alignment="center",
        vertical_alignment="center",
    )

    centered_container = ft.Container(
        content=field_row,
        alignment=ft.alignment.center,

        expand=True
    )

    settings_content = ft.Container(
        content=ft.Column(
            controls=[
                title,
                ft.Divider(height=2, color=ft.Colors.GREY),
                centered_container,
            ],
            spacing=10,
            alignment=ft.alignment.center,
            expand=True,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
        ),
        width=400,
        padding=15,
        margin=10,
        border=ft.border.all(2, ft.Colors.GREY),
        border_radius=8,
        alignment=ft.alignment.center,
        expand=True,
    )

    return settings_content



def telegram_bot(page: ft.Page):

    def start_bot_from_fields(token_field, chat_id_field):
        token = token_field.value.strip()
        chat_id = chat_id_field.value.strip()
        bot = telebot.TeleBot(token)

        @bot.message_handler(commands=['start'])
        def start(msg):
            bot.reply_to(msg, "<b>Приветствую юзер нашей программы Fantom Half-Api | 0.03\n\nЭтот бот был создан для удаленного пользования ботом, а так же для уведомлений об уловах\n\nНажми на /help что бы увидеть все команды</b>", parse_mode="html")


        @bot.message_handler(commands=['help'])
        def help(msg):
            bot.reply_to(msg, "<b>/screenshot - делает скриншот экрана\n/on - запустить программу\n/off - отключить программу</b>", parse_mode="html")

        @bot.message_handler(commands=['on'])
        def on(msg):
            markup = types.InlineKeyboardMarkup()
            markup.add(
                types.InlineKeyboardButton("Default mode", callback_data="mode_def"),
                types.InlineKeyboardButton("Full mode", callback_data="mode_full"),
                types.InlineKeyboardButton("Double Request", callback_data="mode_double"),
                types.InlineKeyboardButton("API mode", callback_data="mode_api"),
                types.InlineKeyboardButton("Half mode", callback_data="mode_half"),
            )

            bot.reply_to(msg, "<b>Выбери режим для запуска:</b>", parse_mode="html", reply_markup=markup)

        @bot.callback_query_handler(func=lambda call: call.data.startswith("mode_"))
        def mode_selector(call):
            global running, start_button

            if running:
                bot.answer_callback_query(call.id, "Программа уже запущена!")
                return

            running = True
            mode = call.data

            if mode == "mode_def":
                func = def_mode
                name = "Default mode"
            elif mode == "mode_full":
                func = full_mode
                name = "Full mode"
            elif mode == "mode_double":
                func = double_request_mode
                name = "Double Request"
            elif mode == "mode_api":
                func = api_mode
                name = "API mode"
            elif mode == "mode_half":
                func = half_mode
                name = "Half mode"
            else:
                bot.answer_callback_query(call.id, "❌ Неизвестный режим")
                return

            bot.edit_message_text(
                f"<b>{name}</b> запущен",
                call.message.chat.id,
                call.message.message_id,
                parse_mode="html"
            )
            start_button.text = "🔴 𝐒𝐓𝐎𝐏"
            page.update()
            threading.Thread(target=func, daemon=True).start()

        @bot.message_handler(commands=['off'])
        def off(msg):
            global running, start_button
            if running:
                running = False
                start_button.text = "🟢 𝐒𝐓𝐀𝐑𝐓"
                page.update()
                bot.reply_to(msg, "<b>Программа успешно остановлена</b>", parse_mode="html")
            else:
                bot.reply_to(msg, "<b>Программа еще не запущена</b>", parse_mode="html")




        @bot.message_handler(commands=['screenshot'])
        def send_screenshot(msg):
            bot.reply_to(msg, "⏳ Делаю скриншот, подожди секунду...")

            with mss.mss() as sct:
                filename = f"screen_{int(time.time())}.png"
                sct.shot(output=filename)

            with open(filename, 'rb') as photo:
                bot.send_photo(msg.chat.id, photo, caption="Готово")

            os.remove(filename)

        def run_bot():
            bot.infinity_polling()

        threading.Thread(target=run_bot, daemon=True).start()


    title = ft.Row(
        controls=[
            ft.Icon(name=ft.Icons.SEND_ROUNDED, size=23, color="white"),
            ft.Text("𝐓𝐞𝐥𝐞𝐠𝐫𝐚𝐦", size=23),
        ],
        spacing=5,
        alignment="start",
        vertical_alignment="center",
    )
    bot_token_field = ft.TextField(
        label="𝐁𝐨𝐭 𝐓𝐨𝐤𝐞𝐧",
        width=250,
        border_color=ft.Colors.GREY,
        focused_border_color=ft.Colors.BLUE,
    )

    chat_id_field = ft.TextField(
        label="𝐂𝐡𝐚𝐭 𝐈𝐃",
        width=250,
        border_color=ft.Colors.GREY,
        focused_border_color=ft.Colors.BLUE,
    )

    save_button = ft.ElevatedButton(
        "𝐒𝐚𝐯𝐞",
        width=180,
        height=90,
        style=ft.ButtonStyle(
            shape=ft.RoundedRectangleBorder(radius=6),
            text_style=ft.TextStyle(size=20),
            side=ft.BorderSide(1, ft.Colors.GREY)
        ),
        on_click=lambda e: start_bot_from_fields(bot_token_field, chat_id_field)
    )
    input_row = ft.Row(
        controls=[ft.Column(controls=[bot_token_field, chat_id_field], spacing=10), ft.Container(expand=True),
                  save_button],
        alignment="spaceBetween",
        vertical_alignment="center"
    )
    content = ft.Container(
        content=ft.Column(
            controls=[
                title,
                ft.Divider(height=5, color=ft.Colors.GREY),
                input_row
            ],
            spacing=15,
            expand=True
        ),
        width=400,
        padding=15,
        margin=10,
        border=ft.border.all(2, ft.Colors.GREY),
        border_radius=8,
        alignment=ft.alignment.center
    )


    return content


def mode_menu(page: ft.Page):
    global selected_mode

    modes = {
        "𝐃𝐞𝐟𝐚𝐮𝐥𝐭": "𝐃𝐞𝐟𝐚𝐮𝐥𝐭 - ʙ ᴨᴇᴩᴇʙодᴇ 'обычный ʍод'\nᴨᴇᴩᴇбиʙᴀᴇᴛ зᴀᴨᴩоᴄ нᴀ одну ᴋоᴨᴇйᴋу боᴧьɯᴇ чᴇʍ нынᴇɯний зᴀᴨᴩоᴄ",
        "𝐅𝐮𝐥𝐥 𝐌𝐨𝐝": "𝐅𝐮𝐥𝐥 𝐌𝐨𝐝 - ʙ ᴨᴇᴩᴇʙодᴇ 'ᴨод ɸуᴧᴧ'\nᴨᴇᴩᴇбиʙᴀᴇᴛ зᴀᴨᴩоᴄ нᴀ одну ᴋоᴨᴇйᴋу ʍᴇньɯᴇ чᴇʍ 1 ᴧоᴛ",
        "𝐀𝐏𝐈 𝐌𝐨𝐝𝐞": "𝐀𝐏𝐈 𝐌𝐨𝐝𝐞 - ʙ ᴨᴇᴩᴇʙодᴇ 'ᴀᴨи ʍод'\nᴨᴇᴩᴇбиʙᴀᴇᴛ зᴀᴨᴩоᴄ до ᴛᴇх ᴨоᴩ ᴨоᴋᴀ ʙᴀɯ зᴀᴨᴩоᴄ нᴇ будᴇᴛ ᴄᴛояᴛь уᴋᴀзᴀнноᴇ ʙᴀʍи ʙᴩᴇʍя нᴀ оᴛʍᴇну зᴀᴨᴩоᴄᴀ",
        "𝐃𝐨𝐮𝐛𝐥𝐞 𝐑𝐞𝐪𝐮𝐞𝐬𝐭": "𝐃𝐨𝐮𝐛𝐥𝐞 𝐑𝐞𝐪𝐮𝐞𝐬𝐭 - ʙ ᴨᴇᴩᴇʙодᴇ 'дʙойной зᴀᴨᴩоᴄ'\nᴨᴇᴩᴇбиʙᴀᴇᴛ ᴨᴇᴩʙый зᴀᴨᴩоᴄ и ᴨоᴛоʍ ᴨоᴄᴧᴇ оᴛʍᴇны ᴨᴇᴩᴇбиʙᴀᴇᴛ ᴇщᴇ ᴩᴀз ᴛочно ᴛᴀᴋой жᴇ зᴀᴨᴩоᴄ",
        "𝐇𝐚𝐥𝐟 𝐌𝐨𝐝𝐞": "𝐇𝐚𝐥𝐟 𝐌𝐨𝐝𝐞 -  ʙ ᴨᴇᴩᴇʙодᴇ 'ᴨоᴧоʙинᴀ'\nᴨᴇᴩᴇбиʙᴀᴇᴛ зᴀᴨᴩоᴄ нᴀ ᴨоᴧоʙину оᴛ ᴩᴀзницы ʍᴇжду ᴧоᴛоʍ и зᴀᴨᴩоᴄоʍ",
        "𝐂𝐮𝐬𝐭𝐨𝐦 𝐎𝐯𝐞𝐫𝐛𝐢𝐝": "𝐂𝐮𝐬𝐭𝐨𝐦 𝐎𝐯𝐞𝐫𝐛𝐢𝐝 - ʙ ᴨᴇᴩᴇʙодᴇ 'ᴋᴀᴄᴛоʍ зᴀᴨᴩоᴄ'\nᴨᴇᴩᴇбиʙᴀᴇᴛ зᴀᴨᴩоᴄ нᴀ оᴨᴩᴇдᴇᴧённую ᴄуʍʍу ᴋоᴛоᴩую ʙы уᴋᴀжиᴛᴇ ",
        "𝐑𝐚𝐧𝐝𝐨𝐦 𝐌𝐨𝐝𝐞": "𝐑𝐚𝐧𝐝𝐨𝐦 𝐌𝐨𝐝𝐞 - ʙ ᴨᴇᴩᴇʙодᴇ 'ᴩᴀндоʍ ʍод'\nᴨᴇᴩᴇбиʙᴀᴇᴛ зᴀᴨᴩоᴄ оᴛ ʙᴀʍи уᴋᴀзᴀнной ʍиниʍᴀᴧьной цᴇной до ʍᴀᴋᴄиʍᴀᴧьной",
        "𝐀𝐰𝐚𝐢𝐭 𝐌𝐨𝐝𝐞": "𝐀𝐰𝐚𝐢𝐭 𝐌𝐨𝐝𝐞 - ʙ ᴨᴇᴩᴇʙодᴇ 'ожидᴀниᴇ'\nᴨᴇᴩᴇбиʙᴀᴇᴛ зᴀᴨᴩоᴄ ᴨоᴄᴧᴇ нᴇᴋоᴛоᴩоᴦо ожидᴀния",
        "𝐀𝐧𝐭𝐢 𝐅𝐮𝐥𝐥": "𝐀𝐧𝐭𝐢 𝐅𝐮𝐥𝐥 - ʙ ᴨᴇᴩᴇʙодᴇ 'ᴀнᴛи ɸуᴧᴧ'\nᴇᴄᴧи ᴩᴀзницᴀ ʍᴇжду ᴧоᴛоʍ и ʙᴀɯиʍ зᴀᴨᴩоᴄоʍ ʍᴇньɯᴇ чᴇʍ уᴋᴀзᴀннᴀя ʙᴀʍи чиᴄᴧо, ᴛо зᴀᴨᴩоᴄ нᴇ будᴇᴛ ᴨᴇᴩᴇбиᴛ"
    }

    switches = {}
    settings_containers = {}

    def toggle_mode(e):
        global selected_mode
        for m, sw in switches.items():
            if sw != e.control:
                sw.value = False
        selected_mode = e.control.data if e.control.value else None
        page.update()

    def toggle_settings(e):
        nonlocal settings_containers
        mode_name = e.control.data

        for m, c in settings_containers.items():
            if m != mode_name:
                c.visible = False

        settings_containers[mode_name].visible = not settings_containers[mode_name].visible
        page.update()

    dialog = ft.AlertDialog(
        modal=True,
        title=ft.Text("", size=16, weight=ft.FontWeight.BOLD),
        content=ft.Text("", size=13, color=ft.Colors.GREY_400),
        actions=[
            ft.TextButton("Закрыть", on_click=lambda e: close_dialog())
        ],
        actions_alignment=ft.MainAxisAlignment.END,
    )
    page.overlay.append(dialog)

    def close_dialog():
        dialog.open = False
        page.update()

    def show_description(e):
        mode_name = e.control.data
        dialog.title.value = mode_name
        dialog.content. value = modes.get(mode_name, "Описание отсутствует")
        dialog.open = True
        page.update()

    mode_blocks = []
    for mode_name in modes.keys():
        info_icon = ft.IconButton(
            icon=ft.Icons.HELP_OUTLINE_ROUNDED,
            icon_size=18,
            data=mode_name,
            tooltip=modes[mode_name],
            on_click=show_description
        )

        sw = ft.Switch(
            value=(selected_mode == mode_name),
            data=mode_name,
            on_change=toggle_mode,
            scale=1.0,
        )
        switches[mode_name] = sw

        settings_btn = None
        if mode_name in ["𝐂𝐮𝐬𝐭𝐨𝐦 𝐎𝐯𝐞𝐫𝐛𝐢𝐝", "𝐑𝐚𝐧𝐝𝐨𝐦 𝐌𝐨𝐝𝐞", "𝐀𝐰𝐚𝐢𝐭 𝐌𝐨𝐝𝐞", "𝐀𝐧𝐭𝐢 𝐅𝐮𝐥𝐥"]:
            settings_btn = ft.IconButton(
                icon=ft.Icons.SETTINGS_ROUNDED,
                icon_size=19,
                data=mode_name,
                tooltip="Настройки мода",
                on_click=toggle_settings,
            )

        top_row_controls = [info_icon, ft.Text(mode_name, size=15, weight=ft.FontWeight.W_500)]
        right_controls = []
        if settings_btn:
            right_controls.append(settings_btn)
        right_controls.append(sw)

        block = ft.Container(
            content=ft.Row(
                controls=[
                    ft.Row(controls=top_row_controls, spacing=6),
                    ft.Row(controls=right_controls, spacing=4),
                ],
                alignment="spaceBetween",
                vertical_alignment="center",
            ),
            padding=8,
            margin=ft.margin.symmetric(vertical=3),
            bgcolor=ft.Colors.with_opacity(0.05, ft.Colors.WHITE),
            border_radius=8,
            border=ft.border.all(1, ft.Colors.with_opacity(0.18, ft.Colors.WHITE)),
        )
        mode_blocks.append(block)

        if mode_name == "𝐂𝐮𝐬𝐭𝐨𝐦 𝐎𝐯𝐞𝐫𝐛𝐢𝐝":
            settings_container = ft.Container(
                content=ft.TextField(
                    label="ʙʙᴇдиᴛᴇ цᴇну ",
                    hint_text="нᴀᴨᴩиʍᴇᴩ: 0.05",
                    dense=True,
                    text_size=13,
                    width=220,
                    border_color=ft.Colors.GREY,
                    focused_border_color=ft.Colors.BLUE,
                    on_change=lambda e: set_custom_bid_amount(e.control.value) if e.control.value else None
                ),
                padding=ft.padding.only(left=35, right=10, bottom=5),
                visible=False,
            )
        elif mode_name == "𝐑𝐚𝐧𝐝𝐨𝐦 𝐌𝐨𝐝𝐞":
            settings_container = ft.Container(
                content=ft.Row(
                    controls=[
                        ft.TextField(
                            label="𝐌𝐢𝐧",
                            dense=True,
                            text_size=13,
                            width=100,
                            border_color=ft.Colors.GREY,
                            focused_border_color=ft.Colors.BLUE,
                            on_change=lambda e: set_random_range(e.control.value, rand_max) if e.control.value else None
                        ),
                        ft.TextField(
                            label="𝐌𝐚𝐱",
                            dense=True,
                            text_size=13,
                            width=100,
                            border_color=ft.Colors.GREY,
                            focused_border_color=ft.Colors.BLUE,
                            on_change=lambda e: set_random_range(rand_min, e.control.value) if e.control.value else None
                        ),
                    ],
                    spacing=10,
                ),
                padding=ft.padding.only(left=35, right=10, bottom=5),
                visible=False,
            )

        elif mode_name == "𝐀𝐰𝐚𝐢𝐭 𝐌𝐨𝐝𝐞":
            settings_container = ft.Container(
                content=ft.TextField(
                    label="ʙᴩᴇʍя ожидᴀния",
                    hint_text="нᴀᴨᴩиʍᴇᴩ: 2.5",
                    dense=True,
                    text_size=13,
                    width=220,
                    border_color=ft.Colors.GREY,
                    focused_border_color=ft.Colors.BLUE,
                    on_change=lambda e: set_await_time(e.control.value) if e.control.value else None
                ),
                padding=ft.padding.only(left=35, right=10, bottom=5),
                visible=False,
            )

        elif mode_name == "𝐀𝐧𝐭𝐢 𝐅𝐮𝐥𝐥":
            settings_container = ft.Container(
                content=ft.TextField(
                    label="ʙʙᴇдиᴛᴇ чиᴄᴧо ",
                    hint_text="нᴀᴨᴩиʍᴇᴩ: 0.50",
                    dense=True,
                    text_size=13,
                    width=220,
                    border_color=ft.Colors.GREY,
                    focused_border_color=ft.Colors.BLUE,
                    on_change=lambda e: set_anti_full_threshold(e.control.value) if e.control.value else None
                ),
                padding=ft.padding.only(left=35, right=10, bottom=5),
                visible=False,
            )

        else:
            settings_container = ft.Container(visible=False)

        settings_containers[mode_name] = settings_container
        mode_blocks.append(settings_container)

    title = ft.Row(
        controls=[
            ft.Icon(name=ft.Icons.TUNE, size=18, color="white"),
            ft.Text("𝐌𝐨𝐝𝐞 𝐒𝐞𝐭𝐭𝐢𝐧𝐠𝐬", size=16),
        ],
        spacing=6,
        alignment="start",
        vertical_alignment="center",
    )

    return ft.Container(
        content=ft.Column(
            controls=[
                title,
                ft.Divider(height=3, color=ft.Colors.GREY),
                ft.Column(
                    controls=mode_blocks,
                    scroll=ft.ScrollMode.ALWAYS,
                    expand=True,
                    spacing=3,
                ),
            ],
            spacing=6,
            expand=True,
        ),
        padding=8,
        margin=6,
        border=ft.border.all(1.2, ft.Colors.GREY),
        border_radius=8,
        expand=True,
    )


def main_window(page: ft.Page):
    page.controls.clear()
    page.window.width = 540
    page.window.height = 340
    page.title = "𝑭𝒂𝒏𝒕𝒐𝒎 𝑯𝒂𝒍𝒇-𝑨𝒑𝒊  |  0.03"
    page.window.resizable = False
    page.window.center()
    tabs = ft.Tabs(
        selected_index=0,
        expand=1,
        tabs=[
            ft.Tab(tab_content=ft.Icon(ft.Icons.HOME, size=22), content=main_menu(page)),
            ft.Tab(tab_content=ft.Icon(ft.Icons.SETTINGS, size=22), content=settings_menu(page)),
            ft.Tab(tab_content=ft.Icon(ft.Icons.APPS, size=22), content=mode_menu(page)),
            ft.Tab(tab_content=ft.Icon(ft.Icons.SEND_ROUNDED, size=22), content=telegram_bot(page))
        ],
    )

    page.add(tabs)


if __name__ == "__main__":
    ft.app(logging_page)