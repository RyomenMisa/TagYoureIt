import os
import ctypes
import subprocess
import threading
import glob
import configparser
import customtkinter as ctk
import hashlib
import datetime

# --- 1. ЗАГРУЗКА ГОТИЧЕСКОГО ШРИФТА ---
font_path = os.path.abspath("OldLondon.ttf")
if os.path.exists(font_path):
    ctypes.windll.gdi32.AddFontResourceExW(font_path, 0x10, 0)
else:
    print("[ОШИБКА] Положи файл OldLondon.ttf в ту же папку, что и скрипт!")

# --- 2. НАСТРОЙКА ОКНА И ЦВЕТОВ ---
app = ctk.CTk(fg_color="#F6E8E3") 
app.title("Tag You're It - EDR Dashboard")
app.geometry("850x580") 
app.resizable(False, False)

COLOR_BG = "#F6E8E3"
COLOR_BORDER = "#292010"
COLOR_CONSOLE = "#DBC3C2"
COLOR_MISA = "#963B3B"
COLOR_ACCENT = "#3B7596"

FONT_TITLE = ("Old London", 54)
FONT_SUBTITLE = ("Old London", 28)
FONT_HEADING = ("Old London", 32) 
FONT_CONSOLE = ("Consolas", 13, "bold") 
FONT_UI = ("Arial", 13, "bold") # Чуть уменьшили шрифт кнопок, чтобы влезли три
FONT_STATUS = ("Consolas", 11, "bold") 

# --- 3. ПОСТРОЕНИЕ ИНТЕРФЕЙСА ---

# Верхний блок
header_frame = ctk.CTkFrame(app, fg_color="transparent")
header_frame.pack(fill="x", pady=(20, 5), padx=30)

title_label = ctk.CTkLabel(header_frame, text="Tag You're It", font=FONT_TITLE, text_color=COLOR_BORDER)
title_label.pack(side="top", anchor="w")

subtitle_label = ctk.CTkLabel(header_frame, text="by Misa", font=FONT_SUBTITLE, text_color=COLOR_MISA)
subtitle_label.pack(side="top", anchor="w", padx=60)

separator = ctk.CTkFrame(app, fg_color=COLOR_BORDER, height=2, corner_radius=0)
separator.pack(fill="x", padx=30, pady=(0, 20))

# Основной рабочий блок
main_frame = ctk.CTkFrame(app, fg_color="transparent")
main_frame.pack(fill="both", expand=True, padx=30, pady=(0, 15))

# Левая часть: Консоль логов
console_border = ctk.CTkFrame(main_frame, fg_color=COLOR_BORDER, corner_radius=8)
console_border.pack(side="left", fill="both", expand=True, padx=(0, 20))

console_text = ctk.CTkTextbox(console_border, fg_color=COLOR_CONSOLE, text_color=COLOR_BORDER, 
                              font=FONT_CONSOLE, corner_radius=6)
console_text.pack(fill="both", expand=True, padx=2, pady=2)

# Правая часть: Меню управления
right_frame = ctk.CTkFrame(main_frame, fg_color="transparent", width=250)
right_frame.pack(side="right", fill="y")

# --- 4. ЛОГИКА И ПРИВЯЗКА КНОПОК ---

def append_to_console(text):
    console_text.insert("end", text)
    console_text.see("end")

def toggle_sensor(sensor_name, switch_var):
    state = "1" if switch_var.get() == 1 else "0"
    config = configparser.ConfigParser()
    if os.path.exists("config.ini"):
        config.read("config.ini")
    else:
        config['SENSORS'] = {}
        
    if 'SENSORS' not in config:
        config['SENSORS'] = {}
        
    config['SENSORS'][sensor_name] = state
    with open("config.ini", "w", encoding="utf-8") as configfile:
        config.write(configfile)
        
    status_text = "ВКЛЮЧЕН" if state == "1" else "ОТКЛЮЧЕН"
    append_to_console(f"[GUI] Сенсор '{sensor_name}': {status_text}\n")

def destroy_quarantine():
    files = glob.glob("*.quarantine")
    if not files:
        append_to_console("[GUI] Карантин пуст. Уничтожать нечего.\n")
        return
    for f in files:
        try:
            os.remove(f)
            append_to_console(f"[КАРАНТИН] Файл {f} стерт в пыль.\n")
        except Exception as e:
            append_to_console(f"[ОШИБКА] Не удалось удалить {f}: {e}\n")

def restore_quarantine():
    files = glob.glob("*.quarantine")
    if not files:
        append_to_console("[GUI] Карантин пуст. Восстанавливать нечего.\n")
        return
        
    for f in files:
        try:
            new_name = f.replace(".quarantine", "")
            os.rename(f, new_name) 
            append_to_console(f"[КАРАНТИН] Объект {new_name} помилован. Права на запуск восстановлены.\n")
        except Exception as e:
            append_to_console(f"[ОШИБКА] Не удалось помиловать {f}: {e}\n")

def autopsy_quarantine():
    files = glob.glob("*.quarantine")
    if not files:
        append_to_console("[GUI] Карантин пуст. Препарировать нечего.\n")
        return
        
    for f in files:
        try:
            with open(f, "rb") as file_obj:
                file_data = file_obj.read()
                
            md5_hash = hashlib.md5(file_data).hexdigest()
            sha256_hash = hashlib.sha256(file_data).hexdigest()
            
            size_kb = len(file_data) / 1024
            creation_time = datetime.datetime.fromtimestamp(os.path.getctime(f)).strftime('%Y-%m-%d %H:%M:%S')
            
            strings = []
            current_string = ""
            for byte in file_data:
                if 32 <= byte <= 126:
                    current_string += chr(byte)
                else:
                    if len(current_string) >= 5:
                        strings.append(current_string)
                    current_string = ""
            
            report_name = f"AUTOPSY_REPORT_{f.replace('.quarantine', '')}.txt"
            with open(report_name, "w", encoding="utf-8") as rep:
                rep.write("====================================================\n")
                rep.write("          ПРОТОКОЛ ПРЕПАРИРОВАНИЯ ОБЪЕКТА           \n")
                rep.write("====================================================\n\n")
                rep.write(f"[+] Идентификатор объекта: {f}\n")
                rep.write(f"[+] Дата изоляции: {creation_time}\n")
                rep.write(f"[+] Размер: {size_kb:.2f} KB\n\n")
                
                rep.write("--- СИГНАТУРНЫЙ АНАЛИЗ (ДНК) ---\n")
                rep.write(f"MD5:    {md5_hash}\n")
                rep.write(f"SHA256: {sha256_hash}\n\n")
                
                rep.write("--- НАЙДЕННЫЕ СТРОКОВЫЕ АРТЕФАКТЫ (Первые 50) ---\n")
                for s in strings[:50]:
                    rep.write(f"> {s}\n")
                rep.write("\n====================================================\n")
                rep.write("Конец протокола.\n")

            append_to_console(f"[ЛАБОРАТОРИЯ] Объект {f} успешно препарирован.\n")
            append_to_console(f"[ЛАБОРАТОРИЯ] Отчет сохранен как: {report_name}\n")
            
        except Exception as e:
            append_to_console(f"[ОШИБКА] Не удалось вскрыть объект {f}: {e}\n")

def update_quarantine_list():
    quarantine_list.delete("0.0", "end")
    files = glob.glob("*.quarantine")
    if files:
        for f in files:
            quarantine_list.insert("end", f + "\n")
    else:
        quarantine_list.insert("end", "Чисто...\n")
    app.after(2000, update_quarantine_list)

# Тумблеры (Сенсоры) 
sensors = ["Эвристический монитор", "Защита от инъекций", "Сетевой локатор", "YARA-сканер", "Honeypot"]
for s in sensors:
    var = ctk.IntVar(value=1)
    switch = ctk.CTkSwitch(right_frame, text=s, font=FONT_UI, text_color=COLOR_BORDER, 
                           progress_color=COLOR_ACCENT, fg_color=COLOR_CONSOLE,           
                           button_color=COLOR_BORDER, button_hover_color="#000000",
                           variable=var, 
                           command=lambda name=s, v=var: toggle_sensor(name, v))
    switch.pack(anchor="w", pady=6)
    switch.select()

# Блок КАРАНТИН
quarantine_label = ctk.CTkLabel(right_frame, text="Quarantine", font=FONT_HEADING, text_color=COLOR_BORDER)
quarantine_label.pack(anchor="w", pady=(15, 5))

quarantine_border = ctk.CTkFrame(right_frame, fg_color=COLOR_BORDER, corner_radius=8)
quarantine_border.pack(fill="both", expand=True, pady=(0, 10))

quarantine_list = ctk.CTkTextbox(quarantine_border, fg_color=COLOR_CONSOLE, text_color=COLOR_BORDER, 
                                 font=FONT_CONSOLE, corner_radius=6, height=80)
quarantine_list.pack(fill="both", expand=True, padx=2, pady=2)

# === 3 НОВЫЕ КНОПКИ В ОДИН РЯД ===
btn_frame = ctk.CTkFrame(right_frame, fg_color="transparent")
btn_frame.pack(fill="x")

btn_destroy = ctk.CTkButton(btn_frame, text="Уничтожить", fg_color=COLOR_MISA, hover_color="#7A2D2D", 
                            text_color=COLOR_BG, font=FONT_UI, corner_radius=6, width=70,
                            command=destroy_quarantine)
btn_destroy.pack(side="left", fill="x", expand=True, padx=(0, 2))

btn_autopsy = ctk.CTkButton(btn_frame, text="Вскрытие", fg_color=COLOR_ACCENT, hover_color="#2D5A75", 
                            text_color=COLOR_BG, font=FONT_UI, corner_radius=6, width=70,
                            command=autopsy_quarantine)
btn_autopsy.pack(side="left", fill="x", expand=True, padx=(2, 2))

btn_restore = ctk.CTkButton(btn_frame, text="Помиловать", fg_color="#5A6B5D", hover_color="#3E4A40", 
                            text_color=COLOR_BG, font=FONT_UI, corner_radius=6, width=70,
                            command=restore_quarantine)
btn_restore.pack(side="left", fill="x", expand=True, padx=(2, 0))

# Нижний статус-бар
status_frame = ctk.CTkFrame(app, fg_color=COLOR_BORDER, height=25, corner_radius=0)
status_frame.pack(fill="x", side="bottom")

status_text = "  SYSTEM KERNEL: ONLINE   ||   PULSE: NORMAL   ||   ZERO PATIENT: NOT DETECTED   ||   EDR BUILD: 1.0.42"
status_label = ctk.CTkLabel(status_frame, text=status_text, font=FONT_STATUS, text_color=COLOR_BG)
status_label.pack(side="left", padx=10)

# --- 5. МОСТ МЕЖДУ PYTHON И C++ ---
edr_process = None

def read_backend_output():
    global edr_process
    app.after(0, append_to_console, "[GUI] Подключение к ядру...\n")
    
    creationflags = subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0

    try:
        edr_process = subprocess.Popen(
            ["TagYoureIt.exe"], 
            stdout=subprocess.PIPE, 
            stderr=subprocess.STDOUT,
            stdin=subprocess.PIPE,
            text=True, 
            creationflags=creationflags,
            bufsize=1,
            errors='replace' 
        )

        for line in iter(edr_process.stdout.readline, ''):
            if line:
                app.after(0, append_to_console, line)
                
    except Exception as e:
        app.after(0, append_to_console, f"[ОШИБКА МОСТА] {e}\n")

def start_backend():
    thread = threading.Thread(target=read_backend_output, daemon=True)
    thread.start()

def on_closing():
    global edr_process
    if edr_process:
        edr_process.terminate() 
    app.destroy()

app.protocol("WM_DELETE_WINDOW", on_closing)

# Запуск приложения
if __name__ == "__main__":
    update_quarantine_list()
    start_backend() 
    app.mainloop()