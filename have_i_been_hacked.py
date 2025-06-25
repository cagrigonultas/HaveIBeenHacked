import tkinter as tk
from tkinter import messagebox, Toplevel, Label
import threading
import subprocess
import psutil
import os
import requests
import hashlib
import pefile
import time
from datetime import datetime, timedelta
import sys
import json

# ===================== API ANAHTARLARI =====================
API_KEY = "VirusTotalAPIkey"
ABUSE_API_KEY = "AbuseIP_API_key"

# ===================== SABİT DOSYA ADLARI =====================
VT_CHECK_LIMIT_PER_DAY = 500
BLACKLIST_FILE = "blacklist_hashes.txt"
HASH_POOL_FILE = "daily_hash_pool.txt"
VT_LAST_UPDATE_FILE = "last_update.txt"



# ===================== TKINTER KURULUMU =====================
root = tk.Tk()
root.title("Have I Been Hacked?")
root.geometry("600x850")
root.resizable(False, False)
root.iconbitmap("have_i_been_hacked.ico")
try:
    icon_path = os.path.join(sys._MEIPASS, "have_i_been_hacked.ico")
except Exception:
    icon_path = "have_i_been_hacked.ico"

try:
    root.iconbitmap(icon_path)
except:
    pass

# ===================== BUTON AÇIKLAMALARI =====================
explanation_text = """
🔍 Taramayı Başlat: Çalışan işlemleri tarar, şüpheli görünenleri analiz eder ve listeler.

🧪 VirusTotal Güncelle: Şüpheli dosyaları VirusTotal ile kontrol eder, zararlı olanları raporlara ekler.

🌐 IP Analizi Yap: Aktif dış bağlantıları analiz eder, şüpheli IP’leri tespit eder ve raporlara ekler

📄 Detaylı Raporu Göster: Şüpheli işlemler ve IP analiz sonuçlarını detaylı şekilde gösterir.

🔌 İnterneti Kes: Ağ bağlantısını keserek sisteminizi izole eder.

🔗 İnterneti Aç: Kesilen ağ bağlantısını geri açar.

👤 Son Kullanıcı Raporu: Sadece tehlikeli işlemleri sade biçimde gösterir.
"""




# ===================== YARDIMCI FONKSİYONLAR =====================

def load_api_keys():
    config_file = "api_config.json"
    if not os.path.exists(config_file):
        return None
    with open(config_file, "r", encoding="utf-8") as f:
        try:
            return json.load(f)
        except:
            return None
        
def prompt_api_keys():
    win = tk.Toplevel()
    win.title("API Anahtarları")
    win.geometry("400x200")

    tk.Label(win, text="VirusTotal API Key:").pack()
    vt_entry = tk.Entry(win, width=40)
    vt_entry.pack()

    tk.Label(win, text="AbuseIPDB API Key:").pack()
    ab_entry = tk.Entry(win, width=40)
    ab_entry.pack()

    def save_keys():
        vt_key = vt_entry.get().strip()
        ab_key = ab_entry.get().strip()
        if not vt_key or not ab_key:
            messagebox.showerror("Hata", "API anahtarları boş bırakılamaz!")
            win.destroy()
            root.destroy()
            return
        keys = {"VT_API_KEY": vt_key, "ABUSE_API_KEY": ab_key}
        with open("api_config.json", "w", encoding="utf-8") as f:
            json.dump(keys, f)
        win.destroy()

    def on_close():
        messagebox.showwarning("Zorunlu Alan", "API anahtarları girilmeden uygulama başlatılamaz.")
        win.destroy()
        root.destroy()

    win.protocol("WM_DELETE_WINDOW", on_close)

    tk.Button(win, text="Kaydet", command=save_keys).pack(pady=10)
    win.transient(root)
    win.grab_set()
    root.wait_window(win)



def show_user_safe_report():
    try:
        if not os.path.exists(BLACKLIST_FILE):
            messagebox.showinfo("Rapor", "Tehlikeli işlem bulunamadı.")
            return

        blacklisted = set(line.strip() for line in open(BLACKLIST_FILE, encoding="utf-8") if line.strip())
        procs = list(psutil.process_iter(['pid', 'name', 'exe']))
        found = []

        for proc in procs:
            try:
                path = proc.info['exe'] or ""
                if not path or not os.path.exists(path):
                    continue
                sha256 = calculate_sha256(path)
                if sha256 in blacklisted:
                    found.append({
                        "name": proc.info['name'],
                        "pid": proc.info['pid'],
                        "path": path,
                        "sha256": sha256
                    })
            except:
                continue

        # Tarihli ve saatli benzersiz dosya adı
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        filename = f"HaveIBeenHacked_UserReport_{timestamp}.txt"
        desktop_path = os.path.join(os.path.expanduser("~"), "Desktop")
        report_file = os.path.join(desktop_path, filename)

        with open(report_file, "w", encoding="utf-8") as f:
            if found:
                f.write("❌ Aktif Tehlikeli İşlemler:\n\n")
                for p in found:
                    f.write(f"İsim: {p['name']} (PID: {p['pid']})\n")
                    f.write(f"Yol: {p['path']}\n")
                    f.write(f"SHA256: {p['sha256']}\n")
                    f.write(f"VirusTotal: https://www.virustotal.com/gui/file/{p['sha256']}\n\n")
            else:
                f.write("⚠️ Aktif tehlikeli işlem bulunamadı.\n")
                f.write("Aşağıda kara listeye alınmış hash değerleri gösterilmiştir:\n\n")
                for h in blacklisted:
                    f.write(f"- {h}\n")

            if ip_report_data:
                f.write("""🌐 Şüpheli IP Bağlantıları\n
                        - 0–20: Güvenli\n
                        - 21–49: Şüpheli\n
                        - 50 ve üzeri: Tehlikeli\n(AbuseIPDB skoru 50+):\n\n""")
                for ip, score in ip_report_data:
                    f.write(f"- {ip} (Skor: {score})\n")
                f.write("\n")

        # GUI gösterimi
        win = tk.Toplevel(root)
        win.title("Son Kullanıcı Raporu")
        win.geometry("600x500")
        try:
            win.iconbitmap("have_i_been_hacked.ico")
        except:
            pass
        text = tk.Text(win, wrap="word")
        text.pack(expand=True, fill="both")

        with open(report_file, "r", encoding="utf-8") as f:
            text.insert("end", f.read())

        messagebox.showinfo("Rapor Kaydedildi", f"Rapor masaüstüne kaydedildi:\n{report_file}")

    except Exception as e:
        messagebox.showerror("Rapor Hatası", str(e))



def show_progress_window(title: str):
    win = Toplevel(root)
    win.title(title)
    win.geometry("400x120")
    win.resizable(False, False)
    label = Label(win, text=title, font=("Arial", 12))
    label.pack(pady=30)
    cancel_event = threading.Event()          # ① iptal bayrağı
    win.protocol("WM_DELETE_WINDOW",
                 lambda: (cancel_event.set(), win.destroy()))  # ② pencereyi kapatınca bayrak + destroy
    return win, label, cancel_event           # ③ üçüncü dönüş değeri


def calculate_sha256(path: str):
    try:
        with open(path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except Exception:
        return None

def is_in_temp_path(path):
    return any(x in path.lower() for x in ("appdata", "temp", "roaming"))

def is_unsigned(path):
    try:
        pe = pefile.PE(path)
        return not hasattr(pe, 'DIRECTORY_ENTRY_SECURITY')
    except Exception:
        return True

def is_autostart_path(path):
    return any(x in path.lower() for x in ("system32\\tasks", "startup"))

def load_blacklist():
    if not os.path.exists(BLACKLIST_FILE):
        return set()
    with open(BLACKLIST_FILE, "r", encoding="utf-8") as f:
        return {line.strip() for line in f if line.strip()}

# ===================== GLOBAL DEĞİŞKENLER =====================
detected = []
ip_report_data = []

# =====================   =====================

api_keys = load_api_keys()
if not api_keys or not api_keys.get("VT_API_KEY") or not api_keys.get("ABUSE_API_KEY"):
    prompt_api_keys()                       # kullanıcıya sor
    api_keys = load_api_keys()
    if not api_keys or not api_keys.get("VT_API_KEY") or not api_keys.get("ABUSE_API_KEY"):
        try:
            root.destroy()
        except:
            pass
        sys.exit()


VT_API_KEY   = api_keys["VT_API_KEY"]
ABUSE_API_KEY = api_keys["ABUSE_API_KEY"]

# ===================== İŞLEM TARAMASI =====================


def scan_thread():
    global detected
    detected.clear()
    win, lbl, cancel = show_progress_window("Tarama başlatılıyor...")

    for fp in (HASH_POOL_FILE, BLACKLIST_FILE):
        if not os.path.exists(fp):
            open(fp, "w").close()

    procs = list(psutil.process_iter(['pid', 'name', 'exe']))
    total = len(procs)
    blacklist = load_blacklist()
    seen = set()

    
    for idx, proc in enumerate(procs):
        if cancel.is_set():
            win.destroy()
            return
        try:
            pid, name = proc.info['pid'], proc.info['name']
            path = proc.info['exe'] or ""
            if not path or not os.path.exists(path):
                continue
            sha256 = calculate_sha256(path)
            if sha256 in seen:
                continue
            seen.add(sha256)

            score, reasons = 0, []
            if sha256 in blacklist:
                detected.append({"name": name, "pid": pid, "path": path, "sha256": sha256,
                                 "status": "TEHLIKELI", "reasons": ["VirusTotal kara listesinde"]})
                continue
            if is_in_temp_path(path):
                score += 3; reasons.append("Temp/AppData")
            if is_unsigned(path):
                score += 2; reasons.append("Dijital imzasız")
            if is_autostart_path(path):
                score += 2; reasons.append("Oto-başlatma")

            if score >= 5:
                detected.append({"name": name, "pid": pid, "path": path, "sha256": sha256,
                                 "status": "SUPHELI", "reasons": reasons})
                if sha256:
                    with open(HASH_POOL_FILE, "a", encoding="utf-8") as f:
                        f.write(sha256 + "\n")
        except (psutil.ZombieProcess, psutil.AccessDenied):
            continue
        lbl.config(text=f"Tarama ilerlemesi: %{int((idx+1)/total*100)}")
        win.update_idletasks()

    win.destroy()
    messagebox.showwarning("Tarama", f"{len(detected)} şüpheli/tehlikeli işlem." if detected else "Şüpheli işlem bulunmadı.")

def start_scan():
    threading.Thread(target=scan_thread, daemon=True).start()
# ===================== VIRUSTOTAL GÜNCELLEME =====================

def vt_thread():
    """HASH_POOL_FILE içindeki benzersiz hash'leri VirusTotal'de kontrol eder,
       zararlı bulunanları BLACKLIST_FILE'a ekler ve işlem ilerlemesini
       açılır pencerede yüzde olarak gösterir."""
    win, lbl, cancel = show_progress_window("VirusTotal güncelleme başlatılıyor...")

    try:
        # -- 24 saat limiti --
        if os.path.exists(VT_LAST_UPDATE_FILE):
            try:
                last = datetime.fromisoformat(open(VT_LAST_UPDATE_FILE).read().strip())
                if datetime.now() - last < timedelta(hours=24):
                    win.destroy()
                    messagebox.showinfo("VirusTotal", "Bugün zaten kontrol yapıldı.")
                    return
            except Exception:
                pass

        # -- Gönderilecek hash'leri hazırla --
        hashes = {h.strip() for h in open(HASH_POOL_FILE, encoding="utf-8") if h.strip()}
        if not hashes:
            win.destroy()
            messagebox.showinfo("VirusTotal", "Gönderilecek hash yok.")
            return

        total = len(hashes)
        checked = 0
        malicious = []

        for h in hashes:
            if cancel.is_set():
                win.destroy()
                return
            if checked >= VT_CHECK_LIMIT_PER_DAY:
                break  # Ücretsiz API limiti
            try:
                resp = requests.get(
                    f"https://www.virustotal.com/api/v3/files/{h}",
                    headers={"x-apikey": API_KEY},
                    timeout=15
                )
                if resp.status_code == 200:
                    stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
                    if stats.get("malicious", 0) > 0:
                        malicious.append(h)
            except Exception:
                pass  # Zaman aşımı veya ağ hatası göz ardı edilir

            checked += 1
            lbl.config(text=f"VirusTotal: %{int(checked / total * 100)}")
            win.update_idletasks()
            time.sleep(16)  # VT rate-limit: ~4 sorgu/dk

        # -- Zararlı hash'leri kara listeye yaz --
        if malicious:
            with open(BLACKLIST_FILE, "a", encoding="utf-8") as f:
                for m in malicious:
                    f.write(m + "\n")

        # -- Temizlik ve zaman damgası --
        open(HASH_POOL_FILE, "w").close()
        open(VT_LAST_UPDATE_FILE, "w").write(datetime.now().isoformat())

        win.destroy()
        msg = (
            f"{checked} hash kontrol edildi. {len(malicious)} zararlı bulundu."
            if malicious else
            f"{checked} hash kontrol edildi. Zararlı bulunmadı."
        )
        messagebox.showinfo("VirusTotal", msg)

    except Exception as e:
        win.destroy()
        messagebox.showerror("VT Hatası", str(e))

def start_vt_update():
    threading.Thread(target=vt_thread, daemon=True).start()
# ===================== IP ANALİZİ =====================

def ip_thread():
    global ip_report_data
    ip_report_data.clear()
    win, lbl, cancel = show_progress_window("IP analizi başlatılıyor...")

    try:
        # Aktif dış bağlantıları topla
        ips = {c.raddr.ip for c in psutil.net_connections(kind='inet') if c.raddr and c.status == 'ESTABLISHED'}
        #ips = {"185.220.101.1"}  # Tor çıkış nodu, AbuseIPDB skoru yüksektir #testtir

        total = len(ips)
        if not total:
            win.destroy()
            messagebox.showinfo("IP Analizi", "Aktif dış bağlantı yok.")
            return

        for idx, ip in enumerate(ips):
            if cancel.is_set():
                win.destroy()
                return
            try:
                r = requests.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    headers={"Key": ABUSE_API_KEY, "Accept": "application/json"},
                    params={"ipAddress": ip, "maxAgeInDays": "30"},
                    timeout=10
                )
                if r.status_code == 200:
                    data = r.json()["data"]
                    score = data.get("abuseConfidenceScore", 0)
                    if score >= 50:
                        ip_report_data.append((ip, score))
            except Exception:
                pass

            lbl.config(text=f"IP analizi: %{int((idx + 1) / total * 100)}")
            win.update_idletasks()
            time.sleep(1.5)  # Rate limit'e uymak için

        win.destroy()

        if ip_report_data:
            report = "\n".join(f"- {ip} (Skor: {score})" for ip, score in ip_report_data)
            messagebox.showwarning("IP Analizi", report)
        else:
            messagebox.showinfo("IP Analizi", "Şüpheli IP bulunmadı.")

    except Exception as e:
        win.destroy()
        messagebox.showerror("IP Hatası", str(e))

def start_ip_analysis():
    threading.Thread(target=ip_thread, daemon=True).start()
# ===================== RAPOR GÖRÜNTÜLE =====================

def show_report():
    if not detected and not ip_report_data:
        return messagebox.showinfo("Rapor", "Hiç şüpheli öğe yok.")

    win = tk.Toplevel(root)
    win.title("Detaylı Rapor")
    win.geometry("650x500")
    try:
        win.iconbitmap("have_i_been_hacked.ico")
    except:
        pass
    txt = tk.Text(win, wrap="word", font=("Arial", 10))
    txt.pack(expand=True, fill="both")

    if detected:
        txt.insert("end", "\n🔍 ŞÜPHELİ / TEHLİKELİ İŞLEMLER:\n\n")
        for p in detected:
            prefix = "❌ TEHLİKELİ" if p["status"] == "TEHLIKELI" else "⚠️ ŞÜPHELİ"
            txt.insert("end", f"{prefix}: {p['name']} (PID: {p['pid']})\n")
            txt.insert("end", f"Yol: {p['path']}\n")
            if p.get("sha256"):
                txt.insert("end", f"SHA256: {p['sha256']}\n")
                txt.insert("end", f"VirusTotal: https://www.virustotal.com/gui/file/{p['sha256']}\n")
            for r in p.get("reasons", []):
                txt.insert("end", f"- {r}\n")
            txt.insert("end", "\n")

    if ip_report_data:
        txt.insert("end", "\n🌐 ŞÜPHELİ IP BAĞLANTILARI:\n\n")
        for ip, score in ip_report_data:
            txt.insert("end", f"- {ip} (Abuse Skoru: {score})\n")
def cut_internet():
    try:
        result = subprocess.run("netsh interface show interface", capture_output=True, text=True, shell=True)
        for line in result.stdout.splitlines():
            if "Connected" in line or "Bağlandı" in line:  # Türkçe sistemlerde "Bağlandı" olabilir
                parts = line.split()
                interface_name = " ".join(parts[3:])
                subprocess.run(f'netsh interface set interface "{interface_name}" admin=disable', shell=True)
        messagebox.showinfo("Internet", "Bağlantı kesildi.")
    except Exception as e:
        messagebox.showerror("Hata", str(e))
def enable_internet():
    try:
        result = subprocess.run("netsh interface show interface", capture_output=True, text=True, shell=True)
        for line in result.stdout.splitlines():
            if "Disabled" in line or "Devre Dışı" in line:
                parts = line.split()
                interface_name = " ".join(parts[3:])
                subprocess.run(f'netsh interface set interface "{interface_name}" admin=enable', shell=True)
        messagebox.showinfo("Internet", "Bağlantı açıldı.")
    except Exception as e:
        messagebox.showerror("Hata", str(e))
# ===================== GUI BUTONLARI =====================

tk.Label(root, text="Have I Been Hacked?", font=("Helvetica", 18, "bold")).pack(pady=20)

tk.Label(root, text=explanation_text, justify="left", font=("Arial", 9), anchor="w").pack(padx=10, pady=(10, 20), fill="x")

tk.Button(root, text="🔍 Tarama Başlat", command=start_scan, width=40).pack(pady=10)

tk.Button(root, text="🧪 VirusTotal Güncelle", command=start_vt_update, width=40).pack(pady=10)

tk.Button(root, text="🌐 IP Analizi Yap", command=start_ip_analysis, width=40).pack(pady=10)

tk.Button(root, text="📄 Detaylı Raporu Göster", command=show_report, width=40).pack(pady=10)

tk.Button(root, text="🔌 İnterneti Kes", command=cut_internet, width=40).pack(pady=10)

tk.Button(root, text="🔗 İnterneti Aç", command=enable_internet, width=40).pack(pady=10)

tk.Button(root, text="👤 Son Kullanıcı Raporu", command=show_user_safe_report, width=40).pack(pady=10)

root.mainloop()



