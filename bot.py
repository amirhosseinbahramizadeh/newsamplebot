"""
ICS/SCADA Scanner Telegram Bot - All-in-One
پشتیبانی: فارسی، انگلیسی، روسی، آلمانی
اسکنر: nmap + pymodbus + snap7
پرداخت: USDT TRC20
"""

import asyncio
import json
import logging
import socket
import sqlite3
import ipaddress
from datetime import datetime, timedelta
from pathlib import Path

import aiohttp
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    ApplicationBuilder, CommandHandler, CallbackQueryHandler,
    ContextTypes, MessageHandler, filters
)

# ============================================================
# ⚙️ تنظیمات — این بخش رو ویرایش کن
# ============================================================
BOT_TOKEN       = "8987526953:AAGIrqskJBixJHh34kjnK9Q5OzyUNSLZUno"
USDT_WALLET     = "TFdiGsZQU5wiQTuRYZrrspa6TBrwjwxAUi"
TRONGRID_API    = "https://api.trongrid.io"
ADMIN_IDS       =   [257908407] # آیدی عددی ادمین‌ها
PRICE_USDT      = 6.0
FREE_SCANS      = 2
PAID_SCANS      = 30
PAID_DAYS       = 30
ALLOW_PUBLIC_IP = True          # True کن اگه می‌خوای IP عمومی هم اسکن بشه

DB_FILE = "bot.db"

# ============================================================
# 🌍 ترجمه‌ها
# ============================================================
TEXTS = {
    "fa": {
        "choose_lang": "🌍 لطفاً زبان خود را انتخاب کنید:",
        "welcome": "👋 سلام {name}!\n\nمن ربات اسکنر ICS/SCADA هستم.\n\n📌 دستورات:\n/scan <IP> — اسکن کامل\n/modbus <IP> — تست Modbus\n/s7 <IP> — تست S7comm\n/quick <IP> — اسکن سریع\n/usage — مصرف من\n/subscribe — خرید اشتراک\n/verify <TX> — تأیید پرداخت\n/language — تغییر زبان\n/help — راهنما\n\n⚠️ فقط روی سیستم‌هایی که مجاز هستی استفاده کن.",
        "help": "📖 راهنما:\n\n/scan 192.168.1.100 — اسکن کامل ICS\n/modbus 192.168.1.100 — تست Modbus\n/s7 192.168.1.100 — تست S7comm\n/quick 192.168.1.100 — اسکن سریع پورت\n/usage — نمایش مصرف\n/subscribe — خرید ۳۰ اسکن با ۶ دلار\n\n⚠️ هشدار قانونی: فقط روی سیستم‌های خودت یا با مجوز کتبی.",
        "scanning": "🔍 در حال اسکن {ip} ...\nچند ثانیه صبر کن.",
        "report_title": "🔍 گزارش اسکن ICS/SCADA",
        "target": "🎯 هدف",
        "duration": "⏱ زمان",
        "seconds": "ثانیه",
        "open_ports": "📡 پورت‌های باز",
        "deep_detect": "🔬 تشخیص عمیق",
        "no_ports": "✅ هیچ پورت ICS شناخته‌شده‌ای باز نیست.",
        "security_warning": "⚠️ این پورت‌ها معمولاً بدون احراز هویت هستن. اگه ICS واقعیه، فوراً ایزوله کن.",
        "invalid_ip": "❌ IP وارد شده معتبر نیست.",
        "no_arg": "❌ لطفاً IP رو وارد کن.\nمثال: /scan 192.168.1.100",
        "public_ip_blocked": "❌ اسکن IP عمومی مجاز نیست.",
        "limit_reached": "🚫 سقف اسکن شما تموم شده!\n\nاشتراک رایگان: {free} اسکن در ماه\nاشتراک ویژه: {paid} اسکن در ماه با {price} دلار USDT\n\nبرای خرید /subscribe رو بزن.",
        "usage": "📊 مصرف شما:\n\nنوع اشتراک: {tier}\nاستفاده‌شده: {used}/{limit}\nانقضا: {expire}",
        "subscribe": "💳 خرید اشتراک ویژه\n\n💰 مبلغ: {price} دلار USDT\n📅 اعتبار: {days} روز\n📊 تعداد اسکن: {paid} بار\n\n📥 آدرس ولت (فقط TRC20):\n`{wallet}`\n\n⚠️ فقط شبکه TRC20!\n⚠️ ارسال به شبکه اشتباه = از دست رفتن پول!\n\nبعد از واریز، هش تراکنش رو بفرست:\n/verify <TX_HASH>",
        "verify_need_hash": "❌ لطفاً هش تراکنش رو وارد کن.\nمثال: /verify abc123...",
        "verify_checking": "🔎 در حال بررسی تراکنش...",
        "verify_ok": "✅ پرداخت تأیید شد!\n\n🎉 الان {paid} اسکن در {days} روز داری.",
        "verify_used": "❌ این تراکنش قبلاً استفاده شده.",
        "verify_wrong": "❌ تراکنش معتبر نیست:\n{reason}",
        "verify_amount": "مبلغ کمتر از {price} دلار USDT است",
        "verify_wallet": "آدرس مقصد اشتباه است",
        "verify_unconfirmed": "تراکنش هنوز تأیید نشده",
        "verify_notfound": "تراکنش پیدا نشد",
        "rate_limit": "⏳ خیلی سریع! چند ثانیه صبر کن.",
        "scan_error": "❌ خطا در اسکن: {err}",
        "lang_changed": "✅ زبان تغییر کرد.",
        "protocols": {
            "502": "Modbus TCP", "102": "Siemens S7comm", "44818": "EtherNet/IP",
            "20000": "DNP3", "4840": "OPC-UA", "47808": "BACnet",
            "1911": "Niagara Fox", "1962": "PCWorx", "9600": "Omron FINS",
            "789": "Red Lion Crimson", "2404": "IEC 104", "20547": "ProConOS"
        },
        "severity": {"critical": "بحرانی", "high": "پرخطر", "medium": "متوسط"},
    },
    "en": {
        "choose_lang": "🌍 Please choose your language:",
        "welcome": "👋 Hi {name}!\n\nI'm the ICS/SCADA Scanner Bot.\n\n📌 Commands:\n/scan <IP> — Full scan\n/modbus <IP> — Modbus test\n/s7 <IP> — S7comm test\n/quick <IP> — Quick port scan\n/usage — My usage\n/subscribe — Buy subscription\n/verify <TX> — Verify payment\n/language — Change language\n/help — Help\n\n⚠️ Only use on systems you're authorized to test.",
        "help": "📖 Help:\n\n/scan 192.168.1.100 — Full ICS scan\n/modbus 192.168.1.100 — Modbus test\n/s7 192.168.1.100 — S7comm test\n/quick 192.168.1.100 — Quick port scan\n/usage — Show usage\n/subscribe — Buy 30 scans for $6\n\n⚠️ Legal: Only scan systems you own or have written permission.",
        "scanning": "🔍 Scanning {ip} ...\nPlease wait.",
        "report_title": "🔍 ICS/SCADA Scan Report",
        "target": "🎯 Target",
        "duration": "⏱ Duration",
        "seconds": "seconds",
        "open_ports": "📡 Open Ports",
        "deep_detect": "🔬 Deep Detection",
        "no_ports": "✅ No known ICS ports open.",
        "security_warning": "⚠️ These ports are usually unauthenticated. Isolate immediately if this is a real ICS.",
        "invalid_ip": "❌ Invalid IP address.",
        "no_arg": "❌ Please provide an IP.\nExample: /scan 192.168.1.100",
        "public_ip_blocked": "❌ Public IP scanning is not allowed.",
        "limit_reached": "🚫 Scan limit reached!\n\nFree tier: {free} scans/month\nPaid tier: {paid} scans/month for ${price}\n\nUse /subscribe to upgrade.",
        "usage": "📊 Your usage:\n\nTier: {tier}\nUsed: {used}/{limit}\nExpires: {expire}",
        "subscribe": "💳 Subscribe — Premium\n\n💰 Price: ${price} USDT\n📅 Valid: {days} days\n📊 Scans: {paid}\n\n📥 Wallet address (TRC20 only):\n`{wallet}`\n\n⚠️ TRC20 network only!\n⚠️ Wrong network = lost funds!\n\nAfter payment, send TX hash:\n/verify <TX_HASH>",
        "verify_need_hash": "❌ Please provide TX hash.\nExample: /verify abc123...",
        "verify_checking": "🔎 Verifying transaction...",
        "verify_ok": "✅ Payment confirmed!\n\n🎉 You now have {paid} scans for {days} days.",
        "verify_used": "❌ This transaction was already used.",
        "verify_wrong": "❌ Invalid transaction:\n{reason}",
        "verify_amount": "Amount less than ${price} USDT",
        "verify_wallet": "Wrong recipient address",
        "verify_unconfirmed": "Transaction not yet confirmed",
        "verify_notfound": "Transaction not found",
        "rate_limit": "⏳ Too fast! Wait a few seconds.",
        "scan_error": "❌ Scan error: {err}",
        "lang_changed": "✅ Language changed.",
        "protocols": {
            "502": "Modbus TCP", "102": "Siemens S7comm", "44818": "EtherNet/IP",
            "20000": "DNP3", "4840": "OPC-UA", "47808": "BACnet",
            "1911": "Niagara Fox", "1962": "PCWorx", "9600": "Omron FINS",
            "789": "Red Lion Crimson", "2404": "IEC 104", "20547": "ProConOS"
        },
        "severity": {"critical": "Critical", "high": "High", "medium": "Medium"},
    },
    "ru": {
        "choose_lang": "🌍 Пожалуйста, выберите язык:",
        "welcome": "👋 Привет {name}!\n\nЯ бот-сканер ICS/SCADA.\n\n📌 Команды:\n/scan <IP> — Полное сканирование\n/modbus <IP> — Тест Modbus\n/s7 <IP> — Тест S7comm\n/quick <IP> — Быстрый скан\n/usage — Моё использование\n/subscribe — Купить подписку\n/verify <TX> — Проверить оплату\n/language — Сменить язык\n/help — Помощь\n\n⚠️ Только для авторизованных систем.",
        "help": "📖 Помощь:\n\n/scan 192.168.1.100 — Полный ICS скан\n/modbus 192.168.1.100 — Тест Modbus\n/s7 192.168.1.100 — Тест S7comm\n/quick 192.168.1.100 — Быстрый скан\n/usage — Показать использование\n/subscribe — 30 сканов за $6\n\n⚠️ Только системы, которые вам принадлежат.",
        "scanning": "🔍 Сканирование {ip} ...\nПодождите.",
        "report_title": "🔍 Отчёт сканирования ICS/SCADA",
        "target": "🎯 Цель",
        "duration": "⏱ Длительность",
        "seconds": "сек",
        "open_ports": "📡 Открытые порты",
        "deep_detect": "🔬 Глубокое обнаружение",
        "no_ports": "✅ Открытых ICS портов не найдено.",
        "security_warning": "⚠️ Эти порты обычно без аутентификации. Изолируйте немедленно.",
        "invalid_ip": "❌ Неверный IP.",
        "no_arg": "❌ Укажите IP.\nПример: /scan 192.168.1.100",
        "public_ip_blocked": "❌ Публичные IP запрещены.",
        "limit_reached": "🚫 Лимит исчерпан!\n\nБесплатно: {free} сканов/мес\nПремиум: {paid} сканов/мес за ${price}\n\n/subscribe для покупки.",
        "usage": "📊 Использование:\n\nТариф: {tier}\nИспользовано: {used}/{limit}\nИстекает: {expire}",
        "subscribe": "💳 Премиум подписка\n\n💰 Цена: ${price} USDT\n📅 Срок: {days} дней\n📊 Сканов: {paid}\n\n📥 Кошелёк (только TRC20):\n`{wallet}`\n\n⚠️ Только сеть TRC20!\n⚠️ Неверная сеть = потеря средств!\n\nПосле оплаты отправьте хэш:\n/verify <TX_HASH>",
        "verify_need_hash": "❌ Укажите хэш транзакции.",
        "verify_checking": "🔎 Проверка транзакции...",
        "verify_ok": "✅ Оплата подтверждена!\n\n🎉 Теперь у вас {paid} сканов на {days} дней.",
        "verify_used": "❌ Эта транзакция уже использована.",
        "verify_wrong": "❌ Неверная транзакция:\n{reason}",
        "verify_amount": "Сумма меньше ${price} USDT",
        "verify_wallet": "Неверный адрес получателя",
        "verify_unconfirmed": "Транзакция не подтверждена",
        "verify_notfound": "Транзакция не найдена",
        "rate_limit": "⏳ Слишком быстро! Подождите.",
        "scan_error": "❌ Ошибка скана: {err}",
        "lang_changed": "✅ Язык изменён.",
        "protocols": {
            "502": "Modbus TCP", "102": "Siemens S7comm", "44818": "EtherNet/IP",
            "20000": "DNP3", "4840": "OPC-UA", "47808": "BACnet",
            "1911": "Niagara Fox", "1962": "PCWorx", "9600": "Omron FINS",
            "789": "Red Lion Crimson", "2404": "IEC 104", "20547": "ProConOS"
        },
        "severity": {"critical": "Критический", "high": "Высокий", "medium": "Средний"},
    },
    "de": {
        "choose_lang": "🌍 Bitte wählen Sie Ihre Sprache:",
        "welcome": "👋 Hallo {name}!\n\nIch bin der ICS/SCADA Scanner Bot.\n\n📌 Befehle:\n/scan <IP> — Vollständiger Scan\n/modbus <IP> — Modbus-Test\n/s7 <IP> — S7comm-Test\n/quick <IP> — Schnellscan\n/usage — Meine Nutzung\n/subscribe — Abo kaufen\n/verify <TX> — Zahlung prüfen\n/language — Sprache ändern\n/help — Hilfe\n\n⚠️ Nur für autorisierte Systeme.",
        "help": "📖 Hilfe:\n\n/scan 192.168.1.100 — Vollständiger ICS-Scan\n/modbus 192.168.1.100 — Modbus-Test\n/s7 192.168.1.100 — S7comm-Test\n/quick 192.168.1.100 — Schnellscan\n/usage — Nutzung anzeigen\n/subscribe — 30 Scans für 6$\n\n⚠️ Nur eigene Systeme scannen.",
        "scanning": "🔍 Scanne {ip} ...\nBitte warten.",
        "report_title": "🔍 ICS/SCADA Scan-Bericht",
        "target": "🎯 Ziel",
        "duration": "⏱ Dauer",
        "seconds": "Sek",
        "open_ports": "📡 Offene Ports",
        "deep_detect": "🔬 Tiefenerkennung",
        "no_ports": "✅ Keine bekannten ICS-Ports offen.",
        "security_warning": "⚠️ Diese Ports sind meist unauthentifiziert. Sofort isolieren!",
        "invalid_ip": "❌ Ungültige IP.",
        "no_arg": "❌ Bitte IP angeben.\nBeispiel: /scan 192.168.1.100",
        "public_ip_blocked": "❌ Öffentliche IPs nicht erlaubt.",
        "limit_reached": "🚫 Limit erreicht!\n\nKostenlos: {free} Scans/Monat\nPremium: {paid} Scans/Monat für ${price}\n\n/subscribe zum Kaufen.",
        "usage": "📊 Nutzung:\n\nTarif: {tier}\nVerwendet: {used}/{limit}\nLäuft ab: {expire}",
        "subscribe": "💳 Premium-Abo\n\n💰 Preis: ${price} USDT\n📅 Gültig: {days} Tage\n📊 Scans: {paid}\n\n📥 Wallet (nur TRC20):\n`{wallet}`\n\n⚠️ Nur TRC20-Netzwerk!\n⚠️ Falsches Netzwerk = Geldverlust!\n\nNach Zahlung TX-Hash senden:\n/verify <TX_HASH>",
        "verify_need_hash": "❌ Bitte TX-Hash angeben.",
        "verify_checking": "🔎 Transaktion wird geprüft...",
        "verify_ok": "✅ Zahlung bestätigt!\n\n🎉 Sie haben jetzt {paid} Scans für {days} Tage.",
        "verify_used": "❌ Diese Transaktion wurde bereits verwendet.",
        "verify_wrong": "❌ Ungültige Transaktion:\n{reason}",
        "verify_amount": "Betrag unter ${price} USDT",
        "verify_wallet": "Falsche Empfängeradresse",
        "verify_unconfirmed": "Transaktion nicht bestätigt",
        "verify_notfound": "Transaktion nicht gefunden",
        "rate_limit": "⏳ Zu schnell! Warten Sie.",
        "scan_error": "❌ Scan-Fehler: {err}",
        "lang_changed": "✅ Sprache geändert.",
        "protocols": {
            "502": "Modbus TCP", "102": "Siemens S7comm", "44818": "EtherNet/IP",
            "20000": "DNP3", "4840": "OPC-UA", "47808": "BACnet",
            "1911": "Niagara Fox", "1962": "PCWorx", "9600": "Omron FINS",
            "789": "Red Lion Crimson", "2404": "IEC 104", "20547": "ProConOS"
        },
        "severity": {"critical": "Kritisch", "high": "Hoch", "medium": "Mittel"},
    },
}

# ============================================================
# 🔌 پورت‌های ICS و سطح خطر
# ============================================================
ICS_PORTS = {
    502: "critical", 102: "critical", 44818: "high",
    20000: "critical", 4840: "high", 47808: "medium",
    1911: "medium", 1962: "high", 9600: "high",
    789: "medium", 2404: "critical", 20547: "high",
}

# ============================================================
# 🗄 دیتابیس
# ============================================================
def init_db():
    con = sqlite3.connect(DB_FILE)
    cur = con.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY,
            language TEXT DEFAULT 'en',
            scans_used INTEGER DEFAULT 0,
            scans_limit INTEGER DEFAULT 2,
            tier TEXT DEFAULT 'free',
            paid_until TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_reset TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_scan_at TIMESTAMP
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS payments (
            tx_hash TEXT PRIMARY KEY,
            user_id INTEGER,
            amount REAL,
            verified INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            target_ip TEXT,
            result TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    con.commit()
    con.close()


def db():
    con = sqlite3.connect(DB_FILE)
    con.row_factory = sqlite3.Row
    return con


def get_user(user_id: int):
    con = db()
    cur = con.cursor()
    cur.execute("SELECT * FROM users WHERE user_id = ?", (user_id,))
    row = cur.fetchone()
    if not row:
        cur.execute("INSERT INTO users (user_id) VALUES (?)", (user_id,))
        con.commit()
        cur.execute("SELECT * FROM users WHERE user_id = ?", (user_id,))
        row = cur.fetchone()
    con.close()
    return dict(row)


def update_user(user_id: int, **kwargs):
    if not kwargs:
        return
    cols = ", ".join(f"{k} = ?" for k in kwargs)
    vals = list(kwargs.values()) + [user_id]
    con = db()
    con.execute(f"UPDATE users SET {cols} WHERE user_id = ?", vals)
    con.commit()
    con.close()


def reset_monthly_if_needed(user: dict) -> dict:
    """ریست ماهانه اسکن‌های رایگان"""
    last = datetime.fromisoformat(user["last_reset"]) if user["last_reset"] else datetime.now()
    if datetime.now() - last >= timedelta(days=30):
        if user["tier"] == "free":
            update_user(user["user_id"], scans_used=0, last_reset=datetime.now().isoformat())
        elif user["paid_until"] and datetime.fromisoformat(user["paid_until"]) < datetime.now():
            update_user(user["user_id"], tier="free", scans_used=0,
                        scans_limit=FREE_SCANS, paid_until=None,
                        last_reset=datetime.now().isoformat())
        return get_user(user["user_id"])
    return user


# ============================================================
# 🌐 اسکنرها
# ============================================================
def nmap_scan(ip: str, ports: list) -> dict:
    """اسکن پورت‌ها با nmap"""
    try:
        import nmap
        nm = nmap.PortScanner()
        port_str = ",".join(str(p) for p in ports)
        nm.scan(hosts=ip, ports=port_str, arguments="-sV -Pn -T4 --host-timeout 30s")
        result = {}
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                for port in nm[host][proto]:
                    state = nm[host][proto][port]["state"]
                    if state == "open":
                        result[port] = {
                            "service": nm[host][proto][port].get("name", ""),
                            "product": nm[host][proto][port].get("product", ""),
                            "version": nm[host][proto][port].get("version", ""),
                        }
        return result
    except Exception as e:
        logging.error(f"nmap error: {e}")
        return {}


def modbus_probe(ip: str, port: int = 502) -> dict:
    """تست واقعی Modbus"""
    try:
        from pymodbus.client import ModbusTcpClient
        client = ModbusTcpClient(ip, port=port, timeout=3)
        if not client.connect():
            return {"connected": False}
        info = {"connected": True}
        try:
            rr = client.read_holding_registers(0, 1, slave=1)
            info["holding_ok"] = not rr.isError()
        except Exception:
            info["holding_ok"] = False
        try:
            # Device Identification
            rr = client.read_device_information(slave=1)
            if not rr.isError() and hasattr(rr, "information"):
                info["vendor"] = rr.information.get(0, "")
                info["product"] = rr.information.get(1, "")
                info["version"] = rr.information.get(2, "")
        except Exception:
            pass
        client.close()
        return info
    except Exception as e:
        logging.error(f"modbus error: {e}")
        return {"connected": False}


def s7_probe(ip: str, port: int = 102) -> dict:
    """تست واقعی S7comm با snap7"""
    try:
        import snap7
        client = snap7.client.Client()
        client.connect(ip, 0, 1, 102)
        if not client.get_connected():
            return {"connected": False}
        info = {"connected": True}
        try:
            cpu = client.get_cpu_info()
            info["module_type"] = cpu.ModuleTypeName
            info["serial"] = cpu.SerialNumber
            info["as_name"] = cpu.ASName
            info["copyright"] = cpu.Copyright
        except Exception:
            pass
        try:
            info["order_code"] = client.get_cpu_info().OrderCode if hasattr(client.get_cpu_info(), "OrderCode") else ""
        except Exception:
            pass
        client.disconnect()
        client.destroy()
        return info
    except Exception as e:
        logging.error(f"s7 error: {e}")
        return {"connected": False}


async def full_scan(ip: str) -> dict:
    """اسکن کامل async"""
    loop = asyncio.get_event_loop()
    ports = list(ICS_PORTS.keys())
    start = datetime.now()
    nmap_res = await loop.run_in_executor(None, nmap_scan, ip, ports)
    deep = {}
    if 502 in nmap_res:
        deep["modbus"] = await loop.run_in_executor(None, modbus_probe, ip, 502)
    if 102 in nmap_res:
        deep["s7"] = await loop.run_in_executor(None, s7_probe, ip, 102)
    duration = (datetime.now() - start).total_seconds()
    return {"ports": nmap_res, "deep": deep, "duration": duration}


# ============================================================
# 💳 تأیید پرداخت USDT TRC20
# ============================================================
async def verify_usdt(tx_hash: str) -> dict:
    """بررسی تراکنش روی TronGrid"""
    try:
        async with aiohttp.ClientSession() as session:
            # اول تراکنش رو بگیر
            url = f"{TRONGRID_API}/v1/transactions/{tx_hash}"
            async with session.get(url, timeout=10) as r:
                data = await r.json()
            if not data.get("data"):
                return {"ok": False, "reason": "notfound"}
            tx = data["data"][0]
            if not tx.get("ret") or tx["ret"][0].get("contractRet") != "SUCCESS":
                return {"ok": False, "reason": "unconfirmed"}
            # بررسی TRC20 transfer
            contracts = tx.get("raw_data", {}).get("contract", [])
            if not contracts:
                return {"ok": False, "reason": "notfound"}
            contract = contracts[0]
            if contract.get("type") != "TriggerSmartContract":
                return {"ok": False, "reason": "notfound"}
            value = contract.get("parameter", {}).get("value", {})
            data_hex = value.get("data", "")
            # پارس TRC20 transfer: a9059cbb + to(32 bytes) + amount(32 bytes)
            if len(data_hex) < 136:
                return {"ok": False, "reason": "notfound"}
            to_hex = data_hex[32:72]
            amount_hex = data_hex[72:136]
            to_addr = "T" + base58check_encode(bytes.fromhex("41" + to_hex[-40:]))
            amount_raw = int(amount_hex, 16)
            amount_usdt = amount_raw / 1_000_000
            if to_addr != USDT_WALLET:
                return {"ok": False, "reason": "wallet", "got": to_addr}
            if amount_usdt < PRICE_USDT:
                return {"ok": False, "reason": "amount", "got": amount_usdt}
            return {"ok": True, "amount": amount_usdt}
    except Exception as e:
        logging.error(f"verify error: {e}")
        return {"ok": False, "reason": "notfound"}


def base58check_encode(payload: bytes) -> str:
    """انکود Base58Check برای آدرس ترون"""
    import hashlib
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    data = payload + checksum
    n = int.from_bytes(data, "big")
    out = ""
    while n > 0:
        n, r = divmod(n, 58)
        out = alphabet[r] + out
    for b in data:
        if b == 0:
            out = "1" + out
        else:
            break
    return out


# ============================================================
# 🛠 ابزارها
# ============================================================
def t(lang: str, key: str) -> str:
    return TEXTS.get(lang, TEXTS["en"]).get(key, key)


def is_valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def lang_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("🇮🇷 فارسی", callback_data="lang_fa"),
         InlineKeyboardButton("🇬🇧 English", callback_data="lang_en")],
        [InlineKeyboardButton("🇷🇺 Русский", callback_data="lang_ru"),
         InlineKeyboardButton("🇩🇪 Deutsch", callback_data="lang_de")],
    ])


def can_scan(user: dict) -> tuple:
    """(allowed, reason)"""
    if user["tier"] == "paid" and user["paid_until"]:
        if datetime.fromisoformat(user["paid_until"]) < datetime.now():
            return False, "expired"
        return user["scans_used"] < PAID_SCANS, "limit"
    return user["scans_used"] < FREE_SCANS, "limit"


def check_rate_limit(user: dict) -> bool:
    if not user.get("last_scan_at"):
        return True
    last = datetime.fromisoformat(user["last_scan_at"])
    return (datetime.now() - last).total_seconds() >= 12  # 5/min


# ============================================================
# 🎬 هندلرها
# ============================================================
async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = get_user(update.effective_user.id)
    if not user.get("language") or user["language"] == "en":
        # اولین بار: انتخاب زبان
        if user["scans_used"] == 0 and user["created_at"]:
            await update.message.reply_text(
                "🌍 Please choose your language / لطفاً زبان را انتخاب کنید:",
                reply_markup=lang_keyboard()
            )
            return
    lang = user["language"]
    await update.message.reply_text(
        t(lang, "welcome").format(name=update.effective_user.first_name or "")
    )


async def cmd_language(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "🌍 Choose language / انتخاب زبان / Выберите язык / Sprache wählen:",
        reply_markup=lang_keyboard()
    )


async def cb_language(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    lang = query.data.replace("lang_", "")
    update_user(query.from_user.id, language=lang)
    await query.edit_message_text(t(lang, "welcome").format(name=query.from_user.first_name or ""))


async def cmd_help(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = get_user(update.effective_user.id)
    await update.message.reply_text(t(user["language"], "help"))


async def cmd_usage(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = reset_monthly_if_needed(get_user(update.effective_user.id))
    lang = user["language"]
    limit = PAID_SCANS if user["tier"] == "paid" else FREE_SCANS
    expire = user["paid_until"] or "—"
    await update.message.reply_text(t(lang, "usage").format(
        tier=user["tier"], used=user["scans_used"], limit=limit, expire=expire
    ))


async def cmd_subscribe(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = get_user(update.effective_user.id)
    lang = user["language"]
    await update.message.reply_text(
        t(lang, "subscribe").format(
            price=PRICE_USDT, days=PAID_DAYS, paid=PAID_SCANS, wallet=USDT_WALLET
        ),
        parse_mode="Markdown"
    )


async def cmd_verify(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = get_user(update.effective_user.id)
    lang = user["language"]
    if not context.args:
        await update.message.reply_text(t(lang, "verify_need_hash"))
        return
    tx_hash = context.args[0].strip()
    # چک تکراری
    con = db()
    cur = con.cursor()
    cur.execute("SELECT * FROM payments WHERE tx_hash = ?", (tx_hash,))
    if cur.fetchone():
        con.close()
        await update.message.reply_text(t(lang, "verify_used"))
        return
    con.close()

    msg = await update.message.reply_text(t(lang, "verify_checking"))
    result = await verify_usdt(tx_hash)
    if not result["ok"]:
        reason_map = {
            "notfound": t(lang, "verify_notfound"),
            "unconfirmed": t(lang, "verify_unconfirmed"),
            "wallet": t(lang, "verify_wallet"),
            "amount": t(lang, "verify_amount").format(price=PRICE_USDT),
        }
        await msg.edit_text(t(lang, "verify_wrong").format(
            reason=reason_map.get(result.get("reason"), "unknown")
        ))
        return

    # ثبت پرداخت و ارتقاء
    con = db()
    con.execute("INSERT INTO payments (tx_hash, user_id, amount, verified) VALUES (?, ?, ?, 1)",
                (tx_hash, user["user_id"], result["amount"]))
    con.commit()
    con.close()
    until = datetime.now() + timedelta(days=PAID_DAYS)
    update_user(user["user_id"],
                tier="paid", scans_used=0, scans_limit=PAID_SCANS,
                paid_until=until.isoformat(), last_reset=datetime.now().isoformat())
    await msg.edit_text(t(lang, "verify_ok").format(paid=PAID_SCANS, days=PAID_DAYS))


# ---------- اسکن ----------
async def do_scan(update: Update, context: ContextTypes.DEFAULT_TYPE, mode: str):
    user = reset_monthly_if_needed(get_user(update.effective_user.id))
    lang = user["language"]

    if not context.args:
        await update.message.reply_text(t(lang, "no_arg"))
        return
    ip = context.args[0].strip()
    if not is_valid_ip(ip):
        await update.message.reply_text(t(lang, "invalid_ip"))
        return
    if not ALLOW_PUBLIC_IP and not is_private(ip):
        await update.message.reply_text(t(lang, "public_ip_blocked"))
        return
    if not check_rate_limit(user):
        await update.message.reply_text(t(lang, "rate_limit"))
        return

    allowed, _ = can_scan(user)
    if not allowed:
        await update.message.reply_text(t(lang, "limit_reached").format(
            free=FREE_SCANS, paid=PAID_SCANS, price=PRICE_USDT
        ))
        return

    msg = await update.message.reply_text(t(lang, "scanning").format(ip=ip))
    try:
        if mode == "quick":
            loop = asyncio.get_event_loop()
            ports = await loop.run_in_executor(None, nmap_scan, ip, list(ICS_PORTS.keys()))
            result = {"ports": ports, "deep": {}, "duration": 0}
        elif mode == "modbus":
            loop = asyncio.get_event_loop()
            r = await loop.run_in_executor(None, modbus_probe, ip, 502)
            result = {"ports": {502: {"service": "modbus"}} if r.get("connected") else {},
                      "deep": {"modbus": r}, "duration": 0}
        elif mode == "s7":
            loop = asyncio.get_event_loop()
            r = await loop.run_in_executor(None, s7_probe, ip, 102)
            result = {"ports": {102: {"service": "s7comm"}} if r.get("connected") else {},
                      "deep": {"s7": r}, "duration": 0}
        else:
            result = await full_scan(ip)
    except Exception as e:
        await msg.edit_text(t(lang, "scan_error").format(err=str(e)))
        return

    # ساخت گزارش
    report = build_report(lang, ip, result)

    # به‌روزرسانی مصرف
    update_user(user["user_id"],
                scans_used=user["scans_used"] + 1,
                last_scan_at=datetime.now().isoformat())
    con = db()
    con.execute("INSERT INTO scans (user_id, target_ip, result) VALUES (?, ?, ?)",
                (user["user_id"], ip, json.dumps(result, default=str)))
    con.commit()
    con.close()

    used = user["scans_used"] + 1
    limit = PAID_SCANS if user["tier"] == "paid" else FREE_SCANS
    report += f"\n\n📊 {used}/{limit}"

    await msg.edit_text(report, parse_mode="Markdown")


def build_report(lang: str, ip: str, result: dict) -> str:
    tr = TEXTS.get(lang, TEXTS["en"])
    lines = [
        tr["report_title"],
        f"{tr['target']}: `{ip}`",
    ]
    if result.get("duration"):
        lines.append(f"{tr['duration']}: {result['duration']:.1f} {tr['seconds']}")
    lines.append("━━━━━━━━━━━━━━━━━━")

    ports = result.get("ports", {})
    if ports:
        lines.append(tr["open_ports"] + ":")
        for port in sorted(ports.keys()):
            sev = ICS_PORTS.get(port, "medium")
            emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡"}[sev]
            proto = tr["protocols"].get(str(port), ports[port].get("service", "?"))
            lines.append(f"{emoji} `{port}/tcp` — {proto} ({tr['severity'][sev]})")
    else:
        lines.append(tr["no_ports"])

    deep = result.get("deep", {})
    if deep:
        lines.append("")
        lines.append("━━━━━━━━━━━━━━━━━━")
        lines.append(tr["deep_detect"] + ":")
        if deep.get("modbus", {}).get("connected"):
            m = deep["modbus"]
            lines.append("✅ Modbus")
            if m.get("vendor"): lines.append(f"   • Vendor: {m['vendor']}")
            if m.get("product"): lines.append(f"   • Product: {m['product']}")
            if m.get("version"): lines.append(f"   • Version: {m['version']}")
            if m.get("holding_ok") is not None:
                lines.append(f"   • Registers readable: {m['holding_ok']}")
        if deep.get("s7", {}).get("connected"):
            s = deep["s7"]
            lines.append("✅ S7comm")
            if s.get("module_type"): lines.append(f"   • PLC Type: {s['module_type']}")
            if s.get("serial"): lines.append(f"   • Serial: {s['serial']}")
            if s.get("as_name"): lines.append(f"   • AS Name: {s['as_name']}")
            if s.get("order_code"): lines.append(f"   • Order: {s['order_code']}")

    lines.append("")
    lines.append("━━━━━━━━━━━━━━━━━━")
    lines.append(tr["security_warning"])
    return "\n".join(lines)


async def cmd_scan(update, context):   await do_scan(update, context, "full")
async def cmd_quick(update, context):  await do_scan(update, context, "quick")
async def cmd_modbus(update, context): await do_scan(update, context, "modbus")
async def cmd_s7(update, context):     await do_scan(update, context, "s7")


# ---------- ادمین ----------
def admin_only(func):
    async def wrapper(update, context):
        if update.effective_user.id not in ADMIN_IDS:
            await update.message.reply_text("❌ Admin only.")
            return
        return await func(update, context)
    return wrapper


@admin_only
async def cmd_users(update: Update, context: ContextTypes.DEFAULT_TYPE):
    con = db()
    cur = con.cursor()
    cur.execute("SELECT user_id, language, tier, scans_used FROM users")
    rows = cur.fetchall()
    con.close()
    txt = "👥 Users:\n\n" + "\n".join(
        f"• `{r['user_id']}` — {r['language']} — {r['tier']} — {r['scans_used']}"
        for r in rows[:50]
    )
    await update.message.reply_text(txt, parse_mode="Markdown")


@admin_only
async def cmd_stats(update: Update, context: ContextTypes.DEFAULT_TYPE):
    con = db()
    cur = con.cursor()
    cur.execute("SELECT COUNT(*) as c FROM users"); users = cur.fetchone()["c"]
    cur.execute("SELECT COUNT(*) as c FROM scans"); scans = cur.fetchone()["c"]
    cur.execute("SELECT COUNT(*) as c FROM payments WHERE verified=1"); pays = cur.fetchone()["c"]
    con.close()
    await update.message.reply_text(f"📊 Stats:\n\n👥 Users: {users}\n🔍 Scans: {scans}\n💰 Payments: {pays}")


@admin_only
async def cmd_adduser(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if len(context.args) < 1:
        await update.message.reply_text("Usage: /adduser <user_id> [scans]")
        return
    uid = int(context.args[0])
    scans = int(context.args[1]) if len(context.args) > 1 else PAID_SCANS
    until = datetime.now() + timedelta(days=PAID_DAYS)
    update_user(uid, tier="paid", scans_used=0, scans_limit=scans, paid_until=until.isoformat())
    await update.message.reply_text(f"✅ User {uid} upgraded.")


@admin_only
async def cmd_broadcast(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("Usage: /broadcast <msg>")
        return
    msg = " ".join(context.args)
    con = db()
    cur = con.cursor()
    cur.execute("SELECT user_id FROM users")
    ids = [r["user_id"] for r in cur.fetchall()]
    con.close()
    ok = 0
    for uid in ids:
        try:
            await context.bot.send_message(uid, msg)
            ok += 1
        except Exception:
            pass
    await update.message.reply_text(f"✅ Sent to {ok}/{len(ids)}")


# ============================================================
# 🚀 اجرا
# ============================================================
def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    init_db()
    app = ApplicationBuilder().token(BOT_TOKEN).build()

    # کاربر
    app.add_handler(CommandHandler("start", cmd_start))
    app.add_handler(CommandHandler("help", cmd_help))
    app.add_handler(CommandHandler("language", cmd_language))
    app.add_handler(CommandHandler("usage", cmd_usage))
    app.add_handler(CommandHandler("subscribe", cmd_subscribe))
    app.add_handler(CommandHandler("verify", cmd_verify))
    app.add_handler(CommandHandler("scan", cmd_scan))
    app.add_handler(CommandHandler("quick", cmd_quick))
    app.add_handler(CommandHandler("modbus", cmd_modbus))
    app.add_handler(CommandHandler("s7", cmd_s7))

    # ادمین
    app.add_handler(CommandHandler("users", cmd_users))
    app.add_handler(CommandHandler("stats", cmd_stats))
    app.add_handler(CommandHandler("adduser", cmd_adduser))
    app.add_handler(CommandHandler("broadcast", cmd_broadcast))

    # دکمه‌ها
    app.add_handler(CallbackQueryHandler(cb_language, pattern="^lang_"))

    print("✅ Bot is running...")
    app.run_polling()


if __name__ == "__main__":
    main()
