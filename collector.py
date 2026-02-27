#!/usr/bin/env python3
"""
VLESS Proxy Collector
Собирает прокси из подписок, тестирует ping и трафик через Xray,
сохраняет TOP 100 в формате Clash + статистика по источникам
"""

import os
import sys
import re
import time
import json
import yaml
import urllib.request
import urllib.parse
import subprocess
import concurrent.futures
import socket
import shutil
import tempfile
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, asdict
import urllib.parse

# === НОВЫЙ ИМПОРТ ДЛЯ GEOIP ===
import geoip2.database

# ============================================================================
# КОНФИГУРАЦИЯ
# ============================================================================

@dataclass
class Config:
    """Конфигурация проекта"""
    sources_file: str = "VlessLinks.txt"
    all_proxies_file: str = "all_proxies.yaml"
    ping_file: str = "ping.yaml"
    traff_file: str = "traff.yaml"
    clash_file: str = "clash.yaml"
    stats_file: str = "sources_stats.txt"
    
    # Параметры тестирования
    ping_timeout: int = 2
    ping_parallel: int = 50
    
    xray_timeout: int = 4
    xray_connect_timeout: int = 4
    xray_parallel: int = 3
    xray_start_timeout: int = 2
    
    # Фильтры
    ping_threshold: int = 500
    max_proxies: int = 10000
    top_count: int = 100
    
    # URLs для тестов
    test_urls: List[str] = None
    
    # Xray
    xray_url: str = "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip"
    xray_zip: str = "Xray-linux-64.zip"
    xray_dir: str = "xray"
    xray_bin: str = "xray/xray"
    
    # GeoIP база
    geoip_db: str = "geoip/GeoLite2-Country.mmdb"
    
    def __post_init__(self):
        if self.test_urls is None:
            self.test_urls = [
                "http://www.gstatic.com/generate_204",
                "https://www.google.com/generate_204",
                "https://cp.cloudflare.com/generate_204"
            ]


# ============================================================================
# МОДЕЛИ ДАННЫХ
# ============================================================================

@dataclass
class VlessProxy:
    """VLESS прокси с распарсенными параметрами"""
    raw_url: str
    uuid: str
    server: str
    port: int
    source: str = ""
    network: str = "tcp"
    host: str = ""
    path: str = ""
    flow: str = ""
    security: str = "none"
    sni: str = ""
    pbk: str = ""
    sid: str = ""
    fp: str = "chrome"
    alpn: str = ""
    service_name: str = ""
    authority: str = ""
    
    @classmethod
    def from_url(cls, url: str, source: str = "") -> Optional['VlessProxy']:
        """Создать объект из vless:// URL"""
        try:
            url = url.strip().strip('"\'')
            
            if not url.startswith('vless://'):
                return None
            
            parsed = urllib.parse.urlparse(url.replace('vless://', 'http://'))
            
            if '@' not in parsed.netloc:
                return None
                
            auth, server_port = parsed.netloc.split('@', 1)
            
            if ':' not in server_port:
                return None
                
            server, port_str = server_port.rsplit(':', 1)
            
            try:
                port = int(port_str)
            except ValueError:
                return None
            
            uuid = urllib.parse.unquote(auth)
            params = dict(urllib.parse.parse_qsl(parsed.query))
            
            proxy = cls(
                raw_url=url,
                uuid=uuid,
                server=server,
                port=port,
                source=source,
                network=params.get('type', 'tcp'),
                host=params.get('host', ''),
                path=params.get('path', ''),
                flow=params.get('flow', ''),
                security=params.get('security', 'none'),
                sni=params.get('sni', ''),
                pbk=params.get('pbk', ''),
                sid=params.get('sid', params.get('shortId', '')),
                fp=params.get('fp', 'chrome'),
                alpn=params.get('alpn', ''),
                service_name=params.get('serviceName', ''),
                authority=params.get('authority', '')
            )
            
            if not proxy.sni and proxy.security in ['tls', 'reality']:
                proxy.sni = proxy.server
            
            return proxy
            
        except Exception as e:
            print(f"  ⚠️ Error parsing URL: {e}", file=sys.stderr)
            return None
    
    def is_valid(self) -> bool:
        """Проверка валидности"""
        return all([
            self.uuid and len(self.uuid) > 0,
            self.server and len(self.server) > 0,
            self.port > 0 and self.port < 65536
        ])
    
    def to_yaml_line(self) -> str:
        """Вернуть строку для YAML файла (без source)"""
        return f"  - {self.raw_url}"
    
    def to_clash_config(self, name: str) -> Dict[str, Any]:
        """Сгенерировать конфиг для Clash"""
        config = {
            "name": name,
            "type": "vless",
            "server": self.server,
            "port": self.port,
            "uuid": self.uuid,
            "network": self.network,
            "tls": self.security in ['tls', 'reality'],
            "udp": True,
        }
        
        if self.security in ['tls', 'reality'] and self.sni:
            config["sni"] = self.sni
        
        if self.flow:
            config["flow"] = self.flow
        
        if self.network == "ws" and (self.path or self.host):
            ws_opts = {}
            if self.path:
                ws_opts["path"] = self.path
            if self.host:
                ws_opts["headers"] = {"Host": self.host}
            config["ws-opts"] = ws_opts
        
        return config
    
    def to_xray_config(self, local_port: int) -> Dict[str, Any]:
        """Сгенерировать конфиг для Xray"""
        
        user = {"id": self.uuid, "encryption": "none"}
        if self.flow:
            user["flow"] = self.flow
        
        outbound_settings = {
            "vnext": [{
                "address": self.server,
                "port": self.port,
                "users": [user]
            }]
        }
        
        stream_settings = {
            "network": self.network,
            "security": self.security
        }
        
        if self.security == "tls":
            tls_settings = {
                "serverName": self.sni or self.server,
                "allowInsecure": True,
                "fingerprint": self.fp
            }
            if self.alpn:
                tls_settings["alpn"] = [a.strip() for a in self.alpn.split(",")]
            stream_settings["tlsSettings"] = tls_settings
        
        elif self.security == "reality":
            reality_settings = {
                "serverName": self.sni or self.server,
                "allowInsecure": True,
                "fingerprint": self.fp
            }
            if self.pbk:
                reality_settings["publicKey"] = self.pbk
            if self.sid:
                reality_settings["shortId"] = self.sid
            stream_settings["realitySettings"] = reality_settings
        
        if self.network == "ws" and (self.path or self.host):
            ws_settings = {}
            if self.path:
                ws_settings["path"] = self.path
            if self.host:
                ws_settings["headers"] = {"Host": self.host}
            stream_settings["wsSettings"] = ws_settings
        
        elif self.network == "grpc":
            grpc_settings = {}
            if self.service_name:
                grpc_settings["serviceName"] = self.service_name
            if self.authority:
                grpc_settings["authority"] = self.authority
            stream_settings["grpcSettings"] = grpc_settings
        
        config = {
            "log": {"loglevel": "warning"},
            "inbounds": [{
                "port": local_port,
                "protocol": "socks",
                "settings": {"auth": "noauth", "udp": True}
            }],
            "outbounds": [{
                "tag": "proxy",
                "protocol": "vless",
                "settings": outbound_settings,
                "streamSettings": stream_settings
            }]
        }
        
        return config


@dataclass
class ProxyTestResult:
    """Результат тестирования прокси"""
    proxy: VlessProxy
    ping_time: Optional[float] = None
    traffic_time: Optional[float] = None
    ping_success: bool = False
    traffic_success: bool = False


@dataclass
class SourceStats:
    """Статистика по источнику"""
    url: str
    total_proxies: int = 0
    ping_passed: int = 0
    traffic_passed: int = 0
    ping_times: List[float] = None
    
    def __post_init__(self):
        if self.ping_times is None:
            self.ping_times = []
    
    def add_ping_result(self, success: bool, time_ms: float):
        if success:
            self.ping_passed += 1
            self.ping_times.append(time_ms)
    
    def add_traffic_result(self, success: bool):
        if success:
            self.traffic_passed += 1
    
    def to_string(self) -> str:
        avg_ping = sum(self.ping_times) / len(self.ping_times) if self.ping_times else 0
        return (
            f"📌 {self.url}\n"
            f"   Total: {self.total_proxies}\n"
            f"   ✅ Ping passed: {self.ping_passed} ({self.ping_passed/self.total_proxies*100:.1f}%)\n"
            f"   ⚡ Avg ping: {avg_ping:.0f}ms\n"
            f"   🚀 Traffic passed: {self.traffic_passed}\n"
        )


# ============================================================================
# УТИЛИТЫ
# ============================================================================

def download_file(url: str, dest: str, timeout: int = 30) -> bool:
    """Скачать файл"""
    try:
        urllib.request.urlretrieve(url, dest)
        return True
    except Exception as e:
        print(f"  ⚠️ Failed to download {url}: {e}", file=sys.stderr)
        return False


def read_lines(filename: str) -> List[str]:
    """Прочитать строки из файла, убрать комментарии и пустые"""
    if not os.path.exists(filename):
        return []
    
    lines = []
    with open(filename, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            lines.append(line)
    return lines


def write_yaml(filename: str, proxies: List[str], header: bool = True):
    """Записать прокси в YAML файл"""
    with open(filename, 'w', encoding='utf-8') as f:
        if header:
            f.write("proxies:\n")
        for proxy in proxies:
            f.write(f"{proxy}\n")


def read_yaml_proxies(filename: str) -> List[str]:
    """Прочитать прокси из YAML файла"""
    if not os.path.exists(filename):
        return []
    
    proxies = []
    with open(filename, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.rstrip()
            if line.startswith('proxies:') or not line:
                continue
            if line.startswith('  - '):
                proxies.append(line)
    return proxies


def ping_test(proxy: VlessProxy, timeout: int = 2) -> Tuple[bool, float]:
    """
    Проверить доступность порта (ping)
    Возвращает (успех, время в мс)
    """
    try:
        start = time.time_ns()
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((proxy.server, proxy.port))
        sock.close()
        
        end = time.time_ns()
        duration = (end - start) / 1_000_000
        
        return result == 0, duration
        
    except Exception:
        return False, 0


def test_proxy_with_xray(proxy: VlessProxy, xray_path: str,
                         test_urls: List[str], timeout: int = 3,
                         start_timeout: int = 2) -> Tuple[bool, float]:
    """
    Проверить прокси через Xray на доступ к нескольким URL (параллельно).
    Возвращает (успех, минимальное время в мс)
    """
    local_port = 1080
    config_file = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False)

    try:
        config = proxy.to_xray_config(local_port)
        json.dump(config, config_file, indent=2)
        config_file.close()

        process = subprocess.Popen(
            [xray_path, '-config', config_file.name],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

        # Ждём готовности порта
        port_ready = False
        for i in range(15):
            time.sleep(0.2)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex(('127.0.0.1', local_port))
            sock.close()
            if result == 0:
                port_ready = True
                break

        if not port_ready:
            process.terminate()
            try:
                process.wait(timeout=2)
            except:
                process.kill()
            return False, 0

        # === ПАРАЛЛЕЛЬНАЯ ПРОВЕРКА ВСЕХ URL ===
        fastest_time = float('inf')
        any_success = False

        def check_single_url(test_url):
            start = time.time_ns()
            curl_cmd = [
                'curl', '-s', '-o', '/dev/null', '-w', '%{http_code}',
                '--socks5-hostname', f'127.0.0.1:{local_port}',
                '--connect-timeout', str(timeout),
                '--max-time', str(timeout + 2),
                test_url
            ]
            try:
                result = subprocess.run(curl_cmd, capture_output=True, text=True, timeout=timeout+2)
                http_code = result.stdout.strip()
            except subprocess.TimeoutExpired:
                http_code = "TIMEOUT"

            end = time.time_ns()
            duration = (end - start) / 1_000_000
            return http_code, duration

        # Запускаем проверку всех URL параллельно
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(test_urls)) as executor:
            futures = {executor.submit(check_single_url, url): url for url in test_urls}
            for future in concurrent.futures.as_completed(futures, timeout=timeout+3):
                try:
                    http_code, duration = future.result()
                    if http_code == '204':
                        any_success = True
                        if duration < fastest_time:
                            fastest_time = duration
                except Exception as e:
                    continue

        process.terminate()
        try:
            process.wait(timeout=2)
        except:
            process.kill()

        if any_success:
            return True, fastest_time
        return False, 0

    except Exception as e:
        print(f"  ⚠️ Xray test error: {e}", file=sys.stderr)
        return False, 0

    finally:
        try:
            os.unlink(config_file.name)
        except:
            pass


def clean_uuid(uuid: str) -> str:
    """Очистить UUID от спецсимволов"""
    return re.sub(r'[^a-zA-Z0-9@.\-]', '', uuid)


def clean_name(name: str) -> str:
    """Очистить имя от спецсимволов"""
    return re.sub(r'[^a-zA-Z0-9.-]', '', name)


# === ФУНКЦИЯ ДЛЯ GEOIP С ПОДРОБНОЙ ОТЛАДКОЙ ===
def get_country_flag(server: str, db_path: str = 'geoip/GeoLite2-Country.mmdb') -> str:
    """
    Определяет код страны и возвращает флаг-эмодзи для сервера.
    Если сервер - домен, пытается получить его IP через DNS.
    Если определить не удалось, возвращает '🌍'.
    """
    import socket
    
    print(f"  🚩 get_country_flag called for: {server}")
    
    # Функция для преобразования кода страны в эмодзи
    def code_to_flag(code):
        if code and len(code) == 2:
            return chr(ord(code[0]) + 127397) + chr(ord(code[1]) + 127397)
        return "🌍"
    
    # Проверяем существование базы данных
    if not os.path.exists(db_path):
        print(f"  ⚠️ GeoIP database NOT FOUND at {db_path}")
        return "🌍"
    else:
        print(f"  ✅ GeoIP database found at {db_path}")
    
    # Проверяем, является ли сервер IP-адресом
    is_ip = re.match(r'^\d+\.\d+\.\d+\.\d+$', server)
    print(f"  🔍 Is IP? {is_ip}")
    
    ip_to_check = server
    if not is_ip:
        # Это домен - пытаемся получить IP
        print(f"  🌐 Resolving domain: {server}...")
        try:
            ip_to_check = socket.gethostbyname(server)
            print(f"  ✅ Resolved to IP: {ip_to_check}")
        except Exception as e:
            print(f"  ❌ Failed to resolve {server}: {e}")
            return "🌍"
    else:
        print(f"  📍 Using IP directly: {ip_to_check}")
    
    # Определяем страну по IP
    try:
        print(f"  🔎 Looking up country for IP: {ip_to_check}")
        with geoip2.database.Reader(db_path) as reader:
            response = reader.country(ip_to_check)
            country_code = response.country.iso_code
            flag = code_to_flag(country_code)
            print(f"  🏁 Country code: {country_code}, Flag: {flag}")
            return flag
    except geoip2.errors.AddressNotFoundError:
        print(f"  ❌ IP {ip_to_check} not found in GeoIP database")
        return "🌍"
    except Exception as e:
        print(f"  ❌ GeoIP error: {e}")
        return "🌍"


# ============================================================================
# ОСНОВНЫЕ ФУНКЦИИ
# ============================================================================

def step1_collect(config: Config) -> Tuple[List[str], Dict[str, SourceStats], Dict[str, str]]:
    """
    ШАГ 1: Сбор прокси из подписок
    Возвращает: (список строк, статистика источников, словарь URL->source)
    """
    print("\n" + "="*60)
    print("ШАГ 1: Сбор прокси из подписок")
    print("="*60)
    
    sources = read_lines(config.sources_file)
    if not sources:
        print(f"❌ {config.sources_file} not found or empty")
        sys.exit(1)
    
    print(f"Found {len(sources)} URLs to process")
    
    all_urls = []
    all_proxies = []
    seen = set()
    source_stats = {}
    
    for idx, source_url in enumerate(sources, 1):
        print(f"[{idx}/{len(sources)}] Processing: {source_url}")
        
        source_stats[source_url] = SourceStats(url=source_url)
        
        try:
            req = urllib.request.Request(
                source_url,
                headers={'User-Agent': 'Mozilla/5.0'}
            )
            with urllib.request.urlopen(req, timeout=10) as response:
                content = response.read().decode('utf-8', errors='ignore')
                
            source_count = 0
            for line in content.splitlines():
                for match in re.finditer(r'vless://[^\s]+', line):
                    url = match.group(0)
                    all_urls.append((url, source_url))
                    source_count += 1
            
            # НЕ обновляем total_proxies здесь - сделаем это после фильтрации
            print(f"  ✅ Found {source_count} proxies (before filtering)")
            
        except Exception as e:
            print(f"  ⚠️ Failed to fetch: {e}")
            continue
    
    print(f"\nProcessing collected data...")
    
    # Словарь URL -> source для точного сопоставления
    url_to_source = {}
    
    for url, source_url in all_urls:
        if '%25' in url:
            continue
        if not re.match(r'vless://[^@]+@[^:]+:\d+', url):
            continue
        if '127.0.0.1' in url:
            continue
        if '🔒' in url:
            continue
        if 'tls' in url:
            continue
        if ' ' in url:
            continue
        if len(url) < 40 or len(url) > 1200:
            continue
        
        proxy = VlessProxy.from_url(url, source_url)
        if proxy and proxy.is_valid():
            key = f"{proxy.server}:{proxy.port}:{proxy.uuid}"
            if key not in seen:
                seen.add(key)
                all_proxies.append(proxy.to_yaml_line())
                url_to_source[url] = source_url
    
    # ТЕПЕРЬ обновляем total_proxies для каждого источника
    # Сначала обнуляем
    for src in source_stats:
        source_stats[src].total_proxies = 0
    
    # Считаем только те, что прошли фильтр
    for url, source_url in all_urls:
        if url in url_to_source:  # если прокси прошёл фильтр
            source_stats[source_url].total_proxies += 1
    
    all_proxies = all_proxies[:config.max_proxies]
    write_yaml(config.all_proxies_file, all_proxies)
    
    print(f"\n✅ Collection completed")
    print(f"Found {len(all_proxies)} proxies after filtering")
    
    return all_proxies, source_stats, url_to_source


def step2_ping_test(config: Config, source_stats: Dict[str, SourceStats], url_to_source: Dict[str, str]) -> List[str]:
    """
    ШАГ 2: Ping-тест
    """
    print("\n" + "="*60)
    print("ШАГ 2: Ping-тест")
    print("="*60)
    
    lines = read_yaml_proxies(config.all_proxies_file)
    if not lines:
        print("⚠️ No proxies to test")
        return []
    
    # Создаём прокси с source из словаря
    proxies_with_source = []
    for line in lines:
        url = line.replace('  - ', '', 1)
        source = url_to_source.get(url, "")
        proxy = VlessProxy.from_url(url, source)
        if proxy:
            proxies_with_source.append((proxy, line))
    
    print(f"Total proxies to ping: {len(proxies_with_source)}")
    print(f"Starting parallel ping ({config.ping_parallel} at a time)...")
    
    results = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=config.ping_parallel) as executor:
        future_to_proxy = {
            executor.submit(ping_test, proxy, config.ping_timeout): (idx, proxy, line)
            for idx, (proxy, line) in enumerate(proxies_with_source)
        }
        
        for future in concurrent.futures.as_completed(future_to_proxy):
            idx, proxy, line = future_to_proxy[future]
            try:
                success, ping_time = future.result()
                
                # Обновляем статистику
                if proxy.source and proxy.source in source_stats:
                    source_stats[proxy.source].add_ping_result(success, ping_time)
                
                if success:
                    print(f"✅ {proxy.server}:{proxy.port} - {ping_time:.0f}ms")
                    results.append((ping_time, line))
                else:
                    print(f"❌ {proxy.server}:{proxy.port} - failed")
            except Exception as e:
                print(f"❌ {proxy.server}:{proxy.port} - error: {e}")
    
    results.sort(key=lambda x: x[0])
    ping_lines = [line for _, line in results]
    write_yaml(config.ping_file, ping_lines)
    
    print(f"\n=== PING TEST RESULTS ===")
    print(f"Total processed: {len(proxies_with_source)}")
    print(f"✅ Passed ping: {len(ping_lines)}")
    print(f"❌ Failed ping: {len(proxies_with_source) - len(ping_lines)}")
    
    return ping_lines


def step3_traffic_test(config: Config, source_stats: Dict[str, SourceStats], url_to_source: Dict[str, str]) -> List[str]:
    """
    ШАГ 3: Трафик-тест через Xray + замер времени
    """
    print("\n" + "="*60)
    print("ШАГ 3: Трафик-тест через Xray")
    print("="*60)
    
    if not os.path.exists(config.xray_bin):
        print("Downloading Xray...")
        if not download_file(config.xray_url, config.xray_zip):
            print("❌ Failed to download Xray")
            return []
        
        import zipfile
        with zipfile.ZipFile(config.xray_zip, 'r') as zip_ref:
            zip_ref.extractall(config.xray_dir)
        os.chmod(config.xray_bin, 0o755)
        print("✅ Xray downloaded")
    
    lines = read_yaml_proxies(config.ping_file)
    if not lines:
        print("⚠️ No proxies to test")
        return []
    
    # Создаём прокси с source из словаря
    proxies_with_source = []
    for line in lines:
        url = line.replace('  - ', '', 1)
        source = url_to_source.get(url, "")
        proxy = VlessProxy.from_url(url, source)
        if proxy:
            proxies_with_source.append((proxy, line))
    
    print(f"\n📋 Prepared {len(proxies_with_source)} proxies for testing")
    print(f"🔄 Starting parallel Xray test ({config.xray_parallel} at a time)...")
    
    results = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=config.xray_parallel) as executor:
        future_to_proxy = {
            executor.submit(
                test_proxy_with_xray, 
                proxy, 
                config.xray_bin, 
                config.test_urls,  # ← теперь передаём список URL
                config.xray_timeout,
                config.xray_start_timeout
            ): (idx, proxy, line)
            for idx, (proxy, line) in enumerate(proxies_with_source)
        }
        
        for future in concurrent.futures.as_completed(future_to_proxy):
            idx, proxy, line = future_to_proxy[future]
            try:
                success, duration = future.result()
                
                # Обновляем статистику
                if proxy.source and proxy.source in source_stats:
                    source_stats[proxy.source].add_traffic_result(success)
                
                if success:
                    print(f"✅ {proxy.server}:{proxy.port} - {duration:.0f}ms")
                    results.append((duration, line))
                else:
                    print(f"❌ {proxy.server}:{proxy.port} - failed")
            except Exception as e:
                print(f"❌ {proxy.server}:{proxy.port} - error: {e}")
    
    results.sort(key=lambda x: x[0])
    traff_lines = [line for _, line in results]
    write_yaml(config.traff_file, traff_lines)
    
    print(f"\n" + "="*60)
    print("=== TRAFFIC TEST RESULTS ===")
    print(f"Total tested: {len(proxies_with_source)}")
    print(f"✅ Passed traffic: {len(traff_lines)}")
    print(f"❌ Failed traffic: {len(proxies_with_source) - len(traff_lines)}")
    print("="*60)
    
    return traff_lines


def step4_generate_clash(config: Config) -> List[str]:
    """
    ШАГ 4: Генерация TOP 100 для Clash
    """
    print("\n" + "="*60)
    print("ШАГ 4: Генерация TOP 100 для Clash")
    print("="*60)
    
    lines = read_yaml_proxies(config.traff_file)
    if not lines:
        print("⚠️ No proxies to generate")
        write_yaml(config.clash_file, [])
        return []
    
    top_lines = lines[:config.top_count]
    clash_lines = []
    seen = set()
    
    # Статистика по доменам
    domain_count = 0
    resolved_count = 0
    
    for idx, line in enumerate(top_lines, 1):
        url = line.replace('  - ', '', 1)
        proxy = VlessProxy.from_url(url)
        
        if not proxy:
            continue
        
        key = f"{proxy.server}:{proxy.port}:{proxy.uuid}"
        if key in seen:
            continue
        seen.add(key)
        
        uuid_short = proxy.uuid[:8] if len(proxy.uuid) >= 8 else proxy.uuid
        
        # === ПОЛУЧАЕМ ФЛАГ С РЕЗОЛВИНГОМ ДОМЕНОВ ===
        flag = get_country_flag(proxy.server, config.geoip_db)
        
        # Считаем статистику по доменам
        if not re.match(r'^\d+\.\d+\.\d+\.\d+$', proxy.server):
            domain_count += 1
            if flag != "🌍":
                resolved_count += 1
        # ==========================================
        
        base_name = clean_name(f"{proxy.server}-{proxy.port}-{uuid_short}")
        name = f"{flag}{base_name}"
        
        clash_config = proxy.to_clash_config(name)
        
        clash_lines.append(f"  - name: \"{clash_config['name']}\"")
        clash_lines.append(f"    type: {clash_config['type']}")
        clash_lines.append(f"    server: \"{clash_config['server']}\"")
        clash_lines.append(f"    port: {clash_config['port']}")
        clash_lines.append(f"    uuid: \"{clash_config['uuid']}\"")
        clash_lines.append(f"    network: {clash_config['network']}")
        clash_lines.append(f"    tls: {str(clash_config['tls']).lower()}")
        clash_lines.append(f"    udp: {str(clash_config['udp']).lower()}")
        
        if 'sni' in clash_config:
            clash_lines.append(f"    sni: \"{clash_config['sni']}\"")
        
        if 'flow' in clash_config:
            clash_lines.append(f"    flow: \"{clash_config['flow']}\"")
        
        if 'ws-opts' in clash_config:
            clash_lines.append(f"    ws-opts:")
            ws = clash_config['ws-opts']
            if 'path' in ws:
                clash_lines.append(f"      path: \"{ws['path']}\"")
            if 'headers' in ws and 'Host' in ws['headers']:
                clash_lines.append(f"      headers:")
                clash_lines.append(f"        Host: \"{ws['headers']['Host']}\"")
        
        clash_lines.append("")
    
    with open(config.clash_file, 'w', encoding='utf-8') as f:
        f.write("proxies:\n")
        for line in clash_lines:
            f.write(f"{line}\n")
    
    # Подсчитываем реальное количество прокси (строки с "  - name:")
    proxies_count = len([l for l in clash_lines if l.startswith('  - name:')])
    
    print(f"\n=== FINAL STATISTICS ===")
    print(f"all_proxies.yaml: {len(read_yaml_proxies(config.all_proxies_file))}")
    print(f"ping.yaml: {len(read_yaml_proxies(config.ping_file))}")
    print(f"traff.yaml: {len(read_yaml_proxies(config.traff_file))}")
    print(f"clash.yaml: {proxies_count} TOP {config.top_count}")
    
    # Вывод статистики по доменам
    if domain_count > 0:
        print(f"\n=== DNS RESOLUTION STATS ===")
        print(f"Domains processed: {domain_count}")
        print(f"Successfully resolved: {resolved_count} ({resolved_count/domain_count*100:.1f}%)")
    
    return clash_lines


def save_source_stats(config: Config, source_stats: Dict[str, SourceStats]):
    """Сохранить статистику по источникам в файл"""
    print("\n" + "="*60)
    print("📊 СОХРАНЕНИЕ СТАТИСТИКИ ПО ИСТОЧНИКАМ")
    print("="*60)
    
    with open(config.stats_file, 'w', encoding='utf-8') as f:
        f.write("="*60 + "\n")
        f.write("📊 СТАТИСТИКА ПО ИСТОЧНИКАМ ПРОКСИ\n")
        f.write("="*60 + "\n\n")
        f.write(f"Дата: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        # Сортируем по количеству прошедших трафик (от лучших к худшим)
        sorted_sources = sorted(
            source_stats.items(),
            key=lambda x: (x[1].traffic_passed, x[1].ping_passed),
            reverse=True
        )
        
        for source_url, stats in sorted_sources:
            if stats.total_proxies > 0:
                f.write(stats.to_string())
                f.write("-"*40 + "\n")
        
        # Общая статистика
        total_proxies = sum(s.total_proxies for s in source_stats.values())
        total_ping = sum(s.ping_passed for s in source_stats.values())
        total_traffic = sum(s.traffic_passed for s in source_stats.values())
        
        f.write("\n" + "="*60 + "\n")
        f.write("📈 ОБЩАЯ СТАТИСТИКА\n")
        f.write("="*60 + "\n")
        f.write(f"Всего прокси: {total_proxies}\n")
        f.write(f"✅ Прошли ping: {total_ping} ({total_ping/total_proxies*100:.1f}%)\n")
        f.write(f"🚀 Прошли трафик: {total_traffic}\n")
    
    print(f"✅ Статистика сохранена в {config.stats_file}")


# ============================================================================
# MAIN
# ============================================================================

def main():
    """Главная функция"""
    print("\n" + "="*60)
    print("🚀 VLESS PROXY COLLECTOR")
    print("="*60)
    
    config = Config()
    
    all_proxies, source_stats, url_to_source = step1_collect(config)
    step2_ping_test(config, source_stats, url_to_source)
    step3_traffic_test(config, source_stats, url_to_source)
    step4_generate_clash(config)
    save_source_stats(config, source_stats)
    
    print("\n" + "="*60)
    print("✅ ALL DONE!")
    print("="*60)


if __name__ == "__main__":
    main()
