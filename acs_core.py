#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import json
import hashlib
import random
import time
import re
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional, Set
import subprocess
import requests
from urllib.parse import urlparse

# ===================== КОНФИГУРАЦИЯ =====================
CONFIG = {
    "github_token": os.environ.get("GITHUB_TOKEN", ""),
    "target_repo": "server-collector",
    "servers_dir": "collected_servers",
    "history_dir": "history",
    "reports_dir": "reports",
    "max_repos_to_scan": 50,
    "min_repos_to_pick": 3,
    "max_repos_to_pick": 8,
    "max_folder_depth": 4,
    "update_interval_hours": 2,
    "file_size_limit_mb": 5,
    "search_keywords": [
        "server config", "nginx config", "apache config", "docker-compose",
        "kubernetes config", "ansible inventory", "terraform variables",
        "prometheus config", "grafana config", "database connection",
        "redis config", "postgresql config", "mysql config", "ssh config",
        "vpn config", "wireguard config", "openvpn config", "firewall rules",
        "load balancer config", "proxy config", "api gateway config",
        "microservices config", "deployment config", "environment variables",
        ".env production", "config.json", "settings.yaml", "application.conf",
        "server.properties", "application.yml", "bootstrap.yml",
        "dockerfile", "docker-compose.yml", "k8s deployment",
        "helm values", "saltstack config", "puppet manifest",
        "chef recipe", "cloudformation template", "arm template",
        "pulumi config", "crossplane config", "consul config",
        "etcd config", "zookeeper config", "kafka config",
        "rabbitmq config", "mongodb config", "elasticsearch config",
        "logstash config", "kibana config", "jenkins config",
        "gitlab-ci.yml", "github workflow", "azure pipeline",
        "terraform.tfvars", "variables.tf", "main.tf", "outputs.tf"
    ],
    "allowed_extensions": {
        ".json", ".yaml", ".yml", ".conf", ".cfg", ".ini", ".toml",
        ".properties", ".env", ".tf", ".tfvars", ".hcl", ".nomad",
        ".dockerfile", ".xml", ".cnf", ".cnf", ".key", ".crt", ".pem"
    },
    "excluded_paths": {
        "node_modules", "__pycache__", ".git", "venv", "env",
        "dist", "build", "target", "out", "bin", "obj", "lib",
        "logs", "tmp", "temp", "cache", "backup", "archive"
    }
}

# ===================== БАЗОВЫЙ КЛАСС =====================
class ServerCollector:
    """Основной сборщик серверных конфигураций"""
    
    def __init__(self, config: Dict = None):
        self.config = config or CONFIG
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"token {self.config['github_token']}",
            "Accept": "application/vnd.github.v3+json"
        })
        self.setup_directories()
        self.history_cache = {}
        self.load_history_cache()
        
    def setup_directories(self):
        """Создаёт все необходимые директории"""
        for dir_name in [self.config['servers_dir'], 
                        self.config['history_dir'],
                        self.config['reports_dir']]:
            Path(dir_name).mkdir(exist_ok=True)
            
    def load_history_cache(self):
        """Загружает историю файлов в кэш"""
        history_path = Path(self.config['history_dir'])
        for file_path in history_path.glob("*.json"):
            try:
                with open(file_path, 'r') as f:
                    data = json.load(f)
                    key = file_path.stem
                    self.history_cache[key] = data
            except Exception as e:
                print(f"Ошибка загрузки истории {file_path}: {e}")

# ===================== ПОИСК РЕПОЗИТОРИЕВ =====================
    def search_github_repos(self, keyword: str, max_results: int = 30) -> List[Dict]:
        """Поиск репозиториев на GitHub по ключевому слову"""
        url = "https://api.github.com/search/repositories"
        params = {
            "q": keyword,
            "sort": "updated",
            "order": "desc",
            "per_page": min(max_results, 100)
        }
        
        try:
            response = self.session.get(url, params=params)
            if response.status_code == 200:
                data = response.json()
                repos = []
                for item in data.get('items', []):
                    repos.append({
                        "full_name": item['full_name'],
                        "url": item['html_url'],
                        "description": item.get('description', ''),
                        "stars": item.get('stargazers_count', 0),
                        "updated_at": item.get('updated_at', ''),
                        "default_branch": item.get('default_branch', 'main')
                    })
                return repos
            else:
                print(f"Ошибка поиска '{keyword}': {response.status_code}")
                return []
        except Exception as e:
            print(f"Исключение при поиске: {e}")
            return []

    def gather_all_repositories(self) -> List[Dict]:
        """Сбор всех уникальных репозиториев по всем ключевым словам"""
        all_repos = {}
        keywords = self.config['search_keywords']
        
        for keyword in keywords:
            print(f"🔍 Поиск по: {keyword}")
            repos = self.search_github_repos(keyword, max_results=20)
            for repo in repos:
                key = repo['full_name']
                if key not in all_repos or repo['stars'] > all_repos[key]['stars']:
                    all_repos[key] = repo
            time.sleep(0.5)  # Защита от rate limiting
        
        repos_list = list(all_repos.values())
        print(f"📊 Найдено уникальных репозиториев: {len(repos_list)}")
        return repos_list

# ===================== АНАЛИЗ РЕПОЗИТОРИЯ =====================
    def get_repository_contents(self, repo_full_name: str, path: str = "", depth: int = 0) -> List[Dict]:
        """Рекурсивное получение содержимого репозитория"""
        if depth > self.config['max_folder_depth']:
            return []
        
        url = f"https://api.github.com/repos/{repo_full_name}/contents/{path}"
        
        try:
            response = self.session.get(url)
            if response.status_code != 200:
                return []
            
            items = response.json()
            if not isinstance(items, list):
                return []
            
            files = []
            for item in items:
                if item['type'] == 'file':
                    file_info = self.analyze_file(item, repo_full_name)
                    if file_info:
                        files.append(file_info)
                elif item['type'] == 'dir':
                    dir_name = item['name']
                    if dir_name not in self.config['excluded_paths']:
                        sub_files = self.get_repository_contents(
                            repo_full_name, 
                            item['path'], 
                            depth + 1
                        )
                        files.extend(sub_files)
            
            return files
            
        except Exception as e:
            print(f"⚠️ Ошибка чтения {repo_full_name}/{path}: {e}")
            return []

    def analyze_file(self, file_item: Dict, repo_full_name: str) -> Optional[Dict]:
        """Анализ файла на предмет серверной конфигурации"""
        file_name = file_item['name']
        file_path = file_item['path']
        file_extension = Path(file_name).suffix.lower()
        
        # Проверка расширения
        if file_extension not in self.config['allowed_extensions']:
            return None
        
        # Проверка размера
        if file_item.get('size', 0) > self.config['file_size_limit_mb'] * 1024 * 1024:
            return None
        
        return {
            "name": file_name,
            "path": file_path,
            "download_url": file_item['download_url'],
            "repo": repo_full_name,
            "size": file_item.get('size', 0)
        }

# ===================== СКАЧИВАНИЕ И ОБРАБОТКА =====================
    def fetch_file_content(self, file_info: Dict) -> Optional[Dict]:
        """Скачивание содержимого файла"""
        try:
            response = self.session.get(file_info['download_url'])
            if response.status_code == 200:
                content = response.text
                content_hash = hashlib.sha256(content.encode('utf-8')).hexdigest()
                
                return {
                    "name": file_info['name'],
                    "path": file_info['path'],
                    "repo": file_info['repo'],
                    "content": content,
                    "hash": content_hash,
                    "size": len(content.encode('utf-8'))
                }
            else:
                return None
        except Exception as e:
            print(f"⚠️ Ошибка скачивания {file_info['repo']}/{file_info['path']}: {e}")
            return None

    def extract_server_info(self, content: str) -> Dict:
        """Извлечение информации о серверах из контента"""
        server_info = {
            "ip_addresses": [],
            "domains": [],
            "ports": [],
            "usernames": [],
            "passwords": [],
            "api_keys": [],
            "database_urls": [],
            "endpoints": []
        }
        
        # IP-адреса
        ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        server_info["ip_addresses"] = re.findall(ip_pattern, content)
        
        # Домены
        domain_pattern = r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}'
        server_info["domains"] = list(set(re.findall(domain_pattern, content)))
        
        # Порты
        port_pattern = r'\b(?:[1-9][0-9]{0,4}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])\b'
        found_ports = re.findall(port_pattern, content)
        server_info["ports"] = [int(p) for p in found_ports if 1 <= int(p) <= 65535]
        
        # Пароли и ключи (простые паттерны)
        password_patterns = [
            r'(?:password|pass|pwd)\s*[:=]\s*([^\s"\']+)',
            r'(?:secret|token|key)\s*[:=]\s*([^\s"\']+)',
            r'[A-Za-z0-9+/]{40,}={0,2}'  # base64 похожее
        ]
        for pattern in password_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            server_info["passwords"].extend(matches)
        
        # Database URLs
        db_pattern = r'(?:postgres|mysql|mongodb|redis|elasticsearch|kafka)://[^\s"\']+'
        server_info["database_urls"] = re.findall(db_pattern, content, re.IGNORECASE)
        
        return server_info

# ===================== УПРАВЛЕНИЕ ИСТОРИЕЙ =====================
    def save_to_history(self, file_data: Dict, server_info: Dict):
        """Сохранение файла в историю"""
        history_key = f"{file_data['repo'].replace('/', '_')}_{file_data['path'].replace('/', '_')}"
        history_path = Path(self.config['history_dir']) / f"{history_key}.json"
        
        history_entry = {
            "hash": file_data['hash'],
            "timestamp": datetime.now().isoformat(),
            "path": file_data['path'],
            "repo": file_data['repo'],
            "size": file_data['size'],
            "server_info": server_info,
            "content_preview": file_data['content'][:500]  # Только для сравнения
        }
        
        with open(history_path, 'w', encoding='utf-8') as f:
            json.dump(history_entry, f, indent=2, ensure_ascii=False)
        
        self.history_cache[history_key] = history_entry

    def compare_with_history(self, file_data: Dict) -> Dict:
        """Сравнение с предыдущей версией файла"""
        history_key = f"{file_data['repo'].replace('/', '_')}_{file_data['path'].replace('/', '_')}"
        
        if history_key not in self.history_cache:
            return {
                "status": "NEW",
                "message": "Новый файл обнаружен",
                "hash": file_data['hash']
            }
        
        old_entry = self.history_cache[history_key]
        old_hash = old_entry.get('hash')
        
        if old_hash == file_data['hash']:
            return {
                "status": "UNCHANGED",
                "message": "Файл не изменился",
                "hash": file_data['hash']
            }
        else:
            return {
                "status": "MODIFIED",
                "message": f"Файл изменён (хэш: {old_hash[:8]} → {file_data['hash'][:8]})",
                "old_hash": old_hash,
                "new_hash": file_data['hash']
            }

# ===================== СОХРАНЕНИЕ РЕЗУЛЬТАТОВ =====================
    def save_server_file(self, file_data: Dict, comparison: Dict, server_info: Dict):
        """Сохранение серверного файла"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        status = comparison['status']
        
        # Формируем безопасное имя файла
        safe_repo = file_data['repo'].replace('/', '_')
        safe_path = file_data['path'].replace('/', '_')
        file_name = f"{timestamp}_{status}_{safe_repo}_{safe_path}"
        
        # Сохраняем содержимое
        file_path = Path(self.config['servers_dir']) / file_name
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(file_data['content'])
        
        # Сохраняем метаданные
        metadata_path = Path(self.config['servers_dir']) / f"{file_name}.meta"
        metadata = {
            "file_name": file_name,
            "timestamp": timestamp,
            "status": status,
            "repo": file_data['repo'],
            "path": file_data['path'],
            "hash": file_data['hash'],
            "size": file_data['size'],
            "comparison": comparison,
            "server_info": server_info,
            "has_sensitive_data": bool(server_info['passwords'] or server_info['api_keys'])
        }
        
        with open(metadata_path, 'w', encoding='utf-8') as f:
            json.dump(metadata, f, indent=2, ensure_ascii=False)
        
        return file_path, metadata_path

# ===================== ГЕНЕРАЦИЯ ОТЧЁТОВ =====================
    def generate_report(self, results: List[Dict]) -> str:
        """Генерация отчёта о работе"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_lines = []
        
        report_lines.append("=" * 80)
        report_lines.append(f"ОТЧЁТ СИСТЕМЫ ACS")
        report_lines.append(f"Время: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report_lines.append("=" * 80)
        report_lines.append("")
        
        # Статистика
        total_files = len(results)
        new_files = sum(1 for r in results if r['status'] == 'NEW')
        modified_files = sum(1 for r in results if r['status'] == 'MODIFIED')
        unchanged_files = sum(1 for r in results if r['status'] == 'UNCHANGED')
        
        report_lines.append("📊 СТАТИСТИКА:")
        report_lines.append(f"  Всего файлов: {total_files}")
        report_lines.append(f"  Новых: {new_files}")
        report_lines.append(f"  Изменённых: {modified_files}")
        report_lines.append(f"  Без изменений: {unchanged_files}")
        report_lines.append("")
        
        # Серверная информация
        all_server_info = []
        for result in results:
            if result.get('server_info'):
                all_server_info.append(result['server_info'])
        
        if all_server_info:
            report_lines.append("🖥️ ОБНАРУЖЕННЫЕ СЕРВЕРЫ:")
            for i, info in enumerate(all_server_info[:20]):  # Только первые 20
                report_lines.append(f"  Сервер {i+1}:")
                if info['ip_addresses']:
                    report_lines.append(f"    IP: {', '.join(set(info['ip_addresses'][:5]))}")
                if info['domains']:
                    report_lines.append(f"    Домены: {', '.join(set(info['domains'][:5]))}")
                if info['ports']:
                    report_lines.append(f"    Порты: {', '.join(map(str, set(info['ports'])[:10]))}")
                if info['passwords']:
                    report_lines.append(f"    ⚠️ Найдены пароли/ключи!")
                report_lines.append("")
        
        # Детали изменений
        report_lines.append("📝 ДЕТАЛИ ИЗМЕНЕНИЙ:")
        for i, result in enumerate(results):
            if result['status'] in ['NEW', 'MODIFIED']:
                report_lines.append(f"  {i+1}. [{result['status']}] {result['repo']}/{result['path']}")
                report_lines.append(f"     Хэш: {result['hash']}")
                report_lines.append("")
        
        report_lines.append("=" * 80)
        
        # Сохраняем отчёт
        report_path = Path(self.config['reports_dir']) / f"report_{timestamp}.txt"
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(report_lines))
        
        return '\n'.join(report_lines)

# ===================== ОСНОВНОЙ ПРОЦЕСС =====================
    def run(self):
        """Запуск процесса сбора"""
        print("=" * 80)
        print("🚀 ЗАПУСК СИСТЕМЫ ACS")
        print(f"⏰ Время: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 80)
        
        # Шаг 1: Поиск репозиториев
        print("\n🔍 Поиск репозиториев...")
        repositories = self.gather_all_repositories()
        
        if not repositories:
            print("❌ Репозитории не найдены")
            return
        
        # Шаг 2: Выбор случайных репозиториев
        print(f"\n🎯 Выбор репозиториев из {len(repositories)} найденных...")
        pick_count = random.randint(
            self.config['min_repos_to_pick'],
            min(self.config['max_repos_to_pick'], len(repositories))
        )
        selected_repos = random.sample(repositories, pick_count)
        
        print(f"📋 Выбрано {len(selected_repos)} репозиториев:")
        for repo in selected_repos:
            print(f"  - {repo['full_name']} (⭐ {repo['stars']})")
        
        # Шаг 3: Парсинг репозиториев
        all_files = []
        server_ips = set()
        server_domains = set()
        
        for repo in selected_repos:
            print(f"\n📁 Обработка {repo['full_name']}...")
            files = self.get_repository_contents(repo['full_name'])
            print(f"  Найдено конфигурационных файлов: {len(files)}")
            
            for file_info in files:
                file_data = self.fetch_file_content(file_info)
                if file_data:
                    # Извлечение серверной информации
                    server_info = self.extract_server_info(file_data['content'])
                    if server_info['ip_addresses'] or server_info['domains']:
                        server_ips.update(server_info['ip_addresses'])
                        server_domains.update(server_info['domains'])
                        file_data['server_info'] = server_info
                    
                    all_files.append(file_data)
                    print(f"  ✓ {file_data['path']} ({len(file_data['content'])} байт)")
            
            time.sleep(1)  # Защита от rate limiting
        
        # Шаг 4: Обработка и сохранение
        results = []
        for file_data in all_files:
            comparison = self.compare_with_history(file_data)
            server_info = file_data.get('server_info', {})
            
            if comparison['status'] in ['NEW', 'MODIFIED']:
                self.save_server_file(file_data, comparison, server_info)
                self.save_to_history(file_data, server_info)
                results.append({
                    'repo': file_data['repo'],
                    'path': file_data['path'],
                    'status': comparison['status'],
                    'hash': file_data['hash'],
                    'server_info': server_info
                })
            else:
                results.append({
                    'repo': file_data['repo'],
                    'path': file_data['path'],
                    'status': comparison['status'],
                    'hash': file_data['hash']
                })
        
        # Шаг 5: Генерация отчёта
        print("\n📊 Генерация отчёта...")
        report = self.generate_report(results)
        print(report)
        
        # Шаг 6: Git push
        self.git_push()
        
        print("\n✅ СБОРКА ЗАВЕРШЕНА")
        print(f"📁 Сохранено файлов: {len([r for r in results if r['status'] in ['NEW', 'MODIFIED']])}")
        print(f"🖥️ Найдено IP-адресов: {len(server_ips)}")
        print(f"🌐 Найдено доменов: {len(server_domains)}")

    def git_push(self):
        """Отправка изменений в Git"""
        try:
            subprocess.run(["git", "add", "."], check=True, capture_output=True)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            commit_msg = f"ACS auto-update {timestamp}"
            subprocess.run(["git", "commit", "-m", commit_msg], check=False, capture_output=True)
            subprocess.run(["git", "push"], check=True, capture_output=True)
            print("✅ Git push выполнен")
        except Exception as e:
            print(f"⚠️ Ошибка Git: {e}")

# ===================== ТОЧКА ВХОДА =====================
if __name__ == "__main__":
    collector = ServerCollector()
    collector.run()
