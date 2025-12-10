# waf_tester.py
"""
Главный класс системы тестирования WAF
"""

import requests
import json
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
import re

from payloads import get_all_payloads
import config


class TestResult:
    """Результат тестирования одного payload"""
    
    def __init__(self, request_id, attack_type, payload, endpoint):
        self.request_id = request_id
        self.attack_type = attack_type
        self.payload = payload
        self.endpoint = endpoint
        self.was_blocked = False
        self.blocked_by_rules = []
        self.status_code = None
        self.response_time = 0
        self.sent_time = None


class WAFTester:
    """Главный класс системы тестирования WAF"""
    
    def __init__(self, target_url=None, log_file=None):
        """
        Инициализация системы тестирования
        
        Args:
            target_url (str): URL целевого сервера
            log_file (str): Путь к логу ModSecurity
        """
        self.target_url = target_url or config.TARGET_URL
        self.log_file = log_file or config.NGINX_LOG_FILE
        self.test_results = []
        self.start_time = None
        self.end_time = None
        
        print(f"[*] Инициализация WAF Tester")
        print(f"    Целевой сервер: {self.target_url}")
        print(f"    Лог файл: {self.log_file}")
    
    def check_connection(self):
        """
        Проверить доступность целевого сервера
        
        Returns:
            bool: True если сервер доступен, False иначе
        """
        try:
            response = requests.get(
                self.target_url,
                timeout=config.REQUEST_TIMEOUT,
                verify=False
            )
            print(f"[✓] Соединение успешно (статус: {response.status_code})")
            return True
        except Exception as e:
            print(f"[✗] Ошибка соединения: {str(e)}")
            return False
    
    def send_payload(self, payload_dict):
        """
        Отправить один payload запрос
        
        Args:
            payload_dict (Dict): Словарь с информацией о payload
        
        Returns:
            TestResult: Результат отправки
        """
        result = TestResult(
            payload_dict["id"],
            payload_dict["attack_type"],
            payload_dict["payload"],
            payload_dict["endpoint"]
        )
        
        try:
            # Формирование полного URL
            full_url = self.target_url + payload_dict["endpoint"]
            
            # Добавление параметра с payload
            params = {payload_dict["parameter"]: payload_dict["payload"]}
            
            start_time = time.time()
            
            # Отправка GET запроса
            response = requests.get(
                full_url,
                params=params,
                timeout=config.REQUEST_TIMEOUT,
                verify=False,
                allow_redirects=False
            )
            
            response_time = time.time() - start_time
            result.sent_time = datetime.now()
            result.status_code = response.status_code
            result.response_time = response_time
            
            # Статусы, указывающие на блокировку
            if response.status_code in [403, 406, 418]:
                result.was_blocked = True
        
        except requests.exceptions.Timeout:
            result.status_code = "TIMEOUT"
        except requests.exceptions.ConnectionError:
            result.status_code = "CONNECTION_ERROR"
        except Exception as e:
            result.status_code = f"ERROR: {str(e)}"
        
        return result
    
    def send_all_payloads(self):
        """
        Отправить все payload параллельно
        """
        payloads = get_all_payloads()
        print(f"\n[*] Отправка {len(payloads)} тестовых запросов...")
        
        self.start_time = datetime.now()
        
        # Параллельная отправка
        with ThreadPoolExecutor(max_workers=config.CONCURRENT_REQUESTS) as executor:
            futures = {
                executor.submit(self.send_payload, payload): payload 
                for payload in payloads
            }
            
            completed = 0
            for future in as_completed(futures):
                result = future.result()
                self.test_results.append(result)
                completed += 1
                
                # Простой прогресс-бар
                percent = (completed / len(payloads)) * 100
                print(f"\r[*] Прогресс: {completed}/{len(payloads)} ({percent:.1f}%)", 
                      end="", flush=True)
                
                time.sleep(config.DELAY_BETWEEN_REQUESTS)
        
        print(f"\n[✓] Все запросы отправлены")
        self.end_time = datetime.now()
    
    def check_logs(self):
        """
        Прочитать логи ModSecurity и определить блокировки
        """
        print(f"\n[*] Проверка логов ModSecurity...")
        
        if not Path(self.log_file).exists():
            print(f"[!] Файл логов не найден: {self.log_file}")
            return
        
        try:
            with open(self.log_file, 'r', encoding='utf-8', errors='ignore') as f:
                log_content = f.read()
            
            # Парсинг JSON логов (ModSecurity пишет одну запись на строку)
            log_lines = log_content.strip().split('\n')
            blocks = []
            
            for line in log_lines:
                if not line.strip():
                    continue
                try:
                    log_entry = json.loads(line)
                    blocks.append(log_entry)
                except json.JSONDecodeError:
                    continue
            
            print(f"[✓] Прочитано {len(blocks)} записей блокировки")
            
            # Соотнесение с test_results
            self._match_blocks_to_results(blocks)
        
        except Exception as e:
            print(f"[!] Ошибка при чтении логов: {str(e)}")
    
    def _match_blocks_to_results(self, blocks):
        """
        Соотнести блокировки в логах с отправленными payload
        
        Args:
            blocks (List[Dict]): Список записей из логов
        """
        for block in blocks:
            try:
                # Извлечение информации из лога
                if 'transaction' not in block:
                    continue
                
                transaction = block['transaction']
                request_uri = transaction.get('request', {}).get('uri', '')
                timestamp_str = transaction.get('timestamp', '')
                
                # Проверка времени блокировки
                if self.start_time:
                    try:
                        block_time = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                        if block_time < self.start_time:
                            continue
                    except:
                        pass
                
                # Поиск соответствующего payload в результатах
                for result in self.test_results:
                    # Простое соотнесение по содержимому payload в URI
                    if result.payload in request_uri:
                        result.was_blocked = True
                        
                        # Извлечение информации о правилах
                        if 'messages' in transaction:
                            for message in transaction['messages']:
                                if 'details' in message:
                                    rule_id = str(message['details'].get('ruleId', 'unknown'))
                                    if rule_id not in result.blocked_by_rules:
                                        result.blocked_by_rules.append(rule_id)
            
            except Exception as e:
                continue
    
    def get_statistics(self):
        """
        Получить статистику тестирования
        
        Returns:
            Dict: Словарь со статистикой
        """
        total_sent = len(self.test_results)
        total_blocked = sum(1 for r in self.test_results if r.was_blocked)
        total_missed = total_sent - total_blocked
        
        # Статистика по типам атак
        stats_by_type = {}
        for attack_type in config.ATTACK_TYPES:
            type_results = [r for r in self.test_results if r.attack_type == attack_type]
            type_blocked = sum(1 for r in type_results if r.was_blocked)
            
            stats_by_type[attack_type] = {
                "sent": len(type_results),
                "blocked": type_blocked,
                "missed": len(type_results) - type_blocked,
                "detection_rate": (type_blocked / len(type_results) * 100) if type_results else 0
            }
        
        # Статистика по правилам
        rule_stats = {}
        for result in self.test_results:
            for rule_id in result.blocked_by_rules:
                if rule_id not in rule_stats:
                    rule_stats[rule_id] = 0
                rule_stats[rule_id] += 1
        
        # Топ правил
        top_rules = sorted(
            rule_stats.items(),
            key=lambda x: x[1],
            reverse=True
        )[:10]
        
        # Пропущенные атаки
        missed_attacks = [r for r in self.test_results if not r.was_blocked]
        
        return {
            "total_sent": total_sent,
            "total_blocked": total_blocked,
            "total_missed": total_missed,
            "detection_rate": (total_blocked / total_sent * 100) if total_sent else 0,
            "stats_by_type": stats_by_type,
            "rule_stats": rule_stats,
            "top_rules": top_rules,
            "missed_attacks": missed_attacks,
            "execution_time": (self.end_time - self.start_time).total_seconds() if self.start_time and self.end_time else 0
        }
    
    def run_full_test(self):
        """
        Запустить полный цикл тестирования
        """
        # Проверка соединения
        if not self.check_connection():
            return False
        
        # Отправка всех payload
        self.send_all_payloads()
        
        # Небольшая задержка для логирования
        print("[*] Ожидание логирования (2 сек)...")
        time.sleep(2)
        
        # Проверка логов
        self.check_logs()
        
        return True

