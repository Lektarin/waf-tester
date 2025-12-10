# config.py
"""
Конфигурация системы тестирования WAF ModSecurity
"""

# Целевой сервер
TARGET_URL = "http://192.168.1.25"
NGINX_LOG_FILE = "/var/log/modsecurity/modsec_audit.log"

# Параметры тестирования
CONCURRENT_REQUESTS = 5
REQUEST_TIMEOUT = 10
DELAY_BETWEEN_REQUESTS = 0.1

# Типы атак для тестирования
ATTACK_TYPES = [
    "sql_injection",
    "xss",
    "command_injection",
    "path_traversal"
]

# Пути для тестирования
TEST_ENDPOINTS = [
    "/",
    "/api/data",
    "/login"
]

# Вывод и логирование
VERBOSE = True
SAVE_RESULTS = True
RESULTS_FILE = "waf_test_report.json"
RESULTS_TEXT_FILE = "waf_test_report.txt"

