# main.py
"""
Главный скрипт системы тестирования WAF ModSecurity
"""

import sys
from pathlib import Path

# Отключение предупреждений о сертификатах
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from waf_tester import WAFTester
from report import print_console_report, save_report_json, save_report_text
import config


def main():
    """
    Главная функция программы
    """
    print("\n╔════════════════════════════════════════════╗")
    print("║  WAF ModSecurity Test System v1.0          ║")
    print("║  Прототип для тестирования правил WAF      ║")
    print("╚════════════════════════════════════════════╝\n")
    
    # Запрос параметров у пользователя
    target_url = input(f"Введите адрес сервера (по умолчанию {config.TARGET_URL}): ").strip()
    if not target_url:
        target_url = config.TARGET_URL
    
    log_file = input(f"Введите путь к логу ModSecurity (по умолчанию {config.NGINX_LOG_FILE}): ").strip()
    if not log_file:
        log_file = config.NGINX_LOG_FILE
    
    # Создание и запуск тестера
    print()
    tester = WAFTester(target_url, log_file)
    
    # Запуск полного теста
    if tester.run_full_test():
        # Получение статистики
        stats = tester.get_statistics()
        
        # Вывод отчёта в консоль
        print_console_report(stats)
        
        # Сохранение отчётов
        if config.SAVE_RESULTS:
            save_report_json(stats, config.RESULTS_FILE)
            save_report_text(stats, config.RESULTS_TEXT_FILE)
        
        print("[✓] Тестирование завершено успешно!")
        return 0
    else:
        print("[✗] Тестирование завершено с ошибкой!")
        return 1


if __name__ == "__main__":
    sys.exit(main())

