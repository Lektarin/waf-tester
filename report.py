# report.py
"""
Генерация отчётов о результатах тестирования
"""

import json
from datetime import datetime


def print_console_report(stats):
    """
    Вывести красивый отчёт в консоль
    
    Args:
        stats (Dict): Статистика тестирования
    """
    total_sent = stats['total_sent']
    total_blocked = stats['total_blocked']
    total_missed = stats['total_missed']
    detection_rate = stats['detection_rate']
    
    # Определение цвета в зависимости от результата
    if detection_rate >= 90:
        rating = "✓ ОТЛИЧНО"
    elif detection_rate >= 70:
        rating = "⚠ ХОРОШО"
    elif detection_rate >= 50:
        rating = "⚠ УДОВЛЕТВОРИТЕЛЬНО"
    else:
        rating = "✗ КРИТИЧНО"
    
    print("\n" + "="*50)
    print("  WAF ModSecurity Test Report")
    print("="*50)
    
    print(f"\n📊 ОБЩАЯ СТАТИСТИКА:")
    print(f"├─ Всего отправлено: {total_sent} запросов")
    print(f"├─ Всего заблокировано: {total_blocked} запросов ({detection_rate:.1f}%)")
    print(f"├─ Пропущено: {total_missed} запросов ({100-detection_rate:.1f}%)")
    print(f"└─ Оценка: {rating}")
    
    print(f"\n📈 СТАТИСТИКА ПО ТИПАМ АТАК:")
    for attack_type, stats_type in stats['stats_by_type'].items():
        sent = stats_type['sent']
        blocked = stats_type['blocked']
        missed = stats_type['missed']
        rate = stats_type['detection_rate']
        
        if missed == 0:
            status = "✓"
        elif missed == 1:
            status = "⚠"
        else:
            status = "✗"
        
        print(f"├─ {attack_type.upper().replace('_', ' ')}:")
        print(f"│  ├─ Отправлено: {sent}")
        print(f"│  ├─ Заблокировано: {blocked} ({rate:.1f}%)")
        print(f"│  └─ {status} Пропущено: {missed}")
    
    # Топ правил
    top_rules = stats['top_rules']
    if top_rules:
        print(f"\n🎯 ТОП СРАБАТЫВАЕМЫХ ПРАВИЛ (максимум 10):")
        for idx, (rule_id, count) in enumerate(top_rules, 1):
            print(f"{idx:2d}. Rule {rule_id}: {count} срабатываний")
    
    # Пропущенные атаки
    missed_attacks = stats['missed_attacks']
    if missed_attacks:
        print(f"\n⚠ ПРОПУЩЕННЫЕ АТАКИ ({len(missed_attacks)} штук):")
        for idx, attack in enumerate(missed_attacks[:5], 1):
            print(f"{idx}. Тип: {attack.attack_type}")
            print(f"   Payload: {attack.payload[:60]}...")
            print(f"   Endpoint: {attack.endpoint}")
    
    # Время выполнения
    exec_time = stats.get('execution_time', 0)
    print(f"\n⏱ Время выполнения: {exec_time:.2f} сек")
    
    print("="*50 + "\n")


def save_report_json(stats, filename):
    """
    Сохранить отчёт в JSON формат
    
    Args:
        stats (Dict): Статистика
        filename (str): Имя файла
    """
    report = {
        "timestamp": datetime.now().isoformat(),
        "summary": {
            "total_payloads": stats['total_sent'],
            "total_blocked": stats['total_blocked'],
            "total_missed": stats['total_missed'],
            "detection_rate": round(stats['detection_rate'], 2)
        },
        "by_attack_type": stats['stats_by_type'],
        "top_rules": [
            {
                "rule_id": rule_id,
                "count": count
            }
            for rule_id, count in stats['top_rules']
        ],
        "missed_attacks": [
            {
                "type": attack.attack_type,
                "payload": attack.payload,
                "endpoint": attack.endpoint
            }
            for attack in stats['missed_attacks']
        ]
    }
    
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    
    print(f"[✓] JSON отчёт сохранён: {filename}")


def save_report_text(stats, filename):
    """
    Сохранить отчёт в текстовый формат
    
    Args:
        stats (Dict): Статистика
        filename (str): Имя файла
    """
    with open(filename, 'w', encoding='utf-8') as f:
        f.write("="*60 + "\n")
        f.write("WAF ModSecurity Test Report\n")
        f.write("="*60 + "\n\n")
        
        f.write(f"Дата: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        # Общая статистика
        f.write("ОБЩАЯ СТАТИСТИКА:\n")
        f.write(f"├─ Всего отправлено: {stats['total_sent']} запросов\n")
        f.write(f"├─ Всего заблокировано: {stats['total_blocked']} запросов ({stats['detection_rate']:.1f}%)\n")
        f.write(f"├─ Пропущено: {stats['total_missed']} запросов ({100-stats['detection_rate']:.1f}%)\n")
        f.write(f"└─ Время выполнения: {stats.get('execution_time', 0):.2f} сек\n\n")
        
        # По типам атак
        f.write("СТАТИСТИКА ПО ТИПАМ АТАК:\n")
        for attack_type, type_stats in stats['stats_by_type'].items():
            f.write(f"├─ {attack_type.upper().replace('_', ' ')}:\n")
            f.write(f"│  ├─ Отправлено: {type_stats['sent']}\n")
            f.write(f"│  ├─ Заблокировано: {type_stats['blocked']} ({type_stats['detection_rate']:.1f}%)\n")
            f.write(f"│  └─ Пропущено: {type_stats['missed']}\n")
        
        # Топ правил
        f.write("\nТОП ПРАВИЛ:\n")
        for idx, (rule_id, count) in enumerate(stats['top_rules'], 1):
            f.write(f"{idx:2d}. Rule {rule_id}: {count} срабатываний\n")
        
        # Пропущенные
        if stats['missed_attacks']:
            f.write(f"\nПРОПУЩЕННЫЕ АТАКИ ({len(stats['missed_attacks'])} штук):\n")
            for idx, attack in enumerate(stats['missed_attacks'][:10], 1):
                f.write(f"{idx}. {attack.attack_type}: {attack.payload}\n")
    
    print(f"[✓] Текстовый отчёт сохранён: {filename}")

