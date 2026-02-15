#!/bin/bash

# 1. Создаем временный Python-скрипт для обработки файлов
# Мы используем Python, так как sed/awk плохо справляются с вложенными скобками { }
cat << 'EOF' > .update_dts.py
import sys
import re
import os

# Новая разметка разделов
NEW_PARTITIONS = """\tpartitions {
\t\tcompatible = "fixed-partitions";
\t\t#address-cells = <1>;
\t\t#size-cells = <1>;

\t\tpartition@0 {
\t\t\tlabel = "BL2";
\t\t\treg = <0x0 0x100000>;
\t\t\tread-only;
\t\t};

\t\tpartition@100000 {
\t\t\tlabel = "u-boot-env";
\t\t\treg = <0x100000 0x80000>;
\t\t};

\t\tpartition@180000 {
\t\t\tlabel = "Factory";
\t\t\treg = <0x180000 0x200000>;
\t\t\tread-only;
\t\t};

\t\tpartition@380000 {
\t\t\tlabel = "FIP";
\t\t\treg = <0x380000 0x200000>;
\t\t\tread-only;
\t\t};

\t\tpartition@580000 {
\t\t\tlabel = "ubi";
\t\t\treg = <0x580000 0x7a80000>;
\t\t};
\t};"""

def find_closing_brace(content, start_idx):
    """Находит парную закрывающую скобку для блока partitions"""
    brace_count = 0
    found_first = False
    
    for i in range(start_idx, len(content)):
        if content[i] == '{':
            brace_count += 1
            found_first = True
        elif content[i] == '}':
            brace_count -= 1
            
        if found_first and brace_count == 0:
            # Проверяем наличие точки с запятой после скобки
            if i + 1 < len(content) and content[i+1] == ';':
                return i + 2
            return i + 1
    return -1

def process_file(filepath):
    with open(filepath, 'r') as f:
        content = f.read()
    
    # Ищем начало блока partitions
    # Регулярное выражение ищет слово partitions перед открывающей скобкой
    match = re.search(r'(\t*|\s*)partitions\s*\{', content)
    if not match:
        return False
        
    start_idx = match.start()
    end_idx = find_closing_brace(content, start_idx)
    
    if end_idx == -1:
        print(f"Ошибка: Не найдена закрывающая скобка в {filepath}")
        return False
        
    print(f"Обновление файла: {filepath}")
    
    # Заменяем блок
    new_content = content[:start_idx] + NEW_PARTITIONS + content[end_idx:]
    
    # Сохраняем (сначала бэкап)
    os.rename(filepath, filepath + '.bak')
    with open(filepath, 'w') as f:
        f.write(new_content)
    return True

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Использование: script.py <file1> <file2> ...")
        sys.exit(1)
        
    for filepath in sys.argv[1:]:
        if not process_file(filepath):
            print(f"Пропущен: {filepath} (блок partitions не найден)")
EOF

# 2. Ищем файлы DTS/DTSI, содержащие 'ax2' в названии, и передаем их скрипту
echo "Поиск файлов DTS для модели ax2..."
FOUND_FILES=$(find . -type f \( -name "*ax2*.dts" -o -name "*ax2*.dtsi" \))

if [ -z "$FOUND_FILES" ]; then
    echo "Файлы *ax2*.dts или *ax2*.dtsi не найдены в текущей директории."
else
    echo "Найдено файлов: $(echo "$FOUND_FILES" | wc -l)"
    python3 .update_dts.py $FOUND_FILES
fi

# 3. Удаляем временный скрипт
rm .update_dts.py
echo "Готово."
