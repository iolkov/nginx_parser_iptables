import re
import datetime
import subprocess

# местонахождение лога nginx
logFile = "/var/log/nginx/access.log"

# регулярное выражение для лога nginx
pattern = r'(\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}) - - \[(\d{2}/\w+/\d{4}:\d{2}:\d{2}:\d{2}) \+\d{4}\] ".+" \d{3} \d+ "-" ".+"$'

# для анализа за 2 мин
ipCountsTwoMin = {} # количество попаданий ip
ipCountsTwoMinTrue = {} # заблокированные ip
# для анализа за 10 мин
ipCountsTenMin = {} # количество попаданий ip
ipCountsTenMinTrue = {} # попавшие ip что не разблокируем

# ip которые разблокируем
iptablesDropIp ={}

# читаем файл logFile
with open(logFile, "r") as file:
    content = file.readlines()

# применяем регулярку к содержимому файла
for line in content:
    matches = re.findall(pattern, line)
    
    # ищем совпадения
    if matches:
        ip = matches[0][0]
        timeStr = matches[0][1]
        
        time = datetime.datetime.strptime(timeStr, "%d/%b/%Y:%H:%M:%S")  # Преобразование строки
        currentTime = datetime.datetime.now()
        timeDifference = currentTime - time

        # Совпадения за 2 мин
        if timeDifference.total_seconds() <= 120:
            if ip in ipCountsTwoMin:
                ipCountsTwoMin[ip] += 1
            else:
                ipCountsTwoMin[ip] = 1
            # блокировка ip попавшие более 10 раз
            for ip, count in ipCountsTwoMin.items():
                if count > 10 and ip not in ipCountsTwoMinTrue:
                    command = ' '.join(['iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'])
                    subprocess.run(command, shell=True)
                    ipCountsTwoMinTrue[ip] = True # добавить в список заблокированных
        
        # совпадений за 10 мин
        if timeDifference.total_seconds() <= 600:
            if ip in ipCountsTenMin:
                ipCountsTenMin[ip] += 1
            else:
                ipCountsTenMin[ip] = 1
            # список ip которые не разблокируем
            for ip, count in ipCountsTenMin.items():
                if count > 1 and ip not in ipCountsTenMinTrue:
                    ipCountsTenMinTrue[ip] = True  # добавить в список ip от которых есть запросы

# Заблокированные ip в iptables
listDropIpCommand = ' '.join(['iptables', '-L', 'INPUT', '-n', '|', 'awk', '\'/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/ {print $4}\''])
listDropIp = subprocess.run(listDropIpCommand, shell=True, capture_output=True, text=True).stdout.strip()

# Переносим ip в массив
if listDropIp:
    iptablesDropIp = {ip: True for ip in listDropIp.split("\n")}

# Разблокировка
for ip in iptablesDropIp:
    if ip not in ipCountsTenMinTrue:
        command = ' '.join(['iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP'])
        subprocess.run(command, shell=True)