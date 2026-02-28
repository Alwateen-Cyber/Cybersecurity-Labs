import re
from collections import Counter

def analyze_log(file_path):
    failed_logins = []
    
    with open(file_path, 'r') as file:
        for line in file:
            if "Failed password" in line:
                ip = re.findall(r'[0-9]+(?:\.[0-9]+){3}', line)
                if ip:
                    failed_logins.append(ip[0])

    counter = Counter(failed_logins)
    
    print("Suspicious IP addresses:")
    for ip, count in counter.items():
        if count > 3:
            print(f"{ip} - {count} failed attempts")

if __name__ == "__main__":
    analyze_log("sample.log")
