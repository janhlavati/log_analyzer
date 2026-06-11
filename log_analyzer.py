import csv
import re
from collections import Counter


def analyze_logs():
    #Regex to extract IP address from failed attempt
    failed_pattern = re.compile(r"Failed login attempt.*from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")
    failed_ip_counter = Counter()
    