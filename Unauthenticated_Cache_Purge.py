import concurrent.futures
import requests

MAX_THREADS = 10

# ANSI escape code for red color
RED = '\033[91m'
# ANSI escape code to reset color
RESET = '\033[0m'

def check_vulnerability(domain):
    url = f"https://{domain.strip()}"
    print("Testing ",url)
    response = requests.request("PURGE", url)
    if response.status_code == 200 and "status" in response.json() and response.json()["status"] == "ok":
        print(f"{RED}{url} is vulnerable{RESET}")

def main():
    domains_file = input("Please enter the file containing the list of domains: ")
    with open(domains_file, "r") as file:
        domains = file.readlines()

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        executor.map(check_vulnerability, domains)

if __name__ == "__main__":
    main()
