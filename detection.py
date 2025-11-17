import re
import tldextract
from pathlib import Path
from contextlib import redirect_stdout
from urllib.parse import urlparse
from colorama import Fore, Style, init
import argparse

init(autoreset=True)


parser = argparse.ArgumentParser(description="Phishing URL Detection Tool")
subparsers = parser.add_subparsers(dest="command", required=True)

url_parser = subparsers.add_parser("url", help="URL(s) to analyze\n")

group = url_parser.add_mutually_exclusive_group(required=True)
group.add_argument("--single", "-s", type=str, help="Analyze a single URL provided in the command line\n")
group.add_argument("--file", "-f", type=str, help="\nAnalyze multiple URLs from a file\n")

url_parser.add_argument("--add", "-a", action="store_true", help="\nAdd a URL to the verified database ONLY if site is verified as legitimate\n")
url_parser.add_argument("--export", "-e", type=str, help="\nExport COMPLETE analysis results to a specified file or creates a file and stores results\n")
url_parser.add_argument("--simple", "-eS", type=str, help="\nExport only the list of verified results to a specified file or creates a file and stores results\n")

args = parser.parse_args()



def load_url_file(file_name):
    urls = []
    base_dir = Path(__file__).parent
    user_file_location = base_dir / "data" / file_name
    with open(user_file_location, 'r', encoding="utf-8") as file:
        urls = file.read().splitlines()
        return urls



def load_database():
    base_dir = Path(__file__).parent
    db_file_location = base_dir / "data" / "verified-urls.txt"
    with open(db_file_location, 'r', encoding="utf-8") as file:
        return file.read().splitlines()

db = load_database()

def check_database(url):
    for entry in db:
        if url == entry:
            return True
    return False

def strip_features(url):

    parsed_url = urlparse(url)
    extracted_features = tldextract.extract(url)
    is_in_database = check_database(url)

    domain = extracted_features.domain
    suffix = extracted_features.suffix
    subdomain = extracted_features.subdomain.split('.') if extracted_features.subdomain else []
    netloc = parsed_url.netloc
    path = parsed_url.path
    query = parsed_url.query
    fragment = parsed_url.fragment
    scheme = parsed_url.scheme

    features = {
        "is_in_database": is_in_database,
        "url_length": len(url),
        "num_subdomains": len(subdomain),
        "secure_protocol": scheme=="https",
        "has_ip_address": bool(re.match(r'^\d{1,3}(\.\d{1,3}){3}$', netloc)),
        "num_special_chars": len(re.findall(r'[-_.@]', url)),
        "num_digits": sum(c.isdigit() for c in url),
        "suspicious_words": int(any(word in url.lower() for word in ['login', 'verify', 'update', 'free', 'click']))}
    return features


def score_url(features):
    global score
    global feedback

    score = 0
    feedback = []
    sn = features["num_subdomains"] - 3
    if features["url_length"] > 75:
        score += 1
        feedback.append("The URL is quite long. This can be a sign of phishing.")
    if features["num_subdomains"] > 3:
        score += 1
        feedback.append("The URL has {sn} more subdomains than normal. This can be a sign of phishing.")
    if not features["secure_protocol"]:
        score += 1
        feedback.append("The URL does not use HTTPS. Most legitimate sites use HTTPS.")
    if features["has_ip_address"]:
        score += 1
        feedback.append("The URL contains an IP address instead of a domain. This is common among phishing URLs.")
    if features["num_special_chars"] > 5:
        score += 1
        feedback.append("The URL contains many special characters. This can be a sign of phishing.")
    if features["num_digits"] > 10:
        score += 1
        feedback.append("The URL contains many digits. This can be a session ID, encoded values, or random digits in order to make the URL longer.")
    if features["suspicious_words"]:
        score += 2
        feedback.append("The URL contains words often used in phishing attemps. THIS IS A STRONG INDICATOR OF PHISHING.")

    return {
        "score": score,
        "feedback": feedback
    }



print("\n=== Phishing URL Detection Tool ===\n")
print("\nCreated by Joaquin Albuja - Version 1.0\n")

if args.single is not None and args.add == True:
    url = args.single
    strip_features(url)

    features = strip_features(url)
    score_url(features)

    final_score = score_url(features)
    print("\n=== Analysis Result ===\n")
    if features["is_in_database"]:
        print(Fore.GREEN + f"[LEGITIMATE] The URL '{url}' is found in our verified database.")
    else:
        print(Fore.RED + f"[SUSPICIOUS] The URL '{url}' is NOT found in our verified database.")
    if score >= 3:
        print(Fore.RED + f"[PHISHING] The URL '{url}' is likely a phishing URL. (Score: {final_score['score']})")
        print(Fore.YELLOW + "\nFeedback:")
        for tip in final_score['feedback']:
            print(Fore.YELLOW + f"- {tip}")
        
    elif score == 2:
        print(Fore.YELLOW + f"[SUSPICIOUS] The URL '{url}' is suspicious. (Score: {final_score['score']})")
        print(Fore.YELLOW + "\nFeedback:")
        for tip in final_score['feedback']:
            print(Fore.YELLOW + f"- {tip}")
    else:
        print(Fore.GREEN + f"[LEGITIMATE] The URL '{url}' appears to be legitimate. (Score: {final_score['score']})")
        if features["is_in_database"] == False:
            with open(Path(__file__).parent / "data" / "verified-urls.txt", 'a', encoding="utf-8") as db_file:
                db_file.write(url + "\n")
        else:
            print(Fore.CYAN + f"The URL '{url}' is already in the verified database, no action taken.")


elif args.single is not None:
    url = args.single
    strip_features(url)

    features = strip_features(url)
    score_url(features)

    final_score = score_url(features)
    print("\n=== Analysis Result ===\n")
    if features["is_in_database"]:
        print(Fore.GREEN + f"[LEGITIMATE] The URL '{url}' is found in our verified database.")
    else:
        print(Fore.RED + f"[SUSPICIOUS] The URL '{url}' is NOT found in our verified database.")
    if score >= 3:
        print(Fore.RED + f"[PHISHING] The URL '{url}' is likely a phishing URL. (Score: {final_score['score']})")
        print(Fore.YELLOW + "\nFeedback:")
        for tip in final_score['feedback']:
            print(Fore.YELLOW + f"- {tip}")
        
    elif score == 2:
        print(Fore.YELLOW + f"[SUSPICIOUS] The URL '{url}' is suspicious. (Score: {final_score['score']})")
        print(Fore.YELLOW + "\nFeedback:")
        for tip in final_score['feedback']:
            print(Fore.YELLOW + f"- {tip}")
    else:
        print(Fore.GREEN + f"[LEGITIMATE] The URL '{url}' appears to be legitimate. (Score: {final_score['score']})")
        
if args.file is not None and args.add == True and args.export is not None:
    file_name = args.file
    export_file = args.export

    user_urls = load_url_file(file_name)

    legitimate_urls = []
    suspicous_urls = []

    with open(Path(__file__).parent / "data" / export_file, 'a', encoding="utf-8") as ef:
        with redirect_stdout(ef):
            for url in user_urls:
        
                features = strip_features(url)
                score_url(features)

                final_score = score_url(features)
        
                print("\n[CHECKING] Analyzing URL:", url)
                if features["is_in_database"]:
                    print(Fore.GREEN + f"[LEGITIMATE] The URL '{url}' is found in our verified database.")
                else:
                    print(Fore.RED + f"[SUSPICIOUS] The URL '{url}' is NOT found in our verified database.")
                if score >= 3:
                    print(Fore.RED + f"[PHISHING] The URL '{url}' is likely a phishing URL. (Score: {final_score['score']})")
                    print(Fore.YELLOW + "Feedback:")
                    for tip in final_score['feedback']:
                        print(Fore.YELLOW + f"- {tip}")
                    suspicous_urls.append(url + "\n")
            
                elif score == 2:
                    print(Fore.YELLOW + f"[SUSPICIOUS] The URL '{url}' is suspicious. (Score: {final_score['score']})")
                    print(Fore.YELLOW + "Feedback:")
                    for tip in final_score['feedback']:
                        print(Fore.YELLOW + f"- {tip}")
                    suspicous_urls.append(url + "\n")
                else:
                    print(Fore.GREEN + f"[LEGITIMATE] The URL '{url}' appears to be legitimate. (Score: {final_score['score']})")
                    if features["is_in_database"] == False:
                        with open(Path(__file__).parent / "data" / "verified-urls.txt", 'a', encoding="utf-8") as db_file:
                            db_file.write(url + "\n")
                    else:
                        print(Fore.CYAN + f"The URL '{url}' is already in the verified database, no action taken.")
                    legitimate_urls.append(url + "\n")
    

    print("\n=== Analysis Complete - Results were sucsessfully saved in " + export_file +" ===\n")
    print("\n=== Analysis Complete ===\n")
    print(Fore.GREEN + f"Total Legitimate URLs: {len(legitimate_urls)}\n")
    print(Fore.YELLOW + f"Total Flagged URLs: {len(suspicous_urls)}\n")
    print("===================================\n")
    print("The following URLs were deemed legitimate:\n")

    for url in legitimate_urls:
        print(Fore.GREEN + url.strip())
    
        


elif args.file is not None and args.add == True:

    file_name = args.file
    user_urls = load_url_file(file_name)
    legitimate_urls = []
    suspicous_urls = []

    print("\n=== Analysis Result ===")
    for url in user_urls:
        features = strip_features(url)
        score_url(features)

        final_score = score_url(features)
        
        print("\n[CHECKING] Analyzing URL:", url)
        if features["is_in_database"]:
            print(Fore.GREEN + f"[LEGITIMATE] The URL '{url}' is found in our verified database.")
        else:
            print(Fore.RED + f"[SUSPICIOUS] The URL '{url}' is NOT found in our verified database.")
        if score >= 3:
            print(Fore.RED + f"[PHISHING] The URL '{url}' is likely a phishing URL. (Score: {final_score['score']})")
            print(Fore.YELLOW + "Feedback:")
            for tip in final_score['feedback']:
                print(Fore.YELLOW + f"- {tip}")
            suspicous_urls.append(url + "\n")
            
        elif score == 2:
            print(Fore.YELLOW + f"[SUSPICIOUS] The URL '{url}' is suspicious. (Score: {final_score['score']})")
            print(Fore.YELLOW + "Feedback:")
            for tip in final_score['feedback']:
                print(Fore.YELLOW + f"- {tip}")
            suspicous_urls.append(url + "\n")
        else:
            print(Fore.GREEN + f"[LEGITIMATE] The URL '{url}' appears to be legitimate. (Score: {final_score['score']})")
            if features["is_in_database"] == False:
                with open(Path(__file__).parent / "data" / "verified-urls.txt", 'a', encoding="utf-8") as db_file:
                    db_file.write(url + "\n")
            else:
                print(Fore.CYAN + f"The URL '{url}' is already in the verified database, no action taken.")
            legitimate_urls.append(url + "\n")
    print("\n=== Analysis Complete ===\n")
    print(Fore.GREEN + f"Total Legitimate URLs: {len(legitimate_urls)}\n")
    print(Fore.YELLOW + f"Total Flagged URLs: {len(suspicous_urls)}\n")
    print("===================================\n")
    print("The following URLs were deemed legitimate:\n")

    for url in legitimate_urls:
        print(Fore.GREEN + url.strip())


elif args.file is not None and args.simple is not None:
    file_name = args.file
    export_file = args.simple

    user_urls = load_url_file(file_name)

    legitimate_urls = []
    suspicous_urls = []


    print("\n=== Analysis Result Results were sucsessfully saved in '" + export_file + "' ===\n")
    for url in user_urls:
        features = strip_features(url)
        score_url(features)

        final_score = score_url(features)
        
        print("\n[CHECKING] Analyzing URL:", url)
        if features["is_in_database"]:
            print(Fore.GREEN + f"[LEGITIMATE] The URL '{url}' is found in our verified database.")
        else:
            print(Fore.RED + f"[SUSPICIOUS] The URL '{url}' is NOT found in our verified database.")
        if score >= 3:
            print(Fore.RED + f"[PHISHING] The URL '{url}' is likely a phishing URL. (Score: {final_score['score']})")
            print(Fore.YELLOW + "Feedback:")
            for tip in final_score['feedback']:
                print(Fore.YELLOW + f"- {tip}")
            suspicous_urls.append(url + "\n")
            
        elif score == 2:
            print(Fore.YELLOW + f"[SUSPICIOUS] The URL '{url}' is suspicious. (Score: {final_score['score']})")
            print(Fore.YELLOW + "Feedback:")
            for tip in final_score['feedback']:
                print(Fore.YELLOW + f"- {tip}")
            suspicous_urls.append(url + "\n")
        else:
            print(Fore.GREEN + f"[LEGITIMATE] The URL '{url}' appears to be legitimate. (Score: {final_score['score']})")
            legitimate_urls.append(url + "\n")
    
    with open(Path(__file__).parent / "data" / export_file, 'a', encoding="utf-8") as ef:
        for url in legitimate_urls:
            ef.write(f"{url}")
    print("\n=== Analysis Complete - Results were sucsessfully saved in " + export_file +" ===\n")
    print("\n=== Analysis Complete ===\n")
    print(Fore.GREEN + f"Total Legitimate URLs: {len(legitimate_urls)}\n")
    print(Fore.YELLOW + f"Total Flagged URLs: {len(suspicous_urls)}\n")
    print("===================================\n")
    print("The following URLs were deemed legitimate:\n")

    for url in legitimate_urls:
        print(Fore.GREEN + url.strip())        


elif args.file is not None:
    file_name = args.file
    user_urls = load_url_file(file_name)
    legitimate_urls = []
    suspicous_urls = []

    print("\n=== Analysis Result ===")
    for url in user_urls:
        features = strip_features(url)
        score_url(features)

        final_score = score_url(features)
        
        print("\n[CHECKING] Analyzing URL:", url)
        if features["is_in_database"]:
            print(Fore.GREEN + f"[LEGITIMATE] The URL '{url}' is found in our verified database.")
        else:
            print(Fore.RED + f"[SUSPICIOUS] The URL '{url}' is NOT found in our verified database.")
        if score >= 3:
            print(Fore.RED + f"[PHISHING] The URL '{url}' is likely a phishing URL. (Score: {final_score['score']})")
            print(Fore.YELLOW + "Feedback:")
            for tip in final_score['feedback']:
                print(Fore.YELLOW + f"- {tip}")
            suspicous_urls.append(url + "\n")
            
        elif score == 2:
            print(Fore.YELLOW + f"[SUSPICIOUS] The URL '{url}' is suspicious. (Score: {final_score['score']})")
            print(Fore.YELLOW + "Feedback:")
            for tip in final_score['feedback']:
                print(Fore.YELLOW + f"- {tip}")
            suspicous_urls.append(url + "\n")
        else:
            print(Fore.GREEN + f"[LEGITIMATE] The URL '{url}' appears to be legitimate. (Score: {final_score['score']})")
            legitimate_urls.append(url + "\n")

    print("\n=== Analysis Complete ===\n")
    print(Fore.GREEN + f"Total Legitimate URLs: {len(legitimate_urls)}\n")
    print(Fore.YELLOW + f"Total Flagged URLs: {len(suspicous_urls)}\n")
    print("===================================\n")
    print("The following URLs were deemed legitimate:\n")

    for url in legitimate_urls:
        print(Fore.GREEN + url.strip())



