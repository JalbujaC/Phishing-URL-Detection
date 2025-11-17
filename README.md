# Phishing URL Detection Tool

This project is a Python-based tool for detecting potentially malicious or phishing URLs by analyzing key characteristics commonly found in harmful links. It evaluates URLs using lexical features such as length, use of IP addresses, presence of suspicious characters, excessive hyphens, and other indicators. The goal is to provide a lightweight, extendable approach for identifying phishing attempts without requiring complex machine learning models or external services. This program also allows users to check vast quantities of URLs automatically. Users can then export their analysis to a desired file. 

## Overview

The tool processes a given URL and extracts a series of features that are often associated with phishing activity. Each feature contributes to an overall risk score, which can then be used to classify the URL as either legitimate or suspicious. Given URLs are also checked against our own personal database of verified URLs. This approach allows users to understand exactly why a URL may be dangerous, making the system transparent and easy to customize.

## Features

* Detects the use of IP addresses instead of domain names
* Identifies long or overly complex URLs
* Flags excessive hyphens, suspicious characters, and misleading structures
* Highlights TLDs and patterns that are frequently associated with phishing
* Evaluates lexical components such as subdomain count and query structure
* Designed for extensibility, allowing future upgrades to incorporate machine learning, domain reputation checks, and external blacklist APIs
* Users may expand on the verified database automatically, if they so choose to.
* Users can export the end results to a file of their choice.

## How It Works

The tool performs a lexical analysis of the URL and computes a score based on predefined rules. These rules represent common heuristics used in phishing detection. After analyzing the URL, the system outputs:

* A categorized breakdown of each risk factor
* A final score representing the likelihood of the URL being malicious
* Plain-text feedback describing each triggered warning

This approach helps users understand the reasoning behind the classification and gives developers flexibility to refine or expand detection criteria.

## Installation
# Requirements
Ensure you have Python 3.8 or higher installed.
Step-by-step Installation
Clone the repository:
```bash
git clone https://github.com/JalbujaC/Phishing-URL-Detection.git
```

Navigate into the project directory:

```bash
cd yourrepository
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Run the tool using one of the available modes:

```bash
python3 detection.py url --single "http://example.com"
```

or:

```bash
python3 detection.py url --file urls.txt
```

## Usage

1. Run the program and enter any URL when prompted.
```bash
python3 detection.py url 
```
2. Enter the flags to direct the program into performing the required task.

Available flags:
--single, -s,               Requires user to provide the url they wish to analyze
--file, -f                  Requires the user to provide a .txt file containing the list of URLs

MODIFIERS

--add, -a                   If added authorizes the program to add legitimate URLs into the database
--simple, -eS                If added, exports only the list of verified URLs into a designated file
--export, -e                If added, exports the COMPLETE report into a designated file

```bash
python3 detection.py url -s <"ENTER URL HERE">
python3 detection.py url -f <"ENTER FILENAME HERE">

python3 detection.py url -s <"ENTER URL HERE"> -a
python3 detection.py url -f <"ENTER FILENAME HERE"> -eS <"ENTER EXPORT FILENAME HERE">
```
2. The tool extracts relevant features and computes a total risk score.
3. Based on the score, the URL is classified as safe or potentially malicious.
4. The output includes detailed explanations of triggered features.

## Future Improvements

The system has been designed so that additional verification methods can be added with minimal changes. Planned enhancements include:

* Integrating WHOIS lookup to analyze domain age
* Checking against known phishing blacklists
* Detecting advanced obfuscation patterns, Unicode homographs, and encoded payloads
* Incorporating machine learning models trained on known phishing and legitimate URLs

## License

This project is released under the MIT License. Contributions and improvements are welcome.
