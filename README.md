# Domain Extractor

Extract valid or partially valid domain names and IPs from malicious or invalid URLs.

Keep in mind that the algorithm is not that perfect, there might be false positives.

Tested on Kali Linux v2023.1 (64-bit).

Check the testing URLs [here](https://github.com/ivan-sincek/domain-extractor/blob/master/examples/urls.txt) and the results [here](https://github.com/ivan-sincek/domain-extractor/blob/master/examples/results.json).

Made for educational purposes. I hope it will help!

Future plans:

* detect IPv6 addresses.

## How to Run

Open your preferred console from [/src/](https://github.com/ivan-sincek/domain-extractor/tree/master/src) and run the commands shown below.

Install required packages:

```fundamental
pip3 install -r requirements.txt
```

Run the script:

```fundamental
python3 domain_extractor.py
```

## Extract Results

Extract hosts from the results:

```bash
jq -r '.[].hosts[]' results.json | sort -u -f | tee -a hosts.txt
```

Extract URLs with valid or partially valid hosts from the results:

```bash
jq -r '.[] | if (.hosts != []) then (.original) else (empty) end' results.json | sort -u -f | tee -a valid_urls.txt
```

Extract URLs with no valid nor partially valid hosts from the results:

```bash
jq -r '.[] | if (.hosts == []) then (.original) else (empty) end' results.json | sort -u -f | tee -a invalid_urls.txt
```

## Usage

```fundamental
Domain Extractor v3.0 ( github.com/ivan-sincek/domain-extractor )

Usage:   python3 domain_extractor.py -f file               -o out
Example: python3 domain_extractor.py -f malicious_urls.txt -o results.json

DESCRIPTION
    Extract valid or partially valid domain names and IPs from URLs
FILE
    File with URLs you want to extract data from
    -f <file> - malicious_urls.txt | etc.
OUT
    Output file
    -o <out> - results.json | etc.
```
