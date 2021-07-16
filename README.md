# Domain Extractor

Extract valid or partially valid domain names and IPs from malicious or invalid URLs.

Keep in mind that the algorithm is not that perfect, there might be false positives.

Tested on Kali Linux v2021.2 (64-bit).

Check the testing URLs [here](https://github.com/ivan-sincek/domain-extractor/tree/master/src/urls.txt) and the results [here](https://github.com/ivan-sincek/domain-extractor/tree/master/src/results.json).

Made for educational purposes. I hope it will help!

Future plans:

* decode Unicode URLs,
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

## Images

<p align="center"><img src="https://github.com/ivan-sincek/domain-extractor/blob/master/img/help.png" alt="Help"></p>

<p align="center">Figure 1 - Help</p>

<p align="center"><img src="https://github.com/ivan-sincek/domain-extractor/blob/master/img/validating.png" alt="Validating"></p>

<p align="center">Figure 2 - Validating</p>
