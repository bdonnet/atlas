"""
This file contains functions to help post processing the scraped URLs that have "error" as fido2 usage.
It should deleted all the irregular URLs, the ones containing at least 2 digits 
and those that came from the same sub domain or that are very similar, such as:

https://www.00o011lrqobabcarxwcv.authenticatorlocalprod.com
https://www.00o14p86tdsdvyrdgqid.authenticatorlocalprod.com
https://www.00o1bqc6y2kslarqpeum.authenticatorlocalprod.com
https://www.00o1rf49tzpycvd970i7.authenticatorlocalprod.com
https://www.00o24plp3pwzmaelrjez.authenticatorlocalprod.com

- at least 2 digits (deleted 170 000)
- at least 3 consecutive that are very similar (deleted 140 000)
- same subdomains at least 3 lines in a row (deleted 10 000)
- first word is the same for at least 3 lines in a row (deleted 70 000)
- (if a packet starts with the same 2 or 3 letters:
    https://www.sdkqjpp.cn
    https://www.sdkserver-drru.op.dbankcloud.ru,
    https://www.sdkserver.op.hicloud.com
    https://www.sdkserversea.zloong.com
    https://www.sdksg.ssp.taxssp.com
    https://www.sdksp.wetvinfo.com ...)

"""

from import_data import *

def digit_filter(input_file, output_file):
        
    digit_regex = re.compile(r".*\d.*\d.*")

    with open(input_file, newline="", encoding="utf-8") as infile, \
        open(output_file, "w", newline="", encoding="utf-8") as outfile:

        reader = csv.DictReader(infile)
        writer = csv.DictWriter(outfile, fieldnames=reader.fieldnames)
        writer.writeheader()

        for row in reader:
            site_url = row.get("site_url", "")
            fido2_usage = row.get("fido2_usage", "")

            has_two_digits = bool(digit_regex.search(site_url))
            is_error = fido2_usage == "error"

            if not (has_two_digits and is_error):
                writer.writerow(row)


def similarity_check(input_file, output_file):

    SIMILARITY_THRESHOLD = 0.70
    MIN_PACKET_SIZE = 3

    def normalize_fido(value):
        return value.strip().lower() if value else ""

    def similar(a, b):
        return SequenceMatcher(None, a, b).ratio()

    with open(input_file, newline="", encoding="utf-8") as infile:
        rows = list(csv.DictReader(infile))

    keep = [True] * len(rows)

    i = 0
    while i < len(rows):
        row = rows[i]
        url = row.get("site_url", "")
        fido = normalize_fido(row.get("fido2_usage", ""))

        if fido != "error":
            i += 1
            continue

        packet_indices = [i]
        j = i + 1

        while j < len(rows):
            next_url = rows[j].get("site_url", "")
            next_fido = normalize_fido(rows[j].get("fido2_usage", ""))

            if next_fido != "error":
                break

            if similar(url, next_url) >= SIMILARITY_THRESHOLD:
                packet_indices.append(j)
                j += 1
            else:
                break

        if len(packet_indices) >= MIN_PACKET_SIZE:
            for idx in packet_indices:
                keep[idx] = False
            i = j
        else:
            i += 1

    with open(output_file, "w", newline="", encoding="utf-8") as outfile:
        writer = csv.DictWriter(outfile, fieldnames=rows[0].keys())
        writer.writeheader()

        for row, k in zip(rows, keep):
            if k:
                writer.writerow(row)


def filter_subdomains(input_file, output_file):
    def normalize_fido(v):
        return v.strip().lower() if v else ""

    def get_subdomain(url):
        try:
            host = urlparse(url).hostname or ""
            parts = host.split(".")
            return ".".join(parts[-2:]) if len(parts) >= 2 else host
        except Exception:
            return ""

    with open(input_file, newline="", encoding="utf-8") as infile, \
         open(output_file, "w", newline="", encoding="utf-8") as outfile:

        reader = csv.DictReader(infile)
        writer = csv.DictWriter(outfile, fieldnames=reader.fieldnames)
        writer.writeheader()

        current_packet = []
        current_subdomain = None

        def flush_packet():
            if (
                len(current_packet) >= 3
                and all(normalize_fido(r["fido2_usage"]) == "error" for r in current_packet)
            ):
                return  # drop
            for r in current_packet:
                writer.writerow(r)

        for row in reader:
            url = row.get("site_url", "")
            sub = get_subdomain(url)

            if current_subdomain is None:
                current_packet = [row]
                current_subdomain = sub
                continue

            if sub == current_subdomain:
                current_packet.append(row)
            else:
                flush_packet()
                current_packet = [row]
                current_subdomain = sub

        flush_packet()
        

def filter_first_word(input_file, output_file):
    def normalize_fido(v):
        return v.strip().lower() if v else ""

    def get_first_dash_token(url):
        try:
            host = urlparse(url).hostname or ""
            host = host.lower()
            if host.startswith("www."):
                host = host[4:]
            return host.split("-")[0]
        except Exception:
            return ""

    with open(input_file, newline="", encoding="utf-8") as infile, \
         open(output_file, "w", newline="", encoding="utf-8") as outfile:

        reader = csv.DictReader(infile)
        writer = csv.DictWriter(outfile, fieldnames=reader.fieldnames)
        writer.writeheader()

        current_packet = []
        current_key = None

        def flush_packet():
            if (
                len(current_packet) >= 3
                and all(normalize_fido(r.get("fido2_usage")) == "error" for r in current_packet)
            ):
                return  # drop entire packet
            for r in current_packet:
                writer.writerow(r)

        for row in reader:
            url = row.get("site_url", "")
            key = get_first_dash_token(url)

            if current_key is None:
                current_packet = [row]
                current_key = key
                continue

            if key == current_key:
                current_packet.append(row)
            else:
                flush_packet()
                current_packet = [row]
                current_key = key

        flush_packet()
        

def filter_first_letters(input_file, output_file):
    def normalize_fido(v):
        return v.strip().lower() if v else ""

    def first3_letters(url):
        try:
            host = urlparse(url).hostname or ""
            # remove 'www.' if present
            if host.startswith("www."):
                host = host[4:]
            host = host.lower()
            return host[:3] if len(host) >= 3 else host
        except Exception:
            return ""

    with open(input_file, newline="", encoding="utf-8") as infile, \
         open(output_file, "w", newline="", encoding="utf-8") as outfile:

        reader = csv.DictReader(infile)
        writer = csv.DictWriter(outfile, fieldnames=reader.fieldnames)
        writer.writeheader()

        current_packet = []

        def flush_packet():
            if not current_packet:
                return

            # check if all fido2_usage are "error"
            all_error = all(normalize_fido(r.get("fido2_usage")) == "error" for r in current_packet)

            # get first 3 letters for all rows
            first3_set = set(first3_letters(r.get("site_url", "")) for r in current_packet)

            # drop packet if at least 3 rows, all errors, and all first 3 letters are the same
            if len(current_packet) >= 3 and all_error and len(first3_set) == 1:
                return

            for r in current_packet:
                writer.writerow(r)

        for row in reader:
            current_packet.append(row)
        
        flush_packet()


def filter_three_letters(input_file, output_file):
    def normalize_fido(v):
        if not v:
            return ""
        return v.strip().lower()

    def is_error(v):
        return normalize_fido(v) == "error"

    def first3_letters(url):
        try:
            host = urlparse(url).hostname or ""
            if host.startswith("www."):
                host = host[4:]
            return host.lower()[:3]
        except Exception:
            return ""

    with open(input_file, newline="", encoding="utf-8") as infile, \
         open(output_file, "w", newline="", encoding="utf-8") as outfile:

        reader = csv.DictReader(infile)
        writer = csv.DictWriter(outfile, fieldnames=reader.fieldnames)
        writer.writeheader()

        current_packet = []
        prev_first3 = None

        for row in reader:
            row_first3 = first3_letters(row.get("site_url", ""))

            # New packet if first3 changes
            if prev_first3 is not None and row_first3 != prev_first3:
                # Process current packet
                if len(current_packet) >= 5:
                    # Drop only 'error' rows
                    to_write = [r for r in current_packet if not is_error(r.get("fido2_usage"))]
                else:
                    # Keep all rows if less than 5
                    to_write = current_packet

                for r in to_write:
                    writer.writerow(r)

                current_packet.clear()

            current_packet.append(row)
            prev_first3 = row_first3

        # Flush the last packet
        if current_packet:
            if len(current_packet) >= 5:
                to_write = [r for r in current_packet if not is_error(r.get("fido2_usage"))]
            else:
                to_write = current_packet
            for r in to_write:
                writer.writerow(r)

