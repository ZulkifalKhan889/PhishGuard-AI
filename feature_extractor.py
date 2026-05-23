
# ═══════════════════════════════════════════════════
# FEATURE EXTRACTOR
# Contains all functions to extract 68 features
# from any URL string
# Used by both training notebook and Streamlit app
# ═══════════════════════════════════════════════════

import re
import math
from urllib.parse import urlparse
import tldextract
import Levenshtein

# ── BRAND AND TLD LISTS ─────────────────────────────

BRAND_LIST = [
    'paypal', 'google', 'facebook', 'microsoft', 'apple',
    'amazon', 'netflix', 'instagram', 'twitter', 'linkedin',
    'whatsapp', 'youtube', 'tiktok', 'snapchat', 'yahoo',
    'ebay', 'walmart', 'chase', 'wellsfargo', 'bankofamerica',
    'steam', 'discord', 'roblox', 'adobe', 'dropbox',
    'spotify', 'uber', 'airbnb', 'pinterest', 'tumblr'
]

HIGH_RISK_TLDS = [
    'tk', 'ml', 'ga', 'cf', 'gq',
    'xyz', 'top', 'club', 'online', 'site',
    'live', 'click', 'link', 'loan', 'win',
    'racing', 'date', 'faith', 'review', 'stream',
    'lat', 'cfd', 'sbs', 'cyou', 'buzz',
    'icu', 'vip', 'pro', 'pw', 'cc'
]

SUSPICIOUS_KEYWORDS = [
    'verify', 'validate', 'update', 'confirm',
    'banking', 'payment', 'credential', 'authenticate',
    'suspended', 'unlock', 'recover', 'restore',
    'unusual', 'activity', 'billing', 'invoice'
]

REDIRECT_PARAMS = [
    'redirect', 'redirect_url', 'redirect_uri',
    'next', 'return', 'return_url', 'url',
    'goto', 'continue', 'forward', 'destination',
    'target', 'rurl', 'dest'
]

URL_SHORTENERS = [
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl',
    'ow.ly', 'short.link', 'tiny.cc', 'is.gd',
    'buff.ly', 'rebrand.ly', 'cutt.ly', 'shorturl.at',
    'tiny.one', 'rb.gy', 'shorte.st'
]

DOMAIN_PHISHING_KEYWORDS = [
    'secure', 'login', 'verify', 'update',
    'account', 'banking', 'payment', 'signin',
    'authenticate', 'validation', 'confirm',
    'support', 'helpdesk', 'service', 'online'
]

LEGITIMATE_BRAND_TLDS = ['com', 'org', 'net', 'edu', 'gov']

# ── UTILITY ─────────────────────────────────────────

def normalize_url(url):
    url = str(url).strip().lower()
    if not url.startswith('http'):
        url = 'https://' + url
    url = url.rstrip('/')
    return url

def calculate_entropy(input_string):
    if len(input_string) == 0:
        return 0
    char_frequency = {}
    for char in input_string:
        if char in char_frequency:
            char_frequency[char] = char_frequency[char] + 1
        else:
            char_frequency[char] = 1
    entropy = 0
    total_chars = len(input_string)
    for char in char_frequency:
        probability = char_frequency[char] / total_chars
        entropy = entropy + (-probability * math.log2(probability))
    return round(entropy, 4)

# ── CATEGORY 1: URL LEVEL FEATURES ──────────────────

def extract_url_features(url):
    features = {}
    url = str(url)
    features['url_length'] = len(url)

    digit_count = 0
    for char in url:
        if char.isdigit():
            digit_count = digit_count + 1
    features['digit_count'] = digit_count

    letter_count = 0
    for char in url:
        if char.isalpha():
            letter_count = letter_count + 1
    features['letter_count'] = letter_count

    special_count = 0
    for char in url:
        if char.isalpha() == False and char.isdigit() == False and char != ' ':
            special_count = special_count + 1
    features['special_char_count'] = special_count

    features['hyphen_count'] = url.count('-')
    features['underscore_count'] = url.count('_')
    features['dot_count'] = url.count('.')
    features['slash_count'] = url.count('/')
    features['question_mark_count'] = url.count('?')
    features['equal_sign_count'] = url.count('=')
    features['at_sign_count'] = url.count('@')
    features['percent_count'] = url.count('%')

    if len(url) > 0:
        features['digit_to_length_ratio'] = digit_count / len(url)
        features['special_char_to_length_ratio'] = special_count / len(url)
    else:
        features['digit_to_length_ratio'] = 0
        features['special_char_to_length_ratio'] = 0

    ip_pattern = re.compile(r'\d+\.\d+\.\d+\.\d+')
    ip_match = re.search(ip_pattern, url)
    features['has_ip_address'] = 1 if ip_match is not None else 0

    return features

# ── CATEGORY 2: DOMAIN LEVEL FEATURES ───────────────

def extract_domain_features(url):
    features = {}
    url = str(url)
    extracted = tldextract.extract(url)
    subdomain = extracted.subdomain
    domain = extracted.domain
    suffix = extracted.suffix
    parsed = urlparse(url)

    #features['domain_length'] = len(domain)
    if subdomain.lower() == 'www':
        
        features['subdomain_length'] = 0
    else:
        
        features['subdomain_length'] = len(subdomain)

    if subdomain == '' or subdomain == 'www':
        features['subdomain_count'] = 0
        features['has_subdomain'] = 0
    elif subdomain.startswith('www.'):
        clean = subdomain[4:]
        features['subdomain_count'] = clean.count('.') + 1
        features['has_subdomain'] = 1
    else:
        features['subdomain_count'] = subdomain.count('.') + 1
        features['has_subdomain'] = 1

    features['subdomain_length'] = len(subdomain)
    features['domain_hyphen_count'] = domain.count('-')

    domain_digit_count = 0
    for char in domain:
        if char.isdigit():
            domain_digit_count = domain_digit_count + 1
    features['domain_digit_count'] = domain_digit_count

    if len(domain) > 0:
        features['domain_digit_ratio'] = domain_digit_count / len(domain)
    else:
        features['domain_digit_ratio'] = 0

    features['is_tld_suspicious'] = 1 if suffix.lower() in HIGH_RISK_TLDS else 0
    features['tld_length'] = len(suffix)
    features['has_www'] = 1 if subdomain.lower() == 'www' else 0
    features['domain_entropy'] = calculate_entropy(domain)

    vowels = 'aeiou'
    vowel_count = 0
    consonant_count = 0
    for char in domain.lower():
        if char in vowels:
            vowel_count = vowel_count + 1
        elif char.isalpha():
            consonant_count = consonant_count + 1

    if consonant_count > 0:
        features['consonant_vowel_ratio'] = vowel_count / consonant_count
    else:
        features['consonant_vowel_ratio'] = 0

    features['has_port_number'] = 1 if parsed.port is not None else 0
    features['domain_unique_char_count'] = len(set(domain))

    domain_words = domain.split('-')
    longest = 0
    for word in domain_words:
        if len(word) > longest:
            longest = len(word)
    features['domain_longest_word_length'] = longest

    return features

# ── CATEGORY 3: PATH AND QUERY FEATURES ─────────────

def extract_path_features(url):
    features = {}
    url = str(url)
    parsed = urlparse(url)
    path = parsed.path
    query = parsed.query

    features['path_length'] = len(path)

    path_parts = path.split('/')
    non_empty_parts = []
    for part in path_parts:
        if part != '':
            non_empty_parts.append(part)
    features['path_depth'] = len(non_empty_parts)

    features['query_length'] = len(query)

    if query != '':
        query_params = query.split('&')
        features['query_param_count'] = len(query_params)
    else:
        features['query_param_count'] = 0

    path_and_query = (path + query).lower()
    keyword_count = 0
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in path_and_query:
            keyword_count = keyword_count + 1
    features['suspicious_keyword_count'] = keyword_count
    features['has_suspicious_keyword'] = 1 if keyword_count > 0 else 0

    query_lower = query.lower()
    has_redirect = 0
    for param in REDIRECT_PARAMS:
        if param + '=' in query_lower:
            has_redirect = 1
            break
    features['has_redirect_param'] = has_redirect
    features['has_encoded_characters'] = 1 if '%' in path else 0

    path_digit_count = 0
    for char in path:
        if char.isdigit():
            path_digit_count = path_digit_count + 1
    features['path_digit_count'] = path_digit_count
    features['path_digit_ratio'] = path_digit_count / len(path) if len(path) > 0 else 0

    last_segment = path.split('/')[-1]
    if '.' in last_segment:
        features['has_file_extension'] = 1
        extension = last_segment.split('.')[-1].lower()
        SUSPICIOUS_EXTENSIONS = [
            'php', 'exe', 'sh', 'bat', 'cmd',
            'zip', 'js', 'scr', 'pif', 'vbs',
            'jar', 'pl', 'cgi', 'asp', 'aspx'
        ]
        features['is_suspicious_extension'] = 1 if extension in SUSPICIOUS_EXTENSIONS else 0
    else:
        features['has_file_extension'] = 0
        features['is_suspicious_extension'] = 0

    return features

# ── CATEGORY 4: BRAND IMPERSONATION FEATURES ────────

def extract_brand_features(url):
    features = {}
    url = str(url)
    extracted = tldextract.extract(url)
    subdomain = extracted.subdomain.lower()
    domain = extracted.domain.lower()
    suffix = extracted.suffix.lower()
    parsed = urlparse(url)
    path = parsed.path.lower()
    full_url = url.lower()

    min_distance = 999
    closest_brand = 'none'
    domain_words = domain.split('-')

    for brand in BRAND_LIST:
        for word in domain_words:
            if len(word) < 4:
                continue
            length_difference = abs(len(word) - len(brand))
            if length_difference > 3:
                continue
            distance = Levenshtein.distance(word, brand)
            if distance < min_distance:
                min_distance = distance
                closest_brand = brand

    if min_distance == 999:
        min_distance = 10

    features['min_brand_distance'] = min_distance
    features['closest_brand'] = closest_brand
    features['is_brand_impersonation'] = 1 if (min_distance <= 2 and min_distance > 0) else 0

    brand_in_subdomain = 0
    for brand in BRAND_LIST:
        if brand in subdomain:
            brand_in_subdomain = 1
            break
    features['brand_in_subdomain'] = brand_in_subdomain

    brand_in_path = 0
    for brand in BRAND_LIST:
        if brand in path:
            brand_in_path = 1
            break
    features['brand_in_path'] = brand_in_path

    brand_in_domain_wrong_tld = 0
    for brand in BRAND_LIST:
        if brand in domain:
            if suffix not in LEGITIMATE_BRAND_TLDS:
                brand_in_domain_wrong_tld = 1
                break
    features['brand_in_domain_not_legitimate_tld'] = brand_in_domain_wrong_tld

    exact_match = 0
    for brand in BRAND_LIST:
        if domain == brand:
            exact_match = 1
            break
    features['exact_brand_match'] = exact_match

    brand_count = 0
    for brand in BRAND_LIST:
        if brand in full_url:
            brand_count = brand_count + 1
    features['brand_count_in_url'] = brand_count

    domain_has_brand = 0
    for brand in BRAND_LIST:
        if brand in domain:
            domain_has_brand = 1
            break
    features['domain_contains_brand_keyword'] = domain_has_brand

    return features

# ── CATEGORY 5: ENTROPY FEATURES ────────────────────

def extract_entropy_features(url):
    features = {}
    url = str(url)
    parsed = urlparse(url)
    extracted = tldextract.extract(url)
    domain = extracted.domain.lower()
    path = parsed.path.lower()

    url_without_scheme = url.replace('http://', '').replace('https://', '')
    features['url_entropy'] = calculate_entropy(url_without_scheme)
    features['path_entropy'] = calculate_entropy(path)

    domain_entropy = calculate_entropy(domain)
    vowels = 'aeiou'
    vowel_count = 0
    for char in domain:
        if char in vowels:
            vowel_count = vowel_count + 1
    vowel_ratio = vowel_count / len(domain) if len(domain) > 0 else 0
    features['has_random_domain'] = 1 if (domain_entropy > 3.5 and vowel_ratio < 0.3) else 0

    consonants = 'bcdfghjklmnpqrstvwxyz'
    consonant_count = 0
    letter_count = 0
    for char in domain.lower():
        if char.isalpha():
            letter_count = letter_count + 1
            if char in consonants:
                consonant_count = consonant_count + 1

    features['consonant_ratio'] = round(consonant_count / letter_count, 4) if letter_count > 0 else 0
    features['vowel_ratio'] = round(vowel_count / letter_count, 4) if letter_count > 0 else 0

    digit_count = 0
    for char in domain:
        if char.isdigit():
            digit_count = digit_count + 1
    features['digit_letter_ratio'] = round(digit_count / letter_count, 4) if letter_count > 0 else 0
    features['unique_char_ratio'] = round(len(set(domain)) / len(domain), 4) if len(domain) > 0 else 0

    longest_sequence = 0
    current_sequence = 0
    for char in domain.lower():
        if char in consonants:
            current_sequence = current_sequence + 1
            if current_sequence > longest_sequence:
                longest_sequence = current_sequence
        else:
            current_sequence = 0
    features['longest_consonant_sequence'] = longest_sequence

    has_repeated = 0
    for i in range(len(domain) - 2):
        if domain[i] == domain[i+1] == domain[i+2]:
            has_repeated = 1
            break
    features['has_repeated_characters'] = has_repeated

    hex_pattern = re.compile(r'%[0-9a-fA-F]{2}')
    hex_matches = re.findall(hex_pattern, url)
    features['hex_encoded_char_count'] = len(hex_matches)
    features['has_hex_encoding'] = 1 if len(hex_matches) > 0 else 0

    return features

# ── CATEGORY 6: SUSPICIOUS PATTERN FEATURES ─────────

def extract_suspicious_pattern_features(url):
    features = {}
    url = str(url)
    parsed = urlparse(url)
    extracted = tldextract.extract(url)
    domain = extracted.domain.lower()
    subdomain = extracted.subdomain.lower()
    suffix = extracted.suffix.lower()
    path = parsed.path.lower()
    query = parsed.query.lower()
    full_url = url.lower()

    features['has_https'] = 1 if parsed.scheme == 'https' else 0

    full_domain = domain + '.' + suffix
    shortener_found = 0
    for shortener in URL_SHORTENERS:
        if full_domain == shortener:
            shortener_found = 1
            break
    features['url_shortener_detected'] = shortener_found

    if subdomain == '' or subdomain == 'www':
        subdomain_levels = 0
    else:
        clean_subdomain = subdomain
        if clean_subdomain.startswith('www.'):
            clean_subdomain = clean_subdomain[4:]
        subdomain_levels = clean_subdomain.count('.') + 1
    features['subdomain_levels'] = subdomain_levels
    features['has_multiple_subdomains'] = 1 if subdomain_levels > 2 else 0

    features['double_slash_in_path'] = 1 if '//' in path else 0

    domain_and_subdomain = domain + ' ' + subdomain
    keyword_in_domain = 0
    for keyword in DOMAIN_PHISHING_KEYWORDS:
        if keyword in domain_and_subdomain:
            keyword_in_domain = 1
            break
    features['has_phishing_keywords_in_domain'] = keyword_in_domain

    features['domain_starts_with_number'] = 1 if (len(domain) > 0 and domain[0].isdigit()) else 0

    COMMON_TLDS = ['com', 'net', 'org', 'gov', 'edu', 'co']
    suspicious_combo = 0
    for tld in COMMON_TLDS:
        if '.' + tld in subdomain:
            suspicious_combo = 1
            break
    features['has_suspicious_tld_combination'] = suspicious_combo

    email_pattern = re.compile(r'[a-zA-Z0-9]+@[a-zA-Z0-9]+\.[a-zA-Z]+')
    email_match = re.search(email_pattern, full_url)
    features['url_has_email_pattern'] = 1 if email_match is not None else 0

    return features

# ── MASTER FUNCTION ──────────────────────────────────

def extract_all_features(url):


    url = normalize_url(url)
    all_features = {}
    all_features.update(extract_url_features(url))
    all_features.update(extract_domain_features(url))
    all_features.update(extract_path_features(url))
    all_features.update(extract_brand_features(url))
    all_features.update(extract_entropy_features(url))
    all_features.update(extract_suspicious_pattern_features(url))
    return all_features
