import re
import math
import urllib.parse
import requests
import tldextract
from bs4 import BeautifulSoup
from thefuzz import fuzz

# The exact feature list order expected by your ONNX model
FEATURE_COLUMNS = [
    "URLLength", "DomainLength", "IsDomainIP", "CharContinuationRate", "TLDLegitimateProb",
    "URLCharProb", "TLDLength", "NoOfSubDomain", "HasObfuscation", "NoOfObfuscatedChar",
    "ObfuscationRatio", "NoOfLettersInURL", "LetterRatioInURL", "NoOfDegitsInURL", "DegitRatioInURL",
    "NoOfEqualsInURL", "NoOfQMarkInURL", "NoOfAmpersandInURL", "NoOfOtherSpecialCharsInURL",
    "SpacialCharRatioInURL", "IsHTTPS", "LineOfCode", "LargestLineLength", "HasTitle",
    "DomainTitleMatchScore", "URLTitleMatchScore", "HasFavicon", "Robots", "IsResponsive",
    "NoOfURLRedirect", "NoOfSelfRedirect", "HasDescription", "NoOfPopup", "NoOfiFrame",
    "HasExternalFormSubmit", "HasSubmitButton", "HasHiddenFields", "HasPasswordField",
    "Bank", "Pay", "Crypto", "HasCopyrightInfo", "NoOfImage", "NoOfCSS", "NoOfJS",
    "NoOfSelfRef", "NoOfEmptyRef", "NoOfExternalRef"
]

# ---------------------------------------------------------------------------
# Character probability table: estimated from benign URL corpus distributions.
# Used to compute URLCharProb in a similar style to the PhiUSIIL dataset.
# ---------------------------------------------------------------------------
_CHAR_LOG_PROBS = {}
for c in 'abcdefghijklmnopqrstuvwxyz':
    _CHAR_LOG_PROBS[c] = math.log(0.055)       # letters: most common
for c in '0123456789':
    _CHAR_LOG_PROBS[c] = math.log(0.020)       # digits: common
for c in '.-_~/':
    _CHAR_LOG_PROBS[c] = math.log(0.012)       # standard URL separators
for c in ':':
    _CHAR_LOG_PROBS[c] = math.log(0.006)       # protocol separator
for c in '?=&#':
    _CHAR_LOG_PROBS[c] = math.log(0.004)       # query string chars (suspicious if many)
for c in '%@+!':
    _CHAR_LOG_PROBS[c] = math.log(0.001)       # encoding / obfuscation chars

_RARE_CHAR_LOG_PROB = math.log(0.0005)         # unknown / very rare chars

# Normalisation constants derived from average benign URL analysis.
_URL_CHAR_PROB_MIN = -8.0   # avg log-prob for a very suspicious URL
_URL_CHAR_PROB_MAX = -2.5   # avg log-prob for a clean short URL


def _compute_url_char_prob(url: str) -> float:
    """
    Compute URLCharProb as the normalised average log-probability of the
    URL's characters based on a benign URL character distribution.
    Returns a float in [0.0, 1.0] where 1.0 is most benign-like.
    """
    if not url:
        return 0.5
    url_lower = url.lower()
    log_probs = [_CHAR_LOG_PROBS.get(c, _RARE_CHAR_LOG_PROB) for c in url_lower]
    avg_log_prob = sum(log_probs) / len(log_probs)
    # Linearly map [_URL_CHAR_PROB_MIN, _URL_CHAR_PROB_MAX] → [0.0, 1.0]
    normalised = (avg_log_prob - _URL_CHAR_PROB_MIN) / (_URL_CHAR_PROB_MAX - _URL_CHAR_PROB_MIN)
    return max(0.0, min(1.0, normalised))


def _find_tag_with_attr_value(soup, tag_name: str, attr: str, pattern) -> bool:
    """
    Safely find a tag whose attribute (which may be a list in BS4) contains
    a value matching `pattern` (string or compiled regex).
    """
    for tag in soup.find_all(tag_name):
        val = tag.get(attr)
        if val is None:
            continue
        # BS4 may return list (e.g. rel) or string
        values = val if isinstance(val, list) else [val]
        for v in values:
            if isinstance(pattern, str):
                if pattern.lower() in v.lower():
                    return True
            else:  # compiled regex
                if pattern.search(v):
                    return True
    return False


def extract_features(url: str, html_content: str = None) -> list:
    """
    Extracts all 48 features from a URL and its HTML content.
    If html_content is None, will attempt to fetch it via requests.
    Returns a list of floats matching the FEATURE_COLUMNS order.
    """
    features = {}

    # --- 1. PARSE URL ---
    parsed_url = urllib.parse.urlparse(url)
    ext = tldextract.extract(url)
    domain = ext.domain
    tld = ext.suffix
    subdomain = ext.subdomain

    # --- 2. URL LEXICAL FEATURES ---
    features["URLLength"] = len(url)
    features["DomainLength"] = len(domain)

    # Check if domain is an IPv4 or IPv6 address
    ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$|([a-f0-9:]+:+)+[a-f0-9]+')
    hostname = parsed_url.hostname or ""
    features["IsDomainIP"] = 1 if ip_pattern.match(hostname) else 0

    # Char Continuation Rate: longest run of a single repeated character / URL length
    max_continuation = max(
        (len(m.group(0)) for m in re.finditer(r'(.)\1*', url)),
        default=0
    )
    features["CharContinuationRate"] = max_continuation / len(url) if len(url) > 0 else 0

    # TLD legitimacy probability
    common_tlds = {'com', 'org', 'net', 'edu', 'gov', 'io', 'co', 'uk', 'de', 'fr', 'jp', 'au', 'ca'}
    features["TLDLegitimateProb"] = 1.0 if tld.split('.')[-1] in common_tlds else 0.1

    # URLCharProb: properly-computed character probability (was hardcoded 1.0 before)
    features["URLCharProb"] = _compute_url_char_prob(url)

    features["TLDLength"] = len(tld)
    features["NoOfSubDomain"] = len(subdomain.split('.')) if subdomain else 0

    obfuscated_chars = url.count('%') + url.count('@')
    features["HasObfuscation"] = 1 if obfuscated_chars > 0 else 0
    features["NoOfObfuscatedChar"] = obfuscated_chars
    features["ObfuscationRatio"] = obfuscated_chars / len(url) if len(url) > 0 else 0

    letters = sum(c.isalpha() for c in url)
    features["NoOfLettersInURL"] = letters
    features["LetterRatioInURL"] = letters / len(url) if len(url) > 0 else 0

    digits = sum(c.isdigit() for c in url)
    features["NoOfDegitsInURL"] = digits
    features["DegitRatioInURL"] = digits / len(url) if len(url) > 0 else 0

    features["NoOfEqualsInURL"] = url.count('=')
    features["NoOfQMarkInURL"] = url.count('?')
    features["NoOfAmpersandInURL"] = url.count('&')

    special_chars = sum(
        not c.isalnum() and c not in {'=', '?', '&'} for c in url
    )
    features["NoOfOtherSpecialCharsInURL"] = special_chars
    features["SpacialCharRatioInURL"] = special_chars / len(url) if len(url) > 0 else 0

    features["IsHTTPS"] = 1 if parsed_url.scheme == 'https' else 0

    # --- 3. FETCH HTML IF NOT PROVIDED ---
    redirect_count = 0
    self_redirect = 0
    fetch_failed = False

    if not html_content:
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                              'AppleWebKit/537.36 (KHTML, like Gecko) '
                              'Chrome/120.0.0.0 Safari/537.36'
            }
            response = requests.get(url, timeout=5, allow_redirects=True, headers=headers)
            html_content = response.text
            redirect_count = len(response.history)
            if redirect_count > 0:
                final_domain = tldextract.extract(response.url).domain
                if final_domain == domain:
                    self_redirect = 1
        except Exception:
            html_content = ""
            fetch_failed = True

    features["NoOfURLRedirect"] = redirect_count
    features["NoOfSelfRedirect"] = self_redirect

    # --- 4. HTML / CONTENT FEATURES ---
    soup = BeautifulSoup(html_content, 'html.parser')
    html_lines = html_content.split('\n')

    features["LineOfCode"] = len(html_lines)
    features["LargestLineLength"] = max((len(line) for line in html_lines), default=0)

    title_tag = soup.find('title')
    title_text = title_tag.get_text(strip=True).lower() if title_tag else ""
    features["HasTitle"] = 1 if title_tag else 0

    features["DomainTitleMatchScore"] = fuzz.ratio(domain.lower(), title_text)
    features["URLTitleMatchScore"] = fuzz.ratio(url.lower(), title_text)

    # Favicon: BS4 returns rel as a list → check each element
    features["HasFavicon"] = 1 if _find_tag_with_attr_value(soup, 'link', 'rel', 'icon') else 0

    # Meta tags: use attrs dict for reliability
    features["Robots"] = 1 if soup.find('meta', attrs={'name': re.compile(r'robots', re.I)}) else 0
    features["IsResponsive"] = 1 if soup.find('meta', attrs={'name': re.compile(r'viewport', re.I)}) else 0
    features["HasDescription"] = 1 if soup.find('meta', attrs={'name': re.compile(r'description', re.I)}) else 0

    features["NoOfPopup"] = html_content.count('window.open')
    features["NoOfiFrame"] = len(soup.find_all('iframe'))

    # Form security analysis
    forms = soup.find_all('form')
    external_forms = 0
    for form in forms:
        action = form.get('action', '').strip().lower()
        if action.startswith('http') and domain.lower() not in action:
            external_forms += 1

    features["HasExternalFormSubmit"] = 1 if external_forms > 0 else 0

    # BS4: use attrs dict for type attribute to avoid Python keyword conflicts
    features["HasSubmitButton"] = 1 if (
        soup.find('input', attrs={'type': 'submit'}) or
        soup.find('button', attrs={'type': 'submit'}) or
        soup.find('button', type=True)  # any button without explicit type defaults to submit
    ) else 0
    features["HasHiddenFields"] = 1 if soup.find('input', attrs={'type': 'hidden'}) else 0
    features["HasPasswordField"] = 1 if soup.find('input', attrs={'type': 'password'}) else 0

    # Keyword detection
    text_content = soup.get_text().lower()
    features["Bank"] = 1 if 'bank' in text_content else 0
    features["Pay"] = 1 if 'pay' in text_content else 0
    features["Crypto"] = 1 if ('crypto' in text_content or 'bitcoin' in text_content) else 0
    features["HasCopyrightInfo"] = 1 if ('copyright' in text_content or '©' in text_content) else 0

    features["NoOfImage"] = len(soup.find_all('img'))
    features["NoOfCSS"] = len(soup.find_all('link', attrs={'rel': 'stylesheet'}))
    features["NoOfJS"] = len(soup.find_all('script'))

    # Link analysis
    links = soup.find_all('a', href=True)
    self_ref = 0
    empty_ref = 0
    ext_ref = 0

    for a in links:
        href = a['href'].strip()
        if not href or href == '#' or href.lower().startswith('javascript:'):
            empty_ref += 1
        elif href.startswith('/') or (domain and domain in href):
            self_ref += 1
        elif href.startswith('http'):
            ext_ref += 1

    features["NoOfSelfRef"] = self_ref
    features["NoOfEmptyRef"] = empty_ref
    features["NoOfExternalRef"] = ext_ref

    # --- 5. FORMAT OUTPUT ---
    feature_vector = [float(features.get(col, 0.0)) for col in FEATURE_COLUMNS]
    return feature_vector


def get_features_dict(url: str, html_content: str = None) -> dict:
    """Returns features as a named dictionary (useful for rule-based scoring)."""
    vector = extract_features(url, html_content)
    return dict(zip(FEATURE_COLUMNS, vector))


# --- TESTING BLOCK ---
if __name__ == "__main__":
    test_url = "https://www.github.com"
    print(f"Extracting features for {test_url}...")
    vector = extract_features(test_url)
    print(f"\nFeature Extraction Complete! Length: {len(vector)}")
    for name, val in zip(FEATURE_COLUMNS, vector):
        print(f"  {name}: {val}")