import re
import urllib.parse
import requests
import tldextract
from bs4 import BeautifulSoup
from thefuzz import fuzz

# The exact feature list order expected by your ONNX model
FEATURE_COLUMNS =[
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

def extract_features(url: str, html_content: str = None) -> list:
    """
    Extracts all 48 features from a URL and its HTML content.
    If html_content is None, it will attempt to fetch it via requests.
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
    
    # Regex to check if domain is an IPv4 or IPv6
    ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$|([a-f0-9:]+:+)+[a-f0-9]+')
    features["IsDomainIP"] = 1 if ip_pattern.match(domain) else 0

    # Char Continuation Rate: Length of longest sequence of identical characters / URL length
    max_continuation = max([len(m.group(0)) for m in re.finditer(r'(.)\1*', url)] + [0])
    features["CharContinuationRate"] = max_continuation / len(url) if len(url) > 0 else 0

    # Probabilities (Heuristic estimations since exact dataset formulas require massive lookup tables)
    common_tlds =['com', 'org', 'net', 'edu', 'gov', 'io', 'co']
    features["TLDLegitimateProb"] = 1.0 if tld in common_tlds else 0.1
    features["URLCharProb"] = 1.0 # Placeholder heuristic
    
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
    
    # Special chars not including = ? & and alphanumeric
    special_chars = sum(not c.isalnum() and c not in['=', '?', '&'] for c in url)
    features["NoOfOtherSpecialCharsInURL"] = special_chars
    features["SpacialCharRatioInURL"] = special_chars / len(url) if len(url) > 0 else 0
    
    features["IsHTTPS"] = 1 if parsed_url.scheme == 'https' else 0

    # --- 3. FETCH HTML IF NOT PROVIDED ---
    redirect_count = 0
    self_redirect = 0
    
    if not html_content:
        try:
            # We use a short timeout to keep it somewhat fast
            response = requests.get(url, timeout=3, allow_redirects=True)
            html_content = response.text
            redirect_count = len(response.history)
            
            # Check if redirect was to the same domain
            if redirect_count > 0:
                final_domain = tldextract.extract(response.url).domain
                if final_domain == domain:
                    self_redirect = 1
        except Exception:
            html_content = "" # Failsafe
            
    features["NoOfURLRedirect"] = redirect_count
    features["NoOfSelfRedirect"] = self_redirect

    # --- 4. HTML/CONTENT FEATURES ---
    soup = BeautifulSoup(html_content, 'html.parser')
    html_lines = html_content.split('\n')
    
    features["LineOfCode"] = len(html_lines)
    features["LargestLineLength"] = max([len(line) for line in html_lines] + [0])
    
    title_tag = soup.find('title')
    title_text = title_tag.text.strip().lower() if title_tag else ""
    features["HasTitle"] = 1 if title_tag else 0
    
    # Fuzzy matching for title scores
    features["DomainTitleMatchScore"] = fuzz.ratio(domain.lower(), title_text)
    features["URLTitleMatchScore"] = fuzz.ratio(url.lower(), title_text)
    
    features["HasFavicon"] = 1 if soup.find('link', rel=re.compile("icon", re.I)) else 0
    features["Robots"] = 1 if soup.find('meta', attrs={'name': re.compile("robots", re.I)}) else 0
    features["IsResponsive"] = 1 if soup.find('meta', attrs={'name': re.compile("viewport", re.I)}) else 0
    features["HasDescription"] = 1 if soup.find('meta', attrs={'name': re.compile("description", re.I)}) else 0
    
    # Content counting
    features["NoOfPopup"] = html_content.count('window.open')
    features["NoOfiFrame"] = len(soup.find_all('iframe'))
    
    # Form security analysis
    forms = soup.find_all('form')
    external_forms = 0
    for form in forms:
        action = form.get('action', '').lower()
        if action.startswith('http') and domain not in action:
            external_forms += 1
            
    features["HasExternalFormSubmit"] = 1 if external_forms > 0 else 0
    features["HasSubmitButton"] = 1 if soup.find('input', type='submit') or soup.find('button', type='submit') else 0
    features["HasHiddenFields"] = 1 if soup.find('input', type='hidden') else 0
    features["HasPasswordField"] = 1 if soup.find('input', type='password') else 0
    
    # Keyword detection (Targeted attacks)
    text_content = soup.get_text().lower()
    features["Bank"] = 1 if 'bank' in text_content else 0
    features["Pay"] = 1 if 'pay' in text_content else 0
    features["Crypto"] = 1 if 'crypto' in text_content or 'bitcoin' in text_content else 0
    features["HasCopyrightInfo"] = 1 if 'copyright' in text_content or '©' in text_content else 0
    
    # Resources
    features["NoOfImage"] = len(soup.find_all('img'))
    features["NoOfCSS"] = len(soup.find_all('link', rel='stylesheet'))
    features["NoOfJS"] = len(soup.find_all('script'))
    
    # Links analysis
    links = soup.find_all('a', href=True)
    self_ref = 0
    empty_ref = 0
    ext_ref = 0
    
    for a in links:
        href = a['href']
        if href == "#" or href.startswith("javascript:"):
            empty_ref += 1
        elif href.startswith('/') or domain in href:
            self_ref += 1
        elif href.startswith('http'):
            ext_ref += 1
            
    features["NoOfSelfRef"] = self_ref
    features["NoOfEmptyRef"] = empty_ref
    features["NoOfExternalRef"] = ext_ref

    # --- 5. FORMAT OUTPUT ---
    # Return exactly in the order of FEATURE_COLUMNS as a list of floats
    feature_vector =[float(features.get(col, 0.0)) for col in FEATURE_COLUMNS]
    
    return feature_vector

# --- TESTING BLOCK ---
if __name__ == "__main__":
    test_url = "https://www.github.com"
    print(f"Extracting features for {test_url}...")
    
    vector = extract_features(test_url)
    
    print("\nFeature Extraction Complete! Extracted array length:", len(vector))
    # Print the first 10 just to verify
    for name, val in zip(FEATURE_COLUMNS[:10], vector[:10]):
        print(f"{name}: {val}")