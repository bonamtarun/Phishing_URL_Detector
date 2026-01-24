from flask import Flask, request, jsonify
from flask_cors import CORS
import re
import urllib.parse

app = Flask(__name__)
CORS(app)

# Simplified phishing detection using heuristics
def analyze_url(url):
    """
    Analyze URL for phishing indicators using heuristic rules
    Returns: (is_suspicious, confidence, reasons)
    """
    suspicious_indicators = []
    score = 0
    
    # Parse URL
    try:
        parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc.lower()
        path = parsed.path.lower()
        
        # Check 1: IP address instead of domain name
        if re.search(r'(\d{1,3}\.){3}\d{1,3}', domain):
            suspicious_indicators.append("Uses IP address instead of domain name")
            score += 30
        
        # Check 2: Excessive length
        if len(url) > 75:
            suspicious_indicators.append("Unusually long URL")
            score += 15
        
        # Check 3: Invalid characters in domain (CRITICAL - domains can't have special chars)
        # Valid domain characters: a-z, 0-9, hyphens, dots
        invalid_domain_chars = ['$', '!', '%', '^', '&', '*', '(', ')', '=', '+', '[', ']', '{', '}', '|', '\\', '/', '?', '<', '>', ',', '~', '`', '#']
        found_invalid = [char for char in invalid_domain_chars if char in domain]
        if found_invalid:
            suspicious_indicators.append(f"Invalid characters in domain: {', '.join(found_invalid)}")
            score += 35
        
        # Check 3b: Suspicious characters (for URL path/params)
        suspicious_chars = ['@']
        char_count = sum(url.count(char) for char in suspicious_chars)
        if char_count > 0:
            suspicious_indicators.append("Contains suspicious @ character (possible credential stealing)")
            score += 30
        
        # Check 4: Protocol validation
        if not url.startswith('http://') and not url.startswith('https://'):
            suspicious_indicators.append("Invalid protocol (not HTTP/HTTPS)")
            score += 35
        elif not url.startswith('https://'):
            suspicious_indicators.append("Not using secure HTTPS protocol")
            score += 45  # Increased from 25 to ensure HTTP URLs are flagged as suspicious
        
        # Check 5: Typosquatting / Brand impersonation (CRITICAL)
        famous_brands = {
            'google': ['g00gle', 'gogle', 'goog1e', 'go-gle', 'g0ogle', 'googl3', 'gooogle', 'go-$ogle', 'g00g1e'],
            'facebook': ['faceb00k', 'facebok', 'facebo0k', 'face-book', 'fac3book', 'faceb00k'],
            'amazon': ['amaz0n', 'amazom', 'amzon', 'ama-zon', 'amazonn', 'amaz00n'],
            'paypal': ['paypai', 'paypa1', 'pay-pal', 'pypal', 'paypall', 'p4ypal'],
            'microsoft': ['micros0ft', 'microsfot', 'micro-soft', 'micr0soft', 'micr0s0ft'],
            'apple': ['app1e', 'appl3', 'appie', 'app-le', 'appl€'],
            'netflix': ['netfl1x', 'netf1ix', 'net-flix', 'netfiix', 'n3tflix'],
            'instagram': ['1nstagram', 'instgram', 'insta-gram', 'inst4gram', 'inst@gram']
        }
        
        domain_name = domain.split('.')[0] if domain else ''
        
        # First check for exact typosquatting matches
        for brand, typos in famous_brands.items():
            # Check for exact brand name typosquatting
            if domain_name in typos:
                suspicious_indicators.append(f"Typosquatting: impersonates '{brand}'")
                score += 40
                break
            # Check for brand name with substitutions in full domain
            for typo in typos:
                if typo in domain:
                    suspicious_indicators.append(f"Possible brand impersonation: '{brand}'")
                    score += 35
                    break
        
        # Second check: Use pattern matching for character substitutions
        # Remove invalid chars and check if it matches a brand name
        # BUT: exclude exact matches (don't flag the real google.com as typosquatting!)
        cleaned_domain = domain_name.replace('-', '').replace('$', 'o').replace('0', 'o').replace('1', 'l').replace('3', 'e').replace('@', 'a')
        for brand in famous_brands.keys():
            # CRITICAL: Only flag if domain_name is NOT exactly the brand name
            if domain_name != brand and cleaned_domain != brand:
                # Check if cleaned domain is very similar to brand name
                if brand in cleaned_domain or cleaned_domain in brand:
                    # Make sure we haven't already flagged this
                    if not any(brand in ind for ind in suspicious_indicators):
                        suspicious_indicators.append(f"Character substitution typosquatting: impersonates '{brand}'")
                        score += 40
                        break
        
        # Check 6: Suspicious keywords
        phishing_keywords = ['login', 'verify', 'account', 'update', 'secure', 'banking', 
                            'paypal', 'ebay', 'amazon', 'signin', 'confirm']
        found_keywords = [kw for kw in phishing_keywords if kw in url.lower()]
        if len(found_keywords) > 1:
            suspicious_indicators.append(f"Contains suspicious keywords: {', '.join(found_keywords)}")
            score += 30
        elif len(found_keywords) == 1:
            suspicious_indicators.append(f"Contains suspicious keyword: {found_keywords[0]}")
            score += 15
        
        # Check 6: Multiple subdomains
        subdomain_count = domain.count('.')
        if subdomain_count > 3:
            suspicious_indicators.append("Too many subdomains")
            score += 15
        
        # Check 7: Suspicious TLDs (expanded list)
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work', 
                          '.co', '.info', '.biz', '.club', '.online', '.site']
        if any(domain.endswith(tld) for tld in suspicious_tlds):
            suspicious_indicators.append("Uses suspicious top-level domain")
            score += 25
        
        # Check 8: Gibberish/Random domain name detection
        # Extract the main domain name (without TLD)
        domain_parts = domain.split('.')
        if len(domain_parts) >= 2:
            main_domain = domain_parts[-2]  # Get the part before the TLD
            gibberish_score = 0
            gibberish_reasons = []
            
            if len(main_domain) >= 6:
                # Check 1: Consonant clusters (multiple consonants in a row)
                vowels = 'aeiou'
                consonant_cluster_count = 0
                current_cluster = 0
                for char in main_domain:
                    if char.isalpha() and char not in vowels:
                        current_cluster += 1
                        if current_cluster >= 3:  # 3+ consonants in a row
                            consonant_cluster_count += 1
                    else:
                        current_cluster = 0
                
                if consonant_cluster_count >= 2:
                    gibberish_reasons.append("multiple consonant clusters")
                    gibberish_score += 15
                
                # Check 2: Repeating patterns (like "nfg" appearing multiple times)
                for i in range(2, len(main_domain) // 2 + 1):
                    pattern = main_domain[:i]
                    if main_domain.count(pattern) >= 2:
                        gibberish_reasons.append(f"repeating pattern '{pattern}'")
                        gibberish_score += 20
                        break
                
                # Check 3: Very low unique character ratio
                unique_ratio = len(set(main_domain)) / len(main_domain)
                if unique_ratio < 0.5:  # Less than 50% unique characters
                    gibberish_reasons.append("high character repetition")
                    gibberish_score += 15
                
                # Check 4: Random-looking character distribution (entropy check)
                # Check if domain looks like keyboard mashing
                common_words = ['google', 'facebook', 'amazon', 'twitter', 'github', 
                               'microsoft', 'apple', 'yahoo', 'reddit', 'youtube']
                is_common = any(word in main_domain for word in common_words)
                
                if not is_common and len(main_domain) >= 8:
                    # Check for unusual character sequences
                    unusual_sequences = ['nfg', 'qwer', 'asdf', 'zxcv', 'hjkl']
                    if any(seq in main_domain for seq in unusual_sequences):
                        gibberish_reasons.append("keyboard-mashing pattern")
                        gibberish_score += 25
            
            # Apply gibberish detection if score is high enough
            if gibberish_score >= 20:
                suspicious_indicators.append(f"Domain appears random/gibberish ({', '.join(gibberish_reasons)})")
                score += gibberish_score
        
        # Check 9: Very short domain names (often used in phishing)
        if len(domain_parts) >= 2:
            main_domain = domain_parts[-2]
            if len(main_domain) <= 3 and not main_domain in ['www', 'api', 'app', 'web']:
                suspicious_indicators.append("Unusually short domain name")
                score += 20
        
        # Check 10: URL shorteners (CRITICAL - these hide the real destination)
        shorteners = ['bit.ly', 'tinyurl', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly', 'adf.ly']
        if any(shortener in domain for shortener in shorteners):
            suspicious_indicators.append("Uses URL shortening service (hides real destination)")
            score += 35
        
        # Determine result - LOWERED THRESHOLD for better security
        if score >= 35:  # Changed from 50 to 35 for stricter detection
            return True, score, suspicious_indicators
        else:
            return False, score, suspicious_indicators
            
    except Exception as e:
        return True, 100, [f"Invalid URL format: {str(e)}"]

@app.route('/check_url', methods=['POST'])
def check_url():
    try:
        data = request.get_json()
        url = data.get("url")
        
        if not url:
            return jsonify({"result": "Invalid input: No URL provided"}), 400
        
        # Analyze the URL
        is_suspicious, confidence, indicators = analyze_url(url)
        
        if is_suspicious:
            result = "🚨 Suspicious URL - Don't open!"
            if indicators:
                result += "\n\nReasons:\n• " + "\n• ".join(indicators)
        else:
            result = "✅ Safe URL"
            if indicators:
                result += "\n\nMinor concerns:\n• " + "\n• ".join(indicators)
        
        return jsonify({"result": result})
        
    except Exception as e:
        return jsonify({"result": f"Error analyzing URL: {str(e)}"}), 500

@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "running", "message": "Phishing URL Detector API is active"})

if __name__ == "__main__":
    import os
    port = int(os.environ.get('PORT', 5000))
    print("=" * 60)
    print("🛡️  Phishing URL Detector - Backend Server")
    print("=" * 60)
    print(f"Server starting on port {port}")
    print("=" * 60)
    app.run(debug=False, host='0.0.0.0', port=port)
