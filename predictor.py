
# ═══════════════════════════════════════════════════
# PREDICTOR
# Loads saved model and generates predictions
# and SHAP explanations for any URL
# ═══════════════════════════════════════════════════

import pickle
import pandas as pd
import numpy as np
from feature_extractor import extract_all_features

# ── LOAD SAVED FILES ─────────────────────────────────

def load_model(model_path='models/final_model.pkl'):
    with open(model_path, 'rb') as f:
        return pickle.load(f)

def load_explainer(explainer_path='models/shap_explainer.pkl'):
    with open(explainer_path, 'rb') as f:
        return pickle.load(f)

def load_feature_columns(columns_path='models/feature_columns.pkl'):
    with open(columns_path, 'rb') as f:
        return pickle.load(f)

def load_cv_results(cv_path='models/cv_results.pkl'):
    with open(cv_path, 'rb') as f:
        return pickle.load(f)

# ── PREDICTION ───────────────────────────────────────

def prepare_features(url, feature_columns):
    # Extract all features from URL
    features = extract_all_features(url)

    # Remove text columns model cannot use
    features.pop('closest_brand', None)
    features.pop('multiple_brands_present', None)

    # Convert to DataFrame
    feature_row = pd.DataFrame([features])

    # Add any missing columns with 0
    for col in feature_columns:
        if col not in feature_row.columns:
            feature_row[col] = 0

    # Ensure correct column order
    feature_row = feature_row[feature_columns]

    return feature_row, features

def predict_url(url, model, feature_columns):

    feature_row, raw_features = prepare_features(url, feature_columns)

    probability = model.predict_proba(feature_row)[0][1]
    prediction = model.predict(feature_row)[0]

    risk_score = round(float(probability) * 100, 1)

    # ── SECURITY OVERRIDE RULES ─────────────────────

    # If clear typosquatting detected
    if raw_features.get('is_brand_impersonation') == 1:
        prediction = 1

    # Raise risk score for very close brand impersonation
    if raw_features.get('min_brand_distance', 10) == 1:
        risk_score = max(risk_score, 85.0)

    return {
        'prediction': int(prediction),
        'risk_score': risk_score,
        'probability': float(probability),
        'is_phishing': bool(prediction == 1),
        'raw_features': raw_features
    }

# ── SHAP EXPLANATION ─────────────────────────────────

def explain_url(url, explainer, feature_columns):
    feature_row, raw_features = prepare_features(url, feature_columns)

    shap_values = explainer.shap_values(feature_row)

    contributions = pd.DataFrame({
        'feature': feature_columns,
        'value': feature_row.values[0],
        'shap_value': shap_values[0]
    })

    contributions['abs_shap'] = contributions['shap_value'].abs()
    contributions = contributions.sort_values('abs_shap', ascending=False)
    contributions = contributions.reset_index(drop=True)

    return contributions

# ── HUMAN READABLE SIGNALS ───────────────────────────

def get_triggered_signals(raw_features):
    signals = []

    if raw_features.get('is_brand_impersonation') == 1:
        brand = raw_features.get('closest_brand', 'a known brand')
        dist = raw_features.get('min_brand_distance', 0)
        signals.append(
            f"Typosquatting detected — domain is {dist} character(s) away from {brand}"
        )

    if raw_features.get('is_tld_suspicious') == 1:
        signals.append(
            "High risk TLD — domain extension commonly used in phishing attacks"
        )

    if raw_features.get('has_ip_address') == 1:
        signals.append(
            "IP address used as domain — no legitimate domain name registered"
        )

    if raw_features.get('brand_in_subdomain') == 1:
        signals.append(
            "Brand name in subdomain — attacker using brand to appear legitimate"
        )

    if raw_features.get('brand_in_path') == 1:
        signals.append(
            "Brand name in URL path — brand hidden in path to deceive users"
        )

    if raw_features.get('has_redirect_param') == 1:
        signals.append(
            "Redirect parameter detected — URL redirects victim to another site after credential theft"
        )

    if raw_features.get('has_phishing_keywords_in_domain') == 1:
        signals.append(
            "Phishing keywords in domain — words like secure, login, verify found in domain name"
        )

    if raw_features.get('url_shortener_detected') == 1:
        signals.append(
            "URL shortener detected — real destination is hidden from the user"
        )

    if raw_features.get('has_port_number') == 1:
        signals.append(
            "Non-standard port number — legitimate websites do not use custom ports"
        )

    if raw_features.get('has_multiple_subdomains') == 1:
        signals.append(
            "Multiple subdomains detected — attackers use deep subdomain chains to hide real domain"
        )

    if raw_features.get('has_suspicious_tld_combination') == 1:
        signals.append(
            "Suspicious TLD combination — attacker adding .com to subdomain to fool users"
        )

    if raw_features.get('has_random_domain') == 1:
        signals.append(
            "Random looking domain — high entropy suggests machine generated phishing domain"
        )

    if raw_features.get('domain_starts_with_number') == 1:
        signals.append(
            "Domain starts with number — legitimate domains almost never start with digits"
        )

    if raw_features.get('has_file_extension') == 1 and raw_features.get('is_suspicious_extension') == 1:
        signals.append(
            "Suspicious file extension — URL points to executable or script file"
        )

    if raw_features.get('has_encoded_characters') == 1:
        signals.append(
            "URL encoded characters in path — attackers encode characters to bypass filters"
        )

    if len(signals) == 0:
        signals.append(
            "Statistical pattern analysis flagged this URL based on combination of subtle signals"
        )

    return signals
