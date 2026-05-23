
# ═══════════════════════════════════════════════════
# VISUALIZER
# Creates all charts for the Streamlit app
# ═══════════════════════════════════════════════════

import plotly.graph_objects as go
import plotly.express as px
import pandas as pd

def create_risk_gauge(risk_score):
    # Creates a circular gauge showing risk score
    # Green = safe, Yellow = caution, Red = danger

    if risk_score < 30:
        color = 'green'
        label = 'LOW RISK'
    elif risk_score < 60:
        color = 'orange'
        label = 'MEDIUM RISK'
    else:
        color = 'red'
        label = 'HIGH RISK'

    fig = go.Figure(go.Indicator(
        mode='gauge+number',
        value=risk_score,
        title={'text': f'Risk Score<br><span style="font-size:0.8em">{label}</span>'},
        number={'suffix': '%', 'font': {'size': 40}},
        gauge={
            'axis': {
                'range': [0, 100],
                'tickwidth': 1,
                'tickcolor': 'darkblue'
            },
            'bar': {'color': color},
            'bgcolor': 'white',
            'steps': [
                {'range': [0, 30],  'color': '#d4edda'},
                {'range': [30, 60], 'color': '#fff3cd'},
                {'range': [60, 100],'color': '#f8d7da'}
            ],
            'threshold': {
                'line': {'color': 'black', 'width': 4},
                'thickness': 0.75,
                'value': risk_score
            }
        }
    ))

    fig.update_layout(
        height=300,
        margin=dict(l=20, r=20, t=50, b=20)
    )

    return fig

def create_shap_chart(contributions, top_n=10):
    # Creates horizontal bar chart showing
    # which features pushed toward phishing or legitimate

    top = contributions.head(top_n).copy()
    top = top.sort_values('shap_value')

    colors = []
    for val in top['shap_value']:
        if val > 0:
            colors.append('#dc3545')
        else:
            colors.append('#28a745')

    fig = go.Figure(go.Bar(
        x=top['shap_value'],
        y=top['feature'],
        orientation='h',
        marker_color=colors,
        text=[f"{v:.3f}" for v in top['shap_value']],
        textposition='outside'
    ))

    fig.update_layout(
        title='Feature Contributions (SHAP Values)',
        xaxis_title='Impact on Prediction',
        yaxis_title='Feature',
        height=400,
        plot_bgcolor='white',
        paper_bgcolor='white',
        showlegend=False,
        xaxis=dict(
            zeroline=True,
            zerolinecolor='black',
            zerolinewidth=2
        )
    )

    fig.add_annotation(
        x=top['shap_value'].max() * 0.7,
        y=top_n - 1,
        text='→ Phishing',
        showarrow=False,
        font=dict(color='red', size=12)
    )

    fig.add_annotation(
        x=top['shap_value'].min() * 0.7,
        y=top_n - 1,
        text='← Legitimate',
        showarrow=False,
        font=dict(color='green', size=12)
    )

    return fig

def create_feature_table(raw_features):
    # Creates a clean table of key feature values

    key_features = {
        'URL Length':              raw_features.get('url_length', 0),
        'Dot Count':               raw_features.get('dot_count', 0),
        'Hyphen Count':            raw_features.get('hyphen_count', 0),
        'Digit Count':             raw_features.get('digit_count', 0),
        'Has IP Address':          'Yes' if raw_features.get('has_ip_address') == 1 else 'No',
        'Has HTTPS':               'Yes' if raw_features.get('has_https') == 1 else 'No',
        'TLD Suspicious':          'Yes' if raw_features.get('is_tld_suspicious') == 1 else 'No',
        'Brand Impersonation':     'Yes' if raw_features.get('is_brand_impersonation') == 1 else 'No',
        'Closest Brand':           raw_features.get('closest_brand', 'none'),
        'Brand Distance':          raw_features.get('min_brand_distance', 0),
        'Subdomain Count':         raw_features.get('subdomain_count', 0),
        'URL Entropy':             round(raw_features.get('url_entropy', 0), 3),
        'Domain Entropy':          round(raw_features.get('domain_entropy', 0), 3),
        'Suspicious Keywords':     raw_features.get('suspicious_keyword_count', 0),
        'Has Redirect Param':      'Yes' if raw_features.get('has_redirect_param') == 1 else 'No',
        'URL Shortener':           'Yes' if raw_features.get('url_shortener_detected') == 1 else 'No',
    }

    df = pd.DataFrame(
        list(key_features.items()),
        columns=['Feature', 'Value']
    )

    return df

def create_metrics_chart(cv_results):

    import numpy as np
    import plotly.graph_objects as go

    # Mapping actual CV keys to display names
    metric_mapping = {
        'test_accuracy': 'Accuracy',
        'test_f1': 'F1 Score',
        'test_roc_auc': 'ROC-AUC',
        'test_pr_auc': 'PR-AUC',
        'test_mcc': 'MCC'
    }

    metrics = list(metric_mapping.values())

    means = [
        np.mean(cv_results[key])
        for key in metric_mapping.keys()
    ]

    stds = [
        np.std(cv_results[key])
        for key in metric_mapping.keys()
    ]

    fig = go.Figure(go.Bar(
        x=metrics,
        y=means,
        error_y=dict(
            type='data',
            array=stds,
            visible=True
        ),
        marker_color=[
            '#007bff',
            '#28a745',
            '#dc3545',
            '#ffc107',
            '#6f42c1'
        ],
        text=[f"{m:.4f}" for m in means],
        textposition='outside'
    ))

    fig.update_layout(
        title='Cross Validation Performance (5-Fold)',
        yaxis=dict(
            range=[0.95, 1.01],
            title='Score'
        ),
        xaxis_title='Metric',
        height=400,
        plot_bgcolor='white',
        paper_bgcolor='white'
    )

    return fig
