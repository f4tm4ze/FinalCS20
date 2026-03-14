<<<<<<< HEAD
import streamlit as st
import plotly.graph_objects as go
import pandas as pd

@st.cache_data
def format_results(prediction, confidence, model_name):
    """Format analysis results for display"""
    if prediction == 1:
        return {
            "status": "malware",
            "message": "MALWARE DETECTED",
            "color": "#FAC898",
            "text_color": "#A35C5C",
            "threat": "HIGH"
        }
    else:
        return {
            "status": "safe",
            "message": "SAFE",
            "color": "#C1E1C1",
            "text_color": "#2E5C4E",
            "threat": "LOW"
        }

def create_confidence_gauge(confidence):
    """Create a confidence gauge chart"""
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=confidence * 100,
        domain={'x': [0, 1], 'y': [0, 1]},
        title={'text': "Confidence Score"},
        gauge={
            'axis': {'range': [0, 100]},
            'bar': {'color': "#F7CAC9"},
            'steps': [
                {'range': [0, 50], 'color': "#C1E1C1"},
                {'range': [50, 75], 'color': "#FFF2B5"},
                {'range': [75, 100], 'color': "#FAC898"}
            ],
            'threshold': {
                'line': {'color': "red", 'width': 4},
                'thickness': 0.75,
                'value': 90
            }
        }
    ))
    fig.update_layout(height=250, margin=dict(l=10, r=10, t=50, b=10))
    return fig

def safe_file_cleanup(file_path):
    """Safely delete temporary file"""
    import os
    try:
        if os.path.exists(file_path):
            os.unlink(file_path)
    except Exception as e:
        st.warning(f"Could not delete temp file: {e}")
=======
import streamlit as st
import plotly.graph_objects as go
import pandas as pd

@st.cache_data
def format_results(prediction, confidence, model_name):
    """Format analysis results for display"""
    if prediction == 1:
        return {
            "status": "malware",
            "message": "MALWARE DETECTED",
            "color": "#FAC898",
            "text_color": "#A35C5C",
            "threat": "HIGH"
        }
    else:
        return {
            "status": "safe",
            "message": "SAFE",
            "color": "#C1E1C1",
            "text_color": "#2E5C4E",
            "threat": "LOW"
        }

def create_confidence_gauge(confidence):
    """Create a confidence gauge chart"""
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=confidence * 100,
        domain={'x': [0, 1], 'y': [0, 1]},
        title={'text': "Confidence Score"},
        gauge={
            'axis': {'range': [0, 100]},
            'bar': {'color': "#F7CAC9"},
            'steps': [
                {'range': [0, 50], 'color': "#C1E1C1"},
                {'range': [50, 75], 'color': "#FFF2B5"},
                {'range': [75, 100], 'color': "#FAC898"}
            ],
            'threshold': {
                'line': {'color': "red", 'width': 4},
                'thickness': 0.75,
                'value': 90
            }
        }
    ))
    fig.update_layout(height=250, margin=dict(l=10, r=10, t=50, b=10))
    return fig

def safe_file_cleanup(file_path):
    """Safely delete temporary file"""
    import os
    try:
        if os.path.exists(file_path):
            os.unlink(file_path)
    except Exception as e:
        st.warning(f"Could not delete temp file: {e}")
>>>>>>> 2b51d82368086acbb8f187ee36bf08591a96c1a9
