import os
import requests
from flask import Flask, request, jsonify, redirect, session, url_for
from flask_cors import CORS
from dotenv import load_dotenv
from urllib.parse import urlencode

# Load environment variables
load_dotenv()

app = Flask(__name__)

# --- NEW: Configuration for OAuth 2.0 and Flask Sessions ---
# A strong, random secret key is required for Flask sessions
app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY', 'your-fallback-secret-key-CHANGE-ME')
CORS(app, supports_credentials=True)

# HubSpot OAuth 2.0 credentials
HUBSPOT_CLIENT_ID = os.getenv('HUBSPOT_CLIENT_ID')
HUBSPOT_CLIENT_SECRET = os.getenv('HUBSPOT_CLIENT_SECRET')
# This must match *exactly* what you set in your HubSpot App settings
HUBSPOT_REDIRECT_URI = os.getenv('HUBSPOT_REDIRECT_URI', 'http://localhost:5000/oauth-callback')

# HubSpot API endpoints
HUBSPOT_AUTH_URL = "https://app.hubspot.com/oauth/authorize"
HUBSPOT_TOKEN_URL = "https://api.hubapi.com/oauth/v1/token"
HUBSPOT_API_BASE_URL = "https://api.hubapi.com/crm/v3"

# Scopes required by this app
# Make sure these match the scopes in your HubSpot App settings
# -- "Tickets" scopes removed as they are not supported by all plans --
SCOPES = [
    "crm.objects.contacts.read",
    "crm.objects.contacts.write",
    "crm.objects.companies.read",
    "crm.objects.companies.write",
    "crm.objects.deals.read",
    "crm.objects.deals.write"
]

# --- Helper Function ---

def get_auth_headers():
    """
    Checks if a user's access token is in the session and returns auth headers.
    If not, returns None.
    """
    if 'hubspot_access_token' not in session:
        return None
    
    # TODO: Add logic here to check if the token is expired and use the
    # refresh_token to get a new one. For this example, we assume it's valid.
    
    access_token = session['hubspot_access_token']
    return {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json'
    }

def is_authenticated():
    """Simple check if user has an access token in their session."""
    return 'hubspot_access_token' in session

# --- NEW: OAuth 2.0 Routes ---

@app.route('/')
def index():
    """
    Main page. Shows a "Connect" button if not authenticated,
    or a "View Contacts" link if authenticated.
    """
    if is_authenticated():
        return (
            '<h1>You are connected to HubSpot!</h1>'
            '<p><a href="/contacts">View Contacts</a></p>'
            '<p><a href="/companies">View Companies</a></a href="/deals"></p>'
            '<p><a href="/deals">View Deals</a></p>'
            '<p><a href="/logout">Logout</a></p>'
        )
    else:
        return '<h1>HubSpot OAuth 2.0 Connect</h1>' \
               '<a href="/auth/hubspot">Connect to HubSpot</a>'

@app.route('/auth/hubspot')
def auth_hubspot():
    """
    Step 1: Redirect the user to HubSpot's authorization page.
    """
    auth_params = {
        'client_id': HUBSPOT_CLIENT_ID,
        'redirect_uri': HUBSPOT_REDIRECT_URI,
        'scope': ' '.join(SCOPES),
    }
    auth_url = f"{HUBSPOT_AUTH_URL}?{urlencode(auth_params)}"
    return redirect(auth_url)

@app.route('/oauth-callback')
def oauth_callback():
    """
    Step 2: HubSpot redirects back here with a 'code'.
    Exchange this code for an access token.
    """
    auth_code = request.args.get('code')
    if not auth_code:
        return "Error: No authorization code provided.", 400

    token_payload = {
        'grant_type': 'authorization_code',
        'client_id': HUBSPOT_CLIENT_ID,
        'client_secret': HUBSPOT_CLIENT_SECRET,
        'redirect_uri': HUBSPOT_REDIRECT_URI,
        'code': auth_code,
    }
    
    try:
        response = requests.post(HUBSPOT_TOKEN_URL, data=token_payload)
        response.raise_for_status()  # Raise an exception for bad status codes
        
        token_data = response.json()
        
        # Store tokens securely in the user's session
        session['hubspot_access_token'] = token_data['access_token']
        session['hubspot_refresh_token'] = token_data['refresh_token']
        session['hubspot_expires_in'] = token_data['expires_in']
        
        return redirect(url_for('index'))
        
    except requests.exceptions.RequestException as e:
        return f"Error exchanging code for token: {e} <br> {e.response.text}", 500

@app.route('/logout')
def logout():
    """Clear the user's session."""
    session.clear()
    return redirect(url_for('index'))


# --- UPDATED: API Routes (Now require user authentication) ---
# These routes now rely on the access token stored in the session.

@app.route('/contacts', methods=['GET'])
def get_contacts():
    headers = get_auth_headers()
    if not headers:
        return jsonify({"error": "Not authenticated. Please visit /auth/hubspot"}), 401

    try:
        url = f"{HUBSPOT_API_BASE_URL}/objects/contacts"
        params = {"properties": "email,firstname,lastname"}
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()
        return jsonify(response.json())
        
    except requests.exceptions.RequestException as e:
        return jsonify({"error": str(e), "response": e.response.text}), e.response.status_code

@app.route('/contacts', methods=['POST'])
def create_contact():
    headers = get_auth_headers()
    if not headers:
        return jsonify({"error": "Not authenticated"}), 401
        
    data = request.json
    if not data or 'email' not in data:
        return jsonify({"error": "Email is required"}), 400

    payload = {
        "properties": {
            "email": data.get('email'),
            "firstname": data.get('firstname'),
            "lastname": data.get('lastname')
        }
    }

    try:
        url = f"{HUBSPOT_API_BASE_URL}/objects/contacts"
        response = requests.post(url, json=payload, headers=headers)
        response.raise_for_status()
        return jsonify(response.json()), 201
        
    except requests.exceptions.RequestException as e:
        return jsonify({"error": str(e), "response": e.response.text}), e.response.status_code

# --- Other CRM Object Routes (Companies, Deals) ---

@app.route('/companies', methods=['GET'])
def get_companies():
    headers = get_auth_headers()
    if not headers:
        return jsonify({"error": "Not authenticated"}), 401
        
    try:
        url = f"{HUBSPOT_API_BASE_URL}/objects/companies"
        params = {"properties": "name,domain,city,phone"}
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()
        return jsonify(response.json())
    except requests.exceptions.RequestException as e:
        return jsonify({"error": str(e), "response": e.response.text}), e.response.status_code

@app.route('/deals', methods=['GET'])
def get_deals():
    headers = get_auth_headers()
    if not headers:
        return jsonify({"error": "Not authenticated"}), 401
        
    try:
        url = f"{HUBSPOT_API_BASE_URL}/objects/deals"
        params = {"properties": "dealname,amount,dealstage,closedate"}
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()
        return jsonify(response.json())
    except requests.exceptions.RequestException as e:
        return jsonify({"error": str(e), "response": e.response.text}), e.response.status_code

# --- (POST routes for companies, deals, tickets removed for brevity) ---
# --- (But can be added following the /contacts POST pattern) ---


if __name__ == '__main__':
    if not HUBSPOT_CLIENT_ID or not HUBSPOT_CLIENT_SECRET:
        print("Error: HUBSPOT_CLIENT_ID and HUBSPOT_CLIENT_SECRET must be set.")
    else:
        app.run(debug=True, port=5000)

