# main.py
import anthropic
import json
import os
import time
import urllib.parse
import requests
import hashlib
# hmac and base64 are not explicitly used in the final logic, but were in the original imports.
# If they were intended for a specific security feature not fully implemented (like request signing),
# they can be kept or removed if truly unused. For now, I'll keep them as per original.
import hmac
import base64

from fastapi import FastAPI, Request, Response, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
import uvicorn # For local execution
from typing import Dict, Any, Optional, List
from pydantic import BaseModel

# --- Configuration ---
# Load environment variables. These MUST be set in your deployment environment (e.g., Render).
WHATSAPP_PHONE_NUMBER_ID = os.environ.get('WHATSAPP_PHONE_NUMBER_ID')
WHATSAPP_ACCESS_TOKEN = os.environ.get('WHATSAPP_ACCESS_TOKEN')
WHATSAPP_WEBHOOK_VERIFY_TOKEN = os.environ.get('WHATSAPP_WEBHOOK_VERIFY_TOKEN')
ANTHROPIC_API_KEY = os.environ.get('ANTHROPIC_API_KEY')
LINKEDIN_CLIENT_ID = os.environ.get('LINKEDIN_CLIENT_ID')
LINKEDIN_CLIENT_SECRET = os.environ.get('LINKEDIN_CLIENT_SECRET')

# APP_BASE_URL will be like 'https://your-app-name.onrender.com' in production
# or 'http://localhost:8000' for local development if not set in local env.
# Ensure the /callback path is included if it's part of your redirect URI.
APP_BASE_URL_CONFIG = os.environ.get("APP_BASE_URL", "http://localhost:8000")
# The redirect URI for LinkedIn should be APP_BASE_URL_CONFIG + "/callback"
LINKEDIN_REDIRECT_URI = f"{APP_BASE_URL_CONFIG}/callback"


# --- Validate Critical Environment Variables ---
CRITICAL_ENV_VARS = {
    "WHATSAPP_PHONE_NUMBER_ID": WHATSAPP_PHONE_NUMBER_ID,
    "WHATSAPP_ACCESS_TOKEN": WHATSAPP_ACCESS_TOKEN,
    "WHATSAPP_WEBHOOK_VERIFY_TOKEN": WHATSAPP_WEBHOOK_VERIFY_TOKEN,
    "ANTHROPIC_API_KEY": ANTHROPIC_API_KEY,
    "LINKEDIN_CLIENT_ID": LINKEDIN_CLIENT_ID,
    "LINKEDIN_CLIENT_SECRET": LINKEDIN_CLIENT_SECRET,
    "APP_BASE_URL": APP_BASE_URL_CONFIG
}

missing_vars = [key for key, value in CRITICAL_ENV_VARS.items() if value is None]
if missing_vars:
    error_message = f"Missing critical environment variables: {', '.join(missing_vars)}. Please set them before running the application."
    print(f"ERROR: {error_message}")
    # In a production scenario, you might want to raise an exception or exit
    # raise ValueError(error_message)


# --- Initialize Anthropic Client ---
# Check if ANTHROPIC_API_KEY is loaded before initializing
if ANTHROPIC_API_KEY:
    client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
else:
    client = None
    print("WARNING: ANTHROPIC_API_KEY not found. Post generation will not work.")

# --- System Prompt for Post Generation ---
SYSTEM_PROMPT = '''You are a professional LinkedIn content creator that crafts engaging, professional posts for professionals.

Your task is to:
- Transform the user's input into a polished, engaging LinkedIn post
- Create content that sounds authentic and professional
- Include relevant hashtags that will maximize post visibility
- Format the post appropriately for LinkedIn (proper paragraph breaks, emojis where appropriate)
- Keep the tone professional but conversational
- Generate posts that encourage engagement (likes, comments, shares)
- Adapt to the user's industry and preferences
- IMPORTANT: Post like an actual human, no such things in actual post such as "Here's your LinkedIn post:"
- IMPORTANT: no use of emoji unless specifically requested or highly appropriate for the context. Prioritize professionalism.

Each post should be under 3,000 characters (LinkedIn's limit) and optimized for engagement.'''

# --- In-memory Storage (Consider a database for production) ---
user_conversations: Dict[str, List[Dict[str, str]]] = {}
pending_posts: Dict[str, str] = {}
user_tokens: Dict[str, Dict[str, Any]] = {}
user_states: Dict[str, Optional[str]] = {}
oauth_states: Dict[str, str] = {}

# --- FastAPI App Initialization ---
app = FastAPI(title="LinkedIn WhatsApp Bot", version="1.0.0")

# --- CORS Middleware ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Pydantic Models for Request/Response Validation ---
class WebhookVerification(BaseModel):
    mode: str
    verify_token: str
    challenge: str

# --- LinkedIn OAuth Functions ---
def get_oauth_url(phone_number: str) -> str:
    """Generate LinkedIn OAuth authorization URL using OIDC scopes"""
    redirect_uri = LINKEDIN_REDIRECT_URI # Use the globally defined redirect URI
    
    raw_state = f"{phone_number}_{int(time.time())}"
    state_hash = hashlib.sha256(raw_state.encode()).hexdigest()
    oauth_states[state_hash] = phone_number
    
    auth_params = {
        "response_type": "code",
        "client_id": LINKEDIN_CLIENT_ID,
        "redirect_uri": redirect_uri,
        "state": state_hash,
        "scope": "openid profile w_member_social"
    }
    
    params_str = "&".join([f"{key}={urllib.parse.quote(str(value))}" for key, value in auth_params.items()])
    return f"https://www.linkedin.com/oauth/v2/authorization?{params_str}"

def get_access_token(authorization_code: str) -> Optional[Dict[str, Any]]:
    """Exchange authorization code for access token"""
    token_url = "https://www.linkedin.com/oauth/v2/accessToken"
    redirect_uri = LINKEDIN_REDIRECT_URI # Must match the one used in get_oauth_url
    
    payload = {
        "grant_type": "authorization_code",
        "code": authorization_code,
        "redirect_uri": redirect_uri,
        "client_id": LINKEDIN_CLIENT_ID,
        "client_secret": LINKEDIN_CLIENT_SECRET
    }
    
    try:
        response = requests.post(token_url, data=payload)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        error_text = response.text if 'response' in locals() and hasattr(response, 'text') else "N/A"
        print(f"Error getting access token: {e} - Response: {error_text}")
        return None

def get_linkedin_user_id(access_token: str) -> Optional[str]:
    """Get the LinkedIn user ID (URN 'sub' field) using the access token via OIDC userinfo endpoint"""
    url = "https://api.linkedin.com/v2/userinfo"
    headers = {"Authorization": f"Bearer {access_token}"}
    
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()
        return data.get("sub")
    except requests.exceptions.RequestException as e:
        error_text = response.text if 'response' in locals() and hasattr(response, 'text') else "N/A"
        print(f"Error getting LinkedIn user ID: {e} - Response: {error_text}")
        return None

def post_to_linkedin(phone_number: str, content: str) -> tuple[bool, str]:
    """Post content to LinkedIn using the LinkedIn API."""
    if phone_number not in user_tokens:
        return False, "You need to authenticate with LinkedIn first. Send 'auth' to begin."
    
    token_data = user_tokens[phone_number]
    access_token = token_data.get("access_token")
    linkedin_id_sub = token_data.get("linkedin_id_sub")
    
    if not access_token:
        return False, "Authentication token not found. Please send 'auth' to reconnect."
    if not linkedin_id_sub:
        return False, "LinkedIn User ID (sub) not found. Please try reconnecting by sending 'auth'."
    
    if time.time() > token_data.get("expires_at", 0):
        return False, "Your LinkedIn token has expired. Please send 'auth' to reconnect."
    
    try:
        url = "https://api.linkedin.com/v2/ugcPosts"
        person_urn = f"urn:li:person:{linkedin_id_sub}"
        
        payload = {
            "author": person_urn,
            "lifecycleState": "PUBLISHED",
            "specificContent": {
                "com.linkedin.ugc.ShareContent": {
                    "shareCommentary": {"text": content},
                    "shareMediaCategory": "NONE"
                }
            },
            "visibility": {"com.linkedin.ugc.MemberNetworkVisibility": "PUBLIC"}
        }
        
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
            "X-Restli-Protocol-Version": "2.0.0",
            "LinkedIn-Version": "202402" # Adjust if LinkedIn updates their recommended version
        }
        
        response = requests.post(url, headers=headers, json=payload)
        
        if response.status_code == 201:
            return True, "Post successfully created on LinkedIn!"
        else:
            error_details = response.text
            try:
                error_json = response.json()
                error_details = json.dumps(error_json, indent=2)
            except json.JSONDecodeError:
                pass
            print(f"LinkedIn API Error: {response.status_code} - {error_details}")
            return False, f"Error posting to LinkedIn (Status {response.status_code}). Details: {error_details[:200]}"
            
    except Exception as e:
        print(f"Exception during LinkedIn post: {e}")
        return False, f"An exception occurred while posting: {str(e)}"

# --- WhatsApp API Functions ---
def send_whatsapp_message(to: str, message_text: str) -> tuple[bool, Any]:
    if not WHATSAPP_PHONE_NUMBER_ID or not WHATSAPP_ACCESS_TOKEN:
        print("WhatsApp API credentials not configured.")
        return False, "WhatsApp API credentials not configured."

    url = f"https://graph.facebook.com/v17.0/{WHATSAPP_PHONE_NUMBER_ID}/messages" # Consider updating API version if needed
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {WHATSAPP_ACCESS_TOKEN}"
    }
    payload = {
        "messaging_product": "whatsapp",
        "recipient_type": "individual",
        "to": to,
        "type": "text",
        "text": {"body": message_text}
    }
    
    try:
        response = requests.post(url, headers=headers, json=payload)
        response.raise_for_status()
        return True, response.json()
    except requests.exceptions.RequestException as e:
        error_text = response.text if 'response' in locals() and hasattr(response, 'text') else str(e)
        print(f"Error sending WhatsApp message: {e} - Response: {error_text}")
        return False, error_text

def send_whatsapp_interactive_buttons(to: str, message_text: str, buttons: List[Dict[str, str]]) -> tuple[bool, Any]:
    if not WHATSAPP_PHONE_NUMBER_ID or not WHATSAPP_ACCESS_TOKEN:
        print("WhatsApp API credentials not configured.")
        return False, "WhatsApp API credentials not configured."

    url = f"https://graph.facebook.com/v22.0/{WHATSAPP_PHONE_NUMBER_ID}/messages" # Using a recent version
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {WHATSAPP_ACCESS_TOKEN}"
    }
    
    button_objects = [{"type": "reply", "reply": button} for button in buttons]
    
    payload = {
        "messaging_product": "whatsapp",
        "recipient_type": "individual",
        "to": to,
        "type": "interactive",
        "interactive": {
            "type": "button",
            "body": {"text": message_text},
            "action": {"buttons": button_objects}
        }
    }
    
    try:
        response = requests.post(url, headers=headers, json=payload)
        response.raise_for_status()
        return True, response.json()
    except requests.exceptions.RequestException as e:
        error_text = response.text if 'response' in locals() and hasattr(response, 'text') else str(e)
        print(f"Error sending WhatsApp interactive message: {e} - Response: {error_text}")
        return False, error_text

# --- Message Handling Logic ---
async def handle_message(phone_number: str, message_text: str):
    lower_text = message_text.lower().strip()
    current_user_state = user_states.get(phone_number)

    if current_user_state == "awaiting_edit" and phone_number in pending_posts:
        pending_posts[phone_number] = message_text
        buttons = [
            {"id": "approve", "title": "✅ Approve & Post"},
            {"id": "cancel", "title": "❌ Cancel"}
        ]
        send_whatsapp_interactive_buttons(
            phone_number,
            f"📝 EDITED LinkedIn post (Character count: {len(message_text)}/3,000):\n\n{message_text}",
            buttons
        )
        user_states[phone_number] = None
        return

    elif current_user_state == "awaiting_regeneration_prompt":
        if phone_number not in user_conversations: user_conversations[phone_number] = []
        user_conversations[phone_number].append({
            "role": "user",
            "content": f"Please regenerate based on the previous idea, but with these considerations: {message_text}"
        })
        user_states[phone_number] = None
        send_whatsapp_message(phone_number, "🔄 Regenerating your LinkedIn post with new considerations...")
        await generate_post(phone_number)
        return

    if lower_text == "start" or lower_text == "help":
        welcome_message = """👋 Welcome to the LinkedIn Post Generator!

I'll help you create professional LinkedIn posts. Just send me:
- Your post idea or topic
- Any specific points
- Target audience (optional)

Commands:
- "auth": Connect your LinkedIn account
- "help": Show this message
- "cancel": Cancel current operation

To get started, send "auth" or your post idea!"""
        send_whatsapp_message(phone_number, welcome_message)

    elif lower_text == "auth":
        if not LINKEDIN_CLIENT_ID:
            send_whatsapp_message(phone_number, "LinkedIn integration is not configured on the server.")
            return
        auth_url = get_oauth_url(phone_number)
        auth_message = f"""🔗 To connect your LinkedIn account, please click this link:
{auth_url}

Once you authorize the app, you'll be automatically connected. No need to copy any code!
Just return to WhatsApp when you see the success message."""
        send_whatsapp_message(phone_number, auth_message)

    # REMOVED: elif lower_text.startswith("code:") because OAuth callback now handles it.

    elif lower_text == "cancel":
        if phone_number in pending_posts: del pending_posts[phone_number]
        user_states[phone_number] = None
        send_whatsapp_message(phone_number, "Operation cancelled. Ready for a new idea!")

    elif lower_text == "regenerate":
        if phone_number not in user_conversations or not user_conversations[phone_number]:
            send_whatsapp_message(phone_number, "There's no previous post context to regenerate. Please send an idea first.")
            return
        if user_conversations[phone_number] and user_conversations[phone_number][-1]["role"] == "assistant":
            user_conversations[phone_number].pop()
        send_whatsapp_message(phone_number, "🔄 To regenerate, please provide specific changes or type 'simple' for a new take on the last idea.")
        user_states[phone_number] = "awaiting_regeneration_prompt"

    elif lower_text == "edit":
        if phone_number in pending_posts:
            send_whatsapp_message(phone_number, f"Current post:\n\n{pending_posts[phone_number]}\n\nPlease send your complete edited version of the post:")
            user_states[phone_number] = "awaiting_edit"
        else:
            send_whatsapp_message(phone_number, "No pending post found to edit. Send an idea first!")
            
    else:
        if phone_number not in user_conversations: user_conversations[phone_number] = []
        user_conversations[phone_number].append({"role": "user", "content": message_text})
        send_whatsapp_message(phone_number, "🔄 Generating your LinkedIn post... This might take a moment.")
        await generate_post(phone_number)

async def generate_post(phone_number: str):
    if not client:
        send_whatsapp_message(phone_number, "Sorry, the post generation service is currently unavailable (Anthropic API key missing).")
        return

    if phone_number not in user_conversations or not user_conversations[phone_number]:
        send_whatsapp_message(phone_number, "Please provide a topic or idea for your LinkedIn post first.")
        return
        
    try:
        response = client.messages.create(
            model="claude-3-sonnet-20240229", 
            max_tokens=1024,
            temperature=0.7,
            system=SYSTEM_PROMPT,
            messages=user_conversations[phone_number]
        ).content[0].text
        
        user_conversations[phone_number].append({"role": "assistant", "content": response})
        pending_posts[phone_number] = response
        
        send_whatsapp_message(
            phone_number,
            f"📝 Here's your LinkedIn post (Character count: {len(response)}/3,000):\n\n{response}"
        )
        
        buttons = [
            {"id": "approve", "title": "✅ Approve & Post"},
            {"id": "regenerate_btn", "title": "🔄 Regenerate"},
            {"id": "edit_btn", "title": "✏️ Edit"},
            {"id": "cancel_btn", "title": "❌ Cancel"}
        ]

        send_whatsapp_interactive_buttons(
            phone_number,
            "What would you like to do?",
            buttons[:3] 
        )
        if len(buttons) > 3:
             send_whatsapp_interactive_buttons(
                phone_number,
                "More options:",
                [buttons[3]]
            )

    except Exception as e:
        print(f"Error generating post with Anthropic: {e}")
        send_whatsapp_message(phone_number, "Sorry, I encountered an error while generating your post. Please try again.")

async def handle_button_click(phone_number: str, button_id: str):
    if button_id == "approve":
        if phone_number in pending_posts:
            post_content = pending_posts[phone_number]
            send_whatsapp_message(phone_number, f"🚀 Posting to LinkedIn...\n\n'{post_content[:100]}...'")
            success, message = post_to_linkedin(phone_number, post_content)
            
            response_message = f"{message}\n\n"
            if success:
                response_message = f"✅ Your post has been successfully published!\n{message}\n\n---\n'{post_content[:100]}...'"
                del pending_posts[phone_number]
            else:
                response_message = f"❌ Direct posting failed.\nReason: {message}\n\nYou can copy and paste this to post manually:\n\n{post_content}"
            send_whatsapp_message(phone_number, response_message)
        else:
            send_whatsapp_message(phone_number, "No pending post found to approve.")

    elif button_id == "regenerate_btn":
        if phone_number not in user_conversations or not user_conversations[phone_number]:
            send_whatsapp_message(phone_number, "There's no previous post context to regenerate. Please send an idea first.")
            return
        if user_conversations[phone_number] and user_conversations[phone_number][-1]["role"] == "assistant":
            user_conversations[phone_number].pop()
        send_whatsapp_message(phone_number, "🔄 To regenerate, please provide specific changes or type 'simple' for a new take on the last idea.")
        user_states[phone_number] = "awaiting_regeneration_prompt"

    elif button_id == "edit_btn":
        if phone_number in pending_posts:
            send_whatsapp_message(phone_number, f"Current post:\n\n{pending_posts[phone_number]}\n\nPlease send your complete edited version of the post:")
            user_states[phone_number] = "awaiting_edit"
        else:
            send_whatsapp_message(phone_number, "No pending post found to edit.")
            
    elif button_id == "cancel_btn":
        if phone_number in pending_posts: del pending_posts[phone_number]
        user_states[phone_number] = None
        send_whatsapp_message(phone_number, "Post creation cancelled. Ready for a new idea!")

# --- FastAPI Routes ---
@app.get("/webhook", tags=["WhatsApp"])
async def verify_webhook(request: Request):
    print("GET /webhook received verification request")
    query_params = dict(request.query_params)
    mode = query_params.get("hub.mode")
    verify_token_query = query_params.get("hub.verify_token")
    challenge = query_params.get("hub.challenge")

    if mode and verify_token_query:
        if mode == "subscribe" and verify_token_query == WHATSAPP_WEBHOOK_VERIFY_TOKEN:
            print("WEBHOOK_VERIFIED")
            return Response(content=challenge, media_type="text/plain")
        else:
            print("Verification failed: Mode or token mismatch.")
            raise HTTPException(status_code=403, detail="Verification failed: Mode or token mismatch")
    
    print("Verification failed: Missing parameters.")
    raise HTTPException(status_code=400, detail="Missing required parameters for verification")

@app.post("/webhook", tags=["WhatsApp"])
async def receive_webhook(request: Request):
    body = await request.json()
    print(f"POST /webhook received: {json.dumps(body, indent=2)}")

    if body.get("object") == "whatsapp_business_account":
        for entry in body.get("entry", []):
            for change in entry.get("changes", []):
                if change.get("field") == "messages":
                    value = change.get("value", {})
                    phone_number = None
                    if "contacts" in value and value["contacts"]:
                         phone_number = value["contacts"][0].get("wa_id")
                    
                    if not phone_number and "messages" in value and value["messages"]:
                        phone_number = value["messages"][0].get("from")

                    if phone_number and "messages" in value:
                        for message_data in value["messages"]:
                            if message_data.get("type") == "text":
                                message_text = message_data.get("text", {}).get("body", "")
                                await handle_message(phone_number, message_text)
                            elif message_data.get("type") == "interactive" and \
                                 message_data.get("interactive", {}).get("type") == "button_reply":
                                button_id = message_data.get("interactive", {}).get("button_reply", {}).get("id")
                                await handle_button_click(phone_number, button_id)
    return {"status": "ok"}

# This is the updated oauth_callback function
@app.get("/callback", tags=["LinkedIn OAuth"])
async def oauth_callback(request: Request):
    """
    Handle OAuth callback from LinkedIn.
    This endpoint now completes the authentication flow and sends a confirmation
    message to the user on WhatsApp instead of asking them to copy the code.
    """
    query_params = dict(request.query_params)
    code = query_params.get("code")
    state_from_linkedin = query_params.get("state")
    
    html_content_base = """
    <html><head><title>LinkedIn Authentication</title>
    <style> body { font-family: sans-serif; padding: 20px; } h1 { color: #0077B5; } </style>
    </head><body>
    """
    html_content_end = "</body></html>"
    
    if not code:
        error_reason = query_params.get("error_description", "No authorization code was provided by LinkedIn.")
        error_html = f"""{html_content_base}
            <h1>Authentication Failed</h1>
            <p>There was an error during LinkedIn authentication:</p>
            <pre>{error_reason}</pre>
            <p>Please try again by sending "auth" to the WhatsApp bot.</p>
        {html_content_end}"""
        return Response(content=error_html, media_type="text/html")
    
    if state_from_linkedin not in oauth_states:
        return Response(content=f"{html_content_base}<h1>Authentication Failed</h1><p>Invalid state parameter. Please try 'auth' again.</p>{html_content_end}", 
                       media_type="text/html")
    
    phone_number = oauth_states.pop(state_from_linkedin, None) # Remove state after use
    if not phone_number: # Should not happen if state was valid, but good to check
        return Response(content=f"{html_content_base}<h1>Authentication Failed</h1><p>Could not associate state with user. Please try 'auth' again.</p>{html_content_end}", 
                       media_type="text/html")

    token_data = get_access_token(code)
    
    if token_data and "access_token" in token_data:
        expires_in = token_data.get("expires_in", 3600)
        linkedin_user_id_sub = get_linkedin_user_id(token_data["access_token"])

        if linkedin_user_id_sub:
            user_tokens[phone_number] = {
                "access_token": token_data["access_token"],
                "expires_at": time.time() + expires_in,
                "linkedin_id_sub": linkedin_user_id_sub
            }
            success_message = "✅ Your LinkedIn account has been successfully connected! You can now create and post content."
            send_whatsapp_message(phone_number, success_message)
            
            success_html = f"""{html_content_base}
                <h1>Authentication Complete!</h1>
                <p>Your LinkedIn account has been successfully connected to the WhatsApp bot.</p>
                <p>You can now return to WhatsApp and start creating LinkedIn posts!</p>
            {html_content_end}"""
            return Response(content=success_html, media_type="text/html")
        else:
            error_message = "✅ Authentication successful, but couldn't retrieve your LinkedIn User ID (sub). Posting might fail. Please try 'auth' again."
            send_whatsapp_message(phone_number, error_message)
            
            error_html = f"""{html_content_base}
                <h1>Authentication Partially Complete</h1>
                <p>Your LinkedIn authentication was successful, but we couldn't retrieve your LinkedIn User ID.</p>
                <p>Please return to WhatsApp and try 'auth' again if you have issues posting.</p>
            {html_content_end}"""
            return Response(content=error_html, media_type="text/html")
    else:
        error_message = "❌ Authentication failed. There was an error exchanging the authorization code for an access token. Please ensure you completed the LinkedIn authorization and try 'auth' again."
        send_whatsapp_message(phone_number, error_message)
        
        error_html = f"""{html_content_base}
            <h1>Authentication Failed</h1>
            <p>There was an error exchanging the authorization code for an access token.</p>
            <p>Please return to WhatsApp and try 'auth' again.</p>
        {html_content_end}"""
        return Response(content=error_html, media_type="text/html")

@app.get("/", tags=["Root"])
async def root():
    return {"message": "LinkedIn WhatsApp Bot is running. Use the /webhook for WhatsApp messages."}

# --- Main Execution Block (for local development) ---
if __name__ == "__main__":
    print(f"Starting server locally on {APP_BASE_URL_CONFIG}")
    port_to_run = 8000
    if "localhost" in APP_BASE_URL_CONFIG:
        url_parts = APP_BASE_URL_CONFIG.split(":")
        if len(url_parts) > 2: # e.g. http://localhost:8000
            try:
                port_str = url_parts[-1].split("/")[0] # Handles potential trailing slash
                port_to_run = int(port_str)
            except ValueError:
                print(f"Could not parse port from APP_BASE_URL: {APP_BASE_URL_CONFIG}. Defaulting to port {port_to_run}.")
                pass

    if missing_vars:
         print(f"Cannot start server due to missing environment variables: {', '.join(missing_vars)}")
    elif not client:
        print("Cannot start server: Anthropic client not initialized (likely missing ANTHROPIC_API_KEY).")
    else:
        uvicorn.run(app, host="0.0.0.0", port=port_to_run)