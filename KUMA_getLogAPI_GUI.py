import streamlit as st
import requests
import json
import os
import time
from datetime import datetime, timedelta, UTC
import logging
from io import BytesIO
from re import sub
import socket

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
logging.basicConfig(filename=os.path.join(os.getcwd(),"logfile.txt"), filemode='a', format='%(asctime)s,%(msecs)d %(name)s %(levelname)s %(message)s', datefmt='%H:%M:%S', level=logging.INFO)

if "succ_request" not in st.session_state:
    st.session_state.succ_request = False
if "succ_get_logs" not in st.session_state:
    st.session_state.succ_get_logs = False
if "succ_send_logs" not in st.session_state:
    st.session_state.succ_send_logs = False
if "api_profiles" not in st.session_state:
    st.session_state.api_profiles = {}
if "selected_api" not in st.session_state and st.session_state.api_profiles:
    st.session_state.selected_api = list(st.session_state.api_profiles.keys())[0]


# Setup
st.set_page_config(page_title="KUMA Community - API2Log", page_icon=":material/arming_countdown:",layout="centered")
st.title("KUMA Community :green[API] HTTP Request Tool")


if "themes" not in st.session_state: 
  st.session_state.themes = {"current_theme": "light",
                    "refreshed": True,
                    
                    "light": {"theme.base": "dark",
                              "theme.backgroundColor": "black",
                              "theme.primaryColor": "#00A88E",
                              "theme.secondaryBackgroundColor": "#383F48",
                              "theme.textColor": "white",
                              "button_face": ":material/dark_mode:"},

                    "dark":  {"theme.base": "light",
                              "theme.backgroundColor": "white",
                              "theme.primaryColor": "#00A88E",
                              "theme.secondaryBackgroundColor": "#ededf3",
                              "theme.textColor": "black",
                              "button_face": ":material/light_mode:"},
                    }

def ChangeTheme():
    current = st.session_state.themes["current_theme"]
    new_theme = "dark" if current == "light" else "light"
    st.session_state.themes["current_theme"] = new_theme
    st.session_state.trigger_theme_rerun = True  # Set flag

if "trigger_theme_rerun" not in st.session_state:
    st.session_state.trigger_theme_rerun = False

if st.session_state.trigger_theme_rerun:
    theme_name = st.session_state.themes["current_theme"]
    theme_settings = st.session_state.themes[theme_name]
    for k, v in theme_settings.items():
        if k.startswith("theme"):
            st._config.set_option(k, v)
    st.session_state.trigger_theme_rerun = False
    st.rerun()  # This works because it's outside the callback

btn_face = st.session_state.themes["light"]["button_face"] if st.session_state.themes["current_theme"] == "light" else st.session_state.themes["dark"]["button_face"]
st.button("Theme "+btn_face, on_click=ChangeTheme)


# State File
STATE_FILE = os.path.join(os.getcwd(), "log_state.json")
if "last_poll" not in st.session_state:
    st.session_state.last_poll = 0

logs = []
new_logs = []


def load_state():
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE, "r") as f:
            try:
                if st.session_state.state_type != "none":
                    return json.load(f).get(st.session_state.state_type)
            except Exception as e:
                st.error(f"❌ Error loading state file, try to delete it manually: {e}")
                logging.error(str(f"[STATE FILE] Error loading state file, try to delete it manually: {e}"))
    if st.session_state.state_type == "timestamp":
        return "2024-05-01T11:00:00+00:00"
    else:
        return 0


def save_state(state):
    with open(STATE_FILE, "w") as f:
        if st.session_state.state_type != "none":
            json.dump({st.session_state.state_type: state}, f)


# Simulated log data source
def get_simulated_logs(since: str):
    now = datetime.now(UTC).isoformat(timespec='seconds')
    simulated_logs = [
        {"id": 1, "timestamp": "2024-05-01T13:00:00", "message": "Service started"},
        {"id": 2, "timestamp": "2024-05-01T14:00:01", "message": "Listening on port 8000"},
        {"id": 3, "timestamp": "2024-05-01T15:00:01", "message": "New connection established"},
    ]
    if st.session_state.state_type == "timestamp":
        return [log for log in simulated_logs if log["timestamp"] > since]
    elif st.session_state.state_type == "id":
        return [log for log in simulated_logs if log["id"] > since]
    else:
        return simulated_logs


# HTTP Request Tool
st.header("Send API Request")
st.session_state.url = st.text_input("Enter a URL", placeholder="https://api.github.com", help="Enter URL")
st.session_state.method = st.selectbox("HTTP Method", ["GET", "POST", "PUT", "DELETE"])
st.session_state.verify_ssl = st.checkbox("Verify SSL Certificates", value=False)
st.session_state.auth_method = st.selectbox("Auth Method", ["No", "Bearer Token", "Basic Auth", "Client Certificate"], index=None)
st.session_state.headers_input = st.text_area("Optional Headers (JSON format)", value="", placeholder=r'{"Authorization": "Bearer $bearer" or "user":"bob","pass":"$password"}', help=r"Avaliable variables \$bearer and \$password", height=100)
st.session_state.auth_data = {}

if st.session_state.auth_method == "Bearer Token":
    st.session_state.auth_data["token"] = st.text_input("Bearer Token", type="password")
    st.session_state.headers_input = sub(r'\$bearer', st.session_state.auth_data["token"], st.session_state.headers_input)
elif st.session_state.auth_method == "Basic Auth":
    st.session_state.auth_data["username"] = st.text_input("Username")
    st.session_state.auth_data["password"] = st.text_input("Password", type="password")
    st.session_state.headers_input = sub(r'\$password', st.session_state.auth_data["password"], st.session_state.headers_input)
elif st.session_state.auth_method == "Client Certificate":
    col1, col2 = st.columns(2, vertical_alignment="top")
    with col1:
        st.session_state.auth_data["cert_file"] = st.file_uploader("Upload Certificate (.pem/.crt)", type=["pem", "crt"])
    with col2:
        st.session_state.auth_data["key_file"] = st.file_uploader("Upload Key (.key, optional)", type=["key"])
else:
    st.session_state.auth_method == "No"


response = None

st.session_state.payload_input = ""
if st.session_state.method in ["POST", "PUT"]:
    st.session_state.payload_input = st.text_area("Optional Payload (for POST/PUT)", height=100)

st.session_state.api_profiles["default"] = {
    "url": st.session_state.url,
    "auth_method": st.session_state.auth_method,
    "auth_data": st.session_state.auth_data
}

def build_auth_params(profile):
    method = profile.get("auth_method")
    data = profile.get("auth_data", {})
    headers = {}
    auth = None
    cert = None

    if method == "Bearer Token":
        headers["Authorization"] = f"Bearer {data.get('token')}"
    elif method == "Basic Auth":
        auth = (data.get("username"), data.get("password"))
    elif method == "Client Certificate":
        cert_file = data.get("cert_file")
        key_file = data.get("key_file")
        if cert_file:
            cert = (BytesIO(cert_file.read()), BytesIO(key_file.read()) if key_file else None)

    return headers, auth, cert

def send_custom_request():
    if st.session_state.auth_method:
        try:
            headers, auth, cert = build_auth_params(st.session_state.api_profiles["default"])
            payload = None
            if st.session_state.payload_input:
                payload = json.loads(st.session_state.payload_input)

            url = st.session_state.api_profiles["default"]["url"]
            method = st.session_state.method
            verify_ssl = st.session_state.verify_ssl

            if method == "GET":
                response = requests.get(url, headers=headers, cert=cert, verify=verify_ssl)
            elif method == "POST":
                response = requests.post(url, json=payload, headers=headers, cert=cert, verify=verify_ssl)
            elif method == "PUT":
                response = requests.put(url, json=payload, headers=headers, cert=cert, verify=verify_ssl)
            elif method == "DELETE":
                response = requests.delete(url, headers=headers, cert=cert, verify=verify_ssl)

            # Store response in session state
            st.session_state.response_data = {
                "text": response.text,
                "status_code": response.status_code,
                "reason": response.reason,
                "headers": dict(response.headers),
                "content_type": response.headers.get("Content-Type", ""),
            }

            try:
                st.session_state.response_data["json"] = response.json()
            except:
                st.session_state.response_data["json"] = None
            rd = st.session_state.response_data
            if rd['status_code'] == 200:
                st.success(f"✅ **Response Code:** `{rd['status_code']}` `{rd['reason']}`   Total Records: `{len(rd['json'])}`")
                logging.info(f"[REQUEST] **Response Code:** `{rd['status_code']}` `{rd['reason']}`   Total Records: `{len(rd['json'])}`")
                st.session_state.succ_request = True
                return f"✅ **Response Code:** `{rd['status_code']}` `{rd['reason']}`   Total Records: `{len(rd['json'])}`"
            else:
                st.session_state.succ_request = False
                st.error(f"❌ **Response Code:** `{rd['status_code']}` `{rd['reason']}`")
                logging.error(str(f"[REQUEST] **Response Code:** `{rd['status_code']}` `{rd['reason']}` {e}"))
                return f"❌ **Response Code:** `{rd['status_code']}` `{rd['reason']}`"
        except Exception as e:
            st.error(f"❌ Error sending request: {e}")
            logging.error(str(f"[REQUEST] Error sending request: {e}"))
    else:
        st.warning(f"⚠️ Choose Auth Method!")


if st.button("Send Request", icon=":material/play_arrow:", key="button_send_request"):
    send_custom_request()

if "response_data" in st.session_state:
    rd = st.session_state.response_data
    logs = rd["json"]

    show_response = st.checkbox("Show Response Headers and Body", value=False)
    if show_response:
        st.subheader("Response Headers")
        with st.container(border=True):
            st.json(rd["headers"])

        st.subheader("Response Body")
        show_raw = st.checkbox("Show as raw text instead of JSON", value=False, help="Limit 5000")

        with st.container(border=True, height=300):
            if show_raw:
                st.code(rd["text"][:5000])
            else:
                st.json(rd["json"])

    content_type = rd["content_type"].lower()

    file_ext = "txt"
    mime = "text/plain"
    content = rd["text"]

    if rd["json"]:
        content = json.dumps(rd["json"], indent=2, ensure_ascii=False)
        file_ext = "json"
        mime = "application/json"
    elif "text/html" in content_type:
        file_ext = "html"
        mime = "text/html"
    elif "xml" in content_type:
        file_ext = "xml"
        mime = "application/xml"
    elif "csv" in content_type:
        file_ext = "csv"
        mime = "text/csv"

    # Calculate size in bytes and convert to human-readable format
    size_bytes = len(content.encode('utf-8'))

    def sizeof_fmt(num, suffix='B'):
        for unit in ['','Ki','Mi','Gi','Ti']:
            if abs(num) < 1024.0:
                return f"{num:.2f} {unit}{suffix}"
            num /= 1024.0
        return f"{num:.2f} Yi{suffix}"

    col1, col2 = st.columns(2, vertical_alignment="center")
    with col1:
        st.download_button(label=f"Download response.{file_ext}", data=content, file_name=f"response.{file_ext}", icon=":material/download:", mime=mime)
    with col2:
        st.markdown(f"**File size:** {sizeof_fmt(size_bytes)}")



st.markdown("---")
st.subheader("Get & Sort logs from request")
st.session_state.state_type = st.selectbox("Choose or Enter log state tracking method:", ("none", "id", "timestamp", "lastSeen"), index=None, placeholder="Select log iteration method...", 
                          help="Chose iteration field or enter your own value (Handle types safely: timestamp as str (ISO), id as int)", accept_new_options=True)
state = load_state()

col1, col2 = st.columns(2, vertical_alignment="center")
with col1:
    if st.button("Delete State File", icon=":material/delete:"):
        if os.path.exists(STATE_FILE):
            os.remove(STATE_FILE)
            with col2:
                st.success("[STATE FILE] ✅ State file deleted.")
                logging.info("[STATE FILE] State file deleted.")
        else:
            with col2:
                st.info("[STATE FILE] ℹ️ No state file found to delete.")
                logging.info("[STATE FILE] No state file found to delete.")
        state = load_state()  # Reload default or reinitialize

col1, col2, col3 = st.columns(3, vertical_alignment="top")
with col1:
    st.write(f"Last state:")
    st.write(f"`{state}`")
with col2:
    st.write(f"File state path:")
    st.write(f"`{os.path.abspath(STATE_FILE)}`")
with col3:
    show_logs = st.checkbox("Show output logs")


def is_new_log(log, state_value, state_type):
    try:
        if st.session_state.state_type == "id":
            return int(log[state_type]) > int(state_value)
        else:
            return str(log[state_type]) > str(state_value)
    except Exception as e:
        return False



def get_logs():
    state = load_state()    
    if st.session_state.state_type != None:
        try:
            logs = st.session_state.response_data.get("json", [])

            try:
                logs = sorted(logs, key=lambda x: x.get(st.session_state.state_type, ""))
            except Exception as e:
                st.warning(f"[GET LOGS] ⚠️ Could not sort records: {e}")
                logging.warning(str(f"[GET LOGS] Could not sort records: {e}"))

            if logs:
                try:
                    new_logs = [log for log in logs if is_new_log(log, state, st.session_state.state_type)]
                    st.session_state.new_logs = new_logs  # Store in session_state
                    if len(new_logs)==0:
                        st.info("[GET LOGS] No new logs available.")
                        logging.info("[GET LOGS] No new logs available.")
                    else:
                        if st.session_state.state_type != "none":
                            save_state(logs[-1][st.session_state.state_type])
                        st.success(f"✅ **{len(st.session_state.new_logs)}** new logs retrieved. Updated last state to: `{load_state()}`")
                        logging.info(f"[GET LOGS] **{len(st.session_state.new_logs)}** new logs retrieved. Updated last state to: `{load_state()}`")
                        st.session_state.succ_get_logs = True

                except Exception as e:
                    st.error(f"❌ Cant compare state with last seen: {e}")
                    logging.error(str(f"[GET LOGS] Cant compare state with last seen: {e}"))
            else:
                st.info("[GET LOGS] No new logs available. Or make new request.")
                logging.info("[GET LOGS] No new logs available. Or make new request.")
            
        except Exception as e:
            st.error(f"[GET LOGS] ❌ Error fetching logs: {e}")
            logging.error(str(f"[GET LOGS] Error fetching logs: {e}"))
            st.session_state.succ_get_logs = False
    else:
        st.warning(f"⚠️ Choose log state tracking method!")


if st.button("Get Logs", icon=":material/download:", key="button_get_logs"):
    get_logs()

    if show_logs and len(st.session_state.new_logs) > 0:
        st.subheader("Log Entries")
        with st.container(border=True, height=300):
            for log in st.session_state.new_logs:
                st.write(f"`{log}`")



st.markdown("---")
st.subheader("Send Logs via TCP Socket")
show_logs = st.checkbox("Show Logs Sended", value=False)

st.session_state.tcp_host = st.text_input("TCP Server Host", placeholder="192.168.0.164")
st.session_state.tcp_port = st.number_input("Port", placeholder=5515, step=1)

def send_logs(max_retries=1, delay=0):
    try:
        new_logs = st.session_state.get("new_logs", [])

        if not new_logs:
            st.info("[SEND] No logs available. Get logs first.")
            logging.info("[SEND] No logs available. Get logs first.")
            return
        
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((st.session_state.tcp_host, int(st.session_state.tcp_port)))

            if show_logs:
                st.subheader("Logs Sended")
                with st.container(border=True, height=300):
                    st.write(f"`{new_logs}`")
            for log in new_logs:
                log_json = json.dumps(log)
                s.sendall(log_json.encode("utf-8") + b"\n")
                st.session_state.succ_send_logs = True
            st.success(f"✅ Sent **{len(new_logs)}** logs to `{st.session_state.tcp_host}:{st.session_state.tcp_port}`")
            logging.info(f"[SEND] Sent **{len(new_logs)}** logs to `{st.session_state.tcp_host}:{st.session_state.tcp_port}`")
            del st.session_state.new_logs

    except Exception as e:
        st.error(f"❌ Error sending logs: {e}")
        logging.error(str(f"[SEND] Error sending logs: {e}"))
        st.session_state.succ_send_logs = False

if st.button("Send Logs", icon=":material/start:", key="button_send_logs"):
    send_logs()



if st.session_state.succ_request & st.session_state.succ_get_logs & st.session_state.succ_send_logs:
    st.markdown("---")
    st.subheader("🌀 Enable Sequential Polling")

    if "auto_polling_enabled" not in st.session_state:
        st.session_state.auto_polling_enabled = False
    if "status_expanded" not in st.session_state:
        st.session_state.status_expanded = True

    col1, col2, col3 = st.columns([1, 1, 1], vertical_alignment="bottom")
    with col1:
        poll_interval = st.number_input("Polling interval (seconds)", min_value=1, max_value=3600, value=60, step=5)
    with col2:
        if st.button("Start Polling", icon=":material/play_circle:", disabled=st.session_state.auto_polling_enabled):
            st.session_state.auto_polling_enabled = True
            st.toast("🟢 Polling started!")
            logging.info("[POLLING] Polling started!")
            time.sleep(1)
            st.rerun()
    with col3:
        if st.button("Stop Polling", icon=":material/stop_circle:", disabled=not(st.session_state.auto_polling_enabled)):
            st.session_state.auto_polling_enabled = False
            st.session_state.cycle = 1
            st.toast("🛑 Polling stopped!")
            logging.info("[POLLING] Polling stopped!")
            time.sleep(2)
            st.rerun()
    
    status_placeholder = st.empty()
    countdown_placeholder = st.empty()

    if "cycle" not in st.session_state:
        st.session_state.cycle = 1

    if st.session_state.auto_polling_enabled:
        with st.status("Polling is active", expanded=st.session_state.status_expanded, state="running"):
            status_placeholder.info(f"**Cycle {st.session_state.cycle}**: Sending Request")
            st.markdown(f"#### Cycle {st.session_state.cycle}")
            func_placeholder = st.empty()
            func_placeholder.markdown(send_custom_request())
            time.sleep(1)

            status_placeholder.info(f"**Cycle {st.session_state.cycle}**: Getting Logs")
            func_placeholder.markdown(get_logs())
            time.sleep(1)

            status_placeholder.info(f"**Cycle {st.session_state.cycle}**: Sending Logs")
            func_placeholder.markdown(send_logs())
            func_placeholder = st.empty()

            logging.info(f"[CYCLE] number: {st.session_state.cycle} executed.")
            st.session_state.cycle+=1
            for remaining in range(poll_interval, 0, -1):
                countdown_placeholder.warning(f"⏳ Next cycle {st.session_state.cycle} in {remaining} seconds...")
                time.sleep(1)
            
            countdown_placeholder.empty()
            st.rerun()

# Disable buttons
st.markdown(
    r"""
    <style>
        .reportview-container {
            margin-top: -2em;
        }
        #MainMenu {visibility: hidden;}
        .stDeployButton {display:none;visibility: hidden;}
        .stAppDeployButton {display:none;visibility: hidden;}
        footer {visibility: hidden;}
        #stDecoration {display:none;}
    </style>
    """, 
    unsafe_allow_html=True)

# Footer
st.markdown(
    r"""
    <hr style="margin-top: 2em;">
    <div style='text-align: center; color: gray; font-size: 0.9em;'>
        Kuma Community © 2025 - API HTTP Request Tool
    </div>
    """,
    unsafe_allow_html=True
)
