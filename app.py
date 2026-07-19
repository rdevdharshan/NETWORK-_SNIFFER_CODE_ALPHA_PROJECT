import time
import threading
from datetime import datetime

from flask import Flask, render_template, jsonify
from flask_socketio import SocketIO

from scapy.all import AsyncSniffer
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP

try:
    # Friendly Windows interface names (description + GUID)
    from scapy.arch.windows import get_windows_if_list
except ImportError:
    get_windows_if_list = None

app = Flask(__name__)
app.config["SECRET_KEY"] = "tapline-dev-secret"
socketio = SocketIO(app, async_mode="threading", cors_allowed_origins="*")

# ---------------------------------------------------------------------------
# Capture state
# ---------------------------------------------------------------------------
sniffer = None
capture_lock = threading.Lock()
packet_count = 0
start_time = None
protocol_totals = {}


def classify_protocol(pkt):
    """Return a short protocol label for a packet."""
    if pkt.haslayer(TCP):
        return "TCP"
    if pkt.haslayer(UDP):
        return "UDP"
    if pkt.haslayer(ICMP):
        return "ICMP"
    if pkt.haslayer(ARP):
        return "ARP"
    if pkt.haslayer(IPv6):
        return "IPv6"
    if pkt.haslayer(IP):
        return f"IP-proto-{pkt[IP].proto}"
    return pkt.lastlayer().name if pkt.lastlayer() else "Other"


def get_endpoints(pkt):
    """Extract (src, dst, sport, dport) where available."""
    src = dst = "-"
    sport = dport = None

    if pkt.haslayer(IP):
        src, dst = pkt[IP].src, pkt[IP].dst
    elif pkt.haslayer(IPv6):
        src, dst = pkt[IPv6].src, pkt[IPv6].dst
    elif pkt.haslayer(ARP):
        src, dst = pkt[ARP].psrc, pkt[ARP].pdst
    else:
        # Fall back to Ethernet addresses
        if hasattr(pkt, "src") and hasattr(pkt, "dst"):
            src, dst = pkt.src, pkt.dst

    if pkt.haslayer(TCP):
        sport, dport = pkt[TCP].sport, pkt[TCP].dport
    elif pkt.haslayer(UDP):
        sport, dport = pkt[UDP].sport, pkt[UDP].dport

    return src, dst, sport, dport


def handle_packet(pkt):
    """Callback fired by AsyncSniffer for every captured packet."""
    global packet_count

    proto = classify_protocol(pkt)
    src, dst, sport, dport = get_endpoints(pkt)

    with capture_lock:
        packet_count += 1
        protocol_totals[proto] = protocol_totals.get(proto, 0) + 1
        current_count = packet_count

    packet_data = {
        "no": current_count,
        "time": datetime.now().strftime("%H:%M:%S.%f")[:-3],
        "src": src,
        "dst": dst,
        "sport": sport,
        "dport": dport,
        "protocol": proto,
        "length": len(pkt),
        "summary": pkt.summary(),
    }

    socketio.emit("packet", packet_data)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/interfaces")
def api_interfaces():
    interfaces = []
    if get_windows_if_list:
        try:
            for iface in get_windows_if_list():
                interfaces.append({
                    "name": iface.get("name", iface.get("guid", "unknown")),
                    "description": iface.get("description", ""),
                })
        except Exception as exc:
            return jsonify({"error": str(exc), "interfaces": []}), 500
    return jsonify({"interfaces": interfaces})


@app.route("/api/status")
def api_status():
    with capture_lock:
        elapsed = round(time.time() - start_time, 1) if start_time else 0
        return jsonify({
            "running": sniffer is not None and sniffer.running,
            "packet_count": packet_count,
            "elapsed": elapsed,
            "protocol_totals": protocol_totals,
        })


# ---------------------------------------------------------------------------
# Socket.IO control events
# ---------------------------------------------------------------------------
@socketio.on("start_capture")
def start_capture(data):
    global sniffer, packet_count, start_time, protocol_totals

    with capture_lock:
        if sniffer is not None and sniffer.running:
            socketio.emit("capture_error", {"error": "Capture already running."})
            return

        iface = data.get("iface") or None
        bpf_filter = data.get("filter") or None

        packet_count = 0
        protocol_totals = {}
        start_time = time.time()

        try:
            sniffer = AsyncSniffer(
                iface=iface,
                filter=bpf_filter,
                prn=handle_packet,
                store=False,
            )
            sniffer.start()
        except Exception as exc:
            sniffer = None
            socketio.emit("capture_error", {"error": str(exc)})
            return

    socketio.emit("capture_started", {"iface": iface or "default", "filter": bpf_filter or ""})


@socketio.on("stop_capture")
def stop_capture():
    global sniffer
    with capture_lock:
        if sniffer is not None:
            try:
                sniffer.stop()
            except Exception:
                pass
            sniffer = None
    socketio.emit("capture_stopped", {"packet_count": packet_count})


if __name__ == "__main__":
    print("Tapline running at http://127.0.0.1:5000")
    print("NOTE: run this from an Administrator command prompt on Windows,")
    print("and make sure Npcap is installed, or packet capture will fail.")
    # debug=True while troubleshooting — shows the full traceback in the
    # browser instead of a generic 500 page. Set back to False once things
    # are working.
    socketio.run(app, host="127.0.0.1", port=5000, debug=True)
