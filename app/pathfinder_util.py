import socket


def get_machine_ip():
    # this gets the exit IP, so if you are on a VPN it will get you the IP on the VPN network and not your local network IP
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip


def sanitize_filename(proposed):
    subs = [(".", "_"), ("/", "-")]
    new = proposed
    for character, replacement in subs:
        new = new.replace(character, replacement)
    return new
