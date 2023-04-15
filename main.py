import argparse
import socket
from queue import Queue
from threading import Thread

N_THREADS = 200
q = Queue()
TIMEOUT = 0.1
ports_info = {}


def tcp_port_scan(port):
    # print(port)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.settimeout(TIMEOUT)
        s.connect((host_ip, port))
    except TimeoutError:
        pass  # print(f"port {port} connection timed-out.")
    except PermissionError:
        pass  # print(f"no permission to connect to port {port}")
    except ConnectionResetError:
        pass  # print(f"remote host forced connection reset on port {port}")
    else:
        ports_info[port] = None
        try:
            s.sendall(b"GET / HTTP/1.1\nhost: " + bytes(host, "utf-8") + b"\n\n")
            data = s.recv(1024)
            data_str = data.decode("utf-8")
            # print(f"port {port} opened, answer: {data_str}")
            if "+OK" in data_str:
                ports_info[port] = "POP3"
            elif "IMAP" in data_str:
                ports_info[port] = "IMAP"
            elif "220" in data_str:
                ports_info[port] = "SMTP"
            if "HTTP" in data_str and "HTTPS" not in data_str:
                ports_info[port] = "HTTP"
        except TimeoutError:
            pass  # print(f"port {port} connection successfull, but data recieving timed out")
        except ConnectionResetError:
            pass  # print(f"remote host forced connection reset on port {port}, when parser tried to recieve data")
        except UnicodeDecodeError:
            pass  # print("РЕМОТЕ ХОСТ ОТВЕТИЛ ПО-ТАТАРСКИ! сәламәт абый тормыш кебек!")

    finally:
        s.close()


def udp_port_scan(port):
    # print(port)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    s.settimeout(TIMEOUT)
    s.connect((host_ip, port))

    try:
        s.sendall(b"UDP LOL XD")
        data = s.recv(1024)
        data_str = data.decode("utf-8")
        print(f"port {port} opened, answer: {data_str}")
    except ConnectionResetError:
        pass
        # print(f"remote host forced connection reset on port {port}, (destination unreachable)")
    except TimeoutError:
        ports_info[port] = None  # print(f"port {port} connection timed-out.")
    finally:
        s.close()


def scan_tcp_thread():
    global q
    while True:
        current_port = q.get()
        tcp_port_scan(current_port)
        q.task_done()


def scan_udp_thread():
    global q
    while True:
        worker = q.get()
        udp_port_scan(worker)
        q.task_done()


def main(ports):
    global q
    for i in range(N_THREADS):
        if tcp:
            t = Thread(target=scan_tcp_thread)
            t.daemon = True
            t.start()
        elif udp:
            t = Thread(target=scan_udp_thread)
            t.daemon = True
            t.start()

    for port in ports:
        q.put(port)

    q.join()


def print_info():
    for port, info in ports_info.items():
        if tcp:
            if info:
                line = "TCP " + str(port) + " " + str(info)
            else:
                line = "TCP " + str(port)
            print(line)
        elif udp:
            if info:
                line = "UDP " + str(port) + " " + str(info)
            else:
                line = "UDP " + str(port)
            print(line)


if __name__ == '__main__':
    # argparser
    parser = argparse.ArgumentParser(description="Simple port scanner")
    parser.add_argument("host", help="Host to scan.")
    parser.add_argument("-t", dest="tcp", action="store_true", default=False)
    parser.add_argument("-u", dest="udp", action="store_true", default=False)
    parser.add_argument("--ports", "-p", dest="port_range", default=[1, 65535],
                        nargs=2,
                        help="Port range to scan, default is 1-65535 (all ports)")
    args = parser.parse_args()
    # argparser => global val's
    tcp = args.tcp
    udp = args.udp
    host, port_range = args.host, args.port_range
    host_ip = socket.gethostbyname(host)
    start_port, end_port = port_range[0], port_range[1]
    start_port, end_port = int(start_port), int(end_port)
    ports = [p for p in range(start_port, end_port + 1)]
    main(ports)
    print_info()
