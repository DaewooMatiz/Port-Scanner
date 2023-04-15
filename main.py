import argparse
import binascii
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
    closed = False
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(TIMEOUT)
        s.connect((host_ip, port))
        s.sendall(binascii.unhexlify(
            "db0011e9000000000001000000000000e7e402a426b15c2d00000000000000000000000000000000e7e50865eea10243"))
        data = s.recv(1024)
        data_str = binascii.hexlify(data)
        #print(f"port {port} opened, answer: {data_str}")
        if b"1c" in data_str:
            ports_info[port] = "NTP"
    except ConnectionResetError:
        closed = True
        # print(f"remote host forced connection reset on port {port}, (destination unreachable)")
    except TimeoutError:
        ports_info[port] = None  # print(f"port {port} connection timed-out.")
    finally:
        s.close()
    if not closed:
        if ports_info[port] is None:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(TIMEOUT)
                s.connect((host_ip, port))
                s.sendall(binascii.unhexlify(
                    "2dc70100000100000000000007626561636f6e7303676370046776743203636f6d0000010001"))
                data = s.recv(1024)
                data_str = binascii.hexlify(data)
                #print(f"port {port} opened, answer: {data_str}")
                if b"2dc7" in data_str:
                    ports_info[port] = "DNS"
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
    parser = argparse.ArgumentParser(description="TCP/UDP PORT SCANNER")
    parser.add_argument("host", help="Host to scan.")
    parser.add_argument("-t", dest="tcp", action="store_true", default=False, help="scan TCP")
    parser.add_argument("-u", dest="udp", action="store_true", default=False, help="scan UDP")
    parser.add_argument("--ports", "-p", dest="port_number", default=[1, 65535],
                        nargs=2,
                        help="Port range to scan, default is 1-65535 (all ports)")
    args = parser.parse_args()
    # argparser => global val's
    tcp = args.tcp
    udp = args.udp
    host, port_number = args.host, args.port_number
    host_ip = socket.gethostbyname(host)
    start_port, end_port = int(port_number[0]), int(port_number[1])
    ports = [p for p in range(start_port, end_port + 1)]
    main(ports)
    print_info()
