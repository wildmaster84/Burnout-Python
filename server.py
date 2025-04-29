import socket
import threading
import struct
from enum import IntEnum
import time
import os
import hashlib
from Crypto.Cipher import ARC4

# === Packet Type Enum ===
class PacketType(IntEnum):
    PING = 0x00
    SINGLE_RESPONSE = 0x80
    MULTIPART_RESPONSE = 0xB0
    SINGLE_REQUEST = 0xC0
    MULTIPART_REQUEST = 0xF0
    UNK_1 = 0x6E

def rc4_md5_v2_encrypt(data):
    # Hash the key using MD5
    md5_key = hashlib.md5(b'baadcodebaadcodebaadcodebaadcode').digest()
    cipher = ARC4.new(md5_key)
    return cipher.encrypt(data)

def rc4_md5_v2_decrypt(data):
    # Hash the key using MD5
    md5_key = hashlib.md5(b'baadcodebaadcodebaadcodebaadcode').digest()
    cipher = ARC4.new(md5_key)
    return cipher.decrypt(data)
# === Helper to track ongoing multipart transactions ===
active_transactions = {}
players = {}

def decode_safe(byte_line):
    result = ""
    processed = {}
    for byte in byte_line:
        try:
            char = bytes([byte]).decode("ascii")
            result += char
        except UnicodeDecodeError:
            result += f"0x{byte:02X}"
        
    return result

# === Parse an incoming packet ===
def parse_packet(data):
    if len(data) < 12:
        raise ValueError("Packet too short")

    command = data[:4].decode()
    packet_type_val = hex(data[4])
    try:
        packet_type = PacketType(packet_type_val)
    except ValueError:
        packet_type = packet_type_val  # raw value if unknown

    txn_id = data[5:8]
    size = struct.unpack('>I', data[8:12])[0]
    body = data[12:size]
    return {
        'command': command,
        'packet_type': packet_type,
        'txn_id': txn_id,
        'size': size,
        'body': body
    }

# === Build a packet ===
def build_packet(command, packet_type, txn_id, body_bytes):
    size = 12 + len(body_bytes)
    header = command.encode()[:4].ljust(4, b'\x00')
    header += struct.pack('B', packet_type)
    header += txn_id.ljust(3, b'\x00')
    header += struct.pack('>I', size).zfill(4)
    return header + body_bytes

# === Send a response packet ===
def send_response(command, body_lines, conn, txn_id):
    encoded_lines = []

    for line in body_lines:
        if isinstance(line, bytes):
            line = line.decode('utf-8', errors='replace')  # Decode safely for processing
        # Process lines with $-prefixed hex strings
        if '=' in line:
            key, value = line.split('=', 1)
            if value.startswith('$'):
                hex_str = value[1:]  # Remove the '$'
                try:
                    raw_bytes = bytes(int(hex_str[i:i+2], 16) for i in range(0, len(hex_str), 2))
                    encoded_line = f"{key}=$".encode() + raw_bytes
                except ValueError:
                    # If bad hex, fall back to regular encoding
                    encoded_line = line.encode()
            else:
                encoded_line = line.encode()
        else:
            encoded_line = line.encode()

        encoded_lines.append(encoded_line)

    body = b'\t'.join(encoded_lines) + b'\x00'

    if command in {"@dir", "sele", "auth", "pers", "fget", "fdup", "+who"}:
        packet = build_packet(command, PacketType.PING, txn_id, body)
        conn.sendall(packet)
        return
    elif command == "@tic":
        return
    elif command == "news" and txn_id == b'new8':
        packet = build_packet(command, PacketType.UNK_1, txn_id, body)
        conn.sendall(packet)
        return
    elif len(body) <= 1024:
        packet = build_packet(command, PacketType.SINGLE_RESPONSE, txn_id, body)
        conn.sendall(packet)
        return
    else:
        packet = build_packet(command, PacketType.MULTIPART_RESPONSE, txn_id, body)
        conn.sendall(packet)
        return;
        #chunks = [body[i:i+1024] for i in range(0, len(body), 1024)]
        #for i, chunk in enumerate(chunks):
        #    packet = build_packet(command, PacketType.MULTIPART_RESPONSE, txn_id, chunk)
        #    conn.sendall(packet)

# === Simplified Send Helper ===
def send(command, body_lines):
    txn_id = b'\x00\x00\x01'  # Or generate as needed
    return build_packet(command, PacketType.SINGLE_REQUEST, txn_id, b'\n'.join(line.encode() for line in body_lines) + b'\n\x00')

# === Heartbeat Thread ===
def start_heartbeat(conn):
    def heartbeat_loop():
        host, port = conn.getpeername()
        while host in players:
            now = time.localtime()
            ref = f"{now.tm_year}.{now.tm_mon}.{now.tm_mday}-{now.tm_hour:02}:{now.tm_min:02}:{now.tm_sec:02}"
            body = [f"REF={ref}"]
            packet = build_packet("~png", PacketType.PING, b'\x00\x00\x00', b'\n'.join(line.encode() for line in body) + b'\n\x00')
            try:
                conn.sendall(packet)
            except Exception:
                break
            time.sleep(15)
    threading.Thread(target=heartbeat_loop, daemon=True).start()

# === Handle a parsed incoming packet ===
def handle_packet(parsed, conn):
    packet_type = parsed['packet_type']
    txn_id = parsed['txn_id']
    body = parsed['body']

    if packet_type == PacketType.MULTIPART_REQUEST:
        active_transactions.setdefault(txn_id, b'')
        active_transactions[txn_id] += body
        return

    if packet_type == PacketType.SINGLE_REQUEST:
        full_body = body
    elif isinstance(packet_type, PacketType) and packet_type == PacketType.MULTIPART_RESPONSE and txn_id in active_transactions:
        full_body = active_transactions.pop(txn_id) + body
    elif isinstance(packet_type, PacketType) and packet_type == PacketType.SINGLE_RESPONSE:
        full_body = body  # Accept single response directly
    else:
        # Fallback: if body ends with null and it's not already known
        full_body = body if txn_id not in active_transactions else active_transactions.pop(txn_id) + body

    if full_body.endswith(b'\x00'):
        full_body = full_body[:-1]

    lines = full_body.split(b'\n')
    data = {}
    for line in lines:
        if not line:
            continue
        if b'=' in line:
            key, value = line.split(b'=', 1)
            # Check if the value starts with a '$' and decode it
            if value.startswith(b'$'):
                hex_value = value.replace(b'$', b'').hex()
                data[key.decode()] = '$' + hex_value
            else:
                data[key.decode()] = value.decode()

    command = parsed['command']
    print(f"[REQ] Command: {command}, TXN: {txn_id.hex()}, Data: {data}")

    # Always initialize transaction ID to avoid unexpected behavior
    if txn_id not in active_transactions:
        active_transactions[txn_id] = b''
    host, port = conn.getpeername()
        
    if command == "@dir":
        response = [
            "ADDR=73.121.221.18",
            "PORT=10134",
            "MASK=ffffffffffffffffffffffffffffffff",
            "SESS=1"
        ]
        send_response(command, response, conn, txn_id)
        return
    elif command == "addr":
        players[host] = {
            'address': data["ADDR"],
            'port': data["PORT"]
        }
        start_heartbeat(conn)
        return
    elif command == "skey":
        if host not in players:
            print(f"{host} not being tracked!")
        players[host].update({
                'skey': data["SKEY"]
            })
        response = [
            "SKEY=$baadcodebaadcodebaadcodebaadcode",
            "DP=XBL2/Burnout-Jan2008/mod"
        ]
        send_response(command, response, conn, txn_id)
        return
    elif command == "news":
        response = [
            "MIN_TIME_SPENT_SYNCYING_TIME=1",
            "MAX_TIME_SPENT_SYNCYING_TIME=30",
            "MAX_TIME_TO_WAIT_FOR_START_TIME=30",
            "MAX_TIME_TO_WAIT_FOR_SILENT_CLIENT_READY=30",
            "MAX_TIME_TO_WAIT_FOR_COMMUNICATING_CLIENT_READY=45",
            "TIME_GAP_TO_LEAVE_BEFORE_START_TIME=5",
            "IDLE_TIMEOUT=30000",
            "SEARCH_QUERY_TIME_INTERVAL=30000",
            "NAT_TEST_PACKET_TIMEOUT=30000",
            "TOS_BUFFER_SIZE=250000",
            "NEWS_BUFFER_SIZE=85000",
            "LOG_OFF_ON_EXIT_ONLINE_MENU=FALSE",
            "TELEMETRY_FILTERS_FIRST_USE=",
            "TELEMETRY_FILTERS_NORMAL_USE=",
            "TIME_BETWEEN_STATS_CHECKS=30",
            "TIME_BETWEEN_ROAD_RULES_UPLOADS=1",
            "TIME_BETWEEN_ROAD_RULES_DOWNLOADS=900",
            "TIME_BEFORE_RETRY_AFTER_FAILED_BUDDY_UPLOAD=600",
            "TIME_BETWEEN_OFFLINE_PROGRESSION_UPLOAD=600",
            "ROAD_RULES_RESET_DATE=\"2007.10.11 18:00:00\"",
            "USE_GLOBAL_ROAD_RULE_SCORES=0",
            "CAR_OLD_ROAD_RULES_TAGFIELD=RULES,RULES1,RULES2,RULES3,RULES4,RULES5,RULES6,RULES7,RULES8,RULES9,RULES10,RULES11,RULES12,RULES13,RULES14,RULES15,RULES16",
            "CAR_ROAD_RULES_TAGFIELD=RULES17",
            "BIKE_DAY_OLD_ROAD_RULES_TAGFIELD=BIKEDAYRULES1,BIKEDAYRULES2",
            "BIKE_DAY_ROAD_RULES_TAGFIELD=BIKEDAYRULES3",
            "BIKE_NIGHT_OLD_ROAD_RULES_TAGFIELD=BIKENIGHTRULES1,BIKENIGHTRULES2",
            "BIKE_NIGHT_ROAD_RULES_TAGFIELD=BIKENIGHTRULES3",
            "BUDDY_SERVER=127.0.0.1",
            "BUDDY_PORT=13505",
            "PEERTIMEOUT=10000",
            "TOS_URL=http://gos.ea.com/easo/editorial/common/2008/tos/tos.jsp?lang=%25s&platform=xbl2&from=%25s",
            "TOSA_URL=http://gos.ea.com/easo/editorial/common/2008/tos/tos.jsp?style=view&lang=%25s&platform=xbl2&from=%25s",
            "TOSAC_URL=http://gos.ea.com/easo/editorial/common/2008/tos/tos.jsp?style=accept&lang=%25s&platform=xbl2&from=%25s",
            "EACONNECT_WEBOFFER_URL=http://gos.ea.com/easo/editorial/common/2008/eaconnect/connect.jsp?site=easo&lkey=$LKEY$&lang=%25s&country=%25s",
            "GPS_REGIONS=127.0.0.1,127.0.0.1,127.0.0.1,127.0.0.1",
            "QOS_LOBBY=127.0.0.1",
            "QOS_PORT=17582",
            "PROFANE_STRING=@/&!",
            "FEVER_CARRIERS=FritzBraun,EricWimp,Matazone,NutKC,FlufflesDaBunny,Flinnster,Molen,LingBot,DDangerous,Technocrat",
            "NEWS_DATE=\"2008.6.11 21:00:00\"",
            "NEWS_URL=http://gos.ea.com/easo/editorial/common/2008/news/news.jsp?lang=%25s&from=%25s&game=Burnout&platform=xbl2",
            "USE_ETOKEN=1",
            "LIVE_NEWS2_URL=http://portal.burnoutweb.ea.com/loading.php?lang=%25s&from=%25s&game=Burnout&platform=xbl2&env=live&nToken=%25s",
            "LIVE_NEWS_URL=https://gos.ea.com/easo/editorial/Burnout/2008/livedata/main.jsp?lang=%25s&from=%25s&game=Burnout&platform=xbl2&env=live&nToken=%25s",
            "STORE_URL_ENCRYPTED=1",
            "STORE_URL=https://pctrial.burnoutweb.ea.com/t2b/page/index.php?lang=%25s&from=%25s&game=Burnout&platform=xbl2&env=live&nToken=%25s",
            "AVATAR_URL_ENCRYPTED=1",
            "AVATAR_URL=https://31.186.250.154:8443/avatar?persona=%25s",
            "BUNDLE_PATH=https://gos.ea.com/easo/editorial/Burnout/2008/livedata/bundle/",
            "ETOKEN_URL=https://31.186.250.154:8443/easo/editorial/common/2008/nucleus/nkeyToNucleusEncryptedToken.jsp?nkey=%25s&signature=%25s",
            "PRODUCT_DETAILS_URL=https://pctrial.burnoutweb.ea.com/t2b/page/ofb_pricepoints.php?productId=%25s&env=live",
            "PRODUCT_SEARCH_URL=https://pctrial.burnoutweb.ea.com/t2b/page/ofb_DLCSearch.php?env=live",
            "STORE_DLC_URL=https://pctrial.burnoutweb.ea.com/t2b/page/index.php?lang=%25s&from=%25s&game=Burnout&platform=xbl2&env=live&nToken=%25s&prodid=%25s",
            "AVAIL_DLC_URL=https://gos.ea.com/easo/editorial/Burnout/2008/livedata/Ents.txt",
            "ROAD_RULES_SKEY=frscores",
            "CHAL_SKEY=chalscores",
            "TELE_DISABLE=AD,AF,AG,AI,AL,AM,AN,AO,AQ,AR,AS,AW,AX,AZ,BA,BB,BD,BF,BH,BI,BJ,BM,BN,BO,BR,BS,BT,BV,BW,BY,BZ,CC,CD,CF,CG,CI,CK,CL,CM,CN,CO,CR,CU,CV,CX,DJ,DM,DO,DZ,EC,EG,EH,ER,ET,FJ,FK,FM,FO,GA,GD,GE,GF,GG,GH,GI,GL,GM,GN,GP,GQ,GS,GT,GU,GW,GY,HM,HN,HT,ID,IL,IM,IN,IO,IQ,IR,IS,JE,JM,JO,KE,KG,KH,KI,KM,KN,KP,KR,KW,KY,KZ,LA,LB,LC,LI,LK,LR,LS,LY,MA,MC,MD,ME,MG,MH,ML,MM,MN,MO,MP,MQ,MR,MS,MU,MV,MW,MY,MZ,NA,NC,NE,NF,NG,NI,NP,NR,NU,OM,PA,PE,PF,PG,PH,PK,PM,PN,PS,PW,PY,QA,RE,RS,RW,SA,SB,SC,SD,SG,SH,SJ,SL,SM,SN,SO,SR,ST,SV,SY,SZ,TC,TD,TF,TG,TH,TJ,TK,TL,TM,TN,TO,TT,TV,TZ,UA,UG,UM,UY,UZ,VA,VC,VE,VG,VN,VU,WF,WS,YE,YT,ZM,ZW,ZZ"
        ]
        send_response(command, response, conn, txn_id)
        return
    elif command == "sele":
        response = [
            "GAMES=0",
            f"MYGAME=\"1 GAMES=0 ROOMS=0 USERS=1 MESGS=1 MESGTYPES=100728964 STATS=500 RANKS=1 USERSETS=1\"",
            "USERS=0",
            "ROOMS=0",
            "USERSETS=0",
            "MESGS=0",
            "MESGTYPES=0",
            "ASYNC=0",
            "CTRL=0",
            "STATS=0",
            "SLOTS=280",
            "INGAME=0",
            "DP=XBL2/Burnout-Jan2008/mod"
        ]
        send_response(command, response, conn, txn_id)
        return
    elif command == "auth":
        players[host].update({
                'xuid': data["XUID"],
                'gamertag': data["GTAG"],
                'puid': data["MID"],
                'mac': data["MAC"],
                'macaddress': data["MADDR"],
                'password': data["PASS"],
                'friends': ''
            })
        response = [
            "LAST=2018.1.1-00:00:00",
            "TOS=1",
            "SHARE=1",
            f"_LUID={players[host].get('puid')}",
            f"NAME={players[host].get('gamertag')}",
            f"PERSONAS={players[host].get('gamertag')}",
            "MAIL=mail@example.com",
            "BORN=19700101",
            "FROM=US",
            "LOC=enUS",
            "SPAM=YN",
            "SINCE=2008.1.1-00:00:00",
            "GFIDS=1",
            f"ADDR={players[host].get('address')}",
            "TOKEN=pc6r0gHSgZXe1dgwo_CegjBCn24uzUC7KVq1LJDKJ0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000."
        ]
        send_response(command, response, conn, txn_id)
        return
    elif command == "pers":
        response = [
            f"NAME={players[host].get('gamertag')}",
            f"PERS={players[host].get('gamertag')}",
            "LAST=2018.1.1-00:00:00",
            "PLAST=2018.1.1-00:00:00",
            "SINCE=2008.1.1-00:00:00",
            "PSINCE=2008.1.1-00:00:00",
            "LKEY=000000000000000000000000000.",
            "STAT=,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,",
            "LOC=enUS",
            f"A={players[host].get('address')}",
            f"MA={players[host].get('macaddress')}",
            f"LA={players[host].get('address')}",
            "IDLE=50000"
        ]
        response2 = [
            "I=1022",
            f"N={players[host].get('gamertag')}",
            f"M={players[host].get('gamertag')}",
            "F=U",
            f"A={players[host].get('address')}",
            "P=1",
            "S=,,",
            "G=0",
            "AT=",
            "CL=511",
            "LV=1049601",
            "MD=0",
            f"LA={players[host].get('address')}",
            "HW=0",
            "RP=0",
            f"MA={players[host].get('macaddress')}",
            "LO=enUS",
            "X=",
            "US=0",
            "PRES=1",
            "VER=7",
            "C=,,,,,,,,"
        ]
        send_response(command, response, conn, txn_id)
        send_response('+who', response2, conn, txn_id)
        return
    elif command == "fget":
        response = [
            players[host].get('friends')
        ]
        send_response(command, [], conn, txn_id)
        return
    elif command == "fupd":
        friends = data["ADD"]
        players[host]['friends'] = friends
        send_response(command, [], conn, txn_id)
        return
        

# === Server Thread per Connection ===
def client_thread(conn, addr):
    print(f"[INFO] Connected by {addr}")
    buffer = b''
    try:
        while True:
            data = conn.recv(4096)
            if not data:
                break
            buffer += data
            while len(buffer) >= 12:
                try:
                    size = struct.unpack('>I', buffer[8:12])[0]
                except:
                    break
                if len(buffer) < size:
                    break
                packet_data = buffer[:size]
                buffer = buffer[size:]
                parsed = parse_packet(packet_data)
                handle_packet(parsed, conn)
    except Exception as e:
        print(f"[ERROR] {addr}: {e}")
    finally:
        conn.close()
        print(f"[INFO] Disconnected {addr}")

# === Start Server ===
def start_server(host='0.0.0.0', port=10134):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen()
        print(f"[INFO] Server listening on {host}:{port}")
        while True:
            conn, addr = s.accept()
            threading.Thread(target=client_thread, args=(conn, addr), daemon=True).start()

if __name__ == "__main__":
    start_server()
