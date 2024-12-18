#receivedMessage = {"af0":1925344,"af1":21763,"af2":104,"cic":57803,"cis":267,"crc":4147,"crs":52218,"cuc":10127,"cus":17936,"deltaN":45118,"eccentricity":4145034218,"fitIntervalFlag":1,"gpsCodeOnL2":0,"gpsWeekNumber":903,"i0":1797754871,"idot":8416,"iodc":582,"iode":225,"l2PDataFlag":1,"m0":1275136875,"messageNumber":1019,"omega":3930460173,"omega0":4205854284,"omegaDot":6837507,"satelliteId":26,"sqrtA":224941315,"svAccuracy":11,"svHealth":62,"tgd":234,"toc":4109,"toe":30083}
receivedMessage = {"af0":1747664,"af1":64575,"af2":126,"cic":50174,"cis":4096,"crc":29712,"crs":65025,"cuc":30018,"cus":9180,"deltaN":7305,"eccentricity":913576050,"fitIntervalFlag":1,"gpsCodeOnL2":0,"gpsWeekNumber":783,"i0":326451766,"idot":10960,"iodc":291,"iode":195,"l2PDataFlag":1,"m0":2400190483,"messageNumber":1019,"omega":1914952727,"omega0":18647439,"omegaDot":8322111,"satelliteId":16,"sqrtA":394198079,"svAccuracy":14,"svHealth":0,"tgd":114,"toc":56343,"toe":27307}
#####################################-----ENCODE RTCM 1002 START----#################################################
#####################################------------BY MOINUL----------#################################################
from pyrtcm import RTCMReader
def hexFromBinary(binary_string):
    # Ensure the input is valid binary
    if not all(char in '01' for char in binary_string):
        raise ValueError("Input contains invalid characters; must be only '0' and '1'.")

    # Convert binary string to integer
    decimal_value = int(binary_string, 2)

    # Convert integer to hexadecimal
    hex_value = hex(decimal_value)[2:] # Remove '0x' prefix and make uppercase

    return hex_value

def generate_crc24q_table():
    poly = 0x1864CFB
    table = []
    for i in range(256):
        crc = i << 16
        for _ in range(8):
            if crc & 0x800000:
                crc = (crc << 1) ^ poly
            else:
                crc <<= 1
        table.append(crc & 0xFFFFFF)
    return table


def crc24(data):
    table = generate_crc24q_table()
    crc = 0
    for byte in data:
        crc = ((crc << 8) & 0xFFFFFF) ^ table[(crc >> 16) ^ byte]
    return crc

def validate_message_type_1019(message):
    # Validate the top-level keys and their types
    if not isinstance(message, dict):
        return False, "Message should be a dictionary."

    required_keys = {
        "messageNumber": int,
        "satelliteId": int,
        "gpsWeekNumber": int,
        "svAccuracy": int,
        "gpsCodeOnL2": int,
        "idot": int,
        "iode": int,
        "toc": int,
        "af2": int,
        "af1": int,
        "af0": int,
        "iodc": int,
        "crs": int,
        "deltaN": int,
        "m0": int,
        "cuc": int,
        "eccentricity": int,
        "cus": int,
        "sqrtA": int,
        "toe": int,
        "cic": int,
        "omega0": int,
        "cis": int,
        "i0": int,
        "crc": int,
        "omega": int,
        "omegaDot": int,
        "tgd": int,
        "svHealth": int,
        "l2PDataFlag": int,
        "fitIntervalFlag": int,
    }

    # Check for the presence and type of each key
    for key, expected_type in required_keys.items():
        if key not in message:
            return False, f"Missing required key: {key}"
        if not isinstance(message[key], expected_type):
            return False, f"Key '{key}' should be of type {expected_type.__name__}"

    return True, "Message is valid."
########################################################################


def encodeRTCM1019(receivedMessage):
    content_binary = format(receivedMessage["messageNumber"], '012b')
    content_binary = content_binary + format(receivedMessage["satelliteId"], '06b')
    content_binary = content_binary + format(receivedMessage["gpsWeekNumber"], '010b')
    content_binary = content_binary + format(receivedMessage["svAccuracy"], '04b')
    content_binary = content_binary + format(receivedMessage["gpsCodeOnL2"], '02b')
    content_binary = content_binary + format(receivedMessage["idot"], '014b')
    content_binary = content_binary + format(receivedMessage["iode"], '08b')
    content_binary = content_binary + format(receivedMessage["toc"], '016b')
    content_binary = content_binary + format(receivedMessage["af2"], '08b')
    content_binary = content_binary + format(receivedMessage["af1"], '016b')
    content_binary = content_binary + format(receivedMessage["af0"], '022b')
    content_binary = content_binary + format(receivedMessage["iodc"], '010b')
    content_binary = content_binary + format(receivedMessage["crs"], '016b')
    content_binary = content_binary + format(receivedMessage["deltaN"], '016b')
    content_binary = content_binary + format(receivedMessage["m0"], '032b')
    content_binary = content_binary + format(receivedMessage["cuc"], '016b')
    content_binary = content_binary + format(receivedMessage["eccentricity"], '032b')
    content_binary = content_binary + format(receivedMessage["cus"], '016b')
    content_binary = content_binary + format(receivedMessage["sqrtA"], '032b')
    content_binary = content_binary + format(receivedMessage["toe"], '016b')
    content_binary = content_binary + format(receivedMessage["cic"], '016b')
    content_binary = content_binary + format(receivedMessage["omega0"], '032b')
    content_binary = content_binary + format(receivedMessage["cis"], '016b')
    content_binary = content_binary + format(receivedMessage["i0"], '032b')
    content_binary = content_binary + format(receivedMessage["crc"], '016b')
    content_binary = content_binary + format(receivedMessage["omega"], '032b')
    content_binary = content_binary + format(receivedMessage["omegaDot"], '024b')
    content_binary = content_binary + format(receivedMessage["tgd"], '08b')
    content_binary = content_binary + format(receivedMessage["svHealth"], '06b')
    content_binary = content_binary + format(receivedMessage["l2PDataFlag"], '01b')
    content_binary = content_binary + format(receivedMessage["fitIntervalFlag"], '01b')

    print(content_binary)


    #header
    messageLength = int(len(content_binary)/8)
    preamble_binary = '11010011'
    reserved_binary = '000000'
    messageLength_binary = format(messageLength, '010b')
    header_binary = preamble_binary + reserved_binary + messageLength_binary


    crc_msg_binary = header_binary + content_binary
    crc_msg_decimal = int(crc_msg_binary, 2)
    #crc_msg_hex = hex(crc_msg_decimal)
    crc_num_bytes = (len(crc_msg_binary) + 7) // 8
    crc_content_bytes = crc_msg_decimal.to_bytes(crc_num_bytes, byteorder='big')
    crc_int = crc24(crc_content_bytes)
    crc_bit_length = 24
    crc_binary_string = format(crc_int, f'0{crc_bit_length}b')

    encodedRTCM_binary = header_binary + content_binary + crc_binary_string
    #print(f"encodedRTCM Binary->{encodedRTCM_binary}, Hex->{hexFromBinary(encodedRTCM_binary)}")

    rtcm_bytes = bytes.fromhex(hexFromBinary(encodedRTCM_binary))
    parsed_data = RTCMReader.parse(rtcm_bytes)
    print(parsed_data)

#####################################-----ENCODE RTCM 1002 END----#################################################
is_valid, message = validate_message_type_1019(receivedMessage)

if(is_valid):
    encodeRTCM1019(receivedMessage)
    print("Valid Message")
else:
    print("Invalid Ephemeris Message")