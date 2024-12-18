receivedMessage = {
    "referenceStationId": 1,
    "gpsEpochTime": 603240000,
    "synchronousGnssFlag": 0,
    "gpsMultipleMessageFlag": 0,
    "divergenceFreeSmoothing": 0,
    "smoothingInterval": 0,
    "satellites": [
        {
            "satelliteId": 2,
            "l1": {
                "codeIndicator": 0,
                "pseudorange": 12582358,
                "phaserangePseudorangeDiff": 524287,
                "lockTimeIndicator": 1,
                "cnr": 104,
                "pseudorangeModulusAmbiguity": 0
            }
        },
        {
            "satelliteId": 8,
            "l1": {
                "codeIndicator": 0,
                "pseudorange": 770790,
                "phaserangePseudorangeDiff": 198931,
                "lockTimeIndicator": 1,
                "cnr": 87,
                "pseudorangeModulusAmbiguity": 0
            }
        }
    ]
}
#####################################-----ENCODE RTCM 1002 START----#################################################
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

def validate_received_message(message):
    # Validate the top-level keys and their types
    if not isinstance(message, dict):
        return False, "Message should be a dictionary."

    required_keys = {
        "referenceStationId": int,
        "gpsEpochTime": int,
        "synchronousGnssFlag": int,
        "gpsMultipleMessageFlag": int,
        "divergenceFreeSmoothing": int,
        "smoothingInterval": int,
        "satellites": list,
    }

    for key, expected_type in required_keys.items():
        if key not in message:
            return False, f"Missing required key: {key}"
        if not isinstance(message[key], expected_type):
            return False, f"Key {key} should be of type {expected_type.__name__}"

    # Validate satellite array
    satellites = message["satellites"]
    if not (1 <= len(satellites) <= 50):
        return False, "Number of satellites should be between 1 and 50."

    for satellite in satellites:
        if not isinstance(satellite, dict):
            return False, "Each satellite should be a dictionary."

        satellite_keys = {
            "satelliteId": int,
            "l1": dict,
        }

        for key, expected_type in satellite_keys.items():
            if key not in satellite:
                return False, f"Missing key {key} in satellite data."
            if not isinstance(satellite[key], expected_type):
                return False, f"Satellite key {key} should be of type {expected_type.__name__}"

        # Validate the "l1" sub-dictionary
        l1 = satellite["l1"]
        l1_keys = {
            "codeIndicator": int,
            "pseudorange": int,
            "phaserangePseudorangeDiff": int,
            "lockTimeIndicator": int,
            "cnr": int,
            "pseudorangeModulusAmbiguity": int,
        }

        for key, expected_type in l1_keys.items():
            if key not in l1:
                return False, f"Missing key {key} in l1 data."
            if not isinstance(l1[key], expected_type):
                return False, f"L1 key {key} should be of type {expected_type.__name__}"

    return True, "Message is valid."
########################################################################


def encodeRTCM1002(receivedMessage):
    # content
    messageNumber = 1002
    messageNumber_binary = format(messageNumber, '012b')
    content_binary = messageNumber_binary

    referenceStationID = receivedMessage["referenceStationId"]
    referenceStationID_binary = format(referenceStationID, '012b')
    content_binary = content_binary + referenceStationID_binary

    gpsEpochTime = receivedMessage["gpsEpochTime"]
    gpsEpochTime_binary = format(gpsEpochTime, '030b')
    content_binary = content_binary + gpsEpochTime_binary

    SyncGNSSFlag = receivedMessage["synchronousGnssFlag"]
    SyncGNSSFlag_binary = format(SyncGNSSFlag, '01b')
    content_binary = content_binary + SyncGNSSFlag_binary

    numberOfSatellites = len(receivedMessage["satellites"])
    numberOfSatellites_binary = format(numberOfSatellites, '05b')
    content_binary = content_binary + numberOfSatellites_binary

    gpsSmoothingIndicator = receivedMessage["divergenceFreeSmoothing"]
    gpsSmoothingIndicator_binary = format(gpsSmoothingIndicator, '01b')
    content_binary = content_binary + gpsSmoothingIndicator_binary

    gpsSmotthingInterval = receivedMessage["smoothingInterval"]
    gpsSmotthingInterval_binary = format(gpsSmotthingInterval, '03b')
    content_binary = content_binary + gpsSmotthingInterval_binary

    for satellite in receivedMessage["satellites"]:
        satelliteID = int(satellite["satelliteId"])
        codeIndicator = int(satellite["l1"]["codeIndicator"])
        pseudorange = int(satellite["l1"]["pseudorange"])
        phaseDiffPseudo = int(satellite["l1"]["phaserangePseudorangeDiff"])
        lockTimeIndicator = int(satellite["l1"]["lockTimeIndicator"])
        pseudoModulusAmbi = int(satellite["l1"]["pseudorangeModulusAmbiguity"])
        cnr = int(satellite["l1"]["cnr"])
        satelliteID_binary = format(satelliteID, '06b')
        codeIndicator_binary = format(codeIndicator, '01b')
        pseudorange_binary = format(pseudorange, '024b')
        phaseDiffPseudo_binary = format(phaseDiffPseudo, '020b')
        lockTimeIndicator_binary = format(lockTimeIndicator, '07b')
        pseudoModulusAmbi_binary = format(pseudoModulusAmbi, '08b')
        cnr_binary = format(cnr, '08b')
        thisContent_binary = satelliteID_binary + codeIndicator_binary + pseudorange_binary + phaseDiffPseudo_binary + lockTimeIndicator_binary + pseudoModulusAmbi_binary + cnr_binary
        content_binary = content_binary + thisContent_binary


    while(len(content_binary)%4 != 0):
        content_binary = content_binary + '00'
    while(len(content_binary)%8 != 0):
        content_binary = content_binary + '0000'
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
is_valid, message = validate_received_message(receivedMessage)

if(is_valid):
    encodeRTCM1002(receivedMessage)
else:
    print("Invalid Message")
