import threading
import time

SOF = 1
EOF = 1
CRC = 0
ACK = 0
CONTROL = 1
ADV_CONTROL = 0
RTR_REQUEST_DATA = 0
RTR_SEND_DATA = 1

ERROR_ACTIVE = "ErrorActive"
ERROR_PASSIVE = "ErrorPassive"
BUSS_OFF = "BusOff"

VICTIM_ECU = "Victim   "
NORMAL_ECU = "Normal   "
ADVERSARY_ECU = "Adversary"

# General Packet: [1, 0, 0, 0, [0, 0, 0, 0, 0, 0, 0, 0], 0, 0, 1]
class Packet:
    def __init__(self, ecu_id, id, rtr, data, control=CONTROL, sof=SOF, ack=ACK, eof=EOF, crc=CRC, active_error_flag=False, passive_error_flag=False):
        # Indicates which ECU sends the packet
        self.ecu_id = ecu_id
        # Start Of Frame --> 0 if the node want to talk to other nodes
        self.sof = sof # For this project always 1
        # Frame Identifier --> the lower the higher is the priority (not an identifier of the sender)
        self.id = id 
        # Remote Trasmission Request --> indicates whether a node sends data or requests data from another node
        self.rtr = rtr # For this project: 0 -> requests data , 1 -> send data
        # Contains the Identifier Extension Bit (IEB) which is dominant 0 for 11 bits ID. 
        # It also contains the 4 bit Data Length Code (DLC) that specifies the length of the data bytes to be transmitted (0 to 8 bytes)
        self.control = control # For this project 1 if normal or victim ECU, 0 if adversary ECU
        # Payload
        self.data = data
        # Check for data integrity
        self.crc = crc # For this project always 0
        # Indicates whether a node has acknowledged and received data correctly
        self.ack = ack # For this project always 0
        # End Of Frame
        self.eof = eof # For this project always 1
    
    def to_Array(self):
        return [self.sof, self.id, self.rtr, self.control, self.data, self.crc, self.ack, self.eof]

    def get_EcuId(self):
        return self.ecu_id

    def get_Id(self):
        return self.id

    def get_Control(self):
        return self.control
    
    def get_Data(self):
        return self.data


class ECU:
    def __init__(self, ecu_id, tec=0, rec=0, retransmission_needed=False, passive_flag=False, active_flag=False, attack_mode=NORMAL_ECU):
        self.ecu_id = ecu_id
        # If TEC or REC > 127 --> mode = ErrorPassive
        # If TEC and REC return < 128 --> mode = ErrorActive
        # If TEC > 255 --> mode = BusOff
        self.tec = tec
        self.rec = rec
        # True if the flags are active, False otherwise
        self.passive_flag = passive_flag
        self.active_flag = active_flag
        self.retransmission_needed = retransmission_needed
        # All ECUs start in Error Active mode
        self.status = ERROR_ACTIVE
        self.attack_mode = attack_mode # Normal ECU; Victim ECU; Adversary ECU
        self.tec_history = []
        self.sent_packets = {}

    def get_ecuId(self):
        return self.ecu_id

    def tec_rec_increment(self):
        self.tec += 8
        self.rec += 8
        self.tec_history.append(self.tec)

    def tec_rec_decrement(self):
        self.tec -= 1
        self.rec -= 1
        self.tec_history.append(self.tec)

    def ecu_status_check(self):
        if self.tec <= 127 and self.rec <= 127:
            self.status = ERROR_ACTIVE
        elif 127 < self.tec <= 255 or 127 < self.rec <= 255:
            self.status = ERROR_PASSIVE
        elif self.tec > 255:
            self.status = BUSS_OFF

    # retransmission --> to understand if the packet is or not a retransmission
    def send_packet(self, packet_id, data, canbus):
        
        if self.ecu_id in canbus.ecus:

            packet = Packet(self.ecu_id ,packet_id, RTR_SEND_DATA, data)
            
            # Send the message to the can-bus (store the packet in the canbus log array)
            with canbus.lock:
                canbus.packet_log.append(packet)
                print(f"| [{self.attack_mode}] | {self.ecu_id} | {packet.get_Id()} | {packet.get_Data()} |")
    
    def inject_attack_packet(self, inject_packID, data, canbus):
        
        if self.ecu_id in canbus.ecus and self.attack_mode == ADVERSARY_ECU:
            
            injected_packet = Packet(self.ecu_id, inject_packID, RTR_SEND_DATA, data, control=ADV_CONTROL)
            
            # Send the message to the can-bus (store the packet in the canbus log array)
            with canbus.lock:
                canbus.packet_log.append(injected_packet)
                print(f"[{self.attack_mode}] | {self.ecu_id} | {injected_packet.get_Control()} | {injected_packet.get_Data()} |")

    def check_for_duplicate(self, packet_id, canbus):
        
        with canbus.lock: # Secure access to the CanBus' packet log array
            
            duplicates = [msg for msg in canbus.packet_log if msg.get_Id() == packet_id and msg.get_EcuId() != self.ecu_id]
            
            if len(duplicates) > 0:
                
                # Check duplicates if differs or not
                for duplicate in duplicates:
                    
                    original_message = self.sent_packets[packet_id]
                    # Check the same id packets
                    if duplicate.to_Array() != original_message.to_Array():
                        self.retransmission_needed = True
                        
                if self.retransmission_needed:
                    
                    self.ecu_status_check()
                    
                    if self.status == ERROR_ACTIVE:
                        
                        self.tec_rec_increment()
                        self.active_flag = True
                    
                    elif self.status == ERROR_PASSIVE:
                        
                        self.tec_rec_increment()

                        if self.attack_mode == ADVERSARY_ECU:
                            
                            self.tec_rec_decrement()
                            self.active_flag = False
                            self.passive_flag = False

                    elif self.status == BUSS_OFF:

                        canbus.disconnect_ecu(self)

                elif self.tec != 0 and self.rec != 0:

                    self.tec_rec_decrement()

            else:

                self.retransmission_needed = False

class CANBus:
    def __init__(self):
        self.ecus = []
        self.packet_log = []
        self.lock = threading.Lock()

    def connect_ecu(self, ecu):
        if ecu not in self.ecus: 
            self.ecus.append(ecu)
            print(f"The ECU {ecu.get_ecuId()} has been connected to the CAN bus")
        else:
            print(f"The ECU {ecu.get_ecuId()} is already connected")

    def disconnect_ecu(self, ecu):
        if ecu in self.ecus:
            self.ecus.remove(ecu)
            print(f"The ECU {ecu.get_ecuId()} has been disconnected from the CAN bus")
        else:
            print(f"The ECU {ecu.get_ecuId()} is not connected")


def simulation(ecu, canbus, interval, packet_id, data):
    while ecu in canbus.ecus:
        if ecu.attack_mode == VICTIM_ECU or ecu.attack_mode == NORMAL_ECU:
            ecu.send_packet(packet_id, data, canbus)
        elif ecu.attack_mode == ADVERSARY_ECU:
            ecu.inject_attack_packet(packet_id, data, canbus)
        
        ecu.check_for_duplicate(packet_id, canbus)

        time.sleep(interval)


canbus = CANBus()
ecu_victim = ECU(1, attack_mode=VICTIM_ECU)
ecu_adversary = ECU(2, attack_mode=ADVERSARY_ECU)

canbus.connect_ecu(ecu_victim)
canbus.connect_ecu(ecu_adversary)

victim_thread = threading.Thread() # .....
adversary_thread = threading.Thread() # .....