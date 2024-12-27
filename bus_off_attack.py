import time
import threading
import matplotlib.pyplot as plt

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

running = True


class Packet:
    def __init__(self, ecu_id, id, rtr, data, control=CONTROL, sof=SOF, ack=ACK, eof=EOF, crc=CRC):
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

    def __init__(self, ecu_id, attack_mode=NORMAL_ECU, adv_target=-1):
        
        self.attack_mode = attack_mode
        # Indicate the target of the adv ECU when attack_mode = Adversary
        # -1 if attack_mode != Adversary, the ecu_id when attack_mode == Adversary
        self.adv_target = adv_target
        self.ecu_id = ecu_id
        # If TEC or REC > 127 --> mode = ErrorPassive
        # If TEC and REC return < 128 --> mode = ErrorActive
        # If TEC > 255 --> mode = BusOff
        self.tec = 0
        self.rec = 0
        # True if the flags has to be sent, False otherwise
        self.passive_flag = False
        self.active_flag = False
        self.retransmission_needed = False
        self.retransmission_delay = 0.1
        # All ECUs start in Error Active mode
        self.status = ERROR_ACTIVE
        
        self.tec_history = [0]
        #self.tec_history.append(self.tec)
        self.tec_timestamp = [time.time()]
        #self.tec_timestamp.append(time.time())
        self.sent_packets = {}  # Store all packets sent with their ID as key

    def ecu_status_check(self):
        
        if self.tec <= 127 and self.rec <= 127:

            self.status = ERROR_ACTIVE

        elif 127 < self.tec <= 255 or 127 < self.rec <= 255:

            self.status = ERROR_PASSIVE
            self.retransmission_delay = 0.5

        elif self.tec > 255:

            self.status = BUSS_OFF

    def send_packet(self, packet_id, data, canbus, retransmission=False):
        
        if self.attack_mode == ADVERSARY_ECU:

            packet = Packet(self.ecu_id, packet_id, RTR_SEND_DATA, data, control=ADV_CONTROL)

        else:

            packet = Packet(self.ecu_id, packet_id, RTR_SEND_DATA, data)
        
        # Memorizza i dettagli del pacchetto inviato (se non è una ritrasmissione)
        if not retransmission:

            self.sent_packets[packet_id] = (data, packet)
        
        with canbus.lock:

            canbus.packet_log.append(packet)
            print(f"{'Retrasmission | ' if retransmission else ''}|  [{self.attack_mode}] | ECU {self.ecu_id} sent packet: ID={packet.get_Id()} PACKET={packet.to_Array()} |")

    def check_duplicate_ids(self, packet_id, canbus):
        """Controlla il log per messaggi con lo stesso ID, ignorando ritrasmissioni."""
        with canbus.lock:

            #self.ecu_status_check()
            duplicates = [msg for msg in canbus.packet_log if msg.get_Id() == packet_id and msg.get_EcuId() != self.ecu_id]
            
            if len(duplicates) > 0:
                #print(f"ECU {self.ecu_id} detected duplicate ID: {packet_id}. Comparing packets...")
                
                # Confronta i pacchetti duplicati
                for duplicate in duplicates:
                    
                    original_data, original_packet = self.sent_packets[packet_id]
                    # Confronta gli array dei pacchetti
                    if duplicate.to_Array() != original_packet.to_Array():
                        #print(f"Packets are different. Retransmitting...")
                        
                        self.retransmission_needed = True

                        if self.status == ERROR_ACTIVE:

                            if self.attack_mode == ADVERSARY_ECU:
                                # Find the victim ecu in case self is an adversary ECU
                                victim_ecu = next((ecu for ecu in canbus.ecus if ecu.ecu_id == self.adv_target), None)

                                if victim_ecu.status == ERROR_ACTIVE:

                                    self.active_flag = True
                                    
                            # Case ECUs are not adversaries    
                            else:

                                self.active_flag = True
                        
                        elif self.status == ERROR_PASSIVE:
                            
                            if self.attack_mode != ADVERSARY_ECU:

                                self.passive_flag = True
                        
            else:
                
                self.retransmission_needed = False

    def tec_rec_check(self, packet_id, canbus):
        
        with canbus.lock:

            self.ecu_status_check()
            duplicates = [msg for msg in canbus.packet_log if msg.get_Id() == packet_id and msg.get_EcuId() != self.ecu_id]
            
            if len(duplicates) > 0:                
                # Confronta i pacchetti duplicati
                for duplicate in duplicates:
                    
                    original_data, original_packet = self.sent_packets[packet_id]
                    # Confronta gli array dei pacchetti
                    if duplicate.to_Array() != original_packet.to_Array():

                        if self.status == ERROR_ACTIVE and self.active_flag:
                            
                            self.tec += 8
                            self.tec_history.append(self.tec)
                            self.tec_timestamp.append(time.time())
                            self.rec += 8

                        elif self.status == ERROR_PASSIVE and self.passive_flag:

                            self.tec += 8
                            self.tec_history.append(self.tec)
                            self.tec_timestamp.append(time.time())
                            self.tec -= 1
                            self.tec_history.append(self.tec)
                            self.tec_timestamp.append(time.time())
                            self.rec += 8
                            self.rec -= 1
                        
                        if self.attack_mode == ADVERSARY_ECU:
                            victim_ecu = next((ecu for ecu in canbus.ecus if ecu.ecu_id == self.adv_target), None)
                            if victim_ecu.passive_flag:

                                self.tec -= 1
                                self.tec_history.append(self.tec)
                                self.tec_timestamp.append(time.time())
                                self.rec -= 1

            self.ecu_status_check()
            print(f"{self.attack_mode} -> tec: {self.tec} rec: {self.rec} activeFlag: {self.active_flag} passiveFlag: {self.passive_flag} {self.status}")
            self.active_flag = False
            self.passive_flag = False


class CANBus:
    def __init__(self):
        
        self.ecus = []
        self.packet_log = []
        self.lock = threading.Lock()  # Lock per la gestione sicura dell'accesso al log dei messaggi

    def connect_ecu(self, ecu):
        
        if ecu not in self.ecus:
            self.ecus.append(ecu)
            print(f"The ECU {ecu.ecu_id} has been connected to the CAN bus")
        else:
            print(f"The ECU {ecu.ecu_id} is already connected")

    def disconnect_ecu(self, ecu):
        
        if ecu in self.ecus:
            self.ecus.remove(ecu)
            print(f"The ECU {ecu.ecu_id} has been disconnected from the CAN bus")
        else:
            print(f"The ECU {ecu.ecu_id} is not connected")


# Funzione per inviare e controllare i messaggi in modo sincronizzato
def run_ecu(ecu, packet_id, data, canbus, barrier):
    
    global running
    while running and ecu in canbus.ecus and len(canbus.ecus) > 1:
        
        canbus.packet_log.clear()
        
        # Check the status of the ECU
        ecu.ecu_status_check()
        # If the ECU is in a bus-off state --> disconnect it from the can bus
        if ecu.status == BUSS_OFF:
            with canbus.lock:
                canbus.disconnect_ecu(ecu)
            running = False
            break

        try:
            # Sincronizzazione prima dell'invio
            barrier.wait(timeout=1)  # Aggiungi un timeout per evitare blocchi indefiniti
        except threading.BrokenBarrierError:
            #print(f"Barrier broken for ECU {ecu.ecu_id}")
            break
        
        if ecu.retransmission_needed:
            # Ritrasmetti il pacchetto precedente
            ecu.send_packet(packet_id, ecu.sent_packets[packet_id][1].get_Data(), canbus, retransmission=True)
        else:
            # Invia un nuovo pacchetto
            ecu.send_packet(packet_id, data, canbus)

        try:
            # Sincronizzazione prima dell'invio
            barrier.wait(timeout=1)  # Aggiungi un timeout per evitare blocchi indefiniti
        except threading.BrokenBarrierError:
            #print(f"Barrier broken for ECU {ecu.ecu_id}")
            break

        ecu.check_duplicate_ids(packet_id, canbus)

        try:
            # Sincronizzazione prima dell'invio
            barrier.wait(timeout=1)  # Aggiungi un timeout per evitare blocchi indefiniti
        except threading.BrokenBarrierError:
            #print(f"Barrier broken for ECU {ecu.ecu_id}")
            break

        ecu.tec_rec_check(packet_id, canbus)
        
        # Aspetta l'intervallo
        time.sleep(ecu.retransmission_delay)
        print("----------------------------------------------------------------")


def plot_tec_history(*ecus):
    for ecu in ecus:
        # Calcola l'asse x come differenza di tempo rispetto al primo timestamp
        x_axis = [t - ecu.tec_timestamp[0] for t in ecu.tec_timestamp]
        if ecu.attack_mode == ADVERSARY_ECU:
            plt.plot(x_axis, ecu.tec_history, label=f"ECU {ecu.ecu_id} ({ecu.attack_mode})", linestyle='--')
        else:
            plt.plot(x_axis, ecu.tec_history, label=f"ECU {ecu.ecu_id} ({ecu.attack_mode})")
    plt.xlabel("Time (seconds)")
    plt.ylabel("Transmit Error Counter (TEC)")
    plt.title("TEC Evolution of ECUs")
    plt.legend()
    plt.grid()
    plt.show()


# Esegui il CAN bus e le ECU
canbus = CANBus()
ecu1 = ECU(1)
ecu2 = ECU(2, attack_mode=ADVERSARY_ECU, adv_target=1)

canbus.connect_ecu(ecu1)
canbus.connect_ecu(ecu2)

# Creazione di una barriera per sincronizzare i due thread
barrier = threading.Barrier(2)

# Avvia i thread per entrambe le ECU
thread1 = threading.Thread(target=run_ecu, args=(ecu1, 100, [1, 0, 1], canbus, barrier))
thread2 = threading.Thread(target=run_ecu, args=(ecu2, 100, [0, 0, 1], canbus, barrier))

thread1.start()
thread2.start()

thread1.join()
thread2.join()

plot_tec_history(ecu1, ecu2)
