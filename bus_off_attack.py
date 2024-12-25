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

class Packet:
    def __init__(self, ecu_id, id, rtr, data, control=CONTROL, sof=SOF, ack=ACK, eof=EOF, crc=CRC):
        self.ecu_id = ecu_id
        self.id = id
        self.rtr = rtr
        self.data = data
        self.control = control
        self.sof = sof
        self.ack = ack
        self.eof = eof
        self.crc = crc

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
    def __init__(self, ecu_id, attack_mode=NORMAL_ECU):
        
        self.attack_mode = attack_mode
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
        # All ECUs start in Error Active mode
        self.status = ERROR_ACTIVE
        self.tec_history = []
        self.tec_history.append(self.tec)
        self.sent_packets = {}  # Store all packets sent with their ID as key

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
                        #self.ecu_status_check()

                        if self.status == ERROR_ACTIVE:
                            self.active_flag = True
                            self.tec_rec_increment()
                        elif self.status == ERROR_PASSIVE:
                            self.active_flag = False
                            if self.attack_mode != ADVERSARY_ECU:
                                self.passive_flag = True
                                self.tec_rec_increment()
                                self.tec_rec_decrement()
                            else:
                                self.tec_rec_decrement()
                    #else:
                        #print(f"Packets are identical. No retransmission needed.")
                        
            else:
                #print(f"ECU {self.ecu_id} found no duplicate for ID: {packet_id}. No retransmission needed.")
                self.retransmission_needed = False


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
    
    while ecu in canbus.ecus and len(canbus.ecus) != 1:
        canbus.packet_log.clear()
        
        # Check the status of the ECU
        ecu.ecu_status_check()
        # If the ECU is in a bus-off state --> disconnect it from the can bus
        if ecu.status == BUSS_OFF:
            canbus.disconnect_ecu(ecu)
            break

        # Sincronizzazione prima dell'invio
        barrier.wait()
        
        if ecu.retransmission_needed:
            # Ritrasmetti il pacchetto precedente
            ecu.send_packet(packet_id, ecu.sent_packets[packet_id][1].get_Data(), canbus, retransmission=True)
        else:
            # Invia un nuovo pacchetto
            ecu.send_packet(packet_id, data, canbus)

        # Sincronizzazione prima del controllo
        barrier.wait()
        print("-------------------------------------------------------------------")
        ecu.check_duplicate_ids(packet_id, canbus)

        # Aspetta l'intervallo
        time.sleep(1)

def plot_tec_history(*ecus):
    for ecu in ecus:
        plt.plot(ecu.tec_history, label=f"ECU {ecu.ecu_id} ({ecu.attack_mode})")
    plt.xlabel("Time (iterations)")
    plt.ylabel("Transmit Error Counter (TEC)")
    plt.title("TEC Evolution of ECUs")
    plt.legend()
    plt.grid()
    plt.show()

# Esegui il CAN bus e le ECU
canbus = CANBus()
ecu1 = ECU(1)
ecu2 = ECU(2, attack_mode=ADVERSARY_ECU)

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
