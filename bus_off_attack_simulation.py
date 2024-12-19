import matplotlib.pyplot as plt

ERROR_ACTIVE = "ErrorActive"
ERROR_PASSIVE = "ErrorPassive"
BUSS_OFF = "BusOff"

class ECU:
    def __init__(self, name, id, data=[], passive_flag=False, active_flag=False, tec=0, rec=0, attack_mode=False):
        self.attack_mode = attack_mode
        self.name = name
        self.id = id
        self.data = data
        # True if the flags are active, False otherwise
        self.passive_flag = passive_flag
        self.active_flag = active_flag
        # All ECUs start in Error Active mode
        self.mode = ERROR_ACTIVE
        # If TEC or REC > 127 --> mode = ErrorPassive
        # If TEC and REC return < 128 --> mode = ErrorActive
        # If TEC > 255 --> mode = BusOff
        self.tec = tec
        self.rec = rec
        self.tec_history = []

    def send_message(self, data):
        self.data = data
        print(f"[{self.name}] | {self.id} | " + " ".join(map(str, data)))

    def retrasmission(self):
        print(f"Retrasmission: [{self.name}] | {self.id} | " + " ".join(map(str, self.data)))

    def inject_attack_message(self, data=[0,0,0,0,0,0,0,0]):
        if self.attack_mode:
            self.data = data
            # Send a all zero message which is surely dominant
            self.send_message(data)

    def ecu_mode_check(self):
        if self.tec <= 127 and self.rec <= 127:
            self.mode = ERROR_ACTIVE
        elif 127 < self.tec <= 255 or 127 < self.rec <= 255:
            self.mode = ERROR_PASSIVE
        elif self.tec > 255:
            self.mode = BUSS_OFF

    def tec_rec_increment(self):
        self.tec += 8
        self.rec += 8
        self.tec_history.append(self.tec)

    def tec_rec_decrement(self):
        self.tec -= 1
        self.rec -= 1
        self.tec_history.append(self.tec)


class CANBus:
    def __init__(self):
        self.victim_ecu = ECU("Victim   ", id=0x01)
        self.adversary_ecu = ECU("Adversary", id=0x01, attack_mode=True)

    def victim_error_active_state(self):
        if not self.victim_ecu.active_flag:
            # Message
            self.victim_ecu.send_message(data=[0x00, 0x00, 0x01, 0x00, 0x00, 0x02, 0x00, 0xFF]) 
        else:
            # Retrasmission of the message due to an error
            self.victim_ecu.retrasmission()

    def adversary_error_active_state(self):
        if not self.adversary_ecu.active_flag:
            # Inject adversary message
            self.adversary_ecu.inject_attack_message() 
        else:
            # Retrasmission of the injected message due to an error
            self.adversary_ecu.retrasmission()

    def simulate(self):
        working = True
        count = 0

        while working:
            
            # VICTIM ECU
            self.victim_ecu.ecu_mode_check()
            if self.victim_ecu.mode == ERROR_ACTIVE:
                if self.victim_ecu.tec != 0:
                    # If not zero there was an error so the retrasmission has an active flag
                    self.victim_ecu.active_flag = True
                self.victim_error_active_state()
            elif self.victim_ecu.mode == ERROR_PASSIVE:
                self.victim_ecu.active_flag = False
                self.victim_ecu.passive_flag = True
                self.victim_ecu.retrasmission()
            elif self.victim_ecu.mode == BUSS_OFF:
                print(f"{self.victim_ecu.name} FAILED TO SEND MESSAGE - IT'S IN BUS-OFF STATE ...")
                print("Waiting for assistance ...")

            
            # ADVERSARY ECU
            self.adversary_ecu.ecu_mode_check()
            if self.adversary_ecu.mode == ERROR_ACTIVE:
                if self.adversary_ecu.tec != 0:
                    # If not zero there was an error so the retrasmission has an active flag
                    self.adversary_ecu.active_flag = True
                self.adversary_error_active_state()
            elif self.adversary_ecu.mode == ERROR_PASSIVE:
                self.adversary_ecu.active_flag = False
                self.adversary_ecu.retrasmission()


            if self.victim_ecu.data != self.adversary_ecu.data:
                #self.victim_ecu.tec_rec_increment()
                
                if self.victim_ecu.passive_flag:
                    # Victim TEC when on Error Passive state increment by 8 and the decrement by 1 after the retrasmission
                    self.victim_ecu.tec_rec_increment()
                    self.victim_ecu.tec_rec_decrement()
                    # Adversary TEC decrement by 1 when victim has the passive flag
                    self.adversary_ecu.tec_rec_decrement()
                
                if self.adversary_ecu.active_flag or count == 0: # for the first interaction i need count
                    # Victim TEC increment by 8 when it has the active flag
                    self.victim_ecu.tec_rec_increment()
                    # Adversary TEC increment by 8 when it has the active flag
                    self.adversary_ecu.tec_rec_increment()
        
            # If one of the ECU is in the BusOff state, the while ends
            if self.victim_ecu.mode == BUSS_OFF or self.adversary_ecu.mode == BUSS_OFF:
                break

        count += 1
    
        self.plot_victimTec_history()

    def plot_victimTec_history(self):
        plt.plot(self.victim_ecu.tec_history, label="Victim TEC")
        plt.xlabel("Time (iterations)")
        plt.ylabel("Transmit Error Counter (TEC)")
        plt.title("TEC Evolution of Victim ECU")
        plt.legend()
        plt.grid()
        plt.show()


if __name__ == "__main__":
    simulation = CANBus()
    simulation.simulate()
                    
