from pymodbus.client import ModbusTcpClient
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ModbusClient")

if __name__ == "__main__":
    # Connect to the Modbus server
    client = ModbusTcpClient("127.0.0.1", port=5020)
    if not client.connect():
        logger.error("Unable to connect to Modbus server.")
        exit(1)

    logger.info("Connected to Modbus server.")

    # Write to holding registers
    write_result = client.write_register(1, 42)
    if write_result.isError():
        logger.error(f"Failed to write to register: {write_result}")
    else:
        logger.info(f"Successfully wrote value to register: {write_result}")

    # Read holding registers
    read_result = client.read_holding_registers(address=0, count=1)
    if read_result.isError():
        logger.error(f"Failed to read holding registers: {read_result}")
    else:
        logger.info(f"Read holding registers: {read_result.registers}")

    # Close the connection
    client.close()
    logger.info("Disconnected from Modbus server.")
