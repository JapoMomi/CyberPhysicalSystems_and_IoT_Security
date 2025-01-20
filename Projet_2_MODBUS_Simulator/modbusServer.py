from pymodbus.server import StartAsyncTcpServer
from pymodbus.datastore import ModbusSlaveContext, ModbusServerContext
from pymodbus.datastore import ModbusSequentialDataBlock
from pymodbus.device import ModbusDeviceIdentification
import logging
import asyncio

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ModbusServer")

# Create Modbus data store
def create_data_store():
    store = ModbusSlaveContext(
        di=ModbusSequentialDataBlock(0, [0] * 10),   # Discrete Inputs
        co=ModbusSequentialDataBlock(0, [0] * 10),   # Coils
        hr=ModbusSequentialDataBlock(0, [0] * 10),   # Holding Registers
        ir=ModbusSequentialDataBlock(0, [0] * 10)    # Input Registers
    )
    return ModbusServerContext(slaves=store, single=True)

# Set device identification
def create_device_identity():
    identity = ModbusDeviceIdentification()
    identity.VendorName = 'Modbus Simulator'
    identity.ProductName = 'ModbusTCP'
    identity.ModelName = 'Server'
    identity.MajorMinorRevision = '1.0'
    return identity

async def run_async_server(context, identity, address):
    await StartAsyncTcpServer(context, identity=identity, address=address)

if __name__ == "__main__":
    logger.info("Starting Modbus TCP Server on 127.0.0.1:5020")
    context = create_data_store()
    identity = create_device_identity()
    address = ("0.0.0.0", 5020)
    asyncio.run(run_async_server(context, identity, address))
    
    
