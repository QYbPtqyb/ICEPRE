import angr
import claripy


# Modbus Protocol
class RecvSymbolProcedure(angr.SimProcedure):
    def run(self, sockfd, buffer_addr, length):
        data_length = self.state.solver.eval(length, cast_to=int)
        print('buffer_addr: {}'.format(buffer_addr))
        buffer = claripy.BVS('buffer', data_length * 8)  # 1 byte
        self.state.memory.store(buffer_addr, buffer)
        self.state.globals['buffer'] = buffer
        len_sym = claripy.BVS("data_length", 32)
        self.state.regs.eax = len_sym
        self.state.globals['data_length'] = len_sym


class MdReceiveConcreteProcedure(angr.SimProcedure):
    def __init__(self, concrete_input):
        super().__init__()
        self.traffic_data = concrete_input
        self.traffic_data_len = len(concrete_input)

    def run(self, ctx, buffer_addr):
        # print('Modbus_receive() hooked!')
        # print('Write concrete input!')
        buffer = claripy.BVV(self.traffic_data, self.traffic_data_len * 8)  # bits
        self.state.memory.store(buffer_addr, buffer)

        len_concrete = claripy.BVV(self.traffic_data_len, 32)
        self.state.regs.eax = len_concrete


class MdReceiveSymbolicProcedure(angr.SimProcedure):
    def __init__(self, symbol_len):
        super().__init__()
        self.traffic_data_len = symbol_len

    def run(self, ctx, buffer_addr):
        # print('Modbus_receive() hooked!')
        # print('Write symbolic input!')
        buffer = claripy.BVS('recv_data', self.traffic_data_len * 8)   # traffic_data_len bytes
        self.state.memory.store(buffer_addr, buffer)
        self.state.globals['recv_data'] = buffer
        # len_sym = claripy.BVS("recv_data_length", 32)
        self.state.regs.eax = self.traffic_data_len
        # self.state.globals['recv_data_length'] = len_sym


# class MdTcpSelectProcedure(angr.SimProcedure):
#     def run(self, ctx, rset, tv, length_to_read):
#         print('_modbus_tcp_select() hooked!')
#         # symbol_s_rc = claripy.BVV(1, 4 * 8)
#         # self.state.regs.eax = symbol_s_rc

# S7comm Protocol
class S7ReceiveConcreteProcedure(angr.SimProcedure):
    def __init__(self, concrete_input):
        super().__init__()
        self.traffic_data = concrete_input
        self.traffic_data_len = len(concrete_input)

    def run(self, class_this, buffer_addr):
        # print('s7_receive hooked!')
        # print('Write concrete input!')
        buffer = claripy.BVV(self.traffic_data, self.traffic_data_len * 8)  # bits
        self.state.memory.store(buffer_addr, buffer)
        # print(buffer_addr)
        # print(self.state.memory.load(buffer_addr, self.traffic_data_len))
        # len_concrete = claripy.BVV(self.traffic_data_len, 32)
        # size_received = len_concrete
        # self.state.memory.store(size_received, len_concrete)


class S7ReceiveSymbolicProcedure(angr.SimProcedure):
    def __init__(self, symbol_len):
        super().__init__()
        self.traffic_data_len = symbol_len

    def run(self, class_this, buffer_addr):
        # print('Modbus_receive() hooked!')
        # print('Write symbolic input!')
        buffer = claripy.BVS('recv_data', self.traffic_data_len * 8)  # traffic_data_len bytes
        self.state.memory.store(buffer_addr, buffer)
        self.state.globals['recv_data'] = buffer

        # len_concrete = claripy.BVV(self.traffic_data_len, 32)
        # size_received = len_concrete
        # self.state.memory.store(size_received, len_concrete)


# MMS Protocol
class MMSReceiveConcreteProcedure(angr.SimProcedure):  # Hooked function: CotpConnection_readToTpktBuffer(pointer:cotpconnection)
    def __init__(self, concrete_input):
        super().__init__()
        self.traffic_data = concrete_input
        self.traffic_data_len = len(concrete_input)

    def run(self, cotp_connection_pointer):
        print('CotpConnection_readToTpktBuffer() hooked!')
        print(cotp_connection_pointer)
        # print('Write concrete input!')
        # cotp_connection_pointer = 0x200000
        readbuffer_addr = 0x201000
        buffer_addr = 0x202000
        payload_addr = 0x204000
        self.state.memory.store(cotp_connection_pointer + 0x30, claripy.BVV(payload_addr, 64),
                                endness=self.state.arch.memory_endness)
        self.state.memory.store(cotp_connection_pointer + 0x40, claripy.BVV(readbuffer_addr, 64), endness=self.state.arch.memory_endness)
        self.state.memory.store(readbuffer_addr, claripy.BVV(buffer_addr, 64), endness=self.state.arch.memory_endness)
        buffer_size_addr = readbuffer_addr + 0xc

        buffer = claripy.BVV(self.traffic_data, self.traffic_data_len * 8)  # bits
        len_concrete = claripy.BVV(self.traffic_data_len, 32)

        self.state.memory.store(buffer_addr, buffer)
        self.state.memory.store(buffer_size_addr, len_concrete, endness=self.state.arch.memory_endness)
        self.state.memory.store(payload_addr + 0xc, claripy.BVV(0, 32), endness=self.state.arch.memory_endness)
        self.state.memory.store(payload_addr + 0x8, claripy.BVV(65000, 32), endness=self.state.arch.memory_endness)

        # print('-'*10)
        # print(cotp_connection_pointer)
        # print(readbuffer_addr)
        # print(buffer_addr)
        # print(self.state.memory.load(buffer_addr, self.traffic_data_len))
        # print('-' * 10)

        return 0


class MMSReceiveSymbolicProcedure(angr.SimProcedure):  # Hooked function: CotpConnection_readToTpktBuffer(pointer:cotpconnection)
    def __init__(self, symbol_len):
        super().__init__()
        self.traffic_data_len = symbol_len

    def run(self, cotp_connection_pointer):
        print('CotpConnection_readToTpktBuffer() hooked!')
        print(cotp_connection_pointer)
        # print('Write concrete input!')
        # cotp_connection_pointer = 0x200000
        readbuffer_addr = 0x201000
        buffer_addr = 0x202000
        payload_addr = 0x204000
        self.state.memory.store(cotp_connection_pointer + 0x30, claripy.BVV(payload_addr, 64), endness=self.state.arch.memory_endness)
        self.state.memory.store(cotp_connection_pointer + 0x40, claripy.BVV(readbuffer_addr, 64), endness=self.state.arch.memory_endness)
        self.state.memory.store(readbuffer_addr, claripy.BVV(buffer_addr, 64), endness=self.state.arch.memory_endness)
        buffer_size_addr = readbuffer_addr + 0xc

        # buffer = claripy.BVV(self.traffic_data, self.traffic_data_len * 8)  # bits
        buffer = claripy.BVS('recv_data', self.traffic_data_len * 8)  # traffic_data_len bytes
        len_concrete = claripy.BVV(self.traffic_data_len, 32)

        self.state.memory.store(buffer_addr, buffer)
        self.state.memory.store(buffer_size_addr, len_concrete, endness=self.state.arch.memory_endness)
        self.state.memory.store(payload_addr + 0xc, claripy.BVV(0, 32), endness=self.state.arch.memory_endness)
        self.state.memory.store(payload_addr + 0x8, claripy.BVV(65000, 32), endness=self.state.arch.memory_endness)

        self.state.globals['recv_data'] = buffer

        print('symbolic hooked')
        return 0


class IECReadConcreteProcedure(angr.SimProcedure):
    def __init__(self, concrete_input):
        super().__init__()
        self.traffic_data = concrete_input
        self.traffic_data_len = len(concrete_input)

    def run(self, ctx, buffer_addr, maxsize):
        print('IEC104 Read() hooked!---concrete')
        # print('Write concrete input!')
        buffer = claripy.BVV(self.traffic_data, self.traffic_data_len * 8)  # bits
        self.state.memory.store(buffer_addr, buffer)

        len_concrete = claripy.BVV(self.traffic_data_len, 16)
        return len_concrete


class IECReadSymbolicProcedure(angr.SimProcedure):
    def __init__(self, symbol_len):
        super().__init__()
        self.traffic_data_len = symbol_len

    def run(self, ctx, buffer_addr, maxsize):
        print('IEC104 read() hooked!---symbol')
        # print('Write symbolic input!')
        buffer = claripy.BVS('recv_data', self.traffic_data_len * 8)   # traffic_data_len bytes
        self.state.memory.store(buffer_addr, buffer)
        self.state.globals['recv_data'] = buffer
        # len_sym = claripy.BVS("recv_data_length", 32)
        # self.state.regs.eax = self.traffic_data_len
        # self.state.globals['recv_data_length'] = len_sym
        len_concrete = claripy.BVV(self.traffic_data_len, 16)
        return len_concrete


class NoOpProcedure(angr.SimProcedure):
    def run(self, s):
        return


class RetFalseProcedure(angr.SimProcedure):
    def run(self):
        return 0


class RetTrueProcedure(angr.SimProcedure):
    def run(self):
        return 1


class TestProcedure(angr.SimProcedure):
    def run(self, pointer):
        print(pointer)
        return


class ReturnIntSymbolProcedure(angr.SimProcedure):
    def run(self, pointer):
        return claripy.BVS('symbol_var', 4 * 8)


class MyPthreadCreate(angr.SimProcedure):
    """
    Simulates the new thread as an equally viable branch of symbolic execution.
    """

    ADDS_EXITS = True

    # pylint: disable=unused-argument,arguments-differ
    def run(self, thread, attr, start_routine, arg):
        self.call(start_routine, (arg,), "terminate_thread", prototype="void *start_routine(void*)")
        return 0

    def terminate_thread(self, thread, attr, start_routine, arg):
        return


class ENIPReceiveConcreteProcedure(angr.SimProcedure):  # Hooked function: Encapsulation::ReceiveTcpMsg(aSocket, BufWriter)
    """
        Ethernet/IP
        Hooked function: Encapsulation::ReceiveTcpMsg(aSocket, BufWriter)
        class BufWriter
        {
            protected:
                uint8_t*    start;
                uint8_t*    limit;
        }
    """
    def __init__(self, concrete_input):
        super().__init__()
        self.traffic_data = concrete_input
        self.traffic_data_len = len(concrete_input)

    def run(self, class_this, buffer_writer_pointer):
        print('Encapsulation::ReceiveTcpMsg(aSocket, BufWriter) hooked!')
        print(buffer_writer_pointer)
        # print('Write concrete input!')
        # buffer_start_addr = 0x200000
        # self.state.memory.store(buffer_writer_pointer, buffer_start_addr, endness=self.state.arch.memory_endness)
        # print(buffer_start_addr)
        # buffer_end_addr = buffer_start_addr + self.traffic_data_len

        buffer = claripy.BVV(self.traffic_data, self.traffic_data_len * 8)  # bits
        len_concrete = claripy.BVV(self.traffic_data_len, 32)

        self.state.memory.store(buffer_writer_pointer, buffer)
        return len_concrete


class ENIPReceiveSymbolicProcedure(angr.SimProcedure):  # Hooked function: Encapsulation::ReceiveTcpMsg(aSocket, BufWriter)
    def __init__(self, symbol_len):
        super().__init__()
        self.traffic_data_len = symbol_len

    def run(self, class_this, buffer_writer_pointer):
        print('Encapsulation::ReceiveTcpMsg(aSocket, BufWriter) hooked!---symbol')
        print(buffer_writer_pointer)
        # print('Write concrete input!')
        # buffer_start_addr = 0x200000
        # self.state.memory.store(buffer_writer_pointer, buffer_start_addr, endness=self.state.arch.memory_endness)
        # print(buffer_start_addr)
        # buffer_end_addr = buffer_start_addr + self.traffic_data_len

        buffer = claripy.BVS('recv_data', self.traffic_data_len * 8)  # traffic_data_len bytes
        self.state.memory.store(buffer_writer_pointer, buffer)
        self.state.globals['recv_data'] = buffer
        # len_sym = claripy.BVS("recv_data_length", 32)
        # self.state.regs.eax = self.traffic_data_len
        # self.state.globals['recv_data_length'] = len_sym
        len_concrete = claripy.BVV(self.traffic_data_len, 32)
        return len_concrete
