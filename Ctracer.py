import sys
from multiprocessing.util import MAXFD

import angr
import archinfo
import claripy
from pandas import interval_range

from CtraceSimProcedure import *
from FilterFunction import iec_filter_func

EIP_OFFSET = 0x44


class CTracer(object):
    """
        CTracer object, follows a concrete input looking for Symbolic Constraints.
    """
    def __init__(self, protocol_name, binary, lib, input_bytes, start_state=None, hooked_symbol=None, hooked_addr=None, end_symbol=None, end_addr=None, hooks=None, from_specified_func=None):
        """
        :param protocol_name  : Protocol name
        :param binary     : The binary to be traced.
        :param lib        : The library to be used.
        :param input_bytes  : Input bytes to feed to the binary.
        :param start_state  : The SimState before hooked function
        :param hooked_symbol/hooked_addr      : Address of input reception function.
        :param from_specified_func  : The name of specified function: Starting symbol execution from this position. Default is Entry point.
        """

        self.protocol = protocol_name
        self.binary = binary
        self.lib = lib

        self.traffic_data = input_bytes
        self.traffic_data_len = len(self.traffic_data)

        # The simprocedures.
        self._hooks = {} if hooks is None else hooks

        self.result_file = 'result/CTrace_result_file.txt'
        self.log_file = 'results/Ctracer_log.txt'

        self.concrete_path = []
        self._hooked_address = hooked_addr
        self._end_address = end_addr
        self.hooked_sym = hooked_symbol
        self.end_sym = end_symbol

        self._proj = self.load_binary()
        # self._cfg = self.generate_cfg()

        self.start_flag = False

        self.traces_info = {}

        # self.hook_by_addr()
        self.start_state = start_state

        self.summary_info = {}

        self.start_from_specified_func = from_specified_func

    def hook_by_addr(self):
        for addr, proc in self._hooks.items():
            self._proj.hook(addr, proc)

    def load_binary(self):
        if self.lib:
            if self.protocol == 's7comm':
                proj = angr.Project(self.binary, ld_path=self.lib, force_load_libs=[self.lib+'libsnap7.so'], auto_load_libs=True)
            else:
                proj = angr.Project(self.binary, ld_path=self.lib)
        else:
            # proj = angr.Project(self.binary)
            if self.protocol == 'ENIP':
                proj = angr.Project(self.binary, auto_load_libs=False)
            elif self.protocol == 'umas-v31':
                main_opts = {'base_addr': 0x20010000, 'arch': archinfo.ArchARM(archinfo.Endness.LE),
                             'entry_point': self._hooked_address, 'backend': 'blob'}
                proj = angr.Project(self.binary, auto_load_libs=False, main_opts=main_opts)
            elif self.protocol == 'CODESYS_V2_564':
                main_opts = {'base_addr': 0x2000, 'arch': archinfo.ArchPPC32(archinfo.Endness.BE),
                             'entry_point': self._hooked_address, 'backend': 'blob'}
                proj = angr.Project(self.binary, auto_load_libs=False, main_opts=main_opts)
            else:
                proj = angr.Project(self.binary)
        return proj

    def generate_cfg(self):
        if self.lib:
            angr_proj = angr.Project(self.binary, ld_path=self.lib, auto_load_libs=False)
            return angr_proj.analyses.CFGFast()
        else:
            angr_proj = angr.Project(self.binary, auto_load_libs=False)
            return angr_proj.analyses.CFGFast()

    def get_func_name_by_addr(self, addr):
        function = self._cfg.functions.floor_func(addr)
        # print(self._cfg.functions.ceiling_func(addr).name)
        # print(self._cfg.functions.get_by_addr(addr).name)
        if hasattr(function, 'name'):
            function_name = function.name
            return function_name
        return 'None'

    def find_path_by_stdout(self, state):
        return b'world' in state.posix.dumps(sys.stdout.fileno())

    @staticmethod
    def find_path_by_addr(state, addr):
        # print(state.regs.ip)
        if isinstance(addr, list):
            return state.solver.eval(state.regs.ip) in addr
        else:
            return addr == state.solver.eval(state.regs.ip)

    @staticmethod
    def reg_check(state):
        reg_symbol_expr = state.inspect.reg_write_expr
        reg_offset = state.inspect.reg_write_offset
        # if state.solver.eval(reg_offset) != 0xb8:
        print('------{}------'.format(state.regs.ip))
        print('write {} to {}'.format(reg_symbol_expr, reg_offset))
        # try:
        #     data = state.solver.eval(state.globals['recv_data'], cast_to=bytes)
        #     print('recv data\'s constraints: {}'.format(data), file=f)
        # except Exception as e:
        #     print('======')
        #     print(e)

    @staticmethod
    def found_symbol(specified_symbol, leaf):
        for iter_leaf in leaf:
            if iter_leaf.args[0] == specified_symbol.args[0]:
                return True
        return False

    def found_op(self, expr, op):
        if isinstance(expr, claripy.ast.Base):
            if expr.op in op:
                return True
            for sub_expr in expr.args:
                if self.found_op(sub_expr, op):
                    return True
            return False
        return False

    # def extract_offset(self, expr):
    #     """
    #     Extract offset from symbolic expression;
    #
    #     Parameters
    #     ----------
    #     expr: symbolic expression
    #
    #     Returns offset(int)
    #     -------
    #
    #     """
    #     if isinstance(expr, claripy.ast.Base):
    #         if expr.op == 'Extract' and expr.args[2].op == 'BVS':
    #             return expr.args[0], expr.args[1]
    #         if expr.op == 'BVV' or expr.op == 'BVS':
    #             return None, None
    #         # if expr.op =='Concat':
    #         offset_list = []
    #         for sub_expr in expr.args:
    #             offset_start, offset_end = self.extract_offset(sub_expr)
    #             if offset_start is not None:
    #                 offset_list.append((offset_start, offset_end))
    #         offset_list.sort(key=lambda x: x[0], reverse=True)
    #         # print(offset_list)
    #         if len(offset_list) == 0:
    #             return None, None
    #         # Determine whether 'offset' is continuous
    #         max_interval = [offset_list[0][0], offset_list[0][1]]
    #         for interval in offset_list[1:]:
    #             # if interval[0] == 207:
    #             #     break
    #             if max_interval[0] == interval[0]:
    #                 if max_interval[1] > interval[1]:
    #                     max_interval[1] = interval[1]
    #             elif max_interval[1] - 1 == interval[0]:
    #                 max_interval[1] = interval[1]
    #         return max_interval[0], max_interval[1]
    #         # for i_expr in expr.args:
    #         #     offset_start, offset_end = self.extract_offset(i_expr)
    #         #     if offset_start:
    #         #         return offset_start, offset_end
    #     return None, None

    # def trace_info_update(self,offset_start,offset_end,reg_symbol_expr,inst_info):
    #     if offset_start == None or offset_end == None:
    #         print(reg_symbol_expr)
    #         return
    #     offset_start_byte = self.bits2byte(offset_start)
    #     offset_end_byte = self.bits2byte(offset_end - 1)
    #     # print(offset_start_byte, offset_end_byte)
    #     # location = '[' + str(offset_start_byte)
    #     # for i in range(offset_start_byte, offset_end_byte):
    #     #     if i == offset_start_byte:
    #     #         continue
    #     #     location += ',{}'.format(i)
    #     # location += ']'
    #     location = (offset_start_byte, offset_end_byte)
    #
    #     if location in self.traces_info:
    #         self.traces_info[location].append(inst_info)
    #     else:
    #         self.traces_info[location] = [inst_info]

    def extract_offset(self, expr):
        """
        Extract offset from symbolic expression;

        Parameters
        ----------
        expr: symbolic expression

        Returns offset(int)
        -------

        """
        if isinstance(expr, claripy.ast.Base):
            if expr.op == 'Extract' and expr.args[2].op == 'BVS':
                return expr.args[0], expr.args[1]
            if expr.op == 'BVV' or expr.op == 'BVS':
                return None, None
            # if expr.op =='Concat':
            offset_list = []
            for sub_expr in expr.args:
                offset_start, offset_end = self.extract_offset(sub_expr)
                if offset_start is not None:
                    offset_list.append(offset_start)
                    offset_list.append(offset_end)
            offset_list.sort(reverse=True)
            # print(offset_list)
            if len(offset_list) == 0:
                return None, None
            # return offset_list[0], offset_list[1]
            if len(offset_list) == 2:
                return offset_list[0], offset_list[1]
            else:
                if expr.op in ['Concat', '__or__']:
                    return offset_list[0], offset_list[-1]
                elif expr.op in ['__and__'] and self.found_op(expr, ['LShR', '__lshift__', '__rshift__']):
                    return offset_list[0], offset_list[-1]
                else:
                    return offset_list[0], offset_list[1]
            # for i_expr in expr.args:
            #     offset_start, offset_end = self.extract_offset(i_expr)
            #     if offset_start:
            #         return offset_start, offset_end
        return None, None

    def get_location_vector(self, expr):
        if isinstance(expr, claripy.ast.Base):
            if expr.op == 'Extract' and expr.args[2].op == 'BVS':
                vector_length = expr.args[0] - expr.args[1] + 1
                l_vector = claripy.BVV((1 << vector_length) - 1, self._proj.arch.bits)
                return l_vector
            if expr.op == 'BVV' or expr.op == 'BVS':
                return claripy.BVV(0, self._proj.arch.bits)
            if expr.op == 'Concat':
                vec = []
                for sub_expr in expr.args:
                    sub_l_vector = self.get_location_vector(sub_expr)
                    vec.append(sub_l_vector)
                return claripy.Concat(*vec)


    def bits2byte(self, bits):
        return int(self.traffic_data_len - (bits + 1) / 8)

    def condition(self, state):
        return self.start_flag

    def extract_info(self, state):
        if state.solver.eval(state.regs.ip) == self._hooked_address:
            self.start_flag = True
            return
        if self.start_flag:
            reg_symbol_expr = state.inspect.reg_write_expr
            reg_offset = state.inspect.reg_write_offset

            if state.solver.eval(reg_offset) != EIP_OFFSET:
                # print('write', reg_symbol_expr, 'to', reg_offset)
                leaf_bv = list(reg_symbol_expr.leaf_asts())
                symbol_recv_data = state.globals['recv_data']
                if self.found_symbol(symbol_recv_data, leaf_bv):
                    # print('------{}------'.format(state.regs.ip))
                    # print(reg_symbol_expr)

                    ip_addr = state.solver.eval(state.regs.ip)
                    bb_irsb = state.project.factory.block(ip_addr).vex
                    bb_addr = state.history.addr
                    bb_capstone = state.project.factory.block(ip_addr).capstone
                    insn_mnemonic = bb_capstone.insns[0].mnemonic

                    # inst_info = {'addr': ip_addr, 'expr': reg_symbol_expr, 'inst_type': insn_mnemonic, 'track': 'reg', 'func': self.get_func_name_by_addr(ip_addr)}
                    inst_info = {'addr': ip_addr, 'expr': reg_symbol_expr, 'inst_type': insn_mnemonic, 'track': 'reg'}
                    # print(state.inspect.reg_write_condition)

                    offset_start, offset_end = self.extract_offset(reg_symbol_expr)
                    if offset_start == None or offset_end == None:
                        print(reg_symbol_expr)
                        return
                    offset_start_byte = self.bits2byte(offset_start)
                    offset_end_byte = self.bits2byte(offset_end-1)
                    # print(offset_start_byte, offset_end_byte)
                    # location = '[' + str(offset_start_byte)
                    # for i in range(offset_start_byte, offset_end_byte):
                    #     if i == offset_start_byte:
                    #         continue
                    #     location += ',{}'.format(i)
                    # location += ']'
                    location = (offset_start_byte, offset_end_byte)

                    if location in self.traces_info:
                        self.traces_info[location].append(inst_info)
                    else:
                        self.traces_info[location] = [inst_info]
                # if symbol_recv_data in leaf_bv:
                #     print(leaf_bv)
                # try:
                #     data = state.solver.eval(state.globals['recv_data'], cast_to=bytes)
                #     print('recv data\'s constraints: {}'.format(data))
                # except Exception as e:
                #     print(e)
            # elif state.solver.eval(state.regs.ip)==0x4057d0:
            #     leaf_bv = list(reg_symbol_expr.leaf_asts())
            #     symbol_recv_data = state.globals['recv_data']
            #     if self.found_symbol(symbol_recv_data, leaf_bv):
            #         print(reg_symbol_expr)
            # if state.solver.eval(state.regs.ip) == state.solver.eval(reg_symbol_expr):
            #     bb_addr = state.solver.eval(state.regs.ip)
            #     bb_irsb = state.project.factory.block(bb_addr).vex
            #     bb_irsb.pp()

    # def extract_reg_read_info(self, state):
    #     print('------{}------'.format(state.regs.ip))
    #     if state.solver.eval(state.regs.ip) == self._hooked_address:
    #         self.start_flag = True
    #         return
    #     # if self.start_flag:
    #     #     reg_symbol_expr = state.inspect.reg_read_expr
    #     #     reg_offset = state.inspect.reg_read_offset

    def temp_write_check(self, state):
        # if self.start_flag:
        tmp_expr = state.inspect.tmp_write_expr

        leaf_bv = list(tmp_expr.leaf_asts())
        symbol_recv_data = state.globals['recv_data']

        if self.found_symbol(symbol_recv_data, leaf_bv):
            # print('------{}------'.format(state.solver.eval(state.regs.ip)))
            # print(tmp_expr)
            # print('op: ', tmp_expr.op)

            ignore_op = ['ZeroExt', 'Concat', 'Extract']
            if tmp_expr.op in ignore_op:
                return

            ip_addr = state.solver.eval(state.regs.ip)
            bb_irsb = state.project.factory.block(ip_addr).vex
            bb_capstone = state.project.factory.block(ip_addr).capstone
            insn_mnemonic = bb_capstone.insns[0].mnemonic

            inst_info = {'addr': ip_addr, 'expr': tmp_expr, 'inst_type': insn_mnemonic, 'track': 'tmp'}
            # inst_info = {ip_addr: {'expr': tmp_expr, 'inst_type': insn_mnemonic}}
            # print(state.inspect.reg_write_condition)

            offset_start, offset_end = self.extract_offset(tmp_expr)
            if offset_start == None or offset_end == None:
                return
            offset_start_byte = self.bits2byte(offset_start)
            offset_end_byte = self.bits2byte(offset_end - 1)
            # print(offset_start_byte, offset_end_byte)

            location = (offset_start_byte, offset_end_byte)

            if location in self.traces_info:
                if inst_info['addr'] != self.traces_info[location][-1]['addr']:
                    self.traces_info[location].append(inst_info)
                # self.traces_info[location].append(inst_info)
            else:
                self.traces_info[location] = [inst_info]

    def address_concretization(self, state):
        addr_expr = state.inspect.mem_read_address

        leaf_bv = list(addr_expr.leaf_asts())
        symbol_recv_data = state.globals['recv_data']

        if self.find_path_by_addr(state, 0x405685):
            print(addr_expr)

    def symbolic_address_handler(self, state):
        symbolic_addr = state.inspect.address_concretization_expr
        action = state.inspect.address_concretization_action
        # print(symbolic_addr)
        leaf_bv = list(symbolic_addr.leaf_asts())
        symbol_recv_data = state.globals['recv_data']
        if self.found_symbol(symbol_recv_data, leaf_bv) and action =='store':
            # print('store to ', symbolic_addr)
            state.solver.add(symbol_recv_data == self.traffic_data)

    def constraint_check(self, state):
        print('addr where constraint added: {}'.format(state.regs.ip))
        cons_list = state.inspect.added_constraints
        print(cons_list)

    @staticmethod
    def get_constraint(state):
        recv_data_sym = state.globals['recv_data']
        print(recv_data_sym)
        data = state.solver.eval(recv_data_sym, cast_to=bytes)
        print('recv data\'s constraints: {}'.format(data))

    def create_state(self):
        if self.protocol == 'iec104':
            entry_state = self._proj.factory.entry_state(
                args=['/home/qybpt/Downloads/IEC104-master/test/iec104_monitor', '-d', '127.0.0.1', '-m', 'server',
                      '-n', '2', '-p', '2404'])
            return entry_state
        elif self.protocol == 'ENIP':
            entry_state = self._proj.factory.entry_state(
                args=['/home/qybpt/Downloads/CIPster-master/examples/POSIX/sample', '127.0.0.1', '255.255.255.0',
                      '127.0.0.1', 'test.com', 'testdevice', '00-15-C5-BF-D0-87'])
            entry_state.options.add(angr.options.LAZY_SOLVES)
            entry_state.options.add(angr.options.UNDER_CONSTRAINED_SYMEXEC)
            return entry_state
        elif self.protocol == 'umas-v31':
            entry_state = self._proj.factory.blank_state()
            entry_state.regs.r0 = 0x2000000
            entry_state.regs.r1 = 0x2001000
            entry_state.regs.r2 = self.traffic_data_len

            entry_state.memory.store(0x2000000 + 0x8, 0x2002000, size=4, endness=entry_state.arch.memory_endness)
            entry_state.memory.store(0x2001000 + 0x8, 0x2003000, size=4, endness=entry_state.arch.memory_endness)

            # buffer = claripy.BVS('recv_data', self.traffic_data_len * 8)  # traffic_data_len bytes
            # entry_state.globals['recv_data'] = buffer
            entry_state.memory.store(0x2002000 - 0x8, self.traffic_data)
            entry_state.memory.store(0x2003000, 0x0, size=self.traffic_data_len, endness=entry_state.arch.memory_endness)
            # entry_state.options.add(angr.options.UNDER_CONSTRAINED_SYMEXEC)
            return entry_state
        elif self.protocol == 'CODESYS_V2_564' or self.protocol == 'CODESYS_V2_573':
            print('init entry_state')
            entry_state = self._proj.factory.blank_state()
            entry_state.regs.r3 = 0x2000000
            # self.init_state.regs.r4 = 0x2001000

            entry_state.memory.store(0x2000000 + 0x4c, 0x1, size=4, endness=entry_state.arch.memory_endness)
            entry_state.memory.store(0x2000000 + 0x34, 0x2001000, size=4, endness=entry_state.arch.memory_endness)
            entry_state.memory.store(0x2000000 + 0x38, 0x2002000, size=4, endness=entry_state.arch.memory_endness)

            # defined function code
            '''
            fc = 0x43
            self.init_state.memory.store(0x2001000, fc, size=1, endness=archinfo.Endness.LE)
            self.init_state.memory.store(0x2001000 + 1, self.input_var, size=INPUT_LENGTH, endness=archinfo.Endness.LE)
            '''
            entry_state.memory.store(0x2001000, self.traffic_data, size=self.traffic_data_len, endness=entry_state.arch.memory_endness)
            entry_state.memory.store(0x2000000, self.traffic_data_len, size=4, endness=entry_state.arch.memory_endness)
            return entry_state
        else:
            entry_state = self._proj.factory.entry_state()
            # entry_state.options.add(angr.options.LAZY_SOLVES)
            entry_state.options.add(angr.options.UNDER_CONSTRAINED_SYMEXEC)
            # entry_state.options.add(angr.options.SYMBOLIC_WRITE_ADDRESSES)
            return entry_state

    def change_state(self, c_state):
        buffer = claripy.BVS('recv_data', self.traffic_data_len * 8)  # traffic_data_len bytes
        c_state.globals['recv_data'] = buffer
        if self.protocol == 'umas-v31':
            c_state.memory.store(0x2002000 - 0x8, buffer)
        elif self.protocol == 'CODESYS_V2_564' or self.protocol == 'CODESYS_V2_573':
            c_state.memory.store(0x2001000, buffer, endness=archinfo.Endness.LE)
        return c_state

    def concrete_exec(self):
        # hook function
        if self.protocol == 'modbus':
            self._proj.hook(self._hooked_address, MdReceiveConcreteProcedure(self.traffic_data))
        elif self.protocol == 's7comm':
            self._proj.hook(self._hooked_address, S7ReceiveConcreteProcedure(self.traffic_data))
        elif self.protocol == 'mms':
            self._proj.hook(self._hooked_address, MMSReceiveConcreteProcedure(self.traffic_data))
        elif self.protocol == 'iec104':
            self._proj.unhook(self._hooked_address)
            self._proj.hook(self._hooked_address, IECReadConcreteProcedure(self.traffic_data))
            # self._proj.hook(0x40615c, NoOpProcedure())  # hook Iec10x_Scheduled
            # self._proj.hook(0x405857, NoOpProcedure())   # hook Iec104_StateMachine
            self._proj.hook(0x406553, NoOpProcedure())  # hook Iec10x_Task
            # self._proj.hook(0x40524d, NoOpProcedure(), length=59)
            self._proj.hook(self._proj.loader.find_symbol('Iec104_Deal_SN').rebased_addr, RetFalseProcedure())  # Iec104_Deal_SN
        elif self.protocol == 'ENIP':
            self._proj.hook(self._hooked_address, ENIPReceiveConcreteProcedure(self.traffic_data))
            self._proj.hook(self._proj.loader.find_symbol('_Z12CipStackInitt').rebased_addr, NoOpProcedure())  # hook CipStackInit
            self._proj.hook(self._proj.loader.find_symbol('_Z25ApplicationInitializationv').rebased_addr, RetFalseProcedure())  # ApplicationInitialization
            self._proj.hook(self._proj.loader.find_symbol('_Z24NetworkHandlerInitializev').rebased_addr, RetFalseProcedure())  # NetworkHandlerInitialize
            self._proj.hook(self._proj.loader.find_symbol('_Z30CheckAndHandleUdpUnicastSocketv').rebased_addr, NoOpProcedure())  # _Z30CheckAndHandleUdpUnicastSocketv
            self._proj.hook(self._proj.loader.find_symbol('_Z37CheckAndHandleUdpLocalBroadcastSocketv').rebased_addr, NoOpProcedure())  # _Z37CheckAndHandleUdpLocalBroadcastSocketv
            self._proj.hook(self._proj.loader.find_symbol('_Z38CheckAndHandleUdpGlobalBroadcastSocketv').rebased_addr, NoOpProcedure())  # _Z38CheckAndHandleUdpGlobalBroadcastSocketv
            self._proj.hook(self._proj.loader.find_symbol('_ZL24checkAndHandleUdpSocketsv').rebased_addr, NoOpProcedure())  # _ZL24checkAndHandleUdpSocketsv
            self._proj.hook(self._proj.loader.find_symbol('_ZL14checkSocketSeti').rebased_addr, RetTrueProcedure())  # _ZL14checkSocketSeti
            self._proj.hook(self._proj.loader.find_symbol('_ZN10SessionMgr22CheckRegisteredSessionEji').rebased_addr, RetTrueProcedure())  # _ZN10SessionMgr22CheckRegisteredSessionEji
            self._proj.hook(self._proj.loader.find_symbol('_Z26GetConnectionByConsumingIdi').rebased_addr, RetTrueProcedure())  # _Z26GetConnectionByConsumingIdi
            # self._proj.hook(self._proj.loader.find_symbol('_ZN8CipClass13ServiceInsertEN11CipInstance3_CIEP10CipService').rebased_addr, RetTrueProcedure())  # _ZN8CipClass13ServiceInsertEN11CipInstance3_CIEP10CipService
            # self._proj.hook(0x42f204, NoOpProcedure())
            # self._proj.hook(self._proj.loader.find_symbol('_Z11GetCipClassi').rebased_addr, RetTrueProcedure())  # _Z11GetCipClassi
        # self._proj.hook(self._proj.loader.find_symbol('parseCotpMessage').rebased_addr, TestProcedure())
        elif self.protocol == 'umas-v31':
            self._proj.hook(0x20176910, angr.SIM_PROCEDURES['libc']['memcpy']())  # memcpy
            self.start_flag = True
        elif self.protocol == 'CODESYS_V2_564' or self.protocol == 'CODESYS_V2_573':
            self._proj.hook(0x18dbd0, ReturnIntSymbolProcedure())
            self._proj.hook(0x18de60, RetTrueProcedure())
            self._proj.hook(0x192880, RetFalseProcedure())
            self.start_flag = True

        entry_state = None
        if self.start_state:
            entry_state = self.start_state.copy()
        elif self.start_from_specified_func is None:
            # entry_state = self._proj.factory.entry_state(add_options=angr.options.unicorn)
            entry_state = self.create_state()
            # if self.protocol == 'iec104':
            #     entry_state = self._proj.factory.entry_state(args=['/home/qybpt/Downloads/IEC104-master/test/iec104_monitor', '-d', '127.0.0.1', '-m', 'server', '-n', '2', '-p', '2404'])
            # elif self.protocol == 'ENIP':
            #     entry_state = self._proj.factory.entry_state(
            #         args=['/home/qybpt/Downloads/CIPster-master/examples/POSIX/sample', '127.0.0.1', '255.255.255.0', '127.0.0.1', 'test.com', 'testdevice', '00-15-C5-BF-D0-87'])
            #     entry_state.options.add(angr.options.LAZY_SOLVES)
            #     entry_state.options.add(angr.options.UNDER_CONSTRAINED_SYMEXEC)
            # else:
            #     entry_state = self._proj.factory.entry_state()
        else:
            entry_state = self._proj.factory.blank_state(addr=self._proj.loader.find_symbol(self.start_from_specified_func).rebased_addr)
            if self.protocol == 'mms':
                # IsoConnection_handleTcpConnection
                entry_state.regs.rdi = 0x203000
                entry_state.memory.store(entry_state.regs.rdi+0x90, claripy.BVV(0x200000, 64), endness=entry_state.arch.memory_endness)
            elif self.protocol == 'fastcgi':
                entry_state.regs.rsi = 0x200000
                entry_state.memory.store(0x200000, claripy.BVV(0x201000, 64), endness=entry_state.arch.memory_endness)  # FCGX_Stream->rdNext
                entry_state.memory.store(0x200010, claripy.BVV(0x201000+self.traffic_data_len, 64), endness=entry_state.arch.memory_endness)  # FCGX_Stream->stop
                entry_state.memory.store(0x201000, claripy.BVV(self.traffic_data, self.traffic_data_len*8))

                entry_state.memory.store(0x200020, claripy.BVV(1, 32), endness=entry_state.arch.memory_endness)  # FCGX_Stream->isReader
                entry_state.memory.store(0x200024, claripy.BVV(0, 32), endness=entry_state.arch.memory_endness)  # FCGX_Stream->isClosed
                self.start_flag = True

        create_thread_function = self._proj.loader.find_symbol('pthread_create')
        if create_thread_function:
            ct_address = create_thread_function.rebased_addr
            print('thread create addr: {}'.format(ct_address))

            # Thread create hook
            if self.protocol == 'iec104':
                self._proj.hook(ct_address, MyPthreadCreate())
            else:
                self._proj.hook(ct_address, angr.SIM_PROCEDURES['posix']['pthread_create']())
        # simgr = self._proj.factory.simgr(entry_state, save_unconstrained=True, veritesting=True)
        simgr = self._proj.factory.simgr(entry_state, save_unconstrained=True)
        # print(start_state.memory.load(query_addr, traffic_data_len))

        # DFS
        dfs_t = angr.exploration_techniques.DFS(deferred_stash="deferred")
        simgr.use_technique(dfs_t)

        # loop seer
        # loopseer = angr.exploration_techniques.LoopSeer(cfg=self._proj.analyses.CFGFast())
        # simgr.use_technique(loopseer)

        iteration = 0
        num_state = 0
        found_state_num = 0
        flag = 1
        debug_flag = 1
        hooked_flag = 0

        while simgr.active:
            if not flag:
                break
            # if not simgr.active:
            #     print('dao di le')
            simgr.step()

            if simgr.unconstrained:
                for unconstrained_state in simgr.unconstrained:
                    print('unconstrained_state jump_source: {}'.format(unconstrained_state.history.jump_source))
                    # jump the icall
                    next_state_addr = unconstrained_state.callstack.ret_addr
                    unconstrained_state.regs.ip = claripy.BVV(next_state_addr, 8 * 8)
                    # recover the callstack
                    unconstrained_state.callstack = unconstrained_state.callstack.next
                    print(unconstrained_state.regs.ip)
                    simgr.move(from_stash='unconstrained', to_stash='active')

            # Gets all states
            # active_states = simgr.active
            # deferred_states = simgr.deferred
            # print(len(simgr.deferred))
            # print(simgr.active)
            # Iterate through all states
            for state in simgr.active:
                # print(state)
                # print(state.memory.load(0x2002000-0x1, 1))
                # if hooked_flag:
                #     print(state)
                #     print(self.get_func_name_by_addr(state.solver.eval(state.regs.ip)))
                # if state.solver.eval(state.regs.ip) < 0x40b397 and debug_flag:
                #     print(self.get_func_name_by_addr(state.solver.eval(state.regs.ip)))
                # elif debug_flag:
                #     print('exceed!')
                # if self.find_path_by_addr(state, 0x50493e):
                #     print(state.regs.eax)
                num_state += 1

                if self.find_path_by_addr(state, self._hooked_address) and self.start_state is None:
                    print('start state: {}'.format(state.regs.ip))
                    self.start_state = state
                # avoid loop
                # modbus
                if self.protocol == 'modbus' and self.find_path_by_addr(state, 0x401cf7):
                    flag = 0
                    break
                if self.protocol == 'iec104' and self.find_path_by_addr(state, 0x4068c9):
                    flag = 0
                    break
                if self.protocol == 'iec104' and self.find_path_by_addr(state, 0x40524d):
                    state.regs.ip = 0x405288
                    # break
                if self.protocol == 'CODESYS_V2_564' and self.find_path_by_addr(state, 0x2a0cc):
                    # print(state.regs.r4)
                    state.regs.ctr = 0x2a0dc
                if self.protocol == 'umas-v31' and self.find_path_by_addr(state, 0x2008cedc):
                    state.regs.ip = 0x2008cee8
                # s7comm
                # 0x4013c8: insn addr after srv_create
                # if self.find_path_by_addr(state, 0x4013c8):
                #     print(state.regs.eax)
                #     # server_o = claripy.BVV(1, 8 * 4)
                #     # state.regs.eax = server_o
                #     # break
                # if self.find_path_by_addr(state, self._proj.loader.find_symbol('parseDataTpdu').rebased_addr):
                # if self.find_path_by_addr(state, 0x44fce7):
                #     print('debug:')
                #     # print(state.solver.eval(state.regs.rbp)-0x10)
                #     print('readbuffer pointer:')
                #     r_a = state.memory.load(state.regs.rdi + 0x40, 8)
                #     print(r_a)
                #     print('bufferaddr:')
                #     print(state.memory.load(r_a, 8))
                #     print(state.memory.load(state.memory.load(r_a, 8), 187))
                #     print(state.memory.load(state.memory.load(state.regs.rbp-0x8, 8), 2))
                #     debug_flag = 1
                # if self.protocol == 'CODESYS_V2_564' and self.find_path_by_addr(state, 0x19572c):
                #     switch_flag = 1
                    # state.callstack.current_return_target = 0x4067de
                if self.find_path_by_addr(state, self._hooked_address):
                    hooked_flag = 1
                if self.find_path_by_addr(state, self._end_address):
                    # if hooked_flag:
                    # if self.find_path_by_addr(state, self._end_address) and hooked_flag:
                    found_state_num += 1
                    # print('-' * 10, found_state_num, '-' * 10)
                    bbl_trace = list(map(int, state.history.bbl_addrs.hardcopy))
                    # print(bbl_trace)
                    # if found_state_num > 5:
                    self.concrete_path = bbl_trace
                    print('-' * 8, 'Concrete Exec Finished', '-' * 8)
                    flag = 0
                    break
                    # else:
                    #     simgr.active.pop()
                    #     simgr.active.append(simgr.deferred[-1])
                    #     simgr.deferred.pop()
                    #     print(simgr.deferred)
            iteration += 1
        self.summary_info['Traffic Data'] = self.traffic_data
        self.summary_info['c_Depth'] = iteration
        self.summary_info['c_State_Num'] = num_state
        self.summary_info['c_Trace'] = self.concrete_path
        with open(self.log_file, 'a') as f:
            print('-' * 30, file = f)
            print('Protocol: {}'.format(self.protocol), file=f)
            print('Traffic: {}'.format(self.traffic_data), file=f)
            print('Depth: {}'.format(iteration), file=f)
            print('Number of states: {}'.format(num_state), file=f)
            print('Trace: {}'.format(self.concrete_path), file=f)

    def symbolic_exec(self):
        # unhook
        self._proj.unhook(self._hooked_address)
        # re-hook function
        if self.protocol == 'modbus':
            self._proj.hook(self._hooked_address, MdReceiveSymbolicProcedure(self.traffic_data_len))
        elif self.protocol == 's7comm':
            self._proj.hook(self._hooked_address, S7ReceiveSymbolicProcedure(self.traffic_data_len))
        elif self.protocol == 'mms':
            self._proj.hook(self._hooked_address, MMSReceiveSymbolicProcedure(self.traffic_data_len))
        elif self.protocol == 'iec104':
            self._proj.hook(self._hooked_address, IECReadSymbolicProcedure(self.traffic_data_len))
            self._proj.hook(0x406553, NoOpProcedure())  # hook Iec10x_Task
        elif self.protocol == 'ENIP':
            self._proj.hook(self._hooked_address, ENIPReceiveSymbolicProcedure(self.traffic_data_len))
            # self._proj.hook(self._proj.loader.find_symbol('_Z12CipStackInitt').rebased_addr,
            #                 NoOpProcedure())  # hook CipStackInit
            self._proj.hook(self._proj.loader.find_symbol('_Z25ApplicationInitializationv').rebased_addr,
                            RetFalseProcedure())  # ApplicationInitialization
            self._proj.hook(self._proj.loader.find_symbol('_Z24NetworkHandlerInitializev').rebased_addr,
                            RetFalseProcedure())  # NetworkHandlerInitialize
            self._proj.hook(self._proj.loader.find_symbol('_Z30CheckAndHandleUdpUnicastSocketv').rebased_addr,
                            NoOpProcedure())  # _Z30CheckAndHandleUdpUnicastSocketv
            self._proj.hook(self._proj.loader.find_symbol('_Z37CheckAndHandleUdpLocalBroadcastSocketv').rebased_addr,
                            NoOpProcedure())  # _Z37CheckAndHandleUdpLocalBroadcastSocketv
            self._proj.hook(self._proj.loader.find_symbol('_Z38CheckAndHandleUdpGlobalBroadcastSocketv').rebased_addr,
                            NoOpProcedure())  # _Z38CheckAndHandleUdpGlobalBroadcastSocketv
            self._proj.hook(self._proj.loader.find_symbol('_ZL24checkAndHandleUdpSocketsv').rebased_addr,
                            NoOpProcedure())  # _ZL24checkAndHandleUdpSocketsv
            self._proj.hook(self._proj.loader.find_symbol('_ZL14checkSocketSeti').rebased_addr,
                            RetTrueProcedure())  # _ZL14checkSocketSeti

        # create_thread_function = self._proj.loader.find_symbol('pthread_create')
        # if create_thread_function:
        #     ct_address = create_thread_function.rebased_addr
        #     print('thread create addr: {}'.format(ct_address))
        #
        #     # Thread create hook
        #     if self.protocol == 'iec104':
        #         self._proj.hook(ct_address, MyPthreadCreate())
        #     else:
        #         self._proj.hook(ct_address, angr.SIM_PROCEDURES['posix']['pthread_create']())

        if self.start_from_specified_func is None:
            # entry_state = self._proj.factory.entry_state(add_options=angr.options.unicorn)
            entry_state = self._proj.factory.entry_state()
            if self.start_state:
                entry_state = self.start_state.copy()
            else:
                entry_state = self.change_state(self.create_state())
                print(entry_state.memory.load(0x2001000, self.traffic_data_len))

        else:
            entry_state = self._proj.factory.blank_state(addr=self._proj.loader.find_symbol(self.start_from_specified_func).rebased_addr)
            if self.protocol == 'mms':
                # IsoConnection_handleTcpConnection
                entry_state.regs.rdi = 0x203000
                entry_state.memory.store(entry_state.regs.rdi+0x90, claripy.BVV(0x200000, 64), endness=entry_state.arch.memory_endness)
            elif self.protocol == 'fastcgi':
                entry_state.regs.rsi = 0x200000
                entry_state.memory.store(0x200000, claripy.BVV(0x201000, 64), endness=entry_state.arch.memory_endness)
                buffer = claripy.BVS('recv_data', self.traffic_data_len * 8)
                entry_state.memory.store(0x201000, buffer)
                entry_state.globals['recv_data'] = buffer

                entry_state.memory.store(0x200010, claripy.BVV(0x201000 + self.traffic_data_len, 64), endness=entry_state.arch.memory_endness)  # FCGX_Stream->stop
                entry_state.memory.store(0x200020, claripy.BVV(1, 32), endness=entry_state.arch.memory_endness)  # FCGX_Stream->isReader
                entry_state.memory.store(0x200024, claripy.BVV(0, 32), endness=entry_state.arch.memory_endness)  # FCGX_Stream->isClosed

        # modbus, S7comm: entry_state
        # entry_state = self._proj.factory.entry_state()
        # MMS entry_state
        # entry_state = self._proj.factory.blank_state(addr=self._proj.loader.find_symbol('IsoConnection_handleTcpConnection').rebased_addr, add_options={angr.options.LAZY_SOLVES})
        # entry_state.regs.rdi = 0x203000
        # entry_state.memory.store(entry_state.regs.rdi + 0x90, claripy.BVV(0x200000, 64), endness=entry_state.arch.memory_endness)
        # entry_state.solver.timeout = 500

        entry_state.inspect.b('reg_write', when=angr.BP_AFTER, action=self.extract_info)
        entry_state.inspect.b('tmp_write', when=angr.BP_AFTER, action=self.temp_write_check, condition=self.condition)
        entry_state.inspect.b('address_concretization', when=angr.BP_BEFORE, action=self.symbolic_address_handler)
        # entry_state.inspect.b('mem_read', when=angr.BP_BEFORE, action=self.address_concretization)

        simgr_s = self._proj.factory.simgr(entry_state, save_unconstrained=True)

        if self.start_from_specified_func is None:
            # modbus/s7comm
            t = angr.exploration_techniques.Tracer(trace=self.concrete_path, aslr=False, fast_forward_to_entry=False)
            simgr_s.use_technique(t)
        else:
            # mms:
            t = angr.exploration_techniques.Tracer(trace=self.concrete_path, aslr=False, fast_forward_to_entry=False)
            simgr_s.use_technique(t)

        # ls = angr.exploration_techniques.LoopSeer(cfg=self._cfg)
        # simgr_s.use_technique(ls)

        # dfs_t = angr.exploration_techniques.DFS(deferred_stash="deferred")
        # simgr_s.use_technique(dfs_t)

        iteration = 0
        num_states = 0
        while simgr_s.active and simgr_s.one_active.globals['trace_idx'] < len(self.concrete_path) - 1:
            simgr_s.step()
            iteration += 1
            # print('iteration: {}'.format(iteration))
            # print('number of active states: {}'.format(len(simgr_s.active)))
            # print('stashes: {}'.format(simgr_s.stashes))
            # print(simgr_s.active[0])
            if simgr_s.unconstrained:
                for unconstrained_state in simgr_s.unconstrained:
                    print('unconstrained_state jump_source: {}'.format(unconstrained_state.history.jump_source))
                    # jump the icall
                    next_state_addr = unconstrained_state.callstack.ret_addr
                    unconstrained_state.regs.ip = claripy.BVV(next_state_addr, 8 * 8)
                    # recover the callstack
                    unconstrained_state.callstack = unconstrained_state.callstack.next
                    print(unconstrained_state.solver.eval(unconstrained_state.regs.ip))
                    simgr_s.move(from_stash='unconstrained', to_stash='active')
            for active_state in simgr_s.active:
                # print(active_state.memory.load(0x2002000 - 0x1, 1))
                # active_state.options.add(angr.options.LAZY_SOLVES)
                # active_state.solver.timeout = 500
                num_states += 1
                # print('{}th active state addr: {}'.format(num_states, active_state.regs.ip))
                # debug:
                # if self.find_path_by_addr(active_state, [0x1928a8, 0x192f94]):
                #     active_state.globals['trace_idx'] += 1
                #     continue
                # if self.find_path_by_addr(active_state, [0x2008c088]):
                #     n = 0x2008cedc
                #     active_state.add_constraints(active_state.regs.ip == n)
                #     active_state.globals['trace_idx'] += 1
                #     print(active_state)
                #     continue
                # print(self.get_func_name_by_addr(active_state.solver.eval(active_state.regs.ip)))

                if self.find_path_by_addr(active_state, self.concrete_path[-1]):
                    simgr_s.move(from_stash='active', to_stash='traced')
                    # print('find')
                    print('-' * 8, 'Symbolic Exec Finished', '-' * 8)
                    break
            if 'traced' not in simgr_s.stashes:
                print('No traced stash!')
                continue
            elif simgr_s.traced:
                state = simgr_s.traced[0]
                bbl_trace = list(map(hex, state.history.bbl_addrs.hardcopy))

                # self.get_constraint(state)

                with open(self.log_file, 'a') as f:
                    print('Symbolic exec:', file=f)
                    print('Depth: {}'.format(iteration), file=f)
                    print('Number of states: {}'.format(num_states), file=f)
                    print('symbolic traced state: {}'.format(state), file=f)
                    print('symbolic traced result: {}'.format(bbl_trace), file=f)
                self.summary_info['s_Depth'] = iteration
                self.summary_info['s_State_Num'] = num_states
                self.summary_info['s_Trace'] = bbl_trace
                break

    def show_trace(self):
        for tag, traces in self.traces_info.items():
            print(tag)
            for trace in traces:
                print('{} : {} | {} | {}'.format(trace['addr'], trace['expr'], trace['inst_type'], trace['track']))

    def concolic_analyze(self):
        # print(self._proj.loader.all_objects)
        print('############ CTracer Start! ############')
        # print(self._proj.loader.find_symbol('modbus_receive'))

        # Gets the address of the specified function
        # Set the hook address and end address
        if self._hooked_address is None:
            if self.hooked_sym is None:
                print('Lack of parameters, at least one is needed for hooked_symbol and hooked_addr ! ')
                return self.traces_info
            else:
                hooked_function = self._proj.loader.find_symbol(self.hooked_sym)
                self._hooked_address = hooked_function.rebased_addr
                # print('hooked function: {} at {}'.format(hooked_function, self._hooked_address))

        if self._end_address is None:
            if self.end_sym is None:
                print('Lack of parameters, at least one is needed for end_symbol and end_addr ! ')
                return self.traces_info
            else:
                if isinstance(self.end_sym, list):
                    self._end_address = []
                    for sym_item in self.end_sym:
                        end_function = self._proj.loader.find_symbol(sym_item)
                        self._end_address.append(end_function.rebased_addr)
                        # print('end function: {} at {}'.format(end_function, self._end_address))
                elif isinstance(self.end_sym, str):
                    end_function = self._proj.loader.find_symbol(self.end_sym)
                    self._end_address = end_function.rebased_addr
                    # print('end function: {} at {}'.format(end_function, self._end_address))

        self.concrete_exec()

        if self.concrete_path:
            self.symbolic_exec()
            # try:
            #     self.symbolic_exec()
            # except Exception as e:
            #     print('Symbolic Execution Failed!')
            #     print(e)
            # self.show_trace()
            print('############ CTracer Ended! ############')
            return self.traces_info
        else:
            print('No path!')
            return self.traces_info

    def update_traffic(self, traffic):
        self.traffic_data = traffic
        self.traffic_data_len = len(traffic)

    # def multi_trace(self, traffic_lst):
    #     for traffic_data_item in traffic_lst:
    #         self.traffic_data = traffic_data_item
    #         self.traffic_data_len = len(traffic_data_item)
    #
    #         trace_item = self.concolic_analyze()

    def get_start_state(self):
        return self.start_state

    def get_summary(self):
        return self.summary_info

    def calc_state_num(self):
        if self._hooked_address is None:
            if self.hooked_sym is None:
                print('Lack of parameters, at least one is needed for hooked_symbol and hooked_addr ! ')
                return self.traces_info
            else:
                hooked_function = self._proj.loader.find_symbol(self.hooked_sym)
                self._hooked_address = hooked_function.rebased_addr
                print('hooked function: {} at {}'.format(hooked_function, self._hooked_address))

        if self._end_address is None:
            if self.end_sym is None:
                print('Lack of parameters, at least one is needed for end_symbol and end_addr ! ')
                return self.traces_info
            else:
                end_function = self._proj.loader.find_symbol(self.end_sym)
                self._end_address = end_function.rebased_addr
                print('end function: {} at {}'.format(end_function, self._end_address))

        entry_state = self.create_state()

        if self.protocol == 'modbus':
            self._proj.hook(self._hooked_address, MdReceiveSymbolicProcedure(self.traffic_data_len))
        elif self.protocol == 'iec104':
            self._proj.hook(self._hooked_address, IECReadSymbolicProcedure(self.traffic_data_len))
            self._proj.hook(0x406553, NoOpProcedure())  # hook Iec10x_Task
        elif self.protocol == 'ENIP':
            self._proj.hook(self._proj.loader.find_symbol('_Z12CipStackInitt').rebased_addr,
                            NoOpProcedure())  # hook CipStackInit
            self._proj.hook(self._proj.loader.find_symbol('_Z25ApplicationInitializationv').rebased_addr,
                            RetFalseProcedure())  # ApplicationInitialization
            self._proj.hook(self._proj.loader.find_symbol('_Z24NetworkHandlerInitializev').rebased_addr,
                            RetFalseProcedure())  # NetworkHandlerInitialize
            self._proj.hook(self._proj.loader.find_symbol('_Z30CheckAndHandleUdpUnicastSocketv').rebased_addr,
                            NoOpProcedure())  # _Z30CheckAndHandleUdpUnicastSocketv
            self._proj.hook(self._proj.loader.find_symbol('_Z37CheckAndHandleUdpLocalBroadcastSocketv').rebased_addr,
                            NoOpProcedure())  # _Z37CheckAndHandleUdpLocalBroadcastSocketv
            self._proj.hook(self._proj.loader.find_symbol('_Z38CheckAndHandleUdpGlobalBroadcastSocketv').rebased_addr,
                            NoOpProcedure())  # _Z38CheckAndHandleUdpGlobalBroadcastSocketv
            self._proj.hook(self._proj.loader.find_symbol('_ZL24checkAndHandleUdpSocketsv').rebased_addr,
                            NoOpProcedure())  # _ZL24checkAndHandleUdpSocketsv
            self._proj.hook(self._proj.loader.find_symbol('_ZL14checkSocketSeti').rebased_addr,
                            RetTrueProcedure())  # _ZL14checkSocketSeti
            # self._proj.hook(self._proj.loader.find_symbol('parseCotpMessage').rebased_addr, TestProcedure())
        elif self.protocol == 'umas-v31':
            self._proj.hook(0x20176910, angr.SIM_PROCEDURES['libc']['memcpy']())  # memcpy

        create_thread_function = self._proj.loader.find_symbol('pthread_create')
        if create_thread_function:
            ct_address = create_thread_function.rebased_addr
            print('thread create addr: {}'.format(ct_address))

            # Thread create hook
            if self.protocol == 'iec104':
                self._proj.hook(ct_address, MyPthreadCreate())
            else:
                self._proj.hook(ct_address, angr.SIM_PROCEDURES['posix']['pthread_create']())
        # simgr = self._proj.factory.simgr(entry_state, save_unconstrained=True, veritesting=True)
        simgr = self._proj.factory.simgr(entry_state, save_unconstrained=True)

        iteration = 0
        num_of_state = 0
        flag = 1
        path_num = 0

        while simgr.active and flag:
            if iteration >= 45:
                break
            simgr.step()

            # Gets all states
            active_states = simgr.active
            # print(active_states)
            # Iterate through all states
            num_of_state += len(active_states)
            for state in active_states:
                if self.find_path_by_addr(state, self._hooked_address):
                    print(num_of_state)
                if self.find_path_by_addr(state, self._end_address):
                    tmp = [537401328, 537401488, 537399096, 537401536, 537401548, 537402052, 537401556, 537402192, 537444392, 537378304, 537141572, 537041888, 537141588, 537378324, 537378200, 537378332, 537444448, 538344724, 538390512, 538390552, 538390604, 538344736, 537444480, 537444488, 537448156, 537450504]
                    # print('find: length is: {}'.format(len(state.history.bbl_addrs.hardcopy)))
                    # print(state.history.bbl_addrs.hardcopy)
                    # if len(tmp) == len(state.history.bbl_addrs.hardcopy):
                    #     flag = 0
                    #     print('find: length is: {}'.format(len(state.history.bbl_addrs.hardcopy)))
                    #     print(state.history.bbl_addrs.hardcopy)
                    #     break
                    path_num += 1
            iteration += 1
        print('Symbol--Depth: {}'.format(iteration))
        print('Symbol--Number of states: {}'.format(num_of_state))
