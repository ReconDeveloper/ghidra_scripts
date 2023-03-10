#!/usr/bin/env python2
# -*- coding:utf-8 -*-

'''
Resources 
https://github.com/HackOvert/GhidraSnippets
''' 

#@author ReconDeveloper
#@category 
#@keybinding 
#@menupath 
#@toolbar 
from ghidra.app.decompiler import DecompInterface, DecompileOptions, PrettyPrinter
from ghidra.framework.plugintool.util import OptionsService
from ghidra.program.model.listing import CodeUnit
from ghidra.program.model.symbol import *
from ghidra.program.model.listing import * 
from ghidra.program.model.address import *
from ghidra.app.util import Option
from ghidra.util.task import TaskMonitor
from java.io import File
from ghidra.app.util.exporter import CppExporter

# `currentProgram` or `getScriptArgs` function is contained in `__main__`
import __main__ as ghidra_app


class Analyzer:

    def __init__(self, program=None, timeout=None):

        # Initialize decompiler with current program
        self._decompiler = DecompInterface()
        self._decompiler.openProgram(program or ghidra_app.currentProgram)
        self._options = DecompileOptions()
        self._tool = state.getTool()
        self._timeout = timeout


    def set_up_decompiler(self):
        if self._tool is not None:
            options_service = self._tool.getService(OptionsService)
            if options_service is not None:
                tool_options = options_service.getOptions("Decompiler")
                self._options.grabFromToolAndProgram(None, tool_options, program)

        #eliminate dead code
        self._options.setEliminateUnreachable(True)
        self._decompiler.setOptions(self._options)

        self._decompiler.toggleCCode(True)
        self._decompiler.toggleSyntaxTree(True)
        self._decompiler.setSimplificationStyle("decompile")

        return self._decompiler

    def get_all_functions(self):
        st = ghidra_app.currentProgram.getSymbolTable()
        si = st.getSymbolIterator()
        symbol_dict = {}
        funcs = []
        while si.hasNext():
            s = si.next()
            if ((s.getSymbolType() == SymbolType.FUNCTION) and (not s.isExternal())
                    and (not s.getName() in symbol_dict.keys())):
                symbol_dict[s.getName()] = s.getAddress()

        for address in symbol_dict.values():
            funcs.append(getFunctionAt(address))
        return funcs
           
    
    def decompile_func(self, func):
        # Decompile
        self._decompiler = self.set_up_decompiler()
        decomp_results = self._decompiler.decompileFunction(func, 0, self._timeout)
        if (decomp_results is not None) and (decomp_results.decompileCompleted()):
            pretty_printer = PrettyPrinter(func, decomp_results.getCCodeMarkup())
            # Get the string of the full function source code
            return pretty_printer.print(False).getC()
        return ""

    def decompile(self):
            
        pseudo_c = ''

        # Enumerate all functions and decompile each function
        funcs = self.get_all_functions()
        for func in funcs:
            if not func.isThunk():
                dec_func = self.decompile_func(func)
                if dec_func:
                    pseudo_c += dec_func

        return pseudo_c

    def list_cross_references(self, dst_func, tag, output_path):
        dst_name = dst_func.getName()
        dst_addr = dst_func.getEntryPoint()
        references = getReferencesTo(dst_addr) #limited to 4096 records
        xref_addresses = []
        f = open(output_path,'a')
        for xref in references:
            if xref.getReferenceType().isCall(): 
                call_addr = xref.getFromAddress()
                src_func = getFunctionContaining(call_addr)
                if src_func is not None:
                    xref_addresses.append(src_func.getEntryPoint())
                    if ((not src_func.isThunk()) and (xref_addresses.count(src_func.getEntryPoint()) < 2)):
                        # Decompile
                        self._decompiler = self.set_up_decompiler()
                        decomp_results = self._decompiler.decompileFunction(src_func, 0, self._timeout)
                        if (decomp_results is not None) and (decomp_results.decompileCompleted()):
                            high_func = decomp_results.getHighFunction()
                            lsm = high_func.getLocalSymbolMap()
                            symbols = lsm.getSymbols()
                            if high_func:
                                #add pre comment tag at candidate point location
                                listing = currentProgram.getListing()
                                code_unit = listing.getCodeUnitAt(call_addr)
                                code_unit.setComment(CodeUnit.PRE_COMMENT, tag + "\n")
                                op_iter = high_func.getPcodeOps()
                                while op_iter.hasNext():
                                    op = op_iter.next()
                                    mnemonic = str(op.getMnemonic())
                                    if mnemonic == "CALL":
                                        inputs = op.getInputs()
                                        addr = inputs[0].getAddress()
                                        args = inputs[1:] # List of VarnodeAST types
                                        if addr == dst_addr:
                                            paramaters = {}
                                            for arg in args:
                                                high_variable = arg.getHigh()
                                                if high_variable is not None:
                                                    #add paramter type and name to dictionary
                                                    value = high_variable.getSymbol().getName() if high_variable.getSymbol() is not None else "Undefined"
                                                    paramaters[str(high_variable.getDataType())] = str(value)      
                                            print >>f, "Call to {} in {} at {} has {} arguments: {}" \
                                                .format(getFunctionContaining(addr).getName(),src_func.getName(), \
                                                        op.getSeqnum().getTarget(), len(args), paramaters) 
        f.close()

    def get_interesting_functions(self, output_path):
        tier_0 = ["fscanf", "_fscanf", "__isoc99_fscanf", "sprintf", "_sprintf", "strcat", "_strcat",
            "strcpy", "_strcpy", "lstrcpyA","scanf, _scanf", "vfscanf", "_vfscanf", "fscanf", "_fscanf", "__isoc99_fscanf",
            "__isoc99_sscanf", "sscanf", "_sscanf", "memcpy", "read", "write", "bcopy", "malloc", "free"] 
        tag = "[Bad] Tier 0"
        st = ghidra_app.currentProgram.getSymbolTable()
        si = st.getSymbolIterator()
        symbol_dict = {}
        funcs = []
        while si.hasNext():
            s = si.next()
            if ((s.getSymbolType() == SymbolType.FUNCTION) and (not s.isExternal())
                    and (s.getName() in tier_0) and (not s.getName() in symbol_dict.keys())):
                symbol_dict[s.getName()] = s.getAddress()

        for address in symbol_dict.values():
            funcs.append(getFunctionAt(address))

        for f in funcs:
           self.list_cross_references(f,tag,output_path)      


def run():

    # getScriptArgs gets argument for this python script using `analyzeHeadless`
    args = ghidra_app.getScriptArgs()
    f = open(args[0],'w')
    print >>f, 'Xref Results \n-----------------------------\n'
    f.close()

    analyzer = Analyzer()
    analyzer.get_interesting_functions(args[0])
    decompiled_source_file = args[1]
    # Do decompilation process
    pseudo_c = analyzer.decompile()

    # Save to output file
    with open(decompiled_source_file, 'w') as fw:
        fw.write(pseudo_c)
        print('[*] saving decompilation to -> {}'.format(decompiled_source_file))

    exporter = CppExporter()
    options = [Option(CppExporter.CREATE_HEADER_FILE, False)]
    exporter.setOptions(options)
    exporter.setExporterServiceProvider(analyzer._tool)
    f = File(args[1])
    exporter.export(f, ghidra_app.currentProgram, None, TaskMonitor.DUMMY)


if __name__ == '__main__':
    run()
