#!/usr/bin/env python
# -*- coding: utf-8 -*-


#the client of Binary Translator Debugger (bdb)

import sys
import cmd
import socket
import subprocess
import os
# import re
import shlex, subprocess
#Parse the log output


#
#  protocol:
#
#  (1) breakpoint info
#
#  send: breakpoint info
#  receive:  break:totalcnt: addr:type:hitcnt
#
#  (2) breakpoint add [addr]
#
#  send :bp_add [addr]
#  receive: OK/KO
#
#
#  (3) breakpoint delete [addr]
#
#  send: bp_del [addr]
#  receive: OK/KO
#
#
#
#

ADDR2LINE_NAME = "addr2line"

class bdb(cmd.Cmd):
    def __init__(self):
        self.connected = False
        cmd.Cmd.prompt = "(bdb)->"
        cmd.Cmd.__init__(self)
        self.ot_mapping = {}
        self.to_mapping = {}
        self.trace = []

        #addr : libs
        self.symbols={}

    def wait_ok(self):
        reply = self.server_sock.recv(512)
        #will block here. TODO: Timeout
        #check received string
        if reply == "OK":
            print "OK"
            return True
        elif reply == "KO":
            print "KO"
            return False

        return False

    #break:[addr]:[type]
    def wait_break(self):
        reply = self.server_sock.recv(512)
        # print reply
        rs = reply.split("\n")
        ret = False
        for r in rs:
            mapping = r.split(":")
            # print mapping
            if mapping[0] == "mapping" and len(mapping) == 3:
                # print mapping
                self.ot_mapping[mapping[1]] = mapping[2]
                self.to_mapping[mapping[2]] = mapping[1]

            if mapping[0] == "trace" and len(mapping) == 2:
                self.trace.append(mapping[1])

            if mapping[0] == "break" and len(mapping) == 2:
                print "break"
                ret = True
        return ret

    def validate_target(self, line):
        cmds = line.split(" ")

        if len(cmds) != 3:
            return False

        if len(cmds[-1].split(":")) == 0:
            return False

        port = cmds[-1].split(":")[1]

        try:
            int(port)
        except ValueError:
            return False

        return True

    def help_target(self):
        print "target remote add [ip:port]"

    def complete_target(self, text, line, begidx, endidx):
        completions = ["remote add localhost:1234"]
        return completions

    def connect_target(self, host, port):
        self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.server_sock.connect((host, port))
        except Exception, e:
            print "Something's wrong with %s. Exception type is %s" % (host, e)
            return False

        # print self.server_sock
        return True

    def do_target(self, line):
        if not self.validate_target(line):
            print "error cmd: target " + line
            return

        if self.connected == True:
            print "already connected"
            return

        cmds = line.split(" ")
        host = cmds[-1].split(":")[0]
        port = int(cmds[-1].split(":")[1])

        if not self.connect_target(host, port):
            print "conncted to server fail!!"
        else:
            print "conncted to server"
            self.connected = True

    def help_breakpoint(self):
        print "\n".join(["breakpoint add addr", "breakpoint delete addr"])


    def complete_breakpoint(self, text, line, begidx, endidx):
        if not text:
            completions = ["add", "delete", "info"][:]
        else:
            completions = [ f
                            for f in ["add","delete","info"]
                            if f.startswith(text)
                            ]
        return completions

    def validate_breakpoint(self, line):
        cmds = line.split(" ")
        if len(cmds) < 1:
            return False

        if (cmds[0] != "add") and (cmds[0] != "delete") and (cmds[0] != "info"):
            return False

        if (cmds[0] == "add") or (cmds[0] == "delete"):
            try:
                addr = int(cmds[1], 0)
            except:
                return False

        return True

    def wait_break_info(self):
        reply = self.server_sock.recv(512)
        rs = reply.split(":")
        if len(rs) < 2:
            print "error response: " + reply
            return False

        if (rs[0] != "break"):
            print "error response: " + reply
            return False

        print "totoal breakpoints: " + str(rs[1])

        # print rs

        #break:totalcnt:addr:type:hitcnt
        for i in range(int(rs[1])):
            print rs[2+i*3] + ":" + rs[2+i*3 + 1] + ":" + rs[2+i*3 + 2]

        return True


    def do_breakpoint(self, line):
        if not self.validate_breakpoint(line):
            print "error cmd: breakpoint " + line
            return False

        if not self.connected:
            print "please connect to server first"
            return False

        cmds = line.split(" ")

        if (cmds[0] == "add"):
            addr = cmds[1]
            self.server_sock.send("bp_add " + addr + "\n")
            self.wait_ok()
        elif (cmds[0] == "delete"):
            addr = cmds[1]
            self.server_sock.send("bp_del " + addr + "\n")
            self.wait_ok()
        elif (cmds[0] == "info"):
            self.server_sock.send("bp_info\n")
            self.wait_break_info()

    def wait_regs(self):
        reply = self.server_sock.recv(512)
        # print reply
        rs = reply.split("\n")
        #r0:value,r1:value..
        for r in rs:
            reg_values = r.split(",")
            i = 0
            for reg in reg_values:
                print reg,
                i += 1
                if (i % 4 ==0):
                    print

        print
        return True

    def do_regs(self, line):
        if not self.connected:
            print "please connect to server first"
            return False
        self.server_sock.send("regs\n")
        self.wait_regs()


    def validate_memory(self, line):
        cmds = line.split(" ")
        if len(cmds) != 2:
            return False

        try:
            addr = int(cmds[0], 0)
            addr = int(cmds[1], 0)
        except:
            return False

        return True

    def wait_memory(self):
        reply = self.server_sock.recv(2500)
        # print reply
        rs = reply.split("\n")
        #addr:value,
        for r in rs:
            mem_values = r.split(",")
            i = 0
            # print mem_values
            for mm in mem_values:
                mm = mm.split(":")
                if (len(mm) != 2):
                    continue
                if (i % 4 == 0):
                    print str(mm[0]) + ":",
                print mm[1] + "  ",
                i += 1
                if (i % 4 ==0):
                    print
        print
        return True

    def do_memory(self,line):
        if not self.connected:
            print "please connect to server first"
            return False

        if not self.validate_memory(line):
            print "error cmd: memory " + line
            return False

        self.server_sock.send("memory " + line + "\n")
        self.wait_memory()

    def do_continue(self, line):
        if not self.connected:
            print "please connect to server first"
            return False

        self.server_sock.send("continue\n")
        self.wait_ok()
        while 1:
            try:
                if (self.wait_break()):
                    break
            except KeyboardInterrupt:
                print "CTRL + C"
                break

    def validate_add_symbol_file(self,line):
        cmds = line.split(" ")
        # print cmds
        if len(cmds) != 2:
            return False
        try:
            addr = int(cmds[1], 0)
        except:
            return False

        if not os.path.exists(cmds[0]):
            print "can not find lib"
            return False

        return True

    #add-symbol-file file addr
    def do_add_symbol_file(self,line):
        if not self.validate_add_symbol_file(line):
            print "error cmd: add-symbol-file " + line
            return False

        cmds = line.split(" ")
        addr = int(cmds[1], 0)

        self.symbols[addr] = cmds[0]

        print "add " + cmds[0] + " successfully"


    def get_library(self, addr):
        addr = addr & (~0xfffff);
        if addr not in self.symbols.keys():
            print "can not find library for addr " + "0x%x" % addr
            print "xxxxxxxxxxxxxxxxxxxxxx"
            return None

        return self.symbols[addr]

    def get_line_info(self, addr):
        lib = self.get_library(addr)
        if lib == None:
            return None

        new_addr = addr & (0xfffff);

        #arm-eabi-addr2line -C -f -e libc.so 155a4
        cmd = ADDR2LINE_NAME + " -C -f -e  " + lib + " " +  "0x%x" % new_addr
        # print cmd

        args = shlex.split(cmd)

        p = subprocess.Popen(args, stdout=subprocess.PIPE)

        p.wait()

        return p.stdout.readlines()


    def trace_print(self, fpath=None):
        fp = None
        if fpath != None:
            fp = open(fpath, "w")
            print "writing to " + fpath

        for tpc in self.trace:
            if tpc in self.to_mapping.keys():
                opc = int(self.to_mapping[tpc], 0)
                if fp:
                    fp.write(tpc + ":" + hex(opc) + "\n")
                else:
                    print tpc + ":" + hex(opc)
            else:
                if fp:
                    fp.write ("can not find opc for tpc: " + tpc + "\n")
                else:
                    print ("can not find opc for tpc: " + tpc )

        print "done"

    def trace_info(self,fpath=None):
        fp = None
        if fpath != None:
            fp = open(fpath, "w")
            print "writing to " + fpath

        for tpc in self.trace:
            if tpc in self.to_mapping.keys():
                opc = int(self.to_mapping[tpc], 0)
                #['dlmalloc\n', '/home/yajin/android/cm10/bionic/libc/bionic/dlmalloc.c:4312\n']
                lines = self.get_line_info(opc)
                if lines != None and len(lines) == 2:
                    if fp:
                        fp.write("["+tpc + ":" + hex(opc)+"]:(" + lines[0].split("\n")[0] + "):" + lines[1].split("\n")[0]+"\n")
                    else:
                        print "["+tpc + ":" + hex(opc)+"]:(" + lines[0].split("\n")[0] + "):" + lines[1].split("\n")[0]

        print "done"

    #print the execution trace
    #trace print
    #trace save [file]
    def do_trace(self, line):
        cmds = line.split(" ")
        fpath = None
        if len(cmds) == 2:
            fpath = cmds[1]

        if cmds[0] == "print":
            self.trace_print(fpath)

        if cmds[0] == "info":
            self.trace_info(fpath)





    def do_quit(self, line):
        sys.exit(-1)

    def do_EOF(self, line):
        return True


if __name__ == '__main__':
    bdb = bdb()
    bdb.cmdloop()





# line_header = "-->"

# import sys
# import re
# import socket


# connected = False
# server_sock = None


# def parse_cmd(cmdline):
#     global connected
#     global server_sock

#     cmds = cmdline.split(" ")
#     # print cmds
#     if len(cmds) ==0:
#         print "error cmd" + cmdline
#         return

#     if cmds[0] == "target" and len(cmds) == 4 and cmds[1] == "remote" and cmds[2] == "add":
#         remote = cmds[3]
#         host = remote.split(":")[0]
#         port = int(remote.split(":")[1])

#         server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#         server_sock.connect((host, port))

#         print line_header,
#         print "conncted"
#         connected = True

#     elif cmds[0] == "bp_add" and len(cmds) == 2:
#         addr = cmds[1]
#         if not connected:
#             print line_header + "server has not been connected."
#         else:
#             #send command to server
#             server_sock.send("bp_add " + addr + "\r\n")
#     elif cmds[0] == "c":
#         if not connected:
#             print line_header + "server has not been connected."
#         else:
#             #send command to server
#             server_sock.send("c\r\n")
#     elif cmds[0] == "q":
#         sys.exit(-1)
#     else:
#         print line_header + "error cmd: " + cmdline


# print "Welcome to bdb: Binary Translator Debugger"


# while (1):
#     print
#     print line_header,
#     line = sys.stdin.readline()
#     #remove spaces
#     line = re.sub(' +',' ',line)
#     parse_cmd(line)

