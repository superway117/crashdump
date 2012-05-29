import sys
import re
import os
import getopt

sohead = re.compile('(.+\.so):')
funchead = re.compile('([0-9a-f]{8}) <(.+)>:')
funcline = re.compile('^[ ]+([0-9a-f]+):.+')
objdumppath = './android/prebuilt/linux-x86/toolchain/arm-eabi-4.2.1/bin/arm-eabi-objdump'
addr2linepath = './android/prebuilt/linux-x86/toolchain/arm-eabi-4.2.1/bin/arm-eabi-addr2line'
libpath = './build/debug/android/target/product/xmm2231ff1_0/symbols/system/lib' 
symbolslibpath = './build/debug/android/target/product/xmm2231ff1_0/symbols/system/lib'



def printUsage():
    print
    print "  usage: python " + sys.argv[0] + " [options] <logfile>"
    print
    print "  -a"
    print "     option to print asm instruction"
    print
    print "  -h"
    print "     print usage "
    sys.exit(1)

def parsestack( lines, libname ):
    crashline = re.compile('.+pc.([0-9a-f]{8}).+%s' % libname )
    ret = []
    for l in lines:
        m = crashline.match(l)
        if m:
            addr =  m.groups()[0]
            ret.append(int(addr,16))
    return ret

def parsestack(lines):
    crashline = re.compile('.+pc.([0-9a-f]{8}).+\/(.+\.so)' )
    ret  = []
    for  l in lines:
        m = crashline.match(l)
        if m:
#first is addr          
#second is lib name         
            line_info = [int(m.groups()[0],16),m.groups()[1]]
            ret.append(line_info)
#           print line_info[0],line_info[1]
    return ret

def parseasm( lines ,debug=False):
    ret = []
    current = None
    restartcode = False
    so = ""
    for l in lines:
        if debug==True:
            print l
        m = funchead.match(l)
        if m:
            startaddr, funcname =  m.groups()
            current = [ funcname, int(startaddr,16), int(startaddr,16), int(startaddr,16), [] ]
            ret.append(current)
            restartcode = True
#           print "function name "+ funcname+":"+startaddr
            continue
        m = funcline.match(l)
        if m:
            addr =  m.groups()[0]
#            print "match funcline "+addr
            if current != None:
                current[3] = int(addr,16)
                current[4].append(l)
            continue
        m = sohead.match(l)
        if m:
            so =  m.groups()[0]
            so = os.path.split(so)[1] 
            continue 

        #Assume anything else is a code line
        if current != None:
            current[4].append(l)
#   for item in ret:
#       print "FUNC:%s code len=%d" % (item[0],len(item[4]))
    return so, ret


    
def produceasm(logfile):
    asmfiles = []
    stack_lines = parsestack(file(logfile).read().split('\n'))
    for stack_info in stack_lines:
        stack_lib = stack_info[1]
        asmfile = "%s.asm" % stack_lib
        already_done = False
        for done_asm in asmfiles:
            #print done_asm,asmfile
            if cmp(done_asm,asmfile)==0:
                already_done=True
                break
        if already_done:
            continue    
        lib_path = "%s/%s" % (libpath,stack_lib)
        command = "%s -S %s > %s" % (objdumppath,lib_path,asmfile)
#       print command
        os.system(command)
        asmfiles.append(asmfile)    

#   print "parse %d lib" % (len(asmfiles))
    return asmfiles

def crashanalyse(asmfiles,logfile,printasm=False):  
    asm_list = []
#   print "%d asm file" % (len(asmfiles))
#parse all asm so files 
    if printasm == True:
        for asmfile in asmfiles:
            libname,asm = parseasm( file(asmfile).read().split('\n'),False)
            asm_info=[libname,asm]
            asm_list.append(asm_info)
       
        
#parse stack file   
    stack_lines = parsestack(file(logfile).read().split('\n'))
    i=0
#match stack addr to so function addr
    for stack_line in stack_lines:
            print  "%d %s" % (i,stack_line)
            i+=1
            found =False
            addr = stack_line[0]
            stack_lib = stack_line[1]

            sysbols_lib_path = "%s/%s" % (symbolslibpath,stack_lib)
            command = "%s -f -e %s 0x%x" % (addr2linepath,sysbols_lib_path,addr)
#           print command
#           os.system(command)
            stream = os.popen(command)
            lines = stream.readlines()
            stream.close()
            if lines != []:
                print lines[0].strip()
                print lines[1].strip()

#           print command
            if printasm == True:
                for asm in asm_list:
                    if found == True:
                        break
                    asm_lib = asm[0]
                    if cmp(stack_lib,asm_lib)!=0:
                        continue    
                    for func, funcstart, segstart, segend, code in asm[1]:
                        if addr >= segstart and addr <= segend:
                            print "instruction addr:0x%08x inside funcion%32s + 0x%04x %s" % ( addr, func, addr-funcstart, "".join(["\n"+x for x in code]))
            print
if __name__ == "__main__":  
    printasm = False    
    try:
        options, arguments = getopt.getopt(sys.argv[1:], "ah", ["asm","help"])
    except getopt.GetoptError, error:
        printUsage()
    for option, value in options:
        if option == "--help":
            printUsage()
        elif option == "--asm" or option == "-a":
            printasm = True
    if len(arguments) == 0:
        printUsage()
    logfile = arguments[0]
    asmfiles = []
    if printasm == True:
        asmfiles = produceasm(logfile)
    crashanalyse(asmfiles,logfile,printasm)
     
