import angr

def solve_two(p):
    base = p.loader.main_object.min_addr

    state = p.factory.blank_state(addr=base + 0x84c)
    arg = state.solver.BVS('serial', 8 * 128)

    rand_addr = 0x0000000041414141
    state.memory.store(rand_addr, arg)
    state.add_constraints(state.regs.x0 == rand_addr)
	
    sm = p.factory.simulation_manager(state)
	# Veritesting is a technique for identifying merge points in software that is being symbolically executed, 
	# this helps combat the 'path explosion' issue
	# Originally described in the following paper: https://users.ece.cmu.edu/~dbrumley/pdf/Avgerinos%20et%20al._2014_Enhancing%20Symbolic%20Execution%20with%20Veritesting.pdf 
    sm.explore(find=base + 0x8a8, avoid=base + 0x8b8, enable_veritesting=True)
    found = sm.found[0]
    answer = found.solver.eval(arg, cast_to=bytes)
    out = answer[:answer.index(b'\x00')]
    print("Hex output: 0x{}".format(out.hex()))
    print("Raw string output: {}".format(out))
     
def solve_one(p):
      # Android NDK library path:
    # load_options['ld_path'] = ['/Users/berndt/Tools/android-ndk-r10e/platforms/android-21/arch-arm/usr/lib']

    base = p.loader.main_object.min_addr

    state = p.factory.blank_state(addr=base + 0x74c)
    arg = state.solver.BVS('serial', 8 * 128)
    rand_addr = 0x0000000041414141
    state.memory.store(rand_addr, arg)
    state.add_constraints(state.regs.x0 == rand_addr)
    sm = p.factory.simulation_manager(state)
    sm.explore(find=base + 0x7e8, avoid=base + 0x7f8, enable_veritesting=True)	
    found = sm.found[0]
    answer = found.solver.eval(arg, cast_to=bytes)
    out = answer[:answer.index(b'\x00')]
    print('Valid serial:')
    print("\tHex output: 0x{}".format(out.hex()))
    print("\tRaw string output: {}".format(out))

def main():
     p = angr.Project('app-release/lib/arm64-v8a/liblicensevalidator.so', load_options={'auto_load_libs':False})
     solve_one(p)
     solve_two(p)


if __name__ == '__main__':
    main()



#zzzyz-qwkk-xphz-qzyz-wzzz-zzzz-zzyy-unyx-z
#bxxgb-zbxb-kfgz-zbfn-pkfo-kcxv-npkk-bcwx-