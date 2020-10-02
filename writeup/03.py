import angr
import claripy
import sys

def main():
    p = angr.Project("../problems/03_angr_symbolic_registers")
    start_address=0x8048980

    init_state = p.factory.blank_state(addr=start_address)

    passwd0 = claripy.BVS('p0', 32)
    passwd1 = claripy.BVS('p1', 32)
    passwd2 = claripy.BVS('p2', 32)

    init_state.regs.eax = passwd0
    init_state.regs.ebx = passwd1
    init_state.regs.edx = passwd2

    simulation = p.factory.simgr(init_state)
    simulation.explore(find=is_successful, avoid=should_abort)

    if simulation.found:
        solution_state = simulation.found[0]
        solution0 = solution_state.solver.eval(passwd0)
        solution1 = solution_state.solver.eval(passwd1)
        solution2 = solution_state.solver.eval(passwd2)
        print("flag: ",hex(solution0), hex(solution1), hex(solution2))
    else:
        print("no flag")

def is_successful(state):
    return b"Good Job." in state.posix.dumps(sys.stdout.fileno())
def should_abort(state):
    return b"Try again."in state.posix.dumps(sys.stdout.fileno())

if __name__ == '__main__':
    main()
