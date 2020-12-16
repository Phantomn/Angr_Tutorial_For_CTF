import angr
import claripy
import sys

def is_successful(state):
    return b'Good Job.' in state.posix.dumps(sys.stdout.fileno())
def should_abort(state):
    return b'Try again.' in state.posix.dumps(sys.stdout.fileno())

def main():
    proj = angr.Project('../problems/04_angr_symbolic_stack')
    start_addr = 0x8048697
    init_state = proj.factory.blank_state(addr=start_addr)

    init_state.regs.ebp = init_state.regs.esp
    passwd1 = init_state.solver.BVS('passwd1', 32)
    passwd2 = init_state.solver.BVS('passwd2', 32)

    padding_len = 0x8
    init_state.regs.esp -= padding_len

    init_state.stack_push(passwd2)
    init_state.stack_push(passwd1)

    simulation = proj.factory.simgr(init_state)
    simulation.explore(find=is_successful, avoid=should_abort)

    if simulation.found:
        solution = simulation.found[0]
        solution_passwd1 = solution.solver.eval(passwd1)
        solution_passwd2 = solution.solver.eval(passwd2)
        print("flag : ", solution_passwd2, solution_passwd1)
    else:
        print("no flag")

if __name__ == '__main__':
    main()
