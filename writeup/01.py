import angr

def main():
    p = angr.Project("../problems/01_angr_avoid")
    init_state = p.factory.entry_state()
    simulation = p.factory.simgr(init_state)
    good = 0x80485e5
    bad = [0x80485a8,0x80485e7]

    simulation.explore(find=good, avoid=bad)

    if simulation.found:
        solution = simulation.found[0]
        print("flag: ", solution.posix.dumps(0))
    else:
        print("no solution")

if __name__== '__main__':
    main()
