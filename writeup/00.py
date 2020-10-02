import angr

def main():
    p = angr.Project("../problems/00_angr_find")
    init_state = p.factory.entry_state()
    simulation = p.factory.simgr(init_state)
    good = 0x804867d
    bad = 0x8048663

    simulation.explore(find=good, avoid=bad)

    if simulation.found:
        solution = simulation.found[0]
        print("flag: ", solution.posix.dumps(0))
    else:
        print("no solution")

if __name__== '__main__':
    main()
