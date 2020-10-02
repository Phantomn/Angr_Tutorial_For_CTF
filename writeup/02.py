import angr
import sys

def main():
	p = angr.Project("../problems/02_angr_find_condition")
	init_state = p.factory.entry_state()
	simulation = p.factory.simgr(init_state)

	simulation.explore(find=is_successful, avoid=should_abort)

	if simulation.found:
		solution = simulation.found[0]
		print("flag : ", solution.posix.dumps(sys.stdin.fileno()))
	else:
		print("no flag")

def is_successful(state):
	return b"Good Job" in state.posix.dumps(sys.stdout.fileno())

def should_abort(state):
	return b"Try again" in state.posix.dumps(sys.stdout.fileno())

if __name__ == "__main__":
	main()
