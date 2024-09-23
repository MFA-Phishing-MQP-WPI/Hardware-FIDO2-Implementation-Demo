from typing import List, Dict, Tuple, Optional

class Parser:
    def __init__(self, args: List[str]):
        self.args = args
        self.options = None
        self.arguments = None

    def parse(self, legal_lengths: Optional[List[int]] = None) -> Dict[str, any]:
        run_conditions: Dict[str, any] = {
            "--launch-from-save": None,
            "-display_crypto_backend": False
        }

        if legal_lengths and (len(self.args) + 1) not in legal_lengths:
            print(f'Invalid number of arguments. Expected {legal_lengths} but got {len(self.args) + 1}')
            print(f'USAGE: python3 demo.py')
            print(f'USAGE: python3 demo.py --launch-from-save <SAVE_FILENAME>.dump')
            print('Aborting execution')
            exit(1)

        if not self.options or  not self.arguments:
            self.options = []
            self.arguments = {}
            Flags, Args = self._arg_affy(self.args)
            for flag in Flags:
                if flag not in run_conditions:
                    print(f'Unknown flag: "{flag}"')
                    print(f'USAGE: python3 demo.py')
                    print(f'USAGE: python3 demo.py --launch-from-save <SAVE_FILENAME>.dump')
                    print('Aborting execution')
                    exit(1)
                run_conditions[flag] = True
            for arg, value in Args.items():
                if arg not in run_conditions:
                    print(f'Unknown argument: "{arg}"')
                    print(f'USAGE: python3 demo.py')
                    print(f'USAGE: python3 demo.py --launch-from-save <SAVE_FILENAME>.dump')
                    print('Aborting execution')
                    exit(1)
                run_conditions[arg] = value
        return run_conditions
    
    def _arg_affy(self, args: List[str]) -> Tuple[List[str], Dict[str, str]]:
        flags = []
        arguments = {}
        i = 0
        while i < len(args):
            if args[i].startswith("--"):
                key = args[i]
                if i + 1 < len(args) and not args[i + 1].startswith("--"):
                    value = args[i + 1]
                    arguments[key] = value
                    i += 2
                else:
                    arguments[key] = None
                    i += 1
            elif args[i].startswith('-'):
                flags.append(args[i])
                i += 1
            else:
                print(f"Not Flag Followed By Not Flag ERRNO{i}: lst: ")
                for i, arg in enumerate(args):
                    print(f'\t{i}. {arg}')
                exit(0)
        return (flags, arguments)
