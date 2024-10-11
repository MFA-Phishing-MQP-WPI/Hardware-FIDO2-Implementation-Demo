from typing import List, Dict, Tuple, Optional
from display import COLOR_CODES
import os



run_conditions: Dict[str, any] = {
    "--launch-from-save": None,
    "-display_crypto_backend": False,
    '-fancy_display_location': False,
    '-help': False,
    '-debug_mode': False,
    '-debug_challenge': False,
    '-debug_yubikey': False,
    '-all_flags': False
}

help_runers: Tuple[Dict[str, str], Dict[str, Tuple[str, str]]] = (
    {
        '-help': 'prints this help message',
        '-display_crypto_backend': 'displays actions completd by the cryptographic backend',
        '-fancy_display_location': 'displays RP name and username when login-context changes - please note the text is large',
        '-debug_mode': 'prints the value of all private keys at runtime start',
        '-debug_challenge': 'lets user edit the values that create the challenge before it is sent to YubiKey for authentication',
        '-debug_yubikey': 'lets user edit the values that create the YubiKey',
        '-all_flags': 'acts as all flags (except for -help flag)'
    },
    {
        '--launch-from-save [.dump file]': 
            (
                'restores the state based on .dump file', 
                '`-launch-from-save temp.dump` will restore the state that was saved to "temp.dump"'
            )
    }
)

class Parser:
    def __init__(self, args: List[str]):
        self.args = args
        self.options = None
        self.arguments = None

    def parse(self, legal_lengths: Optional[List[int]] = None) -> Dict[str, any]:
        global run_conditions

        if legal_lengths and (len(self.args) + 1) not in legal_lengths:
            COLOR_CODES.err('ERROR::UNEXPECTED ARG LEN INVALID', f': Invalid number of arguments. Expected {legal_lengths} but got "{len(self.args) + 1}"')
            self.print_help_statement_and_close()

        if not self.options or not self.arguments:
            self.options = []
            self.arguments = {}
            Flags, Args = self._arg_affy(self.args)
            for flag in Flags:
                if flag not in run_conditions:
                    COLOR_CODES.err('ERROR::Unknown flag', f': flag_name="{flag}"')
                    self.print_help_statement_and_close()
                run_conditions[flag] = True
            for arg, value in Args.items():
                if arg not in run_conditions:
                    COLOR_CODES.err('ERROR::Unknown argument', f': arg_name="{arg}"{COLOR_CODES.RESET}')
                    self.print_help_statement_and_close()
                run_conditions[arg] = value
            if run_conditions['--launch-from-save'] and not os.path.exists(run_conditions['--launch-from-save']):
                COLOR_CODES.err('ERROR::Fail To Open', f": Could not find or open .dump file \"{run_conditions['--launch-from-save']}\" in local dir.")
                self.print_help_statement_and_close()
            if run_conditions['-all_flags']:
                for flag_name in help_runers[0].keys():
                    if flag_name in ['-help', '-all_flags']:
                        continue
                    run_conditions[flag_name] = True
        return run_conditions if not run_conditions['-help'] else self.print_help_statement_and_close()
    
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

    def print_help_statement_and_close(self):
        print(' <<< HELP MESSAGE >>>\n')
        print(f'USAGE:  python3 demo.py  Optional::[ flags ]  Optional::[ [arg_name] [arg_value] ]')
        print('\nFLAGS:')
        for flag, description in help_runers[0].items():
            print(f'  {flag}: \n\t{description}')
        print('\nARGUMENTS:')
        for arg, (description, example) in help_runers[1].items():
            print(f'  {arg}: \n\t{description}')
            print(f'\tExample: {example}')
        print('\n <<< HELP MESSAGE END >>>\n')
        exit()