from plormber.cli.argparser import parse_custom_args, parse_args, get_attack_cls_from_command

def run_custom_attack(cls):
    args = parse_custom_args(cls)
    exploiter = cls(**args)
    exploiter.exploit()

def main():
    args = parse_args()
    cls, args_dict = get_attack_cls_from_command(args)
    exploiter = cls(**(args_dict))
    exploiter.exploit()

if __name__ == "__main__":
    main()