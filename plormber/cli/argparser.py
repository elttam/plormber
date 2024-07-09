import argparse, inspect
import plormber.attacks as attacks
from plormber.attacks.base import BaseORMLeakAttack

def parse_custom_args(cls: BaseORMLeakAttack) -> dict:
    assert issubclass(cls, BaseORMLeakAttack), "Custom attack does not extend the BaseORMLeakAttack class"
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    subparsers = parser.add_subparsers(title='orm-leak-attacks',
                                       description='available orm leak attacks',
                                       dest='command')
    cls.add_command_args(subparsers)
    args = vars(parser.parse_args())
    args.pop("command")
    return args


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    subparsers = parser.add_subparsers(title='orm-leak-attacks',
                                       description='available orm leak attacks',
                                       dest='command')
    
    for _name, cls in inspect.getmembers(attacks, inspect.isclass):
        if issubclass(cls, BaseORMLeakAttack):
            cls.add_command_args(subparsers)
    return parser.parse_args()

def get_attack_cls_from_command(namespace: argparse.Namespace) -> tuple[BaseORMLeakAttack, dict]:
    command = namespace.command
    for _name, cls in inspect.getmembers(attacks, inspect.isclass):
        if issubclass(cls, BaseORMLeakAttack):
            if cls.command_name == command:
                args = vars(namespace)
                args.pop('command')
                return (cls, args)
            
    raise ModuleNotFoundError