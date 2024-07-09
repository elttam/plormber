def strip_empty_str_from_list(to_clean: list[str]) -> list[str]:
    return [x.strip() for x in to_clean if x.strip() != '']