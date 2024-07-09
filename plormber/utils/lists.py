def remove_duped_entries(strs_list: list[str]) -> list[str]:
    """
        Removes duplicated string values from a list

        Args:
            strs_list: a list of strings

        Returns:
            a list with duplicated strings removed
    """
    return list(set(strs_list))
