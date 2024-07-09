import pandas as pd
from plormber.attacks.base import ORMLeakResult


def get_stats_df(df: pd.DataFrame) -> pd.DataFrame:
    """
        Returns a DataFrame with the mean, median, standard deviation and size for each tested value

        Args:
            df: A DataFrame of the results

        Returns:
            A DataFrame with the mean, median, standard deviation and size for each tested value
    """
    df_groupby = df.groupby('test_dump_val')

    stats_df = pd.concat([
        df_groupby['total_time'].mean().rename('mean'),
        df_groupby['total_time'].median().rename('median'),
        df_groupby['total_time'].std().rename('std'),
        df_groupby.size().rename('size')
    ], axis=1)

    stats_df['result'] = stats_df.apply(
        lambda row: df.loc[df['test_dump_val'] == row.name].reset_index().iloc[0]['result'],
        axis=1
    )

    return stats_df


def ormleak_result_to_df(results: list[ORMLeakResult]) -> pd.DataFrame:
    """
        Parses a list of ORMLeakResult instances into a DataFrame

        Args:
            results: A list of ORMLeakResults from sending the payload

        Returns:
            The results in a DataFrame
    """
    return pd.DataFrame([
        {'test_dump_val': result.test.dump_val, 'total_time': result.total_time, 'result': result} 
        for result in results
    ])