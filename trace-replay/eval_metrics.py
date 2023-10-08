import os
from pathlib import Path
from datetime import datetime
import pandas as pd
import numpy as np
from sklearn import metrics

ts_datetime = datetime.now().strftime('%Y-%m-%d-%H-%M-%S-%f')[:-3]

def eval_whisper(stats_global, attack, sampling, total_time):
    outdir = f'{Path(__file__).parents[0]}/eval/whisper'
    if not os.path.exists(f'{Path(__file__).parents[0]}/eval/whisper'):
        os.makedirs(outdir, exist_ok=True)
    outpath_stats_global = os.path.join(outdir, f'{attack}-{sampling}-stats-{ts_datetime}.csv')

    # Collect the global stats and save to a csv.
    df_stats_global = pd.DataFrame(stats_global)
    df_stats_global.to_csv(outpath_stats_global, index=None)
