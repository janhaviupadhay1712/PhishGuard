from pathlib import Path
import pandas as pd
from ucimlrepo import fetch_ucirepo
out=Path(__file__).resolve().parent/'PhiUSIIL_Phishing_URL_Dataset.csv'; ds=fetch_ucirepo(id=967); pd.concat([ds.data.features,ds.data.targets],axis=1).to_csv(out,index=False); print('Saved',out)
