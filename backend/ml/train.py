from pathlib import Path
import json,joblib,pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score,precision_score,recall_score,f1_score,confusion_matrix
from .feature_extractor import extract_features,FEATURE_NAMES
ROOT=Path(__file__).resolve().parents[2]; DATA=ROOT/'dataset'/'PhiUSIIL_Phishing_URL_Dataset.csv'; OUT=ROOT/'backend/ml/artifacts'; OUT.mkdir(parents=True,exist_ok=True)
df=pd.read_csv(DATA); urlcol='URL' if 'URL' in df.columns else 'url'; labelcol='label' if 'label' in df.columns else 'Label'; df=df[[urlcol,labelcol]].dropna().drop_duplicates(subset=[urlcol]); y=(df[labelcol].astype(int)==0).astype(int); X=pd.DataFrame([extract_features(str(u)) for u in df[urlcol]],columns=FEATURE_NAMES)
Xtr,Xte,ytr,yte=train_test_split(X,y,test_size=.2,random_state=42,stratify=y); model=RandomForestClassifier(n_estimators=250,max_depth=18,min_samples_leaf=2,class_weight='balanced',random_state=42,n_jobs=-1); model.fit(Xtr,ytr); p=model.predict(Xte)
metrics={'accuracy':accuracy_score(yte,p),'precision':precision_score(yte,p,zero_division=0),'recall':recall_score(yte,p,zero_division=0),'f1':f1_score(yte,p,zero_division=0),'confusion_matrix':confusion_matrix(yte,p).tolist(),'train_rows':len(Xtr),'test_rows':len(Xte),'phishing_rate':float(y.mean())}
joblib.dump(model,OUT/'model.joblib'); (OUT/'feature_names.json').write_text(json.dumps(FEATURE_NAMES,indent=2)); (OUT/'metrics.json').write_text(json.dumps(metrics,indent=2)); print(json.dumps(metrics,indent=2))
