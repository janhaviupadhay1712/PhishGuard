from backend.ml.feature_extractor import extract_features
def test_feature_extraction():
 f=extract_features('https://example.com/login?verify=1'); assert f['is_https']==1 and f['kw_login']==1
