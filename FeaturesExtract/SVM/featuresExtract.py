import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

data = pd.read_csv('HTTP-CSIC-2010.csv', low_memory=False)
def test(data):
    #Tach 2 bang data va payload
    payload = data.loc[:,("index", "payload","label")]
    data = data.loc[:, ("index","method","url","host","contentLength","cookie","label")]
    data = data.drop_duplicates()
    #Thay cac gia tri thuong gap thanh so
    data = data.replace(["GET", "POST", "PUT"], [1, 2, 3])
    data = data.replace(['localhost:8080', 'localhost:9090'], [0,1])
    data = data.replace(["norm", "anom"], [0,1])
    #Thay gia tri null
    data.loc[:,"contentLength"] = data["contentLength"].fillna(value=0)
    payload.loc[:,"payload"] = payload["payload"].fillna(value="")

    url = data["url"]
    data.insert(3,"digit_path", url.str.count(r'[0-9]')) #So chu so
    data.insert(3,"special_path", url.str.count(r'[^a-zA-Z\d\s\/:\.]')) #Ky tu dac biet
    data.insert(4,"non_an_path", url.str.count(r'[^a-zA-Z\d\s]')) #So ky tu khong phai chu
    data.loc[:,'url'] = data['url'].str.len() #Doi chuoi url thanh so ky tu url
    data.loc[:,'cookie'] = data['cookie'].str.len()
    data = data.rename(columns={"url":"url_length", "cookie":"cookie_length"})
    data = data.set_index("index")
    data = data.drop(columns=["cookie_length"])
    #Tach data 2 phan
    norm = data[data["label"] == 0]
    anom = data[data["label"] == 1]


    #Xu ly payload
    arg_anom = payload[payload['label'] == "anom"].loc[:, ("index", "payload")]
    arg_norm = payload[payload['label'] == "norm"].loc[:, ("index", "payload")]  
    grouped_norm = arg_norm.groupby("index")
    grouped_anom = arg_anom.groupby("index")
    #Do dai payload
    anom.insert(5, "arg_length", grouped_anom.sum()["payload"].str.len())
    norm.insert(5, "arg_length", grouped_norm.sum()["payload"].str.len())
    #So luong dau vao
    anom.insert(6, "arg_num" , grouped_anom.size())
    norm.insert(6, "arg_num" , grouped_norm.size())
    arg_sum_anom = grouped_anom.sum()
    arg_sum_norm = grouped_norm.sum()
    #arg_sum_anom.to_csv("data/arg_sum_anom.csv", index=False)
    #arg_sum_norm.to_csv("data/arg_sum_norm.csv", index=False)
    anom.insert(7,"digit_in_arg", arg_sum_anom["payload"].str.count(r'[0-9]')) #So chu so tai args
    norm.insert(7,"digit_in_arg", arg_sum_norm["payload"].str.count(r'[0-9]'))
    anom.insert(8,"letter_in_arg", arg_sum_anom["payload"].str.count(r'[a-zA-Z]'))#So chu cai tai args
    norm.insert(8,"letter_in_arg", arg_sum_norm["payload"].str.count(r'[a-zA-Z]'))

    total = anom.append(norm) # combine anom and norm
    total = total.reset_index(drop=True) # Reset Index
    #total.to_csv("data/total.csv", index=False)
    total = total.sample(frac=1).reset_index(drop=True) #Tron du lieu
    #Chia du lieu de train
    train = total.iloc[:51065]
    test = total.iloc[51065:].reset_index(drop=True)
    x_train = train.loc[:, train.columns.values[:-1]]
    y_train = train.loc[:, 'label']
    x_test = test.loc[:, test.columns.values[:-1]]
    y_test = test.loc[:,'label']
    x_train.to_csv("../../SVM/data/x_train.csv", index=False)
    y_train.to_csv("../../SVM/data/y_train.csv", index=False)
    x_test.to_csv("../../SVM/data/x_test.csv", index=False)
    y_test.to_csv("../../SVM/data/y_test.csv", index=False)

test(data)
