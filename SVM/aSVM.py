import json
import numpy as np
import pandas as pd
from numpy import *
import os
from sklearn.externals import joblib
from sklearn.model_selection import train_test_split
from sklearn import svm, metrics


class DimensionalityMissMatchException(Exception):
    pass


class DataSetManager(object):
    def __init__(self):
        self.x_train = None
        self.y_train = None
        self.x_test = None
        self.y_test = None
    def load_data_sets(self):
        self.x_train = loadtxt("data/x_train.csv", delimiter=',', skiprows=1)
        self.y_train = loadtxt("data/y_train.csv")
        self.x_test = loadtxt("data/x_test.csv", delimiter=',', skiprows=1)
        self.y_test = loadtxt("data/y_test.csv")


class MySVM(object):
    def __init__(self, xtrain, ytrain, xtest, ytest):
        self.x_train = xtrain
        self.y_train = ytrain
        self.x_test = xtest
        self.y_test = ytest
        self.targets = None
        self.result_file_path = ''

    def cross_validate_split(self):
        
        self.classify(self.x_train, self.x_test, self.y_train, self.y_test)

    def classify(self, x_train, x_test, y_train, y_test):
        classifier = svm.SVC(gamma=0.001, C=10)
        classifier.fit(x_train, y_train)
        y_pred = classifier.predict(x_test)
        target_names = ['Normal', 'Anomalous']
        print("-------------------------------------------------------------------------------")
        print("Classification report for classifier %s:\n%s\n"
              % (classifier, metrics.classification_report(y_true=y_test, y_pred=y_pred, target_names=target_names)))
        conf_matrix = metrics.confusion_matrix(y_test, y_pred)
        # conf_matrix = np.array([[8616, 299], [0, 0]])
        print("Confusion matrix:\n%s" % conf_matrix)
        train_count, _ = shape(x_train)
        test_count, _ = shape(x_test)
        joblib.dump(classifier,'../Application/gui/models/traininga.pkl',0)
        self.write_to_json(self.calculate_metrics(conf_matrix, 0, train_count, test_count))

    def calculate_metrics(self, conf_matrix, count, train_count, test_count):
        TP = float(conf_matrix[0][0])
        FP = float(conf_matrix[0][1])
        FN = float(conf_matrix[1][0])
        TN = float(conf_matrix[1][1])
        accuracy = ((TP + TN) / (TP + TN + FP + FN)) #ti le phan loai dung
        sensitivity = (TP / (TP + FN)) #ti le phan loai Positive dung trong tong so cac TH Pos
        specificity = (TN / (TN + FP)) #ti le loai tru dung tren tong so cac TH Negative
        precision = (TP / (TP + FP)) #ti le phan loai dung Positive
        print "Accuracy: %.3f " % accuracy
        print "Sensitivity: %.3f " % sensitivity
        print "Specificity: %.3f " % specificity
        print "Precision: %.3f " % precision
        kfold = self.kfolds
        dict_key = str(kfold) + '.' + str(count)
        result = dict(accuracy=accuracy, sensitivity=sensitivity, specificity=specificity, precision=precision, training_data=train_count, testing_data=test_count)
        return {dict_key: result}

    def write_to_json(self, result):
        content = dict()
        if os.path.exists(self.result_file_path):
            with open(self.result_file_path, 'r') as infile:
                content = json.load(infile) if infile else {}
        if content.get(str(self.kfolds)):
            k_content = content.get(str(self.kfolds))
            k_content.update(result)
        else:
            content.update({
                self.kfolds: result
            })
        with open(self.result_file_path, 'w') as outfile:
            json.dump(content, outfile)

    def set_result_file_path(self, filepath):
        self.result_file_path = filepath


if __name__ == "__main__":
    data_manager = DataSetManager()
    data_manager.load_data_sets()
    mysvm = MySVM(data_manager.x_train, data_manager.y_train, data_manager.x_test, data_manager.y_test)
    mysvm.set_result_file_path('Results/testresult.json')
    mysvm.cross_validate_split()

