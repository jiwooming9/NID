from nltk.probability import FreqDist
from sklearn.externals import joblib
from nltk import classify
from nltk.classify.naivebayes import NaiveBayesClassifier


try:
    ano = open('../Dataset/Datasets-after-feature-extraction/Naives-Bayes/training/train1_anomalousCombinedWordsss.txt')
    nor = open('../Dataset/Datasets-after-feature-extraction/Naives-Bayes/training/train1_normalCombinedWordsss.txt')
except Exception as e:
    print e


def read_in_chunks(file_object, chunk_size=1024):
    """
        Doc theo khoi 1KB
    """
    while True:
        data = file_object.read(chunk_size)
        if not data:
            break
        yield data

training=[]

"""
    Gan nhan cho tung payload
"""
for piece in read_in_chunks(ano):
    lines=piece.split('\n')
    for words in lines:
        words_separated=[e.lower() for e in words.split()]
        training.append((words_separated,'anomalous'))

for piece in read_in_chunks(nor):
    lines=piece.split('\n')
    for words in lines:
        words_separated=[e.lower() for e in words.split()]
        training.append((words_separated,'normal'))


#print training
joblib.dump(training,'models/training_compressed.pkl',0)

def get_words_in_tweets(training):
    """
        tach tu trong payload
    """
    all_words = []
    for (words, sentiment) in training:
      all_words.extend(words)
    #print all_words
    return all_words

def get_word_features(wordlist):
    """
        tra ve cac tu co tan suat xuat hien nhieu
    """
    wordlist = FreqDist(wordlist)
    #print wordlist.keys(),"------->",wordlist.values()
    return wordlist.keys()

#word_features = get_words_in_tweets(training)
training=joblib.load('models/training_compressed.pkl')
word_features = get_word_features(get_words_in_tweets(training))
joblib.dump(word_features,'models/word_features_compressed.pkl',0)
#print word_features

training=joblib.load('models/training_compressed.pkl')
word_features=joblib.load('models/word_features_compressed.pkl')


def extract_features(document):
    """
        so sanh cac tu trong training voi word_features
    """
    document_words = set(document)
    features = {}
    global word_features	
    for word in word_features:
        features['contains(%s)' % word] = (word in document_words)
    return features

#print extract_features(training[0][0])

training_set = classify.apply_features(extract_features, training)
print "done set"
#print training_set
classifier = NaiveBayesClassifier.train(training_set)
print "done learn"
joblib.dump(classifier, 'models/classifier_compressed.pkl',0)
