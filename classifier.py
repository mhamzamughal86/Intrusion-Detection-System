from sklearn import tree
import pandas 
import string
class DecisionTree():
    
    def __init__(self):
        self.tree_classifier = tree.DecisionTreeClassifier()
        self.__dos = 0
        self.__prob = 0
        self.__normal = 0
        

    def train_classifier(self,dataset, attributes):
        header = list(string.ascii_lowercase[0:19])
        kdd_train = pandas.read_csv(dataset, names=header)
        self.selected_attributes = [x for x,y in enumerate(attributes) if y==1]
        self.selected_index= [header[x] for x, y in enumerate(attributes) if y==1]
        var_train, res_train = kdd_train[self.selected_index], kdd_train[header[18]]
        self.tree_classifier.fit(var_train, res_train)
    def test_dataset(self,packet):
        packet_list = list()
        packet_list.append([packet[x] for x in self.selected_attributes])
        result  = self.tree_classifier.predict(packet_list)
        result = int(result[0])
      
        packet_list.clear()
        return self.__classification(result)
    def __classification(self, status):
        if status == 0:
            self.__normal+=1
            result = 0
        elif status in range(1,6):
            self.__dos+=1
            result = 1
        else:
            self.__prob+=1
            result = 2
        classification = {
            '0' : 'Normal',
            '1' : 'Dos/Neptune',
            '2' : 'Dos/Back',
            '3' : 'Dos/Apache2',
            '4' : 'Dos/Phf',
            '5' : 'Dos/Saint',
            '6' : 'Prob/IpSweep',
            '7' : 'Prob/PortSweep',
            '8' : 'Prob/Satan',
            '9' : 'Prob/Nmap'
        }
        result_class = classification[str(status)]
        return (result, result_class)
    def reset_class_count(self):
        '''Reset the no.of dos,prob and normal count to zero'''
        self.__dos = 0
        self.__prob = 0
        self.__normal = 0
    def get_class_count(self):
        return (self.__normal, self.__dos,self.__prob)
    def get_log(self):
        total = self.__dos+self.__prob+self.__normal
        log = f'Total = {total}\nNormal = {self.__normal}\nDoS = {self.__dos}\nProb = {self.__prob}'
        return log
    @staticmethod
    def get_fitness(var_train, res_train, var_test, res_test):
        #Consume ram<100MB, processor<15%
        clf = tree.DecisionTreeClassifier()
        clf.fit(var_train, res_train)
        return round(clf.score(var_test, res_test),3)