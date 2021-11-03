import random
import string
import pandas
from classifier import DecisionTree

class Individual:

    chromosome = list()
    fitness = 0
    def __init__(self, train_dataset, test_dataset, gene_length=18):
        self.gene_length=int(gene_length)
        self.chromosome = [random.randint(0,1) for x in range(self.gene_length)]
        self.train_dataset = train_dataset
        self.test_dataset = test_dataset
        self.gene_length = gene_length
        
    
    def calculate_fitness(self):
        header = list(string.ascii_lowercase[0:(self.gene_length+1)])
        kdd_train = pandas.read_csv(self.train_dataset, names=header)
        kdd_test = pandas.read_csv(self.test_dataset, names=header)
        selected_index= [header[x] for x, y in enumerate(self.chromosome) if y==1]
        var_train, res_train = kdd_train[selected_index], kdd_train[header[18]]
        var_test, res_test = kdd_test[selected_index], kdd_test[header[18]]
        self.fitness = self.__get_fitness(var_train, res_train, var_test, res_test)*100
    
    def __get_fitness(self,var_train, res_train, var_test, res_test):
        return DecisionTree.get_fitness(var_train, res_train, var_test, res_test)
    

