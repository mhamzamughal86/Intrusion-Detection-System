import Individual
import random


class Population():
    individual = list()
    max_fitness = 0
    max_fittest = list()
    childrens = list()
    def __init__(self,train_dataset,test_dataset,population_size=5, gene_length=18):
        self.population_size = population_size
        self.gene_length=gene_length
        self.train_dataset = train_dataset
        self.test_dataset = test_dataset
        self.no_of_child = self.population_size if (self.population_size%2==0) else self.population_size-1

    def initialize_population(self):
        for x in range(self.population_size):
            self.individual.append(Individual.Individual(self.train_dataset,self.test_dataset))
    
    def calculate_fitness(self):
        for x in range(len(self.individual)):
            self.individual[x].calculate_fitness()
        self.individual = sorted(self.individual, key=self.__get_fitness, reverse=True) #descending sorting
        self.individual = self.individual[0:self.population_size:1] #cut the extra individual with less fitness
        self.max_fittest = self.individual[0].chromosome
        self.max_fitness = self.individual[0].fitness
        
    def __get_fitness(self,ind):
        return ind.fitness
    

    def cross_over(self,parents):
        cut_point = 9  # Or can be generated randomly between range (0 - sizeOfGene)
        c1 = 0
        c2 = 1
        for x in range(self.no_of_child):
            self.childrens.append(Individual.Individual(self.train_dataset,self.test_dataset))
        for parent in parents:
            p1 = self.individual[parent[0]]
            p2 = self.individual[parent[1]]
            self.childrens[c1].chromosome = p2.chromosome[cut_point::] + p1.chromosome[cut_point::]
            self.childrens[c2].chromosome = p1.chromosome[cut_point::] + p2.chromosome[cut_point::]
            c1 = c1+2
            c2 = c2+2
    
    def mutation(self,mutation_rate):
        mutation_rate = float(mutation_rate/100)
        for child in self.childrens:
            gene = child.chromosome
            gene = [self.__flip_bit(gene[x]) if (random.uniform(0,1)<mutation_rate) else gene[x] for x in range(len(gene))]
            child.chromosome = gene
        self.individual.extend(self.childrens)
        self.childrens.clear() # Clear childrens
    
    def __flip_bit(self, bit):
        '''Flip the chromosome bit in mutation process'''  
        return 0  if bit==1 else 1   

    def clear_population(self):
        self.individual.clear()