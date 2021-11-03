import Population
import random


class GAAlgorithm():

    def __init__(self,train_dataset, test_dataset, population_size, mutation_rate,gene_length=18):
        self.train_dataset = train_dataset
        self.test_dataset = test_dataset
        self.population_size = population_size
        self.mutation_rate = mutation_rate
        self.gene_length = int(gene_length)
        self.population = Population.Population(self.train_dataset, self.test_dataset, self.population_size, self.gene_length)

    def initialization(self):
        self.population.initialize_population()
    
    def calculate_fitness(self):
        self.population.calculate_fitness()
    
    def selection(self):
        parents = list()
        end = int(self.population_size/2)
        no_of_parents = int(self.population_size/2)
        for x in range(no_of_parents):
            p1 = random.randint(0,end-1)
            p2 = random.randint(end,self.population_size-1)
            parents.append([p1,p2])
        return parents
    def cross_over(self,parents):
        self.population.cross_over(parents)
    
    def mutation(self):
        self.population.mutation(self.mutation_rate)
    
    def clear_population(self):
        self.population.clear_population()
        
    