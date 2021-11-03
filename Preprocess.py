import os

class Dataset():
    @staticmethod
    def refine_dataset(file_path, file_name):
        type_of_services = ['http', 'http_443', 'domain_u']
        directory = os.path.dirname(file_path)
        new_file_path = Dataset.get_new_file_path(directory,file_name)
        with open(file_path, "r") as file:
            with open(new_file_path, "w") as f:
                for x,line in enumerate(file.readlines()):
                    l = line.split(",")
                    if l[2] in type_of_services:
                        f.write(Dataset.get_attributes(l)+"\n")
        return new_file_path
    
    @staticmethod
    def get_new_file_path(directory, file_name):  # Return path of new file
        os.chdir(directory)
        if os.path.exists(file_name):
            os.remove(file_name)
        return os.path.join(os.getcwd(),file_name)
    
    @staticmethod
    def get_attributes(attribute_list):
        index_list = [0,1,2,4,5,6,7,22,23,28,29,30,31,32,33,34,35,36,41]  #41 is attack type
        index = [1,2,41]
        extrated_attributes = []
        for x in index_list:
            if x in index:
                extrated_attributes.append(Dataset.get_mapping(x,attribute_list[x]))
            else:
                extrated_attributes.append(attribute_list[x])
        line = ','.join(extrated_attributes)
        return line

    @staticmethod
    def get_mapping(index, value):
        protocol = {
            'tcp' : '6',
            'udp' : '17'
        }
        service = {
            'http' : '80',
            'http_443' : '443',
            'domain_u' : '53'
        }
        attack = {
            'normal' : '0',
            'neptune' : '1',
            'back' : '2',
            'apache2' : '3',
            'phf' : '4',
            'saint' : '5',
            'portsweep' : '6',
            'ipsweep' : '7',
            'nmap' : '8',
            'satan' : '9'
        }
        if(index==1):
            return protocol[str(value)]
        elif(index==2):
            return service[str(value)]
        elif(index==41):
            return attack[str(value)]
    # Adding dialog box