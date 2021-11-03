# Change testing panel to avoid segmentation fault
from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtGui import QIcon, QPixmap
from PyQt5.QtWidgets import qApp,QFileDialog,QMessageBox,QMainWindow,QDialog,QDialogButtonBox,QVBoxLayout, QHeaderView, QMessageBox
import os
import time
import pyshark
import matplotlib.pyplot as plt 
import threading
import packet as pack
import GAAlgorithm
import Preprocess as data
import classifier


class Ui_MainWindow(object):
    def __init__(self):
        self.tree_classifier = classifier.DecisionTree()
        self.packet = pack.Packet()
        self.trained = False
        self.stop = False
        self.threadActive = False
        self.pause = False
    def plot_graph(self):
        x = ['Normal','DoS','Prob']
        normal,dos,prob = self.tree_classifier.get_class_count()
        y = [normal,dos,prob]
        plt.bar(x,y,width=0.3,label="BARCHART")
        plt.xlabel('Classes')
        plt.ylabel('Count')
        plt.title('Graph Plotting')
        plt.legend()
        plt.show()

    def train_model(self):
        try:
            train_dataset, train_dataset_type = QFileDialog.getOpenFileName(MainWindow, "Select Training Dataset","","All Files (*);;CSV Files (*.csv)")
            if train_dataset:
                os.chdir(os.path.dirname(train_dataset))
                test_dataset, test_dataset_type = QFileDialog.getOpenFileName(MainWindow, "Select Testing Dataset","","All Files (*);;CSV Files (*.csv)")
            if train_dataset and test_dataset:
                generation  = 0
                train_dataset = data.Dataset.refine_dataset(train_dataset, "Train Preprocess.txt")
                
                test_dataset = data.Dataset.refine_dataset(test_dataset, "Test Preprocess.txt")
                #Start Genetic Algorithm
                ga = GAAlgorithm.GAAlgorithm(train_dataset,test_dataset,population_size=5,mutation_rate=65)
                ga.initialization() # if error occur due to invalid dataset population needs to be clear to avoid append of new population
                ga.calculate_fitness()
                while(ga.population.max_fitness<93 and generation<1):
                    print(f"Generation = {generation}")
                    generation+=1
                    parents = ga.selection()
                    ga.cross_over(parents)
                    ga.mutation()
                    ga.calculate_fitness()
                max_fitest = ga.population.max_fittest
                max_fitness = round(ga.population.max_fitness,1)
                self.tree_classifier.train_classifier(train_dataset,max_fitest)
                self.trained = True
                ga.clear_population()
                self.progressBar.setProperty("value", 100)
                self.showdialog('Model train',f'Model trained successfully with {max_fitness} accuracy',1)
                
        except:
            try:
                ga.clear_population()
            except:
                print("Err 00")
            finally:
                self.showdialog('Model train','Model trained unsuccessfully',2)
                

    def static_testing(self):
        if self.isModelTrained():
            if (self.threadActive):
                self.showdialog('Warning','Please stop currently testing',3)
            else:
                test_dataset, train_dataset_type = QFileDialog.getOpenFileName(MainWindow, "Select Testing Dataset","","All Files (*);;CSV Files (*.csv)")
                if test_dataset:
                    try:
                        test_dataset = data.Dataset.refine_dataset(test_dataset, "Test Dataset.txt")
                        t1 = threading.Thread(target=self.static_testing_thread, name = 'Static testing', args=(test_dataset,))
                        t1.start()
                        self.threadActive = True  
                    except:
                        self.showdialog('Error','Invalid Dataset',2)
        else:
            self.showdialog('Warning','Model not trained',3)
        
    def static_testing_thread(self,dataset):
        row = 0
        self.reset_all_content()
        with open(dataset,"r") as file:
            for line in file.readlines():
                try:
                    line = line.split(',')
                    result, result_type = self.tree_classifier.test_dataset(line)
                    self.insert_data(line,result,result_type,row)
                    
                    row+=1 
                    if self.pause:
                        while(self.pause):
                            pass
                    if self.isStop():
                        self.stop=False
                        break 
                    time.sleep(0.05)
                except:
                    print("Err")
        self.threadActive = False


    def realtime_testing(self):
        if self.isModelTrained():
            if (self.threadActive):
                self.showdialog('Warning','Please stop currently testing',3)
            else:
                t2 = threading.Thread(target=self.realtime_testing_thread, name = 'Realtime testing')
                t2.start()
                self.threadActive = True
        else:
            self.showdialog('Warning','Model not trained',3)
    def realtime_testing_thread(self):
        self.reset_all_content()
        self.packet.initiating_packets()
        t1 = time.time()
        attr_list  = list()
        capture = pyshark.LiveCapture(interface='Wi-Fi')
        row = 0
        try:
            for p in capture.sniff_continuously():
                try:
                    if "<UDP Layer>" in str(p.layers) and "<IP Layer>" in str(p.layers):
                        attr_list = self.packet.udp_packet_attributes(p)
                        result, result_type = self.tree_classifier.test_dataset(attr_list)
                        self.insert_data(attr_list,result,result_type,row)
                        print(attr_list)
                        row+=1 
                    elif "<TCP Layer>" in str(p.layers) and "<IP Layer>" in str(p.layers):
                        attr_list = self.packet.tcp_packet_attributes(p)
                        result, result_type = self.tree_classifier.test_dataset(attr_list)
                        self.insert_data(attr_list,result,result_type,row)
                        print(attr_list)
                        row+=1    
                    if (time.time()-t1) > 5 and not self.isStop:  # 5Seconds
                        print("Updateing List")
                        self.packet.initiating_packets()
                        t1 = time.time()
                    if self.pause:
                            while(self.pause):
                                pass
                    if self.isStop():
                        self.stop=False
                        break 
                except :
                    print("Err")
        except :
                print("Error in loooooop")

    def pause_resume(self):
        if self.pause:
            self.pause = False
            self.btn_start.setText("Pause")
        else:
            self.pause = True
            self.btn_start.setText("Resume")
        

    def save_log_file(self):
        log = self.tree_classifier.get_log()
        url = QFileDialog.getSaveFileName(None, 'Save Log', 'untitled', "Text file (*.txt);;All Files (*)")
        if url[0]:
            try:
                name = url[1]
                url = url[0]
                with open(url, 'w') as file:
                    file.write(log)
                self.showdialog('Saved',f'File saved as {url}',1)    
            except:
                self.showdialog('Error','File not saved',2)

    def stop_capturing_testing(self):
        if self.pause:
            self.pause = False
            self.btn_start.setText('Pause')
        if not self.stop:
            self.stop = True
        if self.threadActive:
            self.threadActive = False    
    def reset_all_content(self):
        if self.pause:
            self.pause = False
            self.btn_start.setText('Pause')
        self.stop=False
        self.tree_classifier.reset_class_count()
        self.panel_capturing.clearContents()
        self.panel_capturing.setRowCount(0)
        self.panel_result.clearContents()
        self.panel_result.setRowCount(0)
        self.panel_testing.clear()
        

    def insert_data(self,line,result,result_type,row):
        self.panel_capturing.insertRow(row)
        for column, item  in enumerate(line[0:4:1]):
            self.panel_capturing.setItem(row,column,QtWidgets.QTableWidgetItem(str(item)))
            self.panel_capturing.scrollToBottom()   
        self.panel_testing.clear()
        self.panel_testing.addItem(str(line[0:4:1]))
        if not result==0:
            result_row = self.panel_result.rowCount()
            self.panel_result.insertRow(result_row)
            x = [row+1, line[1], line[2], result_type]
            for column, item  in enumerate(x):
                self.panel_result.setItem(result_row,column,QtWidgets.QTableWidgetItem(str(item)))
                self.panel_result.scrollToBottom()
        
    def clickexit(self):
        buttonReply = QMessageBox.question(MainWindow, 'Exit', "Are ou sure to exit?", QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if buttonReply == QMessageBox.Yes:
            if self.threadActive:
                self.pause = False
                self.stop = True
            qApp.quit()
        else:
            print('No clicked.')
        

        
        
    def isStop(self):
        return self.stop
    def showdialog(self,title,text, icon_type):
        msg = QMessageBox()
        if icon_type==1:
            msg.setIcon(QMessageBox.Information)
        elif icon_type==2:
            msg.setIcon(QMessageBox.Critical)
        elif icon_type==3:
            msg.setIcon(QMessageBox.Warning)
        msg.setText(text)
        msg.setWindowTitle(title)
        msg.setStandardButtons(QMessageBox.Ok)
        msg.buttonClicked.connect(self.msgbtn)
        retval = msg.exec_()
            
    def msgbtn(self):
        self.progressBar.setProperty("value", 0)
    def isModelTrained(self):
        return self.trained
    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        path = os.path.dirname(os.path.abspath(__file__))
        MainWindow.setWindowIcon(QtGui.QIcon(os.path.join(path,'icon.png')))
        MainWindow.resize(908, 844)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(MainWindow.sizePolicy().hasHeightForWidth())
        MainWindow.setSizePolicy(sizePolicy)
        MainWindow.setIconSize(QtCore.QSize(30, 30))
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.gridLayout = QtWidgets.QGridLayout(self.centralwidget)
        self.gridLayout.setObjectName("gridLayout")
        spacerItem = QtWidgets.QSpacerItem(10, 10, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.gridLayout.addItem(spacerItem, 1, 0, 1, 1)
        spacerItem1 = QtWidgets.QSpacerItem(20, 20, QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Maximum)
        self.gridLayout.addItem(spacerItem1, 4, 1, 1, 1)
        spacerItem2 = QtWidgets.QSpacerItem(20, 10, QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Fixed)
        self.gridLayout.addItem(spacerItem2, 6, 1, 1, 1)
        self.horizontalLayout_2 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_2.setObjectName("horizontalLayout_2")
        spacerItem3 = QtWidgets.QSpacerItem(15, 10, QtWidgets.QSizePolicy.Ignored, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout_2.addItem(spacerItem3)
        self.btn_start = QtWidgets.QPushButton(self.centralwidget)

        self.btn_start.setObjectName("btn_start")
        self.btn_start.setText('Pause')
        self.btn_start.clicked.connect(self.pause_resume)
        self.horizontalLayout_2.addWidget(self.btn_start)

        # ####################################################
        self.btn_pause = QtWidgets.QPushButton(self.centralwidget)
        self.btn_pause.setText("Stop Capturing/Testing")
       
        self.btn_pause.setObjectName("btn_pause")
        self.btn_pause.clicked.connect(self.stop_capturing_testing)
        self.horizontalLayout_2.addWidget(self.btn_pause)
        self.gridLayout.addLayout(self.horizontalLayout_2, 8, 1, 1, 1)
        self.horizontalLayout = QtWidgets.QHBoxLayout()
        self.horizontalLayout.setObjectName("horizontalLayout")
        # #####################################################
        self.btn_modeltrain = QtWidgets.QPushButton(self.centralwidget)
        self.btn_modeltrain.setText("Train Model")
       
        self.btn_modeltrain.setObjectName("btn_modeltrain")
        self.btn_modeltrain.clicked.connect(self.train_model)
        self.horizontalLayout.addWidget(self.btn_modeltrain)
        # ######################################################
        self.btn_statictesting = QtWidgets.QPushButton(self.centralwidget)
        self.btn_statictesting.setText("Static Testing")
       
        self.btn_statictesting.setObjectName("btn_statictesting")
        self.btn_statictesting.clicked.connect(self.static_testing)
        self.horizontalLayout.addWidget(self.btn_statictesting)
        # ######################################################
        self.btn_realtimetesting = QtWidgets.QPushButton(self.centralwidget)
        self.btn_realtimetesting.setText("Realtime Testing")
        
        
        self.btn_realtimetesting.setObjectName("btn_realtimetesting")
        self.btn_realtimetesting.clicked.connect(self.realtime_testing)
        self.horizontalLayout.addWidget(self.btn_realtimetesting)

        # ######################################################
        self.btn_savelog = QtWidgets.QPushButton(self.centralwidget)
        self.btn_savelog.setText("Save Log")
        icon5 = QtGui.QIcon()
       
        self.btn_savelog.setObjectName("btn_savelog")
        self.btn_savelog.clicked.connect(self.save_log_file)
        self.horizontalLayout.addWidget(self.btn_savelog)

        # ######################################################
        self.btn_graph = QtWidgets.QPushButton(self.centralwidget)
        self.btn_graph.setText("Plot Graph")
        
        self.btn_graph.setObjectName("btn_graph")
        self.btn_graph.clicked.connect(self.plot_graph)
        self.horizontalLayout.addWidget(self.btn_graph)

        # ######################################################
        self.btn_exit = QtWidgets.QPushButton(self.centralwidget)
        self.btn_exit.setText("Exit")
        
        
        self.btn_exit.setObjectName("btn_exit")
        self.btn_exit.clicked.connect(self.clickexit)
        self.horizontalLayout.addWidget(self.btn_exit)
        # ######################################################
        self.gridLayout.addLayout(self.horizontalLayout, 3, 1, 1, 2)
        spacerItem4 = QtWidgets.QSpacerItem(20, 10, QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Fixed)
        self.gridLayout.addItem(spacerItem4, 8, 1, 1, 1)
        spacerItem5 = QtWidgets.QSpacerItem(20, 10, QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Fixed)
        self.gridLayout.addItem(spacerItem5, 0, 1, 1, 1)
        self.panel_capturing = QtWidgets.QTableWidget(self.centralwidget)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(10)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.panel_capturing.sizePolicy().hasHeightForWidth())
        self.panel_capturing.setSizePolicy(sizePolicy)
        self.panel_capturing.setRowCount(0)
        self.panel_capturing.setColumnCount(4)
        self.panel_capturing.setObjectName("panel_capturing")
        item = QtWidgets.QTableWidgetItem()
        self.panel_capturing.setHorizontalHeaderItem(0, item)
        item = QtWidgets.QTableWidgetItem()
        self.panel_capturing.setHorizontalHeaderItem(1, item)
        item = QtWidgets.QTableWidgetItem()
        self.panel_capturing.setHorizontalHeaderItem(2, item)
        item = QtWidgets.QTableWidgetItem()
        self.panel_capturing.setHorizontalHeaderItem(3, item)
        self.gridLayout.addWidget(self.panel_capturing, 4, 1, 4, 1)
        self.label = QtWidgets.QLabel(self.centralwidget)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.label.sizePolicy().hasHeightForWidth())
        self.label.setSizePolicy(sizePolicy)
        self.label.setLayoutDirection(QtCore.Qt.LeftToRight)
        self.label.setAutoFillBackground(False)
        self.label.setText("")
        path = os.path.dirname(os.path.abspath(__file__))
        path = path + r'\icons'
        self.label.setPixmap(QtGui.QPixmap(os.path.join(path,'logo.jpg')))
        self.label.setScaledContents(True)
        self.label.setAlignment(QtCore.Qt.AlignCenter)
        self.label.setObjectName("label")
        self.gridLayout.addWidget(self.label, 1, 1, 1, 1)
        spacerItem6 = QtWidgets.QSpacerItem(10, 20, QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Fixed)
        self.gridLayout.addItem(spacerItem6, 2, 1, 1, 1)
        self.panel_testing = QtWidgets.QListWidget(self.centralwidget)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.panel_testing.sizePolicy().hasHeightForWidth())
        self.panel_testing.setSizePolicy(sizePolicy)
        self.panel_testing.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOn)
        self.panel_testing.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarAsNeeded)
        self.panel_testing.setObjectName("panel_testing")
        self.gridLayout.addWidget(self.panel_testing, 9, 1, 1, 1)
        self.progressBar = QtWidgets.QProgressBar(self.centralwidget)
        self.progressBar.setProperty("value", 0)
        self.progressBar.setObjectName("progressBar")
        self.gridLayout.addWidget(self.progressBar, 10, 1, 1, 2)
        # ----------------------------------------------------------------- #
        
        self.panel_result = QtWidgets.QTableWidget(self.centralwidget)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(10)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.panel_result.sizePolicy().hasHeightForWidth())
        self.panel_result.setSizePolicy(sizePolicy)
        self.panel_result.setRowCount(0)
        self.panel_result.setColumnCount(4)
        self.panel_result.setObjectName("panel_result")
        item = QtWidgets.QTableWidgetItem()
        self.panel_result.setHorizontalHeaderItem(0, item)
        item = QtWidgets.QTableWidgetItem()
        self.panel_result.setHorizontalHeaderItem(1, item)
        item = QtWidgets.QTableWidgetItem()
        self.panel_result.setHorizontalHeaderItem(2, item)
        item = QtWidgets.QTableWidgetItem()
        self.panel_result.setHorizontalHeaderItem(3, item)
        self.gridLayout.addWidget(self.panel_result, 4,2,6,1)
        # ----------------------------------------------------------------- #
        MainWindow.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(MainWindow)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 908, 26))
        self.menubar.setObjectName("menubar")
        self.menuFile = QtWidgets.QMenu(self.menubar)
        self.menuFile.setObjectName("menuFile")
        self.menuAbout = QtWidgets.QMenu(self.menubar)
        self.menuAbout.setObjectName("menuAbout")
        MainWindow.setMenuBar(self.menubar)
        self.statusbar = QtWidgets.QStatusBar(MainWindow)
        self.statusbar.setObjectName("statusbar")
        MainWindow.setStatusBar(self.statusbar)
        self.actionNew = QtWidgets.QAction(MainWindow)
        self.actionNew.setObjectName("actionNew")
        self.actionOpen = QtWidgets.QAction(MainWindow)
        self.actionOpen.setObjectName("actionOpen")
        self.actionExit = QtWidgets.QAction(MainWindow)
        self.actionExit.setObjectName("actionExit")
        self.actionHelp = QtWidgets.QAction(MainWindow)
        self.actionHelp.setObjectName("actionHelp")
        self.menuFile.addAction(self.actionNew)
        self.menuFile.addAction(self.actionOpen)
        self.menuFile.addSeparator()
        self.menuFile.addAction(self.actionExit)
        self.actionExit.triggered.connect(qApp.quit)
        self.menuAbout.addAction(self.actionHelp)
        self.menubar.addAction(self.menuFile.menuAction())
        self.menubar.addAction(self.menuAbout.menuAction())

        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "ABNIDS"))
        self.btn_start.setStatusTip(_translate("MainWindow", "Pause/Resume"))
        self.btn_pause.setStatusTip(_translate("MainWindow", "Stop"))
        self.btn_modeltrain.setStatusTip(_translate("MainWindow", "Train Model"))
        self.btn_statictesting.setToolTip(_translate("MainWindow", "Stactic Testing"))
        self.btn_statictesting.setStatusTip(_translate("MainWindow", "Static Testing"))
        self.btn_realtimetesting.setStatusTip(_translate("MainWindow", "Real Time Capturing"))
        self.btn_savelog.setToolTip(_translate("MainWindow", "Real Time Capturing"))
        self.btn_savelog.setStatusTip(_translate("MainWindow", "Real Time Capturing"))
        self.btn_graph.setStatusTip(_translate("MainWindow", "Graph"))
        self.btn_exit.setStatusTip(_translate("MainWindow", "Exit"))
        item = self.panel_capturing.horizontalHeaderItem(0)
        item.setText(_translate("MainWindow", "Duration"))
        item = self.panel_capturing.horizontalHeaderItem(1)
        item.setText(_translate("MainWindow", "Protocol"))  
        item = self.panel_capturing.horizontalHeaderItem(2)
        item.setText(_translate("MainWindow", "Service"))
        item = self.panel_capturing.horizontalHeaderItem(3)
        item.setText(_translate("MainWindow", "Src_Bytes"))
        # ---------------------------------------------------- #
        item = self.panel_result.horizontalHeaderItem(0)
        item.setText(_translate("MainWindow", "Packet #"))
        item = self.panel_result.horizontalHeaderItem(1)
        item.setText(_translate("MainWindow", "Protocol"))  
        item = self.panel_result.horizontalHeaderItem(2)
        item.setText(_translate("MainWindow", "Service"))
        item = self.panel_result.horizontalHeaderItem(3)
        item.setText(_translate("MainWindow", "Class"))
        # ---------------------------------------------------- #
        self.menuFile.setTitle(_translate("MainWindow", "File"))
        self.menuAbout.setTitle(_translate("MainWindow", "About"))
        self.actionNew.setText(_translate("MainWindow", "New"))
        self.actionOpen.setText(_translate("MainWindow", "Open"))
        self.actionExit.setText(_translate("MainWindow", "Exit"))
        self.actionHelp.setText(_translate("MainWindow", "Help"))


if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    MainWindow = QtWidgets.QMainWindow()
    ui = Ui_MainWindow()
    ui.setupUi(MainWindow)
    MainWindow.show()
    sys.exit(app.exec_())
